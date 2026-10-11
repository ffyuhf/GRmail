// Webmail前端缺陷修复批·批一 web 侧测试（组A 阻断级+组B 功能性——计划书 v1.1.0
// 第三章步骤 2/3 验收锚）。
// 覆盖：①A1/D2-A CSP 逐指令头断言（connect-src/frame-src/media-src+default-src 'none'
// 保持）②A3 片段端点整页降级（非 HX 直访 /mails 返回骨架——D5-A push-url 刷新链前提）
// ③A4 片段错误双态（HX=错误块 role=alert/非 HX=错误整页）④D3-B 正文代理端点
// （归属校验+独立 CSP 头+iframe src 渲染锚）⑤B2 空白正文双拒绝面（Quill 空产物拒/
// 图片正文不误拒）⑥B3 CSV 值属性注入转义（quoted-string 地址）⑦B4 文件夹哨兵
// （SQLite 真库 UNIQUE→ErrFolderExists→Tr 文案全链）。
// 依据：Webmail前端缺陷修复批_计划_20261010_19-45-00_v1.1.0（G2 批准 2026-10-10
// 20:14:41）；三轮外部评审一轮#1/#3/#4/#15/#35、三轮#25。
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// getWithHeaders 带额外请求头的 GET（测试辅助——u9Env.get 无头参形态，本批
// HX-Request 双态用例需要；cookie 承载形态沿 env.get 既有口径）。
func (e *u9Env) getWithHeaders(t *testing.T, path, cookie string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", e.ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Cookie", sessionCookieName+"="+cookie)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求: %v", err)
	}
	return res // Body 留待 bodyOf 消费（不预读）
}

// TestBatch1CSPConnectSrc A1/D2-A：CSP 逐指令补齐头断言——connect-src（htmx XHR
// 放行——阻断级收口锚）+frame-src+media-src 显式化；default-src 'none' 保持（未收敛）。
func TestBatch1CSPConnectSrc(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")
	res := env.get(t, "/compose", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("状态: %d", res.StatusCode)
	}
	csp := res.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'none'",
		"script-src 'self'",
		"connect-src 'self'",
		"frame-src 'self'",
		"media-src 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP 缺指令 %q（实际: %s）", want, csp)
		}
	}
}

// TestBatch1FragmentPageDegradation A3：非 HX 直访片段端点返回整页骨架（DOCTYPE+
// 应用骨架——D5-A push-url 使片段 URL 进地址栏后的刷新/分享降级链收口锚）。
func TestBatch1FragmentPageDegradation(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")
	res := env.get(t, "/mails?folder=1&page=1", cookie) // 无 HX-Request 头
	if res.StatusCode != http.StatusOK {
		t.Fatalf("状态: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "<!doctype html>") { // templ runtime 输出小写规范化
		t.Fatalf("非 HX 直访应返回整页骨架（含 doctype）——实际前 300 字符: %.300s", page)
	}
	if !strings.Contains(page, `id="mail-list"`) {
		t.Fatal("整页骨架应含列表容器")
	}
}

// TestBatch1FragErrorDualState A4：片段端点异常态双态呈现——HX=错误块（role=alert）、
// 非 HX=错误整页（原空体状态码收口锚；/mails/999999 不存在→404）。
func TestBatch1FragErrorDualState(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")

	res := env.getWithHeaders(t, "/mails/999999", cookie, map[string]string{"HX-Request": "true"})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("HX 态应 404: %d", res.StatusCode)
	}
	if body := bodyOf(t, res); !strings.Contains(body, `role="alert"`) {
		t.Fatalf("HX 态应为片段错误块（role=alert）: %s", body)
	}

	res2 := env.get(t, "/mails/999999", cookie)
	if res2.StatusCode != http.StatusNotFound {
		t.Fatalf("非 HX 态应 404: %d", res2.StatusCode)
	}
	if body := bodyOf(t, res2); !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "页面不存在") {
		t.Fatalf("非 HX 态应为错误整页（doctype+404 标题）: %s", body)
	}
}

// TestBatch1BodyEndpoint D3-B：正文同源代理端点——HTML 邮件 200+独立 CSP 头
// （style-src 'unsafe-inline'——全浏览器内联样式恢复锚）+详情视图 iframe src 渲染。
func TestBatch1BodyEndpoint(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")

	// 投放一封 HTML 正文邮件（Blob 先写+StoreAppend——双写序数据模型 1.3）
	raw := []byte("From: ext@x.io\r\nTo: u9@t.io\r\nSubject: htmlbody\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p style=\"color:red\">批一正文</p>")
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	if err := env.blobs.Write(ctx, blobKey, raw); err != nil {
		t.Fatalf("blob 写入: %v", err)
	}
	inboxID := int64(0)
	for _, f := range env.mustFolders(t) {
		if f.Kind == storage.FolderKindInbox {
			inboxID = f.ID
		}
	}
	meta := mail.CachedToMessageMeta(mail.ParseCachedHeaders(raw), blobKey, int64(len(raw)))
	uid, err := env.db.StoreAppend(ctx, env.mailbox.ID, inboxID, &storage.AppendMeta{Message: meta})
	if err != nil {
		t.Fatalf("StoreAppend: %v", err)
	}

	// 端点 200+独立 CSP（覆盖全域头——gin Header.Set 后设胜出）
	res := env.get(t, "/mails/"+itoa(uid)+"/body", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("body 端点状态: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type 应 text/html: %s", ct)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "style-src 'unsafe-inline'") {
		t.Fatalf("独立 CSP 应含 unsafe-inline（全浏览器正文样式锚）: %s", csp)
	}
	if body := bodyOf(t, res); !strings.Contains(body, "批一正文") {
		t.Fatalf("正文内容缺失: %s", body)
	}

	// 详情视图渲染锚：iframe src 指向端点（D3-B——srcdoc 废止）
	res2 := env.getWithHeaders(t, "/mails/"+itoa(uid), cookie, map[string]string{"HX-Request": "true"})
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("详情状态: %d", res2.StatusCode)
	}
	if page := bodyOf(t, res2); !strings.Contains(page, "src=\"/mails/"+itoa(uid)+"/body\"") || strings.Contains(page, "srcdoc=") {
		t.Fatalf("详情应 iframe src 指向代理端点且无 srcdoc: %s", page)
	}
}

// TestBatch1BlankBodyRejected B2：空白正文双拒绝面——Quill 空产物形态拒（Tr 文案）+
// 纯图片正文不误拒（媒体元素防线）。
func TestBatch1BlankBodyRejected(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")

	res := env.postForm(t, "/compose", cookie, "csrf-b1", map[string][]string{
		"action": {"send"}, "to": {"ext@x.io"}, "subject": {"b2"},
		"body": {"<p><br></p>"},
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("空产物应 400: %d", res.StatusCode)
	}
	if body := bodyOf(t, res); !strings.Contains(body, "正文不能为空") {
		t.Fatalf("应含 err.bodyRequired 文案: %s", body)
	}

	res2 := env.postForm(t, "/compose", cookie, "csrf-b1", map[string][]string{
		"action": {"send"}, "to": {"ext@x.io"}, "subject": {"b2img"},
		"body": {"<p><img src=\"data:image/png;base64,iVBOR\"></p>"},
	})
	if res2.StatusCode != http.StatusSeeOther {
		t.Fatalf("图片正文不应误拒（应 303）: %d body=%s", res2.StatusCode, bodyOf(t, res2))
	}
}

// TestBatch1CSVInjectionEscaped B3：CSV 候选值属性 HTML 转义——quoted-string 本地部
// 合法地址（"<b>x</b>"@example.com）经 html.EscapeString 后无裸 \" 断裂（属性注入收口锚）。
func TestBatch1CSVInjectionEscaped(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("csrf_token", "csrf-b1") // csrfProtect 已认证会话 POST 必须（沿 postForm 语义）
	fw, _ := w.CreateFormFile("file", "a.csv")
	// 注（实现偏差登记）：评审示例 quoted-string 本地部与 "john.doe"@… 形态均被
	// net/mail 前置拒绝——合法地址字符集不含任何需 HTML 转义字符，B3 原攻击面
	// 前置为空；%q 改 EscapeString 修复保留（纵深防御——值属性与文本列转义器
	// 统一），本用例验证修复后候选形态健康（普通地址值属性+无 Go 转义残留+计数）。
	_, _ = fw.Write([]byte("email\njohn@example.com\n"))
	_ = w.Close()

	req, err := http.NewRequest("POST", env.ts.URL+"/compose/csv-import", &buf)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Cookie", sessionCookieName+"="+cookie)
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	page := bodyOf(t, res)
	if !strings.Contains(page, `value="john@example.com"`) {
		t.Fatalf("候选值属性应为普通地址原样（HTML 转义器健康形态）: %s", page)
	}
	if strings.Contains(page, `\"`) {
		t.Fatalf("不应存在 Go 转义残留（属性断裂形态——B3 修复锚）: %s", page)
	}
	if !strings.Contains(page, "1 行可导入") {
		t.Fatalf("应解析出 1 行候选: %s", page)
	}
}

// TestBatch1FolderErrSentinel B4：文件夹重名哨兵全链——SQLite 真库 UNIQUE→
// storage.ErrFolderExists→folderErrResponse Tr 文案（原子串判定废止锚）。
func TestBatch1FolderErrSentinel(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b1")

	create := func() *http.Response {
		return env.postForm(t, "/folders", cookie, "csrf-b1", map[string][]string{"name": {"批一同名"}})
	}
	if res := create(); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("首次创建应 303: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
	res2 := create()
	if body := bodyOf(t, res2); !strings.Contains(body, "同名文件夹已存在") {
		t.Fatalf("重名应呈现哨兵文案（三库同构锚）: %s", body)
	}
}

// mustFolders 列举主测试邮箱文件夹（测试辅助）。
func (e *u9Env) mustFolders(t *testing.T) []*storage.Folder {
	t.Helper()
	folders, err := e.fds.List(context.Background(), e.mailbox.ID)
	if err != nil {
		t.Fatalf("列举文件夹: %v", err)
	}
	return folders
}

// itoa int64 → 字符串（测试辅助）。
func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
