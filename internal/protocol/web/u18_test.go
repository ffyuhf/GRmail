// U18 e2e 全链与深级双语测试（NFR-015 全离线——newU9Env httptest 形态复用）。
// 覆盖：①富文本发送链（登录→POST HTML 态→Submit 捕获 alternative→Sent 副本——
// U17 登记项①收口）②CSV 端点全链（multipart 上传→候选片段——U16 登记项④收口）
// ③纯文本路径零回归（U17 末态等价锚）④五对管理模板深级双语（U16 登记项③收口）。
// 依据：U18 计划书 1.5④⑤⑦；契约 v1.13.0 3.2。
// 修改历史：
//
//	2026-09-26 16:12:00 | 新建 | U18 登记项收尾（计划书步骤 3/4，G2 批准 2026-09-26 15:25:47）
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// u18SentFolderID Sent 文件夹 ID（sentFolderIDOf 同源查询——测试侧直查）。
func u18SentFolderID(t *testing.T, env *u9Env) int64 {
	t.Helper()
	folders, err := env.fds.List(context.Background(), env.mailbox.ID)
	if err != nil {
		t.Fatalf("列文件夹: %v", err)
	}
	for _, f := range folders {
		if f.Kind == "sent" {
			return f.ID
		}
	}
	t.Fatalf("sent 文件夹未初始化")
	return 0
}

// postMultipart multipart 表单 POST（CSV 上传链专用——postForm 为 urlencoded 形态）。
func (e *u9Env) postMultipart(t *testing.T, path, cookie, csrf, field, filename, content string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf)
	fw, _ := mw.CreateFormFile(field, filename)
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, &buf)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie}) // postForm 同形态
	res, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("请求 %s: %v", path, err)
	}
	return res
}

// TestU18RichComposeSentCopyChain 富文本发送链 e2e（U17 登记项①收口）：
// POST body=HTML 态→Submit 捕获 raw 含 alternative 双 part→Sent 文件夹自动副本（blobKey 复用）。
func TestU18RichComposeSentCopyChain(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-u18")

	res := env.postForm(t, "/compose", cookie, "csrf-u18", map[string][]string{
		"action": {"send"}, "to": {"rich@ext.io"}, "subject": {"富文本链"},
		"body": {"<p>富文本<b>正文</b></p>"},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("富文本发送应 303: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
	if len(env.submit.Captured) != 1 {
		t.Fatalf("提交管道应捕获 1 次: %d", len(env.submit.Captured))
	}
	raw := string(env.submit.Raws[0])
	if !strings.Contains(raw, "multipart/alternative") || !strings.Contains(raw, "text/html") {
		t.Fatalf("MIME 应为 alternative 双形态（rfc2046 §5.1.4）: %s", raw)
	}
	if !strings.Contains(raw, "<p>富文本<b>正文</b></p>") {
		t.Fatalf("html part 应含原文 HTML")
	}

	// Sent 副本（U16 archiveSentCopy——blobKey 复用 CAS 幂等）
	items, total, err := env.db.PageList(context.Background(), storage.ListQuery{
		MailboxID: env.mailbox.ID, FolderID: u18SentFolderID(t, env), Limit: 5})
	if err != nil || total != 1 {
		t.Fatalf("Sent 副本应 1 封: total=%d err=%v", total, err)
	}
	detail, err := env.db.GetDetail(context.Background(), env.mailbox.ID, items[0].ID)
	if err != nil {
		t.Fatalf("Sent 副本详情: %v", err)
	}
	sum := sha256.Sum256(env.submit.Raws[0]) // blob_key=hex(SHA-256(raw))——CAS 同源计算
	if detail.BlobKey != hex.EncodeToString(sum[:]) {
		t.Fatalf("Sent 副本应复用提交 blobKey（CAS 幂等）: %q", detail.BlobKey)
	}
}

// TestU18CsvImportEndpointChain CSV 端点全链（U16 登记项④收口）：
// multipart 上传→候选片段渲染（地址+姓名+checkbox）。
func TestU18CsvImportEndpointChain(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-u18")

	csv := "email,name\nalice@ext.io,Alice\nbob@ext.io,Bob\nbad-line\n"
	res := env.postMultipart(t, "/compose/csv-import", cookie, "csrf-u18", "file", "contacts.csv", csv)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("CSV 导入应 200: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
	page := bodyOf(t, res)
	for _, want := range []string{"alice@ext.io", "bob@ext.io", "Alice", "Bob"} {
		if !strings.Contains(page, want) {
			t.Fatalf("候选片段缺少要素 %q page=%.300s", want, page)
		}
	}
}

// TestU18PlainTextPathZeroRegression 纯文本发送路径零回归（U17 交付语义锚——
// web 层 body 字段恒 HTML 态：纯文本正文经 htmlToPlain 派生 plain part+原文 html part；
// 行为等价断言=303+捕获 1 次+主题/正文承载正确，MIME 形态归 U17 构造层矩阵不重锚）。
func TestU18PlainTextPathZeroRegression(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-u18")

	res := env.postForm(t, "/compose", cookie, "csrf-u18", map[string][]string{
		"action": {"send"}, "to": {"plain@ext.io"}, "subject": {"纯文本回归"},
		"body": {"纯文本正文"},
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("纯文本发送应 303: %d", res.StatusCode)
	}
	if len(env.submit.Captured) != 1 {
		t.Fatalf("应捕获 1 次: %d", len(env.submit.Captured))
	}
	raw := string(env.submit.Raws[0])
	if !strings.Contains(raw, "Subject:") || !strings.Contains(raw, "纯文本正文") {
		t.Fatalf("主题与正文承载应正确: %s", raw)
	}
}

// TestU18DeepI18nRender 五对管理模板深级双语（U16 登记项③收口）：
// en 态关键文案呈现+缺省 zh 零回归（管理域键族消费验证）。
func TestU18DeepI18nRender(t *testing.T) {
	// admin/tokens：lang 首参组件直驱（en；G4 增强行形态——AdminMailboxRow 视图模型；
	// D3 B 形态签名增 nav 参——直驱形态传 nil〔AppFrame 降级分支〕）
	w := httptest.NewRecorder()
	if err := templates.AdminMailboxesView(templates.LangEN,
		[]*templates.AdminMailboxRow{{Address: "en@t.io", Status: string(storage.MailboxStatusShadow)}}, "", "csrf", nil).Render(context.Background(), w); err != nil {
		t.Fatalf("admin en 渲染: %v", err)
	}
	for _, want := range []string{"Mailbox accounts", "Create mailbox", "Address", "Actions"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("admin en 缺少 %q", want)
		}
	}
	w = httptest.NewRecorder()
	if err := templates.TokensView(templates.LangEN, nil, "raw-token-x", "", "csrf", nil).Render(context.Background(), w); err != nil {
		t.Fatalf("tokens en 渲染: %v", err)
	}
	for _, want := range []string{"Generate token", "Existing tokens", "No tokens yet", "shown only once"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("tokens en 缺少 %q", want)
		}
	}
	// settings/setup/sieve：Lang 数据字段驱动（string 沿 U16 先例）
	w = httptest.NewRecorder()
	if err := templates.SettingsView(templates.SettingsData{Lang: "en"}).Render(context.Background(), w); err != nil {
		t.Fatalf("settings en 渲染: %v", err)
	}
	for _, want := range []string{"Settings", "SPF verification (rfc7208)", "Session idle timeout"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("settings en 缺少 %q", want)
		}
	}
	w = httptest.NewRecorder()
	if err := templates.SetupView(templates.SetupData{Lang: "en", Step: 1, Total: 6, Title: "Database"}).Render(context.Background(), w); err != nil {
		t.Fatalf("setup en 渲染: %v", err)
	}
	for _, want := range []string{"Setup wizard", "step 1 / 6", "SQLite (built-in default", "Next"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("setup en 缺少 %q", want)
		}
	}
	w = httptest.NewRecorder()
	if err := templates.SieveListView(&templates.SieveListData{Lang: templates.LangEN, CSRF: "csrf"}).Render(context.Background(), w); err != nil {
		t.Fatalf("sieve en 渲染: %v", err)
	}
	for _, want := range []string{"Sieve scripts", "New script", "implicit keep"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("sieve en 缺少 %q", want)
		}
	}
	// 缺省 zh 零回归锚（空 Lang 归 zh）
	w = httptest.NewRecorder()
	if err := templates.SetupView(templates.SetupData{Step: 1, Total: 6, Title: "数据库"}).Render(context.Background(), w); err != nil {
		t.Fatalf("setup zh 渲染: %v", err)
	}
	if !strings.Contains(w.Body.String(), "初始部署") || !strings.Contains(w.Body.String(), "数据库") {
		t.Fatalf("缺省 zh 渲染应与既有行为一致")
	}
}
