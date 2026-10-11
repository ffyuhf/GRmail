// Webmail前端缺陷修复批·批二 web 侧测试（组C~H 续接收尾——计划书 v1.0.0 第三章
// 步骤 1~4 验收锚；G2 批准 2026-10-11 13:28:34）。
// 覆盖：①E1 NoRoute 404 错误整页（完成态）②F9/D8-A /admin/password admin 门卫
// （admin 200/mailbox 403 错误页——域隔离显隐一致）③D10 三入口密码下限（admin
// 行内 create 实链+HashPassword 服务端哨兵——改密双通道/向导经同一哨兵承载）④C15
// 空态出口与未读文案分叉⑤G7 html lang=zh-CN（BCP-47 子标签）/en 直通⑥C12 纯文本
// 正文排版基座（双文档包裹 text/html+pre+style）⑦D5 校验失败附件清空提示（multipart
// 就地呈现分支）⑧common.reload 键渲染（F5 呈现缺陷回归锚）。
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"GRmail/internal/account"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// TestBatch2NoRoute404 E1：完成态未知路径→404 错误整页（ErrorPageView+404 标题+
// 返回首页链接——原空体状态码收口锚；向导态 302 分支由 setupGate 承载不在此测）。
func TestBatch2NoRoute404(t *testing.T) {
	env := newU9Env(t) // ServerConfig.SetupDone 未注入=恒 true（完成态）
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b2")
	res := env.get(t, "/no-such-path-batch2", cookie)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("未知路径应 404: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "<!doctype html>") || !strings.Contains(page, "页面不存在") {
		t.Fatalf("应为 404 错误整页（doctype+标题）: %s", page)
	}
	if !strings.Contains(page, "返回首页") {
		t.Fatal("错误整页应含返回首页出口")
	}
}

// TestBatch2F9AdminPasswordGuard F9/D8-A：/admin/password 增 admin 门卫——admin 主体
// 200 正常表单；mailbox 主体 403 错误整页（原 GET 双主体可达+页面自适应的域隔离
// 显隐矛盾收口锚；POST 侧既有主体校验保持）。
func TestBatch2F9AdminPasswordGuard(t *testing.T) {
	env := newU9Env(t)
	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b2a")
	res := env.get(t, "/admin/password", adminCookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin 主体应 200: %d body=%s", res.StatusCode, bodyOf(t, res))
	}
	if page := bodyOf(t, res); !strings.Contains(page, "修改密码") {
		t.Fatalf("admin 形态应呈现改密表单: %s", page)
	}

	mbCookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b2b")
	res2 := env.get(t, "/admin/password", mbCookie)
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("mailbox 主体应 403: %d", res2.StatusCode)
	}
	page2 := bodyOf(t, res2)
	if !strings.Contains(page2, "<!doctype html>") || !strings.Contains(page2, "无权访问") {
		t.Fatalf("403 应为错误整页（E1 呈现层）: %s", page2)
	}
}

// TestBatch2D10MinLenEntries D10：三入口密码下限统一——admin 行内 create 实链
// （ErrPasswordTooShort→admin.errShortPass 文案）+服务端 HashPassword 哨兵单元
// （改密双通道/向导步 2 经同一哨兵承载，前端 minlength=8 已统一）。
func TestBatch2D10MinLenEntries(t *testing.T) {
	// 服务端哨兵（全部设密入口的公共承载）
	if _, err := account.HashPassword("short7!"); !errors.Is(err, account.ErrPasswordTooShort) {
		t.Fatalf("7 字符应 ErrPasswordTooShort: %v", err)
	}
	if _, err := account.HashPassword("8chars!!"); err != nil {
		t.Fatalf("8 字符应通过: %v", err)
	}

	// admin 行内 create 实链：短密码→页面呈现下限文案（不再静默可设）
	env := newU9Env(t)
	adminCookie := env.u9Session(t, storage.SubjectTypeAdmin, 999, "csrf-b2c")
	res := env.postForm(t, "/admin/mailboxes", adminCookie, "csrf-b2c", map[string][]string{
		"action": {"create"}, "address": {"short-pw@t.io"}, "password": {"short7!"},
	})
	if res.StatusCode != http.StatusOK { // 操作失败重渲染列表页（200+错误横幅）
		t.Fatalf("create 短密码应重渲染: %d", res.StatusCode)
	}
	if page := bodyOf(t, res); !strings.Contains(page, "密码长度至少 8 个字符") {
		t.Fatalf("应呈现 admin.errShortPass 文案: %s", page)
	}
}

// TestBatch2C15EmptyStateExit C15：空态出口与文案分叉——未读筛选空=专属文案+
// 返回收件箱出口（清除筛选）；普通空=原空态文案（语义错位与死路收口锚）。
func TestBatch2C15EmptyStateExit(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b2")
	var inboxID int64
	for _, f := range env.mustFolders(t) {
		if f.Kind == storage.FolderKindInbox {
			inboxID = f.ID
		}
	}

	res := env.getWithHeaders(t, "/mails?folder="+itoa(inboxID)+"&unread=1", cookie,
		map[string]string{"HX-Request": "true"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("未读空态状态: %d", res.StatusCode)
	}
	frag := bodyOf(t, res)
	if !strings.Contains(frag, "没有未读邮件") {
		t.Fatalf("未读空态应专属文案（mail.emptyUnread）: %s", frag)
	}
	if !strings.Contains(frag, "返回收件箱") {
		t.Fatal("未读空态应含返回收件箱出口（mail.backInbox）")
	}

	res2 := env.get(t, "/mails?folder="+itoa(inboxID), cookie) // 非 HX 整页（普通空态）
	page := bodyOf(t, res2)
	if !strings.Contains(page, "此文件夹暂无邮件") {
		t.Fatalf("普通空态应保持原文案: %s", page)
	}
	if strings.Contains(page, "没有未读邮件") {
		t.Fatal("普通空态不应复用未读文案（分叉锚）")
	}
}

// TestBatch2LangAttr G7：html lang 属性 BCP-47——zh 缺省输出 zh-CN（zh 语区规范
// 子标签）；en 直通（Lang 枚举值保持 zh 零迁移——仅输出属性映射）。
func TestBatch2LangAttr(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b2")
	res := env.get(t, "/compose", cookie)
	page := bodyOf(t, res)
	if !strings.Contains(page, `<html lang="zh-CN"`) {
		t.Fatalf("zh 应输出 zh-CN（BCP-47）: %s", page[:min(400, len(page))])
	}

	// en cookie（双 cookie 手工请求——getWithHeaders 单 cookie 形态限制）
	req, err := http.NewRequest("GET", env.ts.URL+"/compose", nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Cookie", sessionCookieName+"="+cookie+"; lang=en")
	res2, rerr := http.DefaultClient.Do(req)
	if rerr != nil {
		t.Fatalf("请求: %v", rerr)
	}
	defer func() { _ = res2.Body.Close() }()
	page2 := bodyOf(t, res2)
	if !strings.Contains(page2, `<html lang="en"`) {
		t.Fatalf("en 应直通输出: %s", page2[:min(400, len(page2))])
	}
}

// TestBatch2PlainBodyDocBase C12：纯文本正文经 /mails/{id}/body 双文档包裹——
// text/html+排版基座（style 注入+pre 等宽；原 text/plain 呈现包裹后 HTML 源码的
// 落码缺口修正锚——iframe 内排版基线收口）。
func TestBatch2PlainBodyDocBase(t *testing.T) {
	env := newU9Env(t)
	ctx := context.Background()
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b2")

	raw := []byte("From: ext@x.io\r\nTo: u9@t.io\r\nSubject: plaintext\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n批二纯文本正文行")
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	if err := env.blobs.Write(ctx, blobKey, raw); err != nil {
		t.Fatalf("blob 写入: %v", err)
	}
	var inboxID int64
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

	res := env.get(t, "/mails/"+itoa(uid)+"/body", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("body 端点状态: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("纯文本包裹后应 text/html（排版基座承载）: %s", ct)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "<style>") || !strings.Contains(page, "<pre") {
		t.Fatalf("应含基座样式与 pre 等宽容器: %s", page)
	}
	if !strings.Contains(page, "批二纯文本正文行") {
		t.Fatal("正文内容缺失")
	}
}

// TestBatch2ComposeAttachRepick D5：校验失败+multipart 附件→就地呈现+附件清空
// 提示（attachRePick——multipart 重渲染 file input 必空的用户告知；刷新重放零
// 副作用分支承载）。
func TestBatch2ComposeAttachRepick(t *testing.T) {
	env := newU9Env(t)
	cookie := env.u9Session(t, storage.SubjectTypeMailbox, env.mailbox.ID, "csrf-b2")

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("csrf_token", "csrf-b2")
	_ = w.WriteField("action", "send")
	_ = w.WriteField("to", "") // 空 To 触发校验失败
	_ = w.WriteField("subject", "d5")
	_ = w.WriteField("body", "<p>d5</p>")
	fw, _ := w.CreateFormFile("attachments", "note.txt")
	_, _ = fw.Write([]byte("attachment-bytes"))
	_ = w.Close()

	req, err := http.NewRequest("POST", env.ts.URL+"/compose", &buf)
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
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("校验失败应 400: %d", res.StatusCode)
	}
	page := bodyOf(t, res)
	if !strings.Contains(page, "收件人不能为空") {
		t.Fatalf("应含校验错误文案: %s", page)
	}
	if !strings.Contains(page, "附件选择已被清空") {
		t.Fatalf("应含附件重选提示（compose.attachRePick）: %s", page)
	}
}

// TestBatch2ReloadKeyRender F5 回归锚：common.reload 键已定义（Tr 不回落键名——
// 无邮箱视图「刷新」呈现而非字面 common.reload）。
func TestBatch2ReloadKeyRender(t *testing.T) {
	for _, lang := range []templates.Lang{templates.LangZH, templates.LangEN} {
		if got := templates.Tr(lang, "common.reload"); got == "common.reload" {
			t.Fatalf("common.reload 键缺失（%s 渲染回落键名）", lang)
		}
	}
}
