// GRmail Webmail 写信/草稿/搜索（U9 计划书步骤 8/9；U17 富文本扩展）。
// 写信依据：Q5-A 裁决（2026-09-19 01:55:24——纯文本+multipart 附件；草稿最小闭环；
// 发件身份 mailbox=自身地址、admin=任意本域地址 FR-002；经 SubmissionPipeline.Submit
// 复用授权/DKIM/入队链——流程设计 3.1「Webmail 发信」同链路）；契约 v1.5.0 3.2。
// 授权口径：FR-002 授权判定在 web 会话层完成（requireAuth+subject_type——admin 主体
// 有权任意 From）；管道 authorizeSender 的一致性校验经 AuthUser=From 机械满足（SMTP
// 会话防线面向真实认证身份，web 语义等价——计划书 1.5 登记）。
// 草稿依据：Drafts 文件夹 StoreAppend（同 U6 APPEND 路径）+编辑覆盖（旧稿 HardDelete）。
// 搜索依据：Q6-A（2026-09-19 01:56:06——仅元数据缓存列 OR LIKE，跨文件夹全局）。
// U16 增量：草稿/Sent 副本 BodyCache 填充（Q3-A 四写入路径之四）+Sent 文件夹自动副本
// （Q4-A——web 层插入，仅 Webmail 路径，SMTP 客户端 APPEND 自存不重复）+CSV 批量收件人
// 导入端点（Q5-A——服务端解析，契约 v1.12.0 3.2）。
// U17 增量：富文本写信（Q2/Q3 裁决——契约 v1.13.0）：body 字段承载编辑器 HTML 态+
// 构造层 htmlBody 参数（multipart/alternative 双形态——rfc2046 §5.1.4）+草稿回填
// BodyHTML 优先（富文本草稿再编辑不失真——G3）。
// 修改历史：
//
//	2026-09-19 10:40:00 | 新建 | U9 Webmail 核心（计划书步骤 8/9，G2 批准 2026-09-19 10:00:41）
//	2026-09-24 16:42:00 | 扩展 | U16 Webmail 体验收尾（计划书步骤 3/6，G2 批准 2026-09-24 11:51:57）：
//	  草稿 BodyCache 填充+Sent 副本（archiveSentCopy 尽力语义）+CSV 导入端点+错误文案 i18n 化
//	2026-09-24 23:06:00 | 扩展 | U17 富文本编辑器（计划书步骤 4，G2 批准 2026-09-24 22:51:39）：
//	  BuildOutgoingMail htmlBody 调用+fillFromDraft HTML 优先分支
package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// composeData 收敛至 templates.ComposeData（跨包拍平——web 仅装配）。

// applyEditorConf 编辑器压缩参数注入（D8#11——S4-W Q2-A 裁决「config 承载+模板
// data-* 注入」；CfgSnapshot nil=测试形态，兜底 U22 既有缺省档 1920/0.85）。
func (s *Server) applyEditorConf(d *templates.ComposeData) {
	d.ImageMaxEdge, d.JpegQuality = 1920, 0.85
	if s.cfg.CfgSnapshot == nil {
		return
	}
	if cfg := s.cfg.CfgSnapshot(); cfg != nil {
		if cfg.Editor.ImageMaxEdge > 0 {
			d.ImageMaxEdge = cfg.Editor.ImageMaxEdge
		}
		if cfg.Editor.JpegQuality > 0 && cfg.Editor.JpegQuality <= 1 {
			d.JpegQuality = cfg.Editor.JpegQuality
		}
	}
}

// composeGET 写信页（GET /compose）：空表单 / ?reply={id} 回信预填（G8）/ ?draft={id}
// 草稿再编辑回填（Q5-A 草稿最小闭环）。
func (s *Server) composeGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	sess, _ := currentSession(c)
	data := &templates.ComposeData{Lang: string(langOf(c)), IsAdmin: view.IsAdmin, CSRF: sess.CSRFToken, Nav: s.sidebarDataFor(c)}
	s.applyEditorConf(data) // D8#11：压缩参数快照注入（CfgSnapshot 热加载态——每渲染取最新）
	ctx := c.Request.Context()

	// 管理员主体增强批次 G5（D12）：发件地址默认预填当前视图主邮箱（admin=主邮箱/
	// postmaster 地址——空置消除）；Domain 供前端前缀自动补 @主域（mailbox 主体
	// from 输入框不呈现——发信自身地址语义保持）。
	if view.IsAdmin {
		data.From = view.Label
	}
	data.Domain = s.cfg.Domain

	if rid := c.Query("reply"); rid != "" {
		if id, e := strconv.ParseInt(rid, 10, 64); e == nil && id > 0 {
			if msg, e := s.messages.GetDetail(ctx, view.MailboxID, id); e == nil {
				data.To = msg.FromAddr
				if !strings.HasPrefix(strings.ToLower(msg.Subject), "re:") {
					data.Subject = "Re: " + msg.Subject
				} else {
					data.Subject = msg.Subject
				}
			}
		}
	}
	if did := c.Query("draft"); did != "" {
		if id, e := strconv.ParseInt(did, 10, 64); e == nil && id > 0 {
			s.fillFromDraft(c, view, data, id)
		}
	}
	renderPage(c, http.StatusOK, templates.ComposeView(data))
}

// fillFromDraft 草稿回填（blob 读+ParseDisplay 正文+缓存列收件人/主题；附件不回传——
// 编辑态需重新附加，Q5-A 最小闭环口径）。
func (s *Server) fillFromDraft(c *gin.Context, view *mailboxView, data *templates.ComposeData, id int64) {
	ctx := c.Request.Context()
	msg, err := s.messages.GetDetail(ctx, view.MailboxID, id)
	if err != nil {
		return
	}
	if raw, rerr := s.blobs.Read(ctx, msg.BlobKey); rerr == nil {
		if display, derr := mail.ParseDisplay(raw); derr == nil {
			// U17：富文本草稿 HTML 优先回填（编辑器注入态）；纯文本草稿回退既有路径
			data.Body = display.BodyText
			if display.BodyHTML != "" {
				data.Body = display.BodyHTML
			}
		}
	}
	data.To = trimJSONList(msg.ToAddrs)
	data.Cc = trimJSONList(msg.CcAddrs)
	data.Subject = msg.Subject
	data.DraftID = msg.ID
}

// trimJSONList 缓存列 JSON 数组串 → 逗号分隔表单值（["a@x","b@y"] → a@x, b@y）。
func trimJSONList(jsonArr string) string {
	if jsonArr == "" {
		return ""
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(jsonArr, "["), "]")
	inner = strings.ReplaceAll(inner, "\"", "")
	return strings.Join(strings.FieldsFunc(inner, func(r rune) bool { return r == ',' }), ", ")
}

// composePOST 写信提交（POST /compose）：action=send 发送入队 / save_draft 存草稿。
// 附件经 multipart files（内存态——上限 35MiB 与 SIZE 缺省档同源防御）。
func (s *Server) composePOST(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	sess, _ := currentSession(c)
	data := &templates.ComposeData{
		Nav:  s.sidebarDataFor(c), // D3 B 形态——全站侧栏
		Lang: string(langOf(c)),   // U16 Q2-A：双语渲染
		To:   c.PostForm("to"), Cc: c.PostForm("cc"), Bcc: c.PostForm("bcc"),
		Subject: c.PostForm("subject"), Body: c.PostForm("body"),
		From: strings.TrimSpace(c.PostForm("from")), IsAdmin: view.IsAdmin,
		DraftID: parseFormInt64(c.PostForm("draft_id")), CSRF: sess.CSRFToken,
	}
	s.applyEditorConf(data) // D8#11：压缩参数快照注入（POST 重渲染路径同载）
	if serr := s.composeValidate(c, data); serr != "" {
		data.ErrText = serr
		renderPage(c, http.StatusBadRequest, templates.ComposeView(data))
		return
	}
	attachments, aerr := readFormAttachments(c)
	if aerr != nil {
		data.ErrText = aerr.Error()
		renderPage(c, http.StatusBadRequest, templates.ComposeView(data))
		return
	}

	// 发件身份定夺（Q5-A）：mailbox 主体 From=自身地址（MailboxRepo.ListByStatus(active)
	// 按 ID 反查——单管理员规模推导，零契约增量）；admin 主体 From=表单值（本域校验）
	from, ferr := s.ensureFromAddr(c, view, data.From)
	if ferr != "" {
		data.ErrText = ferr
		renderPage(c, http.StatusForbidden, templates.ComposeView(data))
		return
	}
	data.From = from

	// U17（Q3 裁决）：body 字段承载编辑器 HTML 态——构造层 htmlBody 消费
	// （multipart/alternative 双 part——plain 由 htmlToPlain 派生）
	raw, berr := mail.BuildOutgoingMail(from, data.To, data.Cc, data.Subject, "", data.Body, attachments)
	if berr != nil {
		data.ErrText = "邮件构造失败：" + berr.Error()
		renderPage(c, http.StatusBadRequest, templates.ComposeView(data))
		return
	}

	action := c.PostForm("action")
	switch action {
	case "send":
		if serr := s.composeSend(c, view, data, from, raw); serr != "" {
			data.ErrText = serr
			renderPage(c, http.StatusInternalServerError, templates.ComposeView(data))
			return
		}
		c.Redirect(http.StatusSeeOther, "/")
	case "save_draft":
		if serr := s.composeSaveDraft(c, view, data, raw); serr != "" {
			data.ErrText = serr
			renderPage(c, http.StatusInternalServerError, templates.ComposeView(data))
			return
		}
		c.Redirect(http.StatusSeeOther, "/?folder="+strconv.FormatInt(s.draftsFolderIDOf(c, view), 10))
	default:
		c.Status(http.StatusBadRequest)
	}
}

// composeValidate 表单校验（收件人/主题/正文非空——Bcc 允许空；admin From 由后续域校验）。
func (s *Server) composeValidate(c *gin.Context, d *templates.ComposeData) string {
	switch {
	case strings.TrimSpace(d.To) == "" && strings.TrimSpace(d.Bcc) == "":
		return "收件人不能为空"
	case strings.TrimSpace(d.Subject) == "":
		return "主题不能为空"
	case d.Body == "":
		return "正文不能为空"
	}
	return ""
}

// ensureFromAddr 发件身份定夺（Q5-A 双主体语义）：
// admin 主体 → 表单 From（必填+本域后缀校验——FR-002 任意本域地址）；
// mailbox 主体 → 自身地址（MailboxRepo.ListByStatus(active) 按 subject_id 反查——
// 契约 2.1 既有五方法内路径，单管理员规模三态枚举推导零签名增量）。
// 返回：定夺地址；错误提示（空串=通过）。
func (s *Server) ensureFromAddr(c *gin.Context, view *mailboxView, formFrom string) (string, string) {
	if view.IsAdmin {
		if formFrom == "" {
			return "", "发件地址不能为空"
		}
		if !strings.HasSuffix(strings.ToLower(formFrom), "@"+strings.ToLower(s.cfg.Domain)) {
			return "", "发件地址须为本域地址（FR-002）"
		}
		return formFrom, ""
	}
	mailboxes, err := s.mailboxes.ListByStatus(c.Request.Context(), storage.MailboxStatusActive)
	if err != nil {
		sessLogger(c).Error("发件身份反查失败", "error", err)
		return "", "发件身份解析失败，请稍后重试"
	}
	for _, m := range mailboxes {
		if m.ID == view.MailboxID {
			return m.Address, ""
		}
	}
	return "", "发件身份解析失败（邮箱状态异常）"
}

// composeSend 发送入队（SubmissionPipeline 复用——流程设计 3.1 同链路）。
// AuthUser=From（一致性分支机械满足——web 会话层已完成 FR-002 授权判定）。
func (s *Server) composeSend(c *gin.Context, view *mailboxView, data *templates.ComposeData, from string, raw []byte) string {
	recipients := mail.SplitRecipients(data.To + "," + data.Cc + "," + data.Bcc)
	if len(recipients) == 0 {
		return "收件人地址非法"
	}
	err := s.submit.Submit(c.Request.Context(), &mail.Submission{
		Envelope: auth.Envelope{
			Helo: "webmail", RemoteIP: net.ParseIP(c.ClientIP()), MailFrom: from,
		},
		AuthUser:   from,
		Recipients: recipients,
	}, raw)
	if err != nil {
		sessLogger(c).Error("发送入队失败", "error", err)
		return "发送失败（已记录，请稍后重试）"
	}
	// 编辑态发送：旧草稿清理（覆盖语义）
	if data.DraftID > 0 {
		if derr := s.messages.HardDelete(c.Request.Context(), []int64{data.DraftID}); derr != nil {
			sessLogger(c).Warn("发送后旧草稿清理失败", "draft_id", data.DraftID, "error", derr)
		}
	}
	// U16 Q4-A：Sent 文件夹自动副本（仅 Webmail 路径——SMTP 客户端经 IMAP APPEND 自存
	// 已覆盖标准路径不重复；blobKey 复用 CAS 幂等零重写；尽力失败语义——失败 Warn
	// 不改变发送成功结果，沿 TouchLastUsed 先例）
	s.archiveSentCopy(c, view, data, raw)
	sessLogger(c).Info("Webmail 发送入队", "rcpts", len(recipients), "log_id", c.GetString(ctxKeyLogID))
	return ""
}

// archiveSentCopy 发送成功后 Sent 文件夹自动副本（U16 Q4-A——U9 登记项①收口）。
// 实现：blobKey=SHA-256(raw) 复用（Submit 已写 Blob——CAS 幂等零重写）+StoreAppend
// （sent 系统文件夹——沿 Drafts 同路径）；meta 与草稿同构（BodyCache 填充——
// Q3-A 出站信正文可检索）；失败 Warn 尽力（已入队事实不回滚）。
// 参数：c 请求上下文（日志）；view 主体视图；data 表单（From 展示态）；raw 发送原始字节。
// 返回：无（尽力语义——错误仅记日志）。
func (s *Server) archiveSentCopy(c *gin.Context, view *mailboxView, data *templates.ComposeData, raw []byte) {
	ctx := c.Request.Context()
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	folderID := s.sentFolderIDOf(c, view)
	if folderID <= 0 {
		sessLogger(c).Warn("Sent 副本跳过（sent 文件夹不可用）", "mailbox_id", view.MailboxID)
		return
	}
	meta := mail.CachedToMessageMeta(mail.ParseCachedHeaders(raw), blobKey, int64(len(raw)))
	meta.BodyCache = mail.BodyCacheOf(raw)
	if _, err := s.messages.StoreAppend(ctx, view.MailboxID, folderID, &storage.AppendMeta{Message: meta}); err != nil {
		sessLogger(c).Warn("Sent 副本写入失败（发送不受影响）", "error", err)
	}
}

// sentFolderIDOf 定位 Sent 系统文件夹（缺位 0——沿 draftsFolderIDOf 先例）。
func (s *Server) sentFolderIDOf(c *gin.Context, view *mailboxView) int64 {
	folders, err := s.folders.List(c.Request.Context(), view.MailboxID)
	if err != nil {
		return 0
	}
	for _, f := range folders {
		if f.Kind == storage.FolderKindSent {
			return f.ID
		}
	}
	return 0
}

// composeSaveDraft 草稿保存（Blob 先写+StoreAppend(Drafts)——双写顺序数据模型 1.3；
// 编辑态旧稿覆盖删除）。
func (s *Server) composeSaveDraft(c *gin.Context, view *mailboxView, data *templates.ComposeData, raw []byte) string {
	ctx := c.Request.Context()
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	if err := s.blobs.Write(ctx, blobKey, raw); err != nil {
		sessLogger(c).Error("草稿 blob 写入失败", "error", err)
		return "草稿保存失败"
	}
	folderID := s.draftsFolderIDOf(c, view)
	if folderID <= 0 {
		return "草稿文件夹不可用"
	}
	meta := mail.CachedToMessageMeta(mail.ParseCachedHeaders(raw), blobKey, int64(len(raw)))
	meta.BodyCache = mail.BodyCacheOf(raw) // U16 Q3-A：草稿正文缓存（四写入路径之四）
	if _, err := s.messages.StoreAppend(ctx, view.MailboxID, folderID, &storage.AppendMeta{Message: meta}); err != nil {
		sessLogger(c).Error("草稿落库失败", "error", err)
		return "草稿保存失败"
	}
	if data.DraftID > 0 {
		if derr := s.messages.HardDelete(ctx, []int64{data.DraftID}); derr != nil {
			sessLogger(c).Warn("旧草稿覆盖清理失败", "draft_id", data.DraftID, "error", derr)
		}
	}
	sessLogger(c).Info("草稿保存", "draft_over", data.DraftID > 0)
	return ""
}

// draftsFolderIDOf 定位 Drafts 系统文件夹（缺位 0）。
func (s *Server) draftsFolderIDOf(c *gin.Context, view *mailboxView) int64 {
	folders, err := s.folders.List(c.Request.Context(), view.MailboxID)
	if err != nil {
		return 0
	}
	for _, f := range folders {
		if f.Kind == storage.FolderKindDrafts {
			return f.ID
		}
	}
	return 0
}

// readFormAttachments multipart 附件上传读取（内存态；总量上限 35MiB——SIZE 缺省档）。
func readFormAttachments(c *gin.Context) ([]mail.OutgoingAttachment, error) {
	form, err := c.MultipartForm()
	if err != nil || form == nil || len(form.File["attachments"]) == 0 {
		return nil, nil
	}
	const limit = 36700160
	total := 0
	out := make([]mail.OutgoingAttachment, 0, len(form.File["attachments"]))
	for _, fh := range form.File["attachments"] {
		if fh.Size > int64(limit) || total+int(fh.Size) > limit {
			return nil, errAttachmentTooLarge
		}
		f, oerr := fh.Open()
		if oerr != nil {
			return nil, oerr
		}
		buf := make([]byte, fh.Size)
		if _, oerr = f.Read(buf); oerr != nil {
			_ = f.Close()
			return nil, oerr
		}
		_ = f.Close()
		total += int(fh.Size)
		out = append(out, mail.OutgoingAttachment{
			Filename: fh.Filename, ContentType: fh.Header.Get("Content-Type"), Data: buf,
		})
	}
	return out, nil
}

// errAttachmentTooLarge 附件超限哨兵（35MiB——SIZE 缺省档同源）。
var errAttachmentTooLarge = errors.New("附件总大小超限（35MiB）")

// parseFormInt64 表单 int64 解析（空/非法 0）。
func parseFormInt64(v string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return n
}

// searchGET 关键词搜索（GET /search?keyword=——空关键词回列表；结果片段复用列表组件）。
func (s *Server) searchGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	keyword := strings.TrimSpace(c.Query("keyword"))
	if keyword == "" {
		s.mailsFragmentGET(c)
		return
	}
	data := s.loadMailListData(c, view, parseListParams(c), keyword, true, currentCSRF(c))
	if data == nil {
		return
	}
	renderFragment(c, http.StatusOK, templates.MailListFragment(data))
}

// currentCSRF 当前会话 CSRF token 取值捷径（空会话返回空串）。
func currentCSRF(c *gin.Context) string {
	if sess, ok := currentSession(c); ok {
		return sess.CSRFToken
	}
	return ""
}
