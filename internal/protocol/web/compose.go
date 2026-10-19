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
//	2026-10-17 02:36:00 | 修正 | 生产缺陷修复批 E-乙（G2 批准 2026-10-17 02:30「批准，乙 C」）：
//	  composeSend 消费 Submit 返回的真实投递 CAS 键；archiveSentCopy 改用该键——原对
//	  构造原文 raw 重算 K2（≠Submit 落盘的 K1=staged 键）且 K2 永不写盘，StoreAppend
//	  以 K2 建 messages 行=幽灵行（Sent 副本点不开，U16 批〔2026-09-24〕起存量缺陷）
//	  就此终结；副本行自此引用实际落盘文件（呈现实际投递件——含前置头与 DKIM 签名）
package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// htmlTagRe HTML 标签剥离正则（B2 空白判定辅助）。
var htmlTagRe = regexp.MustCompile(`(?is)<[^>]*>`)

// htmlBodyBlank 富文本正文空白判定（Webmail前端缺陷修复批 B2——批一：三轮评审一轮
// #15 收口）。原判定 d.Body=="" 恒假（Quill 空编辑器产物 <p><br></p> 非空——用户可
// 发出无正文邮件且不报错）；本函数剥离全部标签与实体后纯文本空白即空白，媒体元素
// （img/video/audio/iframe）正文视为非空（纯图片邮件合法——误拒防线）。前端
// compose.js 提交前精确 trim Quill 空产物形态（第一道防线），本函数为服务端第二道。
func htmlBodyBlank(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<img") || strings.Contains(lower, "<video") ||
		strings.Contains(lower, "<audio") || strings.Contains(lower, "<iframe") {
		return false
	}
	text := htmlTagRe.ReplaceAllString(body, "")
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	return strings.TrimSpace(text) == ""
}

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
			} else {
				// B7（批一）：回信源失配提示——原静默空白页（评审一轮#17）收口；
				// 空白写信页照常可用（提示不阻断）。
				data.ErrText = templates.Tr(langOf(c), "compose.replyGone")
				sessLogger(c).Warn("回信源读取失败（空白页承载）", "id", id, "error", e)
			}
		}
	}
	if did := c.Query("draft"); did != "" {
		if id, e := strconv.ParseInt(did, 10, 64); e == nil && id > 0 {
			if msg, gerr := s.messages.GetDetail(ctx, view.MailboxID, id); gerr != nil {
				// B7：草稿失配提示（同上——fillFromDraft 内部错误已静默，此处前置判定承载）。
				data.ErrText = templates.Tr(langOf(c), "compose.draftGone")
				sessLogger(c).Warn("草稿读取失败（空白页承载）", "id", id, "error", gerr)
			} else {
				_ = msg
				s.fillFromDraft(c, view, data, id)
			}
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
	// 前端四缺陷修复批 E-2-A（G2 批准 2026-10-19 19:18「全A」）：草稿原发件地址
	// 回填——管理员草稿保留保存时输入的任意发件地址（FR-002 草稿态完整性）；空
	// From 草稿维持 composeGET 预填兜底（D12 语义保持——仅非空覆盖）。
	if msg.FromAddr != "" {
		data.From = msg.FromAddr
	}
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
	// A6（批三——Webmail前端缺陷修复批三）：校验按 action 分组——send 全量校验
	// 保持；save_draft 仅基础承载（收件人允许空+主题/正文可存半成品——U9 Q5-A
	// 草稿最小闭环语义兑现：原先行整体校验致无收件人草稿被「收件人不能为空」
	// 拦截〔评审判定 A6 实测 400 证据〕；构造层与落库层自然承载草稿边界）。
	action := c.PostForm("action")
	if action == "send" {
		if serr := s.composeValidate(c, data); serr != "" {
			// D5（批二）：就地呈现+附件清空提示（multipart 重渲染 file input 必空——
			// 提示用户重选；刷新重放零副作用——校验失败无写入，PRG 重定向代价为
			// 表单内容全丢，计划书「就地呈现」分支承载）。
			data.ErrText = serr
			if readFormHasAttachments(c) {
				data.ErrText += " " + templates.Tr(langOf(c), "compose.attachRePick")
			}
			renderPage(c, http.StatusBadRequest, templates.ComposeView(data))
			return
		}
	}
	attachments, aerr := readFormAttachments(c)
	if aerr != nil {
		// B5：附件超限 Tr 化（原文直出改键消费——err.attachTooLarge U18 既有键）。
		data.ErrText = templates.Tr(langOf(c), "err.attachTooLarge")
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
		// B5：构造失败模糊化（内部 err 原文仅日志——界面 Tr 键；评审三轮#23 直出收口）。
		sessLogger(c).Error("邮件构造失败", "error", berr)
		data.ErrText = templates.Tr(langOf(c), "err.buildFailed")
		renderPage(c, http.StatusBadRequest, templates.ComposeView(data))
		return
	}

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
// Webmail前端缺陷修复批 B2/B5（批一）：正文判空改 htmlBodyBlank（Quill 空产物收口）；
// 文案 Tr 化（err.* U18 既有键——英文界面中文残留〔评审一轮#33〕收口）。
func (s *Server) composeValidate(c *gin.Context, d *templates.ComposeData) string {
	lang := langOf(c)
	switch {
	case strings.TrimSpace(d.To) == "" && strings.TrimSpace(d.Bcc) == "":
		return templates.Tr(lang, "err.toRequired")
	case strings.TrimSpace(d.Subject) == "":
		return templates.Tr(lang, "err.subjectRequired")
	case htmlBodyBlank(d.Body):
		return templates.Tr(lang, "err.bodyRequired")
	}
	return ""
}

// ensureFromAddr 发件身份定夺（Q5-A 双主体语义）：
// admin 主体 → 表单 From（必填+本域后缀校验——FR-002 任意本域地址）；
// mailbox 主体 → 自身地址（MailboxRepo.ListByStatus(active) 按 subject_id 反查——
// 契约 2.1 既有五方法内路径，单管理员规模三态枚举推导零签名增量）。
// 返回：定夺地址；错误提示（空串=通过）。
// B5（批一）：文案 Tr 化（err.from* U18 既有键）。
func (s *Server) ensureFromAddr(c *gin.Context, view *mailboxView, formFrom string) (string, string) {
	lang := langOf(c)
	if view.IsAdmin {
		if formFrom == "" {
			return "", templates.Tr(lang, "err.fromRequired")
		}
		if !strings.HasSuffix(strings.ToLower(formFrom), "@"+strings.ToLower(s.cfg.Domain)) {
			return "", templates.Tr(lang, "err.fromLocalOnly")
		}
		return formFrom, ""
	}
	mailboxes, err := s.mailboxes.ListByStatus(c.Request.Context(), storage.MailboxStatusActive)
	if err != nil {
		sessLogger(c).Error("发件身份反查失败", "error", err)
		return "", templates.Tr(lang, "err.fromResolve")
	}
	for _, m := range mailboxes {
		if m.ID == view.MailboxID {
			return m.Address, ""
		}
	}
	return "", templates.Tr(lang, "err.fromAbnormal")
}

// composeSend 发送入队（SubmissionPipeline 复用——流程设计 3.1 同链路）。
// AuthUser=From（一致性分支机械满足——web 会话层已完成 FR-002 授权判定）。
func (s *Server) composeSend(c *gin.Context, view *mailboxView, data *templates.ComposeData, from string, raw []byte) string {
	lang := langOf(c)
	recipients := mail.SplitRecipients(data.To + "," + data.Cc + "," + data.Bcc)
	if len(recipients) == 0 {
		return templates.Tr(lang, "err.rcptInvalid")
	}
	// E-乙（生产缺陷修复批 v1.52.0）：消费 Submit 返回的真实投递 CAS 键——Sent
	// 副本行引用实际落盘文件（幽灵行缺陷终结）。
	sentBlobKey, err := s.submit.Submit(c.Request.Context(), &mail.Submission{
		Envelope: auth.Envelope{
			Helo: "webmail", RemoteIP: net.ParseIP(c.ClientIP()), MailFrom: from,
		},
		AuthUser:   from,
		Recipients: recipients,
	}, raw)
	if err != nil {
		sessLogger(c).Error("发送入队失败", "error", err)
		return templates.Tr(lang, "err.sendFailed")
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
	s.archiveSentCopy(c, view, data, raw, sentBlobKey)
	sessLogger(c).Info("Webmail 发送入队", "rcpts", len(recipients), "log_id", c.GetString(ctxKeyLogID))
	return ""
}

// archiveSentCopy 发送成功后 Sent 文件夹自动副本（U16 Q4-A——U9 登记项①收口）。
// E-乙（生产缺陷修复批 v1.52.0，G2 批准 2026-10-17 02:30）：BlobKey 消费 Submit
// 返回的真实投递键（staged 字节的 CAS 键）——原实现对构造原文 raw 重算 K2（≠Submit
// 落盘的 K1）且 K2 从未写盘，StoreAppend 以 K2 建 messages 行=幽灵行（Sent 副本
// 点不开的根因，U16 起存量缺陷）；本版起副本行引用真实文件（详情可读，呈现实际
// 投递件）。StoreAppend 的 CAS 复用语义自此真正成立（K1 行已由 StoreSubmission
// 建立——同键复用主体，仅追加 Sent 关联行）。失败 Warn 尽力（已入队事实不回滚）。
// 参数：c 请求上下文（日志）；view 主体视图；data 表单（From 展示态）；raw 构造
// 原文（元数据解析源——Subject/收件人等缓存列与投递件一致：前置头不改变这些字段）；
// blobKey Submit 返回的真实投递 CAS 键。返回：无（尽力语义——错误仅记日志）。
func (s *Server) archiveSentCopy(c *gin.Context, view *mailboxView, data *templates.ComposeData, raw []byte, blobKey string) {
	ctx := c.Request.Context()
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
	lang := langOf(c)
	sum := sha256.Sum256(raw)
	blobKey := hex.EncodeToString(sum[:])
	if err := s.blobs.Write(ctx, blobKey, raw); err != nil {
		sessLogger(c).Error("草稿 blob 写入失败", "error", err)
		return templates.Tr(lang, "err.draftSave")
	}
	folderID := s.draftsFolderIDOf(c, view)
	if folderID <= 0 {
		return templates.Tr(lang, "err.draftNoFolder")
	}
	meta := mail.CachedToMessageMeta(mail.ParseCachedHeaders(raw), blobKey, int64(len(raw)))
	meta.BodyCache = mail.BodyCacheOf(raw) // U16 Q3-A：草稿正文缓存（四写入路径之四）
	if _, err := s.messages.StoreAppend(ctx, view.MailboxID, folderID, &storage.AppendMeta{Message: meta}); err != nil {
		sessLogger(c).Error("草稿落库失败", "error", err)
		return templates.Tr(lang, "err.draftSave")
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

// readFormHasAttachments 表单是否携带附件文件（D5——非空附件+校验失败场景提示
// 「需重选」；读取失败按无附件保守口径——提示仅为增强）。
func readFormHasAttachments(c *gin.Context) bool {
	form, err := c.MultipartForm()
	return err == nil && form != nil && len(form.File["attachments"]) > 0
}

// parseFormInt64 表单 int64 解析（空/非法 0）。
func parseFormInt64(v string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return n
}

// searchGET 关键词搜索（GET /search?keyword=——空关键词回列表；结果片段复用列表组件）。
// Webmail前端缺陷修复批 A3（批一）：非 HX 直访返回整页骨架（搜索 URL 刷新/分享——
// D5-A push-url 联动；原裸片段响应降级链路断裂收口）。
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
	if c.GetHeader("HX-Request") == "" {
		renderPage(c, http.StatusOK, templates.MailPageView(data))
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
