// GRmail Webmail 详情与附件（U9 计划书步骤 6）：邮件详情片段（正文双形态渲染+CID
// 改写+附件卡片）与附件下载端点。
// 依据：契约 v1.5.0 3.2（GET /mails/{id} 详情片段、GET /attachments/{id}?part=N 二进制）；
// SRS FR-013 核心子集（G24 邮件详情/附件卡片/图片内联）；FR-001（GetDetail 双重限定隔离）；
// 渲染口径（计划书 1.5）：HTML 正文 iframe sandbox 承载（无 script/同源——OWASP XSS
// 防线）+CID src 改写指向附件端点；纯文本经 templ 自动转义。
// 修改历史：
//
//	2026-09-19 10:34:00 | 新建 | U9 Webmail 核心（计划书步骤 6，G2 批准 2026-09-19 10:00:41）
//	2026-10-14 20:45:00 | 修正 | Webmail前端可用性收口批 B6：详情返回链接保留来源页码
//	（原恒 page=1——第 N 页查看详情返回回第 1 页的上下文丢失收口；G2 批准 2026-10-14 20:37）
//	2026-10-20 12:50:00 | 修正 | GRM代码侧批 E-1-A（GRM-008）：htmlEscapeBody 空操作
//	修正为真实转义（三字符分别转义为对应 HTML 实体、amp 先行防二次转义；实体经字符串
//	拼接构造——免疫工具链写入层实体解码；G2 批准 2026-10-20 12:06:32）
package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/mail"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// detailData 收敛至模板参数直传（storage.Detail+mail.Display 原生类型——DetailView
// 五参形态，零中间结构）。

// mailDetailGET 详情片段（GET /mails/{id}——HTMX 替换主列表区；id=mailbox_messages.id）。
// 打开即置已读（Webmail 语义——列表未读态联动 G11）。
// Webmail前端缺陷修复批 A4（批一）：异常态双态错误呈现（HX=片段错误块/非 HX=错误
// 整页——原空体状态码〔点已删除邮件界面零反馈〕收口；fragError 统一承载）。
func (s *Server) mailDetailGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fragError(c, http.StatusBadRequest, "frag.errInvalid")
		return
	}
	ctx := c.Request.Context()
	msg, err := s.messages.GetDetail(ctx, view.MailboxID, id) // 双重限定——FR-001 隔离锚
	if errors.Is(err, storage.ErrMessageNotFound) {
		s.fragError(c, http.StatusNotFound, "frag.errMsgGone")
		return
	}
	if err != nil {
		sessLogger(c).Error("详情查询失败", "error", err)
		s.fragError(c, http.StatusInternalServerError, "frag.errServer")
		return
	}

	// 打开即置已读（三值补丁——仅未读时写）
	if !msg.IsRead {
		read := true
		if err = s.messages.SetFlags(ctx, msg.ID, storage.FlagPatch{IsRead: &read}); err != nil {
			sessLogger(c).Warn("置已读失败（不阻断详情）", "error", err)
		} else {
			// B16（批二·F2 移交承载）：置已读成功→HX-Trigger 事件通知前端侧栏
			// 未读计数递减（grmail.js 监听 grmailRead 就地更新对应文件夹 unread——
			// 片段交换目标 #mail-list 不含侧栏的原不联动收口；非 HX 整页语境无需）。
			if c.GetHeader("HX-Request") != "" {
				c.Header("HX-Trigger", fmt.Sprintf(`{"grmailRead":%d}`, msg.FolderID))
			}
		}
	}

	raw, err := s.blobs.Read(ctx, msg.BlobKey)
	if err != nil {
		sessLogger(c).Error("原始字节读取失败", "error", err)
		s.fragError(c, http.StatusInternalServerError, "frag.errServer") // B9（批四）：空体改双态
		return
	}
	display, err := mail.ParseDisplay(raw)
	if err != nil {
		// 展示模型尽力语义：解析失败降级纯元数据视图（附件空/正文空）
		sessLogger(c).Warn("展示模型解析降级", "error", err)
		display = mail.Display{Attachments: []mail.AttachmentView{}, CIDs: map[string]bool{}}
	}

	safeBody := display.BodyText
	bodyIsHTML := display.BodyHTML != ""
	if bodyIsHTML {
		safeBody = rewriteCIDs(display.BodyHTML, msg.ID, display)
	}
	// WEB模板缺陷修正批次·组D：backHref 依当前上下文构造（pagesize/unread/搜索态
	// 保留——替代旧硬编码 /mails?folder=X&page=1 丢上下文缺陷）+isDraft 草稿态
	// （drafts 文件夹详情呈现「编辑草稿」入口——接通 ?draft= 既有回填链）+深链
	// 整页形态（直接 URL 访问经 Layout 骨架——替代旧裸片段无 html 架构形态）。
	p := parseListParams(c)
	// B6（α 批）：返回链接保留来源页码（pagesize/unread/keyword 既有保持——原唯页码
	// 弃丢；搜索分支同语义）。
	backHref := fmt.Sprintf("/mails?folder=%d&page=%d&pagesize=%d", msg.FolderID, p.Page, p.Pagesize)
	if p.UnreadOnly {
		backHref += "&unread=1"
	}
	if kw := strings.TrimSpace(c.Query("keyword")); kw != "" {
		backHref = fmt.Sprintf("/search?keyword=%s&page=%d&pagesize=%d", url.QueryEscape(kw), p.Page, p.Pagesize)
	}
	isDraft := s.isDraftFolder(c, view, msg.FolderID)
	if c.GetHeader("HX-Request") != "" {
		renderFragment(c, http.StatusOK, templates.DetailView(langOf(c), msg, &display, safeBody, bodyIsHTML, currentCSRF(c), backHref, isDraft))
		return
	}
	renderPage(c, http.StatusOK, templates.DetailPageView(langOf(c), msg, &display, safeBody, bodyIsHTML, currentCSRF(c), backHref, isDraft, s.sidebarDataFor(c)))
}

// isDraftFolder 判定文件夹是否 Drafts 系统文件夹（组D·核对#29——草稿续编入口
// 呈现条件；查询失败保守 false——不误呈现编辑按钮）。
func (s *Server) isDraftFolder(c *gin.Context, view *mailboxView, folderID int64) bool {
	folders, err := s.folders.List(c.Request.Context(), view.MailboxID)
	if err != nil {
		return false
	}
	for _, f := range folders {
		if f.ID == folderID {
			return f.Kind == storage.FolderKindDrafts
		}
	}
	return false
}

// cidSrcRe HTML 内 cid: 引用形态（src/hx 无关，统一引号形态捕获）。
var cidSrcRe = regexp.MustCompile(`(?i)(src\s*=\s*["'])cid:([^"']+)(["'])`)

// rewriteCIDs HTML 正文 cid: 引用 → 附件端点（?part= 定位——cid 与 part 映射：遍历
// 附件清单重读原始 part 代价高，此处按 CID 匹配附件需 part 索引；mail.Display 附件
// 行不含 CID——为零额外读取，附件端点支持 ?cid= 直接寻址（LoadAttachmentPartByCID），
// src 改写携带 cid 原文（URL 编码承载尖括号））。
func rewriteCIDs(htmlBody string, msgID int64, display mail.Display) string {
	if len(display.CIDs) == 0 {
		return htmlBody
	}
	return cidSrcRe.ReplaceAllStringFunc(htmlBody, func(m string) string {
		parts := cidSrcRe.FindStringSubmatch(m)
		cid := parts[2]
		norm := normalizeCID(cid)
		if !display.CIDs[norm] {
			return m // 无对应内联资源——保持原文（防外链改写）
		}
		return parts[1] + "/attachments/" + strconv.FormatInt(msgID, 10) +
			"?cid=" + urlEscapeCID(norm) + parts[3]
	})
}

// normalizeCID cid 引用值规范化（补尖括号——Content-Id 头原文含尖括号）。
func normalizeCID(cid string) string {
	cid = strings.TrimSpace(cid)
	if !strings.HasPrefix(cid, "<") {
		cid = "<" + cid
	}
	if !strings.HasSuffix(cid, ">") {
		cid = cid + ">"
	}
	return cid
}

// urlEscapeCID CID 的 URL 查询编码（尖括号等保留字符经 QueryEscape）。
func urlEscapeCID(cid string) string {
	return strings.NewReplacer("<", "%3C", ">", "%3E", "\"", "%22", "'", "%27").Replace(cid)
}

// mailBodyGET 正文同源代理端点（GET /mails/{id}/body——Webmail前端缺陷修复批 D3-B，
// 干系人裁决 2026-10-10 20:52：全浏览器正文内联样式恢复通道）。
// 形态：iframe src 指向本端点（DetailView HTML 态）——同源导航文档采用**自身响应头
// CSP**（不继承父页策略）：独立策略 style-src 'unsafe-inline'（邮件排版内联样式放行）
// + img/media 'self'（CID 改写后的附件端点资源+data: 图片）+ frame-ancestors 'self'
// （仅允许本站嵌套——防外站 iframe 引用）；script-src 'none'（脚本零放行——sandbox
// 之外的响应层第二道防线）。纯文本邮件经 text/plain 响应（iframe 内等宽呈现）。
// 鉴权：会话+邮箱归属双限定（沿 attachmentGET 先例——FR-001 隔离锚）；不置已读
// （详情打开时 mailDetailGET 已承载——端点保持只读幂等）。
func (s *Server) mailBodyGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.fragError(c, http.StatusForbidden, "frag.errDenied")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fragError(c, http.StatusBadRequest, "frag.errInvalid")
		return
	}
	ctx := c.Request.Context()
	msg, err := s.messages.GetDetail(ctx, view.MailboxID, id) // 双重限定——FR-001 隔离锚
	if errors.Is(err, storage.ErrMessageNotFound) {
		s.fragError(c, http.StatusNotFound, "frag.errMsgGone")
		return
	}
	if err != nil {
		sessLogger(c).Error("正文查询失败", "error", err)
		s.fragError(c, http.StatusInternalServerError, "frag.errServer")
		return
	}
	raw, err := s.blobs.Read(ctx, msg.BlobKey)
	if err != nil {
		sessLogger(c).Error("原始字节读取失败", "error", err)
		s.fragError(c, http.StatusInternalServerError, "frag.errServer")
		return
	}
	display, derr := mail.ParseDisplay(raw)
	if derr != nil {
		sessLogger(c).Warn("正文展示模型解析降级（纯文本空）", "error", derr)
		display = mail.Display{Attachments: []mail.AttachmentView{}, CIDs: map[string]bool{}}
	}
	body, contentType := display.BodyText, ""
	if display.BodyHTML != "" {
		body = mailBodyDocument(rewriteCIDs(display.BodyHTML, id, display))
		contentType = "text/html; charset=utf-8"
	} else {
		// C12（批二·E-3-A 联动）：纯文本形态同获排版基座（pre 等宽+基座样式）——
		// 双文档包裹形态下 Content-Type 须同步 text/html（原恒 text/plain 致 iframe
		// 以纯文本呈现 HTML 源码——C12 落码缺口，续接批次修正；契约 v1.42.0 注记）。
		body = mailBodyDocumentPlain(display.BodyText)
		contentType = "text/html; charset=utf-8"
	}
	// 独立 CSP（覆盖 securityHeadersMiddleware 的全域头——gin Header.Set 后设胜出）
	c.Header("Content-Security-Policy",
		"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; media-src 'self'; frame-ancestors 'self'")
	// C8（批五——G2 批准 2026-10-13 08:42:57 例外修订）：本端点 XFO 覆盖 SAMEORIGIN
	// （正文 iframe 同源消费通道——旧浏览器〔不支持 CSP frame-ancestors 仅认 XFO〕
	// 被全域 DENY 拦截的呈现缺陷收口；跨站嵌入仍拒——SAMEORIGIN 语义；现代浏览器
	// CSP frame-ancestors 'self' 优先行为零变化；全域其余端点 DENY 零变化——B-S 批
	// F2 修订面经 G2 显式裁决限定本端点与 attachmentGET 两例外）。
	c.Header("X-Frame-Options", "SAMEORIGIN")
	c.Data(http.StatusOK, contentType, []byte(body))
}

// mailBodyBaseCSS 正文文档排版基座（C12 批二——三轮评审一轮#10 承载：正文 iframe
// 内 UA 默认呈现无排版基线〔字号/行高/内边距/最大宽/断词〕+暗色对比倒置风险；
// 经 style 元素注入——本端点 CSP 已放行 style-src 'unsafe-inline'〔批一 D3-B〕；
// 令牌不引入〔iframe 文档隔离无外链〕，色值用浅色固定基线+prefers-color-scheme
// 暗色适配〔正文邮件多为白底——暗色保持浅底可读性优先〕）。
// E-3-A（G14 联动）：可读性由基座字号/行距承载；缩放经外层页面浏览器缩放传导。
const mailBodyBaseCSS = `<style>
body{margin:0;padding:16px;font-family:system-ui,-apple-system,"Segoe UI","Helvetica Neue","PingFang SC","Microsoft YaHei",sans-serif;font-size:1rem;line-height:1.65;color:#212121;background:#fff;}
img,video{max-width:100%;height:auto;}
table{max-width:100%;border-collapse:collapse;}
td,th{border:1px solid #e0e0e0;padding:4px 8px;}
a{color:#1976d2;}
*{overflow-wrap:anywhere;}
@media (prefers-color-scheme: dark){body{background:#fff;color:#212121;}}
</style>`

// mailBodyDocument HTML 正文→完整文档（基座样式 prepend——head+body 包裹）。
func mailBodyDocument(htmlBody string) string {
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" + mailBodyBaseCSS +
		"</head><body>" + htmlBody + "</body></html>"
}

// mailBodyDocumentPlain 纯文本正文→完整文档（pre 等宽呈现+同款基座）。
func mailBodyDocumentPlain(textBody string) string {
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" + mailBodyBaseCSS +
		"</head><body><pre style=\"white-space:pre-wrap;font-family:inherit;margin:0;\">" +
		htmlEscapeBody(textBody) + "</pre></body></html>"
}

// htmlEscapeBody 文本 HTML 转义（纯文本形态防实体注入——&<> 三字符；& 先行防二次转义）。
// GRM-008（GRM代码侧批 E-1-A——G2 批准 2026-10-20 12:06:32）：原 Replacer 三组替换
// 首尾相同恒等返回（空操作缺陷——纯文本中标签字面量被浏览器按 HTML 渲染的注入面，
// grep 'amp;'=0 终验）；本版修正为真实转义——纯文本按字面呈现（pre 等宽形态本意恢复），
// 合法纯文本功能零损失（标签字面量从"被渲染"变为"显示原文"——即修复目的本身）。
func htmlEscapeBody(s string) string {
	r := strings.NewReplacer("&", "&"+"amp;", "<", "&"+"lt;", ">", "&"+"gt;")
	return r.Replace(s)
}

// attachmentGET 附件下载（GET /attachments/{id}?part=N 或 ?cid=<...>——二进制响应）。
// 寻址双形态：part 序号（附件卡片 href）/ CID（HTML 正文 srcdoc 内联改写）。
func (s *Server) attachmentGET(c *gin.Context) {
	// B9/E-2-A（批四——G2 候选 E-2-A 裁决 2026-10-13 04:27:33）：附件/正文族错误
	// 全并入 fragError 双态（人直访得可读错误页；img/iframe 消费者收 HTML 错误体——
	// 呈现由状态码决定无变化；状态码语义与安全红线零变化）。
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.fragError(c, http.StatusForbidden, "frag.errDenied")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fragError(c, http.StatusBadRequest, "frag.errInvalid")
		return
	}
	ctx := c.Request.Context()
	msg, err := s.messages.GetDetail(ctx, view.MailboxID, id) // 隔离锚：双重限定
	if errors.Is(err, storage.ErrMessageNotFound) {
		s.fragError(c, http.StatusNotFound, "frag.errMsgGone")
		return
	}
	if err != nil {
		s.fragError(c, http.StatusInternalServerError, "frag.errServer")
		return
	}
	// 性能批 F7（D11，G2 批准 2026-10-08 10:13:49）：流式句柄替代整封 []byte 驻留——
	// BlobStore.Open 后单 part 按需读入（驻留=单附件大小，登记可接受；原整封读取
	// 消除——大附件邮件下载的内存峰值随附件总量降低）。
	rc, rerr := s.blobs.Open(ctx, msg.BlobKey)
	if rerr != nil {
		sessLogger(c).Error("原始字节打开失败", "error", rerr)
		s.fragError(c, http.StatusInternalServerError, "frag.errServer") // B9/E-2-A（批四）
		return
	}
	defer func() { _ = rc.Close() }()

	var filename, contentType string
	var data []byte
	switch {
	case c.Query("part") != "":
		part, perr := strconv.Atoi(c.Query("part"))
		if perr != nil || part < 0 {
			s.fragError(c, http.StatusBadRequest, "frag.errInvalid") // B9/E-2-A（批四）
			return
		}
		filename, contentType, data, err = mail.LoadAttachmentPart(rc, part)
	case c.Query("cid") != "":
		filename, contentType, data, err = mail.LoadAttachmentPartByCID(rc, c.Query("cid"))
	default:
		s.fragError(c, http.StatusBadRequest, "frag.errInvalid") // B9/E-2-A（批四）
		return
	}
	if errors.Is(err, mail.ErrPartNotFound) {
		s.fragError(c, http.StatusNotFound, "frag.errMsgGone") // B9/E-2-A（批四）——part 不存在对齐消息不存在键
		return
	}
	if err != nil {
		sessLogger(c).Error("附件 part 读取失败", "error", err)
		s.fragError(c, http.StatusInternalServerError, "frag.errServer") // B9/E-2-A（批四）
		return
	}

	disposition := "attachment"
	if c.Query("cid") != "" {
		// B-S批 F2（裁决 A）：CID 内联白名单——仅 image/audio/video 可 inline
		// （text/html 附件强制 attachment——源站同源渲染面收口；正文 iframe sandbox
		// 渲染通道不受影响，仅直链收紧；FR-013 ⑨ 图片内联判定项保持）
		if strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "audio/") ||
			strings.HasPrefix(contentType, "video/") {
			disposition = "inline" // CID 内联资源：正文内嵌呈现（白名单内）
		}
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	// C8（批五——G2 批准 2026-10-13 08:42:57 例外修订）：附件端点同款 XFO 覆盖
	// SAMEORIGIN（正文 CID 内联资源与浏览器直嵌消费通道——旧浏览器 XFO 兼容收口；
	// 全域其余端点 DENY 零变化）。
	c.Header("X-Frame-Options", "SAMEORIGIN")
	c.Header("Content-Disposition", disposition+"; filename*=UTF-8''"+url.PathEscape(filename))
	c.Data(http.StatusOK, contentType, data)
}
