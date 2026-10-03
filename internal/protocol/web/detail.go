// GRmail Webmail 详情与附件（U9 计划书步骤 6）：邮件详情片段（正文双形态渲染+CID
// 改写+附件卡片）与附件下载端点。
// 依据：契约 v1.5.0 3.2（GET /mails/{id} 详情片段、GET /attachments/{id}?part=N 二进制）；
// SRS FR-013 核心子集（G24 邮件详情/附件卡片/图片内联）；FR-001（GetDetail 双重限定隔离）；
// 渲染口径（计划书 1.5）：HTML 正文 iframe sandbox 承载（无 script/同源——OWASP XSS
// 防线）+CID src 改写指向附件端点；纯文本经 templ 自动转义。
// 修改历史：
//
//	2026-09-19 10:34:00 | 新建 | U9 Webmail 核心（计划书步骤 6，G2 批准 2026-09-19 10:00:41）
package web

import (
	"errors"
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
func (s *Server) mailDetailGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	msg, err := s.messages.GetDetail(ctx, view.MailboxID, id) // 双重限定——FR-001 隔离锚
	if errors.Is(err, storage.ErrMessageNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		sessLogger(c).Error("详情查询失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// 打开即置已读（三值补丁——仅未读时写）
	if !msg.IsRead {
		read := true
		if err = s.messages.SetFlags(ctx, msg.ID, storage.FlagPatch{IsRead: &read}); err != nil {
			sessLogger(c).Warn("置已读失败（不阻断详情）", "error", err)
		}
	}

	raw, err := s.blobs.Read(ctx, msg.BlobKey)
	if err != nil {
		sessLogger(c).Error("原始字节读取失败", "error", err)
		c.Status(http.StatusInternalServerError)
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
	renderFragment(c, http.StatusOK, templates.DetailView(langOf(c), msg, &display, safeBody, bodyIsHTML, currentCSRF(c)))
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

// attachmentGET 附件下载（GET /attachments/{id}?part=N 或 ?cid=<...>——二进制响应）。
// 寻址双形态：part 序号（附件卡片 href）/ CID（HTML 正文 srcdoc 内联改写）。
func (s *Server) attachmentGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		c.Status(http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()
	msg, err := s.messages.GetDetail(ctx, view.MailboxID, id) // 隔离锚：双重限定
	if errors.Is(err, storage.ErrMessageNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	raw, err := s.blobs.Read(ctx, msg.BlobKey)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	var filename, contentType string
	var data []byte
	switch {
	case c.Query("part") != "":
		part, perr := strconv.Atoi(c.Query("part"))
		if perr != nil || part < 0 {
			c.Status(http.StatusBadRequest)
			return
		}
		filename, contentType, data, err = mail.LoadAttachmentPart(raw, part)
	case c.Query("cid") != "":
		filename, contentType, data, err = mail.LoadAttachmentPartByCID(raw, c.Query("cid"))
	default:
		c.Status(http.StatusBadRequest)
		return
	}
	if errors.Is(err, mail.ErrPartNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		sessLogger(c).Error("附件 part 读取失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	disposition := "attachment"
	if c.Query("cid") != "" {
		disposition = "inline" // CID 内联资源：正文内嵌呈现
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Header("Content-Disposition", disposition+"; filename*=UTF-8''"+url.PathEscape(filename))
	c.Data(http.StatusOK, contentType, data)
}
