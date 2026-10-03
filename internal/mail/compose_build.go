// mail 域出站邮件构造（U9 写信）：multipart/mixed（text/plain 正文+附件）MIME 组装；
// U17 富文本扩展：htmlBody 非空时正文构造 multipart/alternative 双形态。
// 依据：SRS v1.0.1 FR-013（3.8 富文本写信 G3——Q2/Q3 裁决 2026-09-24 22:42:55/22:48:11）；
// rfc2046 §5.1.4（multipart/alternative 构造方 MUST 递增序——L1388-1392「最朴素格式在
// 前、最丰富格式在后」；收件方显示其能显示的最后一个格式 L1351-1352）与 §5.1.1
// （L1183-1187 嵌套 multipart 各层 boundary 必须不同——multipart.NewWriter 双实例
// 随机 boundary 天然互异）；rfc5322 头形态（From/To/Cc/Subject——rfc2047 编码经
// net/mail Address/mime 承载）；Date/Message-ID 缺失补齐归提交管道（rfc6409 8.2/8.3
// SHOULD——SubmissionPipeline.Submit 既有职责，本构造不写两头）；BCC 语义：仅入信封
// 收件人（调用方组装 Recipients），头区不落——rfc5322 隐私语义。
// 修改历史：
//
//	2026-09-19 10:20:00 | 新建 | U9 Webmail 核心（计划书步骤 8 配套构造层，G2 批准 2026-09-19 10:00:41）
//	2026-09-24 22:58:00 | 扩展 | U17 富文本编辑器（计划书步骤 3，G2 批准 2026-09-24 22:51:39）：
//	  BuildOutgoingMail 增 htmlBody 参数+multipart/alternative 双 part 递增序构造+
//	  附件 mixed 嵌套+htmlToPlain 派生+textHtmlPartHeader
//	2026-09-27 11:42:00 | 修正 | U22 富文本高级特性（S4-W 候选 A 裁决 2026-09-27 11:39:02）：
//	  replaceTagWithNewline 带属性开标签整段至 > 替换换行（原仅替换 "<tag " 三字符
//	  前缀致属性段残留——U22 align/indent 控件产出 p class/style 形态触发的既有边界）
//	2026-09-28 22:18:00 | 修正 | RFC规范修正 RF-A（G2 批准 2026-09-28 22:16:57）：F-L6 头区
//	  补 MIME-Version: 1.0（rfc2045 §4 顶层必须）；F-L1 正文 CRLF 规范化（rfc5322bis
//	  §2.3——CR/LF MUST 成对，webmail LF 正文存储态合规+POP3 size 收敛）；F-L7 附件 part
//	  补 CTE: base64+内容 base64 编码 76 字符行宽（rfc2045 §2.7/§6——二进制附件 7bit 安全）
//	2026-09-29 17:27:00 | 修正 | RFC候选修正批次 RF-H：F-L8 构造面——正文 part 按内容
//	  按需声明 CTE: 8bit（rfc2045 §6——UTF-8 正文与缺省 7bit 声明矛盾；纯 ASCII 保持
//	  缺省合规；单形态/alternative plain+html/mixed 正文三路径统一）
package mail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"

	"GRmail/internal/storage"
)

// CachedToMessageMeta 解析产物 → storage 落库元数据转换（草稿 StoreAppend 路径——
// 提交路径同款转换在 submit.go submissionMessageMeta 私有，本导出版供 web 草稿消费；
// 验证结论缓存列出站侧为空，同提交路径口径）。
// 参数：p 解析产物；blobKey CAS 键；size 字节数。返回：messages 行元数据。
func CachedToMessageMeta(p ParsedHeaders, blobKey string, size int64) storage.MessageMeta {
	return storage.MessageMeta{
		MessageID: p.MessageID, BlobKey: blobKey, RawSize: size,
		Subject: p.Subject, FromAddr: p.FromAddr, ToAddrs: p.ToAddrs, CcAddrs: p.CcAddrs,
		SentAt: p.SentAt,
	}
}

// OutgoingAttachment 写信附件输入（接入层文件上传的内存态）。
type OutgoingAttachment struct {
	Filename    string
	ContentType string // 空值兜底 application/octet-stream
	Data        []byte
}

// BuildOutgoingMail 组装出站邮件原始字节：头区（From/To/Cc/Subject）+正文实体+附件。
// htmlBody 空（U16 末态等价——既有调用与纯文本信零适配）：
//   - 无附件：单一 text/plain（非 multipart——最小合规形态）
//   - 有附件：multipart/mixed（首个 part=text/plain 正文，其后逐附件 part）
//
// htmlBody 非空（U17 双形态——rfc2046 §5.1.4 构造方 MUST 递增序）：
//   - 无附件：multipart/alternative{ text/plain（htmlToPlain 派生）在前，
//     text/html（原文）在后 }——最朴素在前、最丰富在后
//   - 有附件：multipart/mixed{ alternative 子实体, 附件 parts }——嵌套各层
//     boundary 唯一（L1183-1187；两个 multipart.NewWriter 随机 boundary 天然互异）
//
// 参数：from 发件地址；to/cc 逗号分隔或单地址原样输入（经 mail.Address 规范编码）；
// subject 主题（rfc2047 编码）；body 纯文本正文（htmlBody 非空时忽略——plain part
// 由 htmlToPlain(htmlBody) 派生）；htmlBody 富文本正文原文（空=纯文本路径）；
// attachments 附件清单（可为空）。
// 返回：完整 RFC 5322 字节（未含 Date/Message-ID——提交管道补齐）。
// SRS 条目：FR-013（3.8 G3/G9）；TC-013。设计物：契约 v1.13.0 2.3 v1.13.0 变更注释。
func BuildOutgoingMail(from, to, cc, subject, body, htmlBody string, attachments []OutgoingAttachment) ([]byte, error) {
	fromHeader, err := formatAddressHeader(from)
	if err != nil {
		return nil, fmt.Errorf("发件地址非法: %w", err)
	}
	toHeader, err := formatAddressListHeader(to)
	if err != nil {
		return nil, fmt.Errorf("收件地址非法: %w", err)
	}

	var buf bytes.Buffer
	writeHeader(&buf, "From", fromHeader)
	writeHeader(&buf, "To", toHeader)
	if strings.TrimSpace(cc) != "" {
		ccHeader, cerr := formatAddressListHeader(cc)
		if cerr != nil {
			return nil, fmt.Errorf("抄送地址非法: %w", cerr)
		}
		writeHeader(&buf, "Cc", ccHeader)
	}
	writeHeader(&buf, "Subject", mime.QEncoding.Encode("utf-8", subject))
	// F-L6：MIME 一致性声明（rfc2045 §4 L478-479——顶层消息必须；沿 dsn.go 先例）
	writeHeader(&buf, "MIME-Version", "1.0")

	if htmlBody == "" {
		// 纯文本路径（body 经 F-L1 CRLF 规范化——存储态 rfc5322bis §2.3 合规）
		normBody := normalizeBodyCRLF(body)
		if len(attachments) == 0 {
			writeHeader(&buf, "Content-Type", "text/plain; charset=utf-8")
			if hasEightBit([]byte(normBody)) {
				// F-L8：UTF-8 正文与 CTE 缺省 7bit 声明矛盾——显式 8bit（rfc2045 §6）
				writeHeader(&buf, "Content-Transfer-Encoding", "8bit")
			}
			buf.WriteString("\r\n")
			buf.WriteString(normBody)
			return buf.Bytes(), nil
		}
		mw := multipart.NewWriter(&buf)
		writeHeader(&buf, "Content-Type", "multipart/mixed; boundary="+mw.Boundary())
		buf.WriteString("\r\n")
		if err := writePlainAndAttachments(mw, normBody, attachments); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}

	// 富文本路径（U17——alternative 双 part 递增序；F-L1：plain 派生与 html 原文均 CRLF 规范化）
	alt, err := buildAlternative(normalizeBodyCRLF(htmlToPlain(htmlBody)), normalizeBodyCRLF(htmlBody))
	if err != nil {
		return nil, err
	}
	if len(attachments) == 0 {
		// 无附件：顶层即 alternative
		writeHeader(&buf, "Content-Type", alt.contentType)
		buf.WriteString("\r\n")
		buf.Write(alt.body)
		return buf.Bytes(), nil
	}
	// 有附件：mixed 嵌 alternative（首 part）+附件——两层 boundary 各自随机互异
	mw := multipart.NewWriter(&buf)
	writeHeader(&buf, "Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	buf.WriteString("\r\n")
	ap, aerr := mw.CreatePart(alt.partHeader())
	if aerr != nil {
		return nil, fmt.Errorf("创建正文 alternative part: %w", aerr)
	}
	if _, aerr = ap.Write(alt.body); aerr != nil {
		return nil, fmt.Errorf("写正文 alternative: %w", aerr)
	}
	if err := writeAttachmentParts(mw, attachments); err != nil {
		return nil, err
	}
	if err = mw.Close(); err != nil {
		return nil, fmt.Errorf("收尾 multipart: %w", err)
	}
	return buf.Bytes(), nil
}

// alternativeEntity 构造完成的 alternative 子实体（contentType 完整头值+定稿字节）。
type alternativeEntity struct {
	contentType string // multipart/alternative; boundary=xxx
	body        []byte // 定稿子实体字节（含 boundary 定界）
}

// partHeader 作为 mixed 首 part 嵌入时的 part 头（Content-Type=alternative 全值）。
func (a *alternativeEntity) partHeader() textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", a.contentType)
	return h
}

// buildAlternative 构造 multipart/alternative 子实体：plain part 在前+html part 在后
// （rfc2046 §5.1.4 构造方 MUST 递增序——L1388-1392）。
// 参数：plain 派生纯文本；html 富文本原文。返回：子实体（boundary 已定稿）。
func buildAlternative(plain, html string) (*alternativeEntity, error) {
	var abuf bytes.Buffer
	aw := multipart.NewWriter(&abuf)
	pp, err := aw.CreatePart(textPlainPartHeader(plain))
	if err != nil {
		return nil, fmt.Errorf("创建 plain part: %w", err)
	}
	if _, err = pp.Write([]byte(plain)); err != nil {
		return nil, fmt.Errorf("写 plain part: %w", err)
	}
	hp, err := aw.CreatePart(textHtmlPartHeader(html))
	if err != nil {
		return nil, fmt.Errorf("创建 html part: %w", err)
	}
	if _, err = hp.Write([]byte(html)); err != nil {
		return nil, fmt.Errorf("写 html part: %w", err)
	}
	if err = aw.Close(); err != nil {
		return nil, fmt.Errorf("收尾 alternative: %w", err)
	}
	return &alternativeEntity{contentType: "multipart/alternative; boundary=" + aw.Boundary(), body: abuf.Bytes()}, nil
}

// writePlainAndAttachments 纯文本路径 mixed 内容写入（正文 part+逐附件 part+收尾）。
// 参数：mw mixed writer；body 纯文本正文；attachments 附件清单。返回：错误。
func writePlainAndAttachments(mw *multipart.Writer, body string, attachments []OutgoingAttachment) error {
	tp, err := mw.CreatePart(textPlainPartHeader(body))
	if err != nil {
		return fmt.Errorf("创建正文 part: %w", err)
	}
	if _, err = tp.Write([]byte(body)); err != nil {
		return fmt.Errorf("写正文: %w", err)
	}
	if err := writeAttachmentParts(mw, attachments); err != nil {
		return err
	}
	if err = mw.Close(); err != nil {
		return fmt.Errorf("收尾 multipart: %w", err)
	}
	return nil
}

// writeAttachmentParts 逐附件 part 写入（纯文本/富文本两条路径共用）。
// F-L7：附件 part 补 Content-Transfer-Encoding: base64 并将内容 base64 编码后按
// 76 字符行宽分行写入（rfc2045 §2.7 L359-364——7bit 数据禁高位八位组/NUL/998+ 长行；
// §6.8 base64 行宽上限 76）——二进制附件 7bit 通道安全。
// 参数：mw multipart writer；attachments 附件清单。返回：错误。
func writeAttachmentParts(mw *multipart.Writer, attachments []OutgoingAttachment) error {
	for _, a := range attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", ct)
		h.Set("Content-Transfer-Encoding", "base64")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))
		ap, aerr := mw.CreatePart(h)
		if aerr != nil {
			return fmt.Errorf("创建附件 part: %w", aerr)
		}
		if aerr = writeBase64Body(ap, a.Data); aerr != nil {
			return fmt.Errorf("写附件 %s: %w", a.Filename, aerr)
		}
	}
	return nil
}

// base64LineLen base64 编码输出行宽（rfc2045 §6.8——每行不超过 76 字符）。
const base64LineLen = 76

// writeBase64Body 将原始字节 base64 编码后按行宽分行写出（每行 CRLF 结尾）。
// 参数：w part 写入器；data 原始字节。返回：错误。
func writeBase64Body(w io.Writer, data []byte) error {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(enc, data)
	for i := 0; i < len(enc); i += base64LineLen {
		end := i + base64LineLen
		if end > len(enc) {
			end = len(enc)
		}
		if _, err := w.Write(enc[i:end]); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return err
		}
	}
	return nil
}

// normalizeBodyCRLF 正文行尾规范化（F-L1——rfc5322bis §2.3 L527-528「CR and LF MUST
// only occur together as CRLF」）：独立 LF → CRLF；既有 CRLF 保持不重复展开。
// 沿 sender.go writeDataBody 出站补救同款语义，收敛于构造入口使存储态（POP3 size
// 口径 rfc1939 §11——F-P1 根因）与外发态一致。孤立 \r 不属本函数处置面（罕见于
// 文本输入，MIME 解析侧容忍）。
// 参数：s 原始正文。返回：CRLF 规范化正文。
func normalizeBodyCRLF(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// writeHeader 单头写入（CRLF 行尾——rfc5322）。
func writeHeader(buf *bytes.Buffer, key, value string) {
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

// textPlainPartHeader 正文 part 头（text/plain; charset=utf-8；multipart.CreatePart
// 入参为 textproto.MIMEHeader）。F-L8：body 含 8bit 八位组时显式声明 CTE: 8bit
// （rfc2045 §6——UTF-8 正文与缺省 7bit 声明矛盾；纯 ASCII 保持缺省合规）。
func textPlainPartHeader(body string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	setBodyCTE(h, body)
	return h
}

// textHtmlPartHeader 富文本正文 part 头（text/html; charset=utf-8——U17 alternative
// html part；textPlainPartHeader 同构——F-L8 CTE 同语义）。
func textHtmlPartHeader(body string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", "text/html; charset=utf-8")
	setBodyCTE(h, body)
	return h
}

// setBodyCTE 正文 part 的 CTE 按需声明（F-L8——rfc2045 §6：含 ≥0x80 八位组时
// "Content-Transfer-Encoding: 8bit"；纯 ASCII 保持缺省 7bit 合规零头）。
func setBodyCTE(h textproto.MIMEHeader, body string) {
	if hasEightBit([]byte(body)) {
		h.Set("Content-Transfer-Encoding", "8bit")
	}
}

// htmlToPlain HTML→纯文本派生（U17：alternative 双形态的 text/plain part 内容源——
// Q3 裁决「标签剥离」）。纯函数尽力语义：块级元素换行映射+标签剥离+转义实体解码+
// 连续空行压缩；畸形 HTML 容错产出可读文本（不保证语义完备）。
// 参数：htmlBody 富文本正文原文。返回：可读纯文本。
// 实现思路（rfc2046 §5.1.4 plain part 为最朴素呈现——收件端无 HTML 能力时回退视图）：
// ①块级闭合/自闭合标签映射换行（br/p/div/li/h1-h6/blockquote/pre/tr/ul/ol/table）；
// ②li 开标签补 "- " 项前缀；③剥离全部标签；④html.UnescapeString 实体解码；
// ⑤三连以上换行压缩为两连。
func htmlToPlain(htmlBody string) string {
	if htmlBody == "" {
		return ""
	}
	s := htmlBody
	// 行内换行（自闭合）与块级闭合标签→换行
	for _, tag := range []string{"br", "p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "tr", "ul", "ol", "table"} {
		s = replaceTagWithNewline(s, tag)
	}
	// 剩余标签剥离（开标签/注释/未知元素）
	for {
		start := strings.Index(s, "<")
		if start < 0 {
			break
		}
		end := strings.Index(s[start:], ">")
		if end < 0 {
			s = s[:start] // 未闭合残尾标签丢弃
			break
		}
		s = s[:start] + s[start+end+1:]
	}
	s = html.UnescapeString(s)
	// li 项前缀在剥离后逐行补（块级 li 行首 "- "）不可行——改为剥离前标记：已在 replaceTagWithNewline 统一换行，
	// 此处仅压缩空行与修剪行尾空白
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " \t\r")
	}
	s = strings.Join(lines, "\n")
	// 压缩 3+ 连续换行为 2 连（段落间距上限）
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(s)
}

// replaceTagWithNewline 单标签（开/闭/自闭合任一形态）替换为换行。
// 带属性开标签（<tag 属性…>）整段至首个 > 含属性替换（U22 修正：原仅替换
// "<tag " 三字符前缀，属性段残留于 > 之前致剥离循环无 "<" 可寻而 break——
// U22 align/indent 控件产出 p class/style 形态触发的既有边界；属性值含 >
// 的病态形态按至首个 > 截断——与剥离循环同容错口径的尽力语义）。
// 参数：s 源文本；tag 标签名（小写匹配——HTML 不敏感语义容错）。返回：替换后文本。
func replaceTagWithNewline(s, tag string) string {
	lower := strings.ToLower(s)
	for _, form := range []string{"</" + tag + ">", "<" + tag + "/>"} {
		for {
			idx := strings.Index(lower, form)
			if idx < 0 {
				break
			}
			s = s[:idx] + "\n" + s[idx+len(form):]
			lower = strings.ToLower(s)
		}
	}
	// 带属性开标签（<tag …>——任意属性整段至首个 > 含属性替换为换行）
	for {
		prefix := "<" + tag + " "
		idx := strings.Index(lower, prefix)
		if idx < 0 {
			break
		}
		end := strings.Index(s[idx:], ">")
		if end < 0 {
			s = s[:idx] + "\n" // 未闭合残尾（至串尾整段丢弃）
		} else {
			s = s[:idx] + "\n" + s[idx+end+1:]
		}
		lower = strings.ToLower(s)
	}
	// 无属性纯开标签（<tag>）
	for {
		idx := strings.Index(lower, "<"+tag+">")
		if idx < 0 {
			break
		}
		s = s[:idx] + "\n" + s[idx+len(tag)+2:]
		lower = strings.ToLower(s)
	}
	return s
}

// formatAddressHeader 单地址 → 编码头值（mail.Address 编码承载显示名/非 ASCII——
// 本路径输入为裸地址，Address.String() 保留尖括号规范形态）。
func formatAddressHeader(addr string) (string, error) {
	a, err := mail.ParseAddress(strings.TrimSpace(addr))
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

// formatAddressListHeader 逗号/分号分隔多地址 → 编码头值（全量解析，任一非法即拒）。
func formatAddressListHeader(list string) (string, error) {
	parts := splitAddressList(list)
	if len(parts) == 0 {
		return "", fmt.Errorf("地址列表为空")
	}
	addrs := make([]string, 0, len(parts))
	for _, p := range parts {
		a, err := mail.ParseAddress(strings.TrimSpace(p))
		if err != nil {
			return "", err
		}
		addrs = append(addrs, a.String())
	}
	return strings.Join(addrs, ", "), nil
}

// splitAddressList 逗号/分号/空白混合分隔拆分（表单输入宽容口径）。
func splitAddressList(list string) []string {
	f := func(r rune) bool { return r == ',' || r == ';' || r == '\n' }
	out := make([]string, 0, 4)
	for _, p := range strings.FieldsFunc(list, f) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SplitRecipients 出站信封收件人拆分（To+Cc+Bcc 表单输入 → 小写规范化列表——
// Submission.Recipients 语义；web 接入层组装信封时消费）。
func SplitRecipients(list string) []string {
	parts := splitAddressList(list)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.ToLower(strings.TrimSpace(p)))
	}
	return out
}
