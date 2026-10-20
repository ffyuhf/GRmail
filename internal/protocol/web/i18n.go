// GRmail Web 界面语言与 CSV 导入（U16，Q2-A/Q5-A 裁决 2026-09-24 11:47:58）。
// 语言依据：G29 参照（SSR 形态——服务端文案表承载于 templates.Tr）；判定序
// cookie lang（zh|en）→缺省 zh（与 U15 末态行为一致——零回归锚）；切换端点
// GET /lang（cookie 设置+next 站内路径重定向——防开放重定向）。
// CSV 依据：G5 参照（服务端解析形态——Q5-A 裁决；分隔符检测/表头中英列识别/
// net/mail 验证/无效行跳过计数）；端点 POST /compose/csv-import（multipart ≤2MB）。
// SRS 条目：FR-013（3.8 中英双语/CSV 子项）；TC-013；契约 v1.12.0 3.1/3.2。
// 修改历史：
//
//	2026-09-24 21:46:00 | 新建 | U16 Webmail 体验收尾（计划书步骤 4/6，G2 批准 2026-09-24 11:51:57）
//	2026-10-15 00:40:00 | 修正 | Webmail前端可见性一致性令牌批 β C2/E-1-A：候选表
//	容器挂 .table-wrap 类（并入统一表格体系——仅类名消费零逻辑变化）
//	（依据：β批计划书 v1.0.0 1.2 C2+候选 E-1-A，G2 批准 2026-10-15 00:12）
//	2026-10-20 12:50:00 | 修正 | GRM代码侧批 E-3-A（GRM-010）：langSetGET next 校验
//	收敛共用 isSafeLocalRedirectPath（反斜杠变体与编码形态同拒——与 session.go
//	safeRedirectPath 双消费点同批同步；G2 批准 2026-10-20 12:06:32）
package web

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/web/templates"
)

// langCookieName 语言偏好 cookie 名（非会话凭据——无 __Host- 前缀义务；Secure+
// SameSite=Lax 沿静态资源宽松口径；1 年有效）。
const langCookieName = "lang"

// langOf 当前请求界面语言（cookie 判定序——缺省 zh）。
// 参数：c 请求上下文。返回：规范化语言。
func langOf(c *gin.Context) templates.Lang {
	v, err := c.Cookie(langCookieName)
	if err != nil {
		return templates.LangZH
	}
	return templates.NormalizeLang(v)
}

// langSetGET 语言切换端点（GET /lang?l=en|zh&next=/path——契约 v1.12.0 3.1）：
// cookie 设置+重定向 next；站外路径拒绝回 /（防开放重定向——OWASP 口径）；
// 无会话要求（语言偏好先于认证承载）。CSRF：无状态变更语义（仅 cookie 偏好）——无承载。
func (s *Server) langSetGET(c *gin.Context) {
	target := templates.NormalizeLang(c.Query("l"))
	next := c.Query("next")
	// GRM-010（GRM代码侧批 E-3-A——G2 批准 2026-10-20 12:06:32）：校验收敛共用
	// isSafeLocalRedirectPath（session.go）——反斜杠变体 "/\evil.com" 与编码形态
	// "/%5Cevil.com" 同拒（原仅拒 "//"；本端点与 safeRedirectPath 双点同步）。
	if !isSafeLocalRedirectPath(next) {
		next = "/" // 站内相对路径白名单（// 与 /\ 反斜杠/编码形态同拒）
	}
	// F12（C23，2026-10-10 C级债务收尾批）：HttpOnly=true——非凭据偏好 cookie 的
	// 防御纵深（JS 侧零消费实证——grmail.js 仅操作 /lang 链接 href；服务端读取
	// 不受 HttpOnly 影响，行为零变化）。
	// D4-B（Webmail前端缺陷修复批批一——干系人裁决 2026-10-10 20:14）：Secure 按
	// 请求 scheme 动态——明文部署（-p 端口/向导期 80）下语言偏好可写入生效（原恒
	// Secure 被浏览器静默丢弃致切换失效）；HTTPS 部署零变化。披露：明文通道低敏感
	// 偏好 cookie 可被中间人读取（非凭据——__Host-sid 会话 cookie 恒 Secure不受影响）。
	// E-4（外部审计缺陷修复批 W-02——gin c.SetCookie 七参签名无 SameSite 位）：
	// 改 http.SetCookie 显式 SameSite=Lax——与本函数既有注释口径一致化（原实际未设）。
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     langCookieName,
		Value:    string(target),
		MaxAge:   365 * 24 * 3600,
		Path:     "/",
		Secure:   c.Request.TLS != nil, // D4-B：按请求 scheme 动态（保持）
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	c.Redirect(http.StatusFound, next)
}

// csvImportMaxBytes 上传 CSV 大小上限（2MB 工程常量——计划书 1.5⑤）。
const csvImportMaxBytes = 2 << 20

// csvImportPOST CSV 批量收件人导入端点（POST /compose/csv-import——契约 v1.12.0 3.2，
// Q5-A）：multipart 字段 file→分隔符检测→表头列识别（中英双语清单——G5 逐字）→
// net/mail 地址验证→候选勾选片段（HTML——前端 fetch innerHTML 消费）；解析型端点
// 无落库（csrfProtect 沿会话绑定形态——纵深防御）。
func (s *Server) csvImportPOST(c *gin.Context) {
	// B6（Webmail前端缺陷修复批批一）：四处错误文案 Tr 化（原英文纯文本——中文
	// 界面语言不符，三轮评审三轮#9）。
	lang := langOf(c)
	fh, err := c.FormFile("file")
	if err != nil || fh == nil {
		c.Data(http.StatusBadRequest, "text/plain; charset=utf-8", []byte(templates.Tr(lang, "csv.fileRequired")))
		return
	}
	if fh.Size > csvImportMaxBytes {
		c.Data(http.StatusRequestEntityTooLarge, "text/plain; charset=utf-8", []byte(templates.Tr(lang, "csv.tooLarge")))
		return
	}
	f, oerr := fh.Open()
	if oerr != nil {
		c.Data(http.StatusBadRequest, "text/plain; charset=utf-8", []byte(templates.Tr(lang, "csv.readFailed")))
		return
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, fh.Size)
	if _, rerr := f.Read(buf); rerr != nil {
		c.Data(http.StatusBadRequest, "text/plain; charset=utf-8", []byte(templates.Tr(lang, "csv.readFailed")))
		return
	}
	rows, skipped := parseCSVRecipients(buf)
	var b bytes.Buffer
	// C2/E-1-A（β 批）：容器挂 .table-wrap 双类——并入统一表格体系（app.css 自有
	// 边框规则废止；仅类名消费零逻辑变化）。
	b.WriteString(`<div class="csv-candidates table-wrap"><p>`)
	b.WriteString(templates.Tr(lang, "compose.csvTarget"))
	// E3（Webmail前端缺陷修复批批二）：候选表补表头 th（scope=col——原无 thead 行
	// 结构不规范）+勾选框程序化名称（aria-label=候选地址——读屏逐行可辨）。
	b.WriteString(`</p><table><thead><tr><th scope="col"><span class="sr-only">`)
	b.WriteString(templates.Tr(lang, "common.selectAllCol"))
	b.WriteString(`</span></th><th scope="col">`)
	b.WriteString(templates.Tr(lang, "csv.colAddr"))
	b.WriteString(`</th><th scope="col">`)
	b.WriteString(templates.Tr(lang, "csv.colName"))
	b.WriteString(`</th></tr></thead><tbody>`)
	for _, r := range rows {
		// 安全原子性批 F8（2026-10-06）：地址/姓名列 HTML 转义（Go 标准库）——
		// 该片段经 compose.templ innerHTML 消费，未转义姓名可注入标记/脚本语义
		// （Addr 虽经 net/mail 校验仍统一转义——纵深防御）。
		// B3（批一）：value 属性改 html.EscapeString——原 %q 为 Go 字符串字面量
		// 转义（" → \"）非 HTML 属性转义，quoted-string 本地部合法地址
		// （如 "<b>x</b>"@example.com——net/mail 接受）致属性断裂 DOM 注入
		// （三轮评审三轮#25）；与文本列同一转义器对齐。
		fmt.Fprintf(&b, `<tr><td><input type="checkbox" class="csv-addr" aria-label="%s" value="%s"/></td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(r.Addr), html.EscapeString(r.Addr), html.EscapeString(r.Addr), html.EscapeString(r.Name))
	}
	b.WriteString(`</tbody></table><p>`)
	// B6：计数行 Trf 化（原硬编码英文 "%d rows, %d skipped"）。
	fmt.Fprintf(&b, "%s", templates.Trf(lang, "csv.rowsFmt", len(rows), skipped))
	b.WriteString(` <button type="button" id="csv-merge-btn">`)
	b.WriteString(templates.Tr(lang, "compose.csvConfirm"))
	b.WriteString(`</button></p></div>`)
	c.Data(http.StatusOK, "text/html; charset=utf-8", b.Bytes())
}

// csvRecipient CSV 候选行（地址+姓名——G5 列识别产物）。
type csvRecipient struct {
	Addr string
	Name string
}

// csvEmailColumns 邮箱列表头候选（中英双语——G5 逐字）。
var csvEmailColumns = map[string]bool{
	"email": true, "e-mail": true, "mail": true,
	"邮箱": true, "邮件": true, "电子邮件": true,
}

// csvNameColumns 姓名列表头候选（中英双语——G5 逐字）。
var csvNameColumns = map[string]bool{
	"name": true, "姓名": true, "名字": true, "昵称": true, "称呼": true,
}

// parseCSVRecipients CSV 字节→候选行集（分隔符检测（`,` `;` `\t` `|` 首行频次取最大）
// +表头列识别+地址验证；无效行跳过计数——G5 形态；同地址去重保序）。
// 参数：raw CSV 字节。返回：候选行集与跳过计数。
func parseCSVRecipients(raw []byte) ([]csvRecipient, int) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, 0
	}
	firstLine := raw
	if idx := bytes.IndexByte(raw, '\n'); idx >= 0 {
		firstLine = raw[:idx]
	}
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.Comma = detectCsvDelimiter(string(firstLine))
	reader.FieldsPerRecord = -1 // 宽松行（列数不齐跳过）
	records, err := reader.ReadAll()
	if err != nil || len(records) == 0 {
		return nil, 0
	}
	header := records[0]
	emailIdx, nameIdx := -1, -1
	for i, col := range header {
		key := strings.ToLower(strings.TrimSpace(col))
		if emailIdx < 0 && csvEmailColumns[key] {
			emailIdx = i
		}
		if nameIdx < 0 && csvNameColumns[key] {
			nameIdx = i
		}
	}
	if emailIdx < 0 {
		// 无可识别表头：单列文件按整列地址尝试（G5 宽容口径——无表头纯地址清单；
		// 首行也按数据解析）
		emailIdx, nameIdx = 0, -1
	} else {
		records = records[1:] // 表头行剔除
	}
	out := make([]csvRecipient, 0, len(records))
	seen := map[string]bool{}
	skipped := 0
	for _, rec := range records {
		if emailIdx >= len(rec) {
			skipped++
			continue
		}
		addr := strings.TrimSpace(rec[emailIdx])
		if addr == "" || seen[addr] {
			skipped++
			continue
		}
		if _, perr := mail.ParseAddress(addr); perr != nil {
			skipped++
			continue
		}
		name := ""
		if nameIdx >= 0 && nameIdx < len(rec) {
			name = strings.TrimSpace(rec[nameIdx])
		}
		seen[addr] = true
		out = append(out, csvRecipient{Addr: addr, Name: name})
	}
	return out, skipped
}

// detectCsvDelimiter 分隔符检测（首行四候选频次取最大——G5 形态；缺省逗号）。
// 参数：line 首行文本。返回：csv.Reader 分隔符 rune。
func detectCsvDelimiter(line string) rune {
	best, bestN := ',', -1
	for _, d := range []byte{',', ';', '\t', '|'} {
		if n := strings.Count(line, string(d)); n > bestN {
			best, bestN = rune(d), n
		}
	}
	return best
}
