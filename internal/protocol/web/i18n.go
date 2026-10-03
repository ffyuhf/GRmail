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
package web

import (
	"bytes"
	"encoding/csv"
	"fmt"
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
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/" // 站内相对路径白名单（// 协议相对形态同拒）
	}
	c.SetCookie(langCookieName, string(target), 365*24*3600, "/", "", true, false)
	c.Redirect(http.StatusFound, next)
}

// csvImportMaxBytes 上传 CSV 大小上限（2MB 工程常量——计划书 1.5⑤）。
const csvImportMaxBytes = 2 << 20

// csvImportPOST CSV 批量收件人导入端点（POST /compose/csv-import——契约 v1.12.0 3.2，
// Q5-A）：multipart 字段 file→分隔符检测→表头列识别（中英双语清单——G5 逐字）→
// net/mail 地址验证→候选勾选片段（HTML——前端 fetch innerHTML 消费）；解析型端点
// 无落库（csrfProtect 沿会话绑定形态——纵深防御）。
func (s *Server) csvImportPOST(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil || fh == nil {
		c.Data(http.StatusBadRequest, "text/plain; charset=utf-8", []byte("CSV file required"))
		return
	}
	if fh.Size > csvImportMaxBytes {
		c.Data(http.StatusRequestEntityTooLarge, "text/plain; charset=utf-8", []byte("CSV too large (2MB)"))
		return
	}
	f, oerr := fh.Open()
	if oerr != nil {
		c.Data(http.StatusBadRequest, "text/plain; charset=utf-8", []byte("CSV open failed"))
		return
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, fh.Size)
	if _, rerr := f.Read(buf); rerr != nil {
		c.Data(http.StatusBadRequest, "text/plain; charset=utf-8", []byte("CSV read failed"))
		return
	}
	rows, skipped := parseCSVRecipients(buf)
	lang := langOf(c)
	var b bytes.Buffer
	b.WriteString(`<div class="csv-candidates"><p>`)
	b.WriteString(templates.Tr(lang, "compose.csvTarget"))
	b.WriteString(`</p><table>`)
	for _, r := range rows {
		fmt.Fprintf(&b, `<tr><td><input type="checkbox" class="csv-addr" value=%q/></td><td>%s</td><td>%s</td></tr>`,
			r.Addr, r.Addr, r.Name)
	}
	b.WriteString(`</table><p>`)
	fmt.Fprintf(&b, "%d rows, %d skipped", len(rows), skipped)
	b.WriteString(` <button type="button" onclick="grmailCsvMerge()">`)
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
