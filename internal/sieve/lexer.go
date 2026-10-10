// sieve 词法器：rfc5228 §2 词法封闭集——标识符/标签/数字/引号串/text: 多行串/两类注释/标点。
// 规范锚点：§2.1（token 大小写不敏感、NUL 禁止、CRLF 行界）；§2.2（空白：空白符/tab/换行，
// 量不限）；§2.3（# 行注释与 /* */ 块注释——语义等价空白，块注释不嵌套）；§2.4.1（数字
// K/M/G 二进制后缀紧邻）；§2.4.2（引号串转义仅 \\ 与 \"；text: 多行 dot-stuff 还原——
// 「. 前缀行剥一个点，.. 前缀保留」§2.4.2 L440-457）。
// 工程口径（登记）：行界宽容接受 \r\n 与 \n（PUTSCRIPT 客户端常见 LF 形态——Dovecot 同域
// 宽容先例；text: 串值行界统一 \n 输出）。
// 修改历史：
//
//	2026-09-21 00:47:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 4）
//	2026-10-10 16:05:00 | 修正 | C级债务收尾批 F18④/C19④（G2 批准 2026-10-10
//	  15:45:40）：lexNumber 后缀乘法溢出预检——累积值虽有 (1<<62)/10 上界防护，
//	  ×K/M/G 仍可越 int64 回绕为负值绕过终检（如 4e17G≈4.3e26 溢出）；乘前预检
package sieve

import (
	"fmt"
	"strings"
)

// tokenKind 词法 token 类别。
type tokenKind int

// token 类别枚举（rfc5228 §8.1 Lexical Tokens）。
const (
	tkEOF       tokenKind = iota
	tkIdent               // 标识符（命令/测试名——已归一小写）
	tkTag                 // :tag（已归一小写）
	tkNumber              // 数字（K/M/G 已展开为字节数）
	tkString              // 引号串或 text: 多行串（值已转义还原+dot-unstuff）
	tkLParen              // (
	tkRParen              // )
	tkLBrace              // {
	tkRBrace              // }
	tkComma               // ,
	tkSemicolon           // ;
	tkLBracket            // [（string-list——rfc5228 §8.2 文法）
	tkRBracket            // ]
)

// token 单个词法单元。
type token struct {
	kind tokenKind
	str  string // ident/tag 名或字符串值
	num  int64  // tkNumber 值
	line int    // 源行号（错误定位——PUTSCRIPT/CHECKSCRIPT 编译期拒绝文本）
}

// lexer 词法器（逐字符扫描；零 IO——NFR-015 纯函数）。
type lexer struct {
	src  string
	pos  int
	line int
}

// newLexer 构造词法器。
// 参数：src 脚本源文本。返回：词法器实例。
func newLexer(src string) *lexer {
	return &lexer{src: src, pos: 0, line: 1}
}

// SyntaxError 编译期语法错误（行号定位——CHECKSCRIPT/PUTSCRIPT/Web 保存共用拒绝依据）。
type SyntaxError struct {
	Line int
	Msg  string
}

// Error 实现 error 接口。
func (e *SyntaxError) Error() string {
	return fmt.Sprintf("sieve 语法错误（第 %d 行）: %s", e.Line, e.Msg)
}

// syntaxErr 便捷构造。
func syntaxErr(line int, format string, args ...any) error {
	return &SyntaxError{Line: line, Msg: fmt.Sprintf(format, args...)}
}

// next 全部 token（词法分析主入口；遇词法错误即停）。
func (l *lexer) next() (token, error) {
	for {
		// 跳过空白（§2.2；\r\n 与 \n 均行界——工程宽容口径）
		for l.pos < len(l.src) {
			c := l.src[l.pos]
			if c == ' ' || c == '\t' {
				l.pos++
			} else if c == '\n' {
				l.pos++
				l.line++
			} else if c == '\r' {
				l.pos++
				if l.pos < len(l.src) && l.src[l.pos] == '\n' {
					l.pos++
				}
				l.line++
			} else {
				break
			}
		}
		if l.pos >= len(l.src) {
			return token{kind: tkEOF, line: l.line}, nil
		}
		c := l.src[l.pos]
		// NUL 拒绝（§2.1：NUL is never permitted）
		if c == 0 {
			return token{}, syntaxErr(l.line, "脚本含 NUL 字节（rfc5228 §2.1 禁止）")
		}
		// 行注释（§2.3：# 至 CRLF）
		if c == '#' {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' && l.src[l.pos] != '\r' {
				l.pos++
			}
			continue
		}
		// 块注释（§2.3：/* */ 跨行不嵌套）
		if c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*' {
			startLine := l.line
			l.pos += 2
			closed := false
			for l.pos < len(l.src) {
				if l.src[l.pos] == '\n' {
					l.line++
				}
				if l.src[l.pos] == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
					l.pos += 2
					closed = true
					break
				}
				l.pos++
			}
			if !closed {
				return token{}, syntaxErr(startLine, "块注释未闭合")
			}
			continue
		}
		break
	}

	c := l.src[l.pos]
	line := l.line
	switch {
	case c == '(':
		l.pos++
		return token{kind: tkLParen, line: line}, nil
	case c == ')':
		l.pos++
		return token{kind: tkRParen, line: line}, nil
	case c == '{':
		l.pos++
		return token{kind: tkLBrace, line: line}, nil
	case c == '}':
		l.pos++
		return token{kind: tkRBrace, line: line}, nil
	case c == ',':
		l.pos++
		return token{kind: tkComma, line: line}, nil
	case c == '[':
		l.pos++
		return token{kind: tkLBracket, line: line}, nil
	case c == ']':
		l.pos++
		return token{kind: tkRBracket, line: line}, nil
	case c == ';':
		l.pos++
		return token{kind: tkSemicolon, line: line}, nil
	case c == ':':
		return l.lexTag()
	case c == '"':
		return l.lexQuoted()
	case isDigit(c):
		return l.lexNumber()
	case isIdentStart(c):
		return l.lexIdentOrText()
	default:
		return token{}, syntaxErr(line, "非法字符 %q", string(rune(c)))
	}
}

// lexTag 解析 :tag（§2.6.2；标识符形态——已归一小写）。
func (l *lexer) lexTag() (token, error) {
	line := l.line
	l.pos++ // ':'
	if l.pos >= len(l.src) || !isIdentStart(l.src[l.pos]) {
		return token{}, syntaxErr(line, "空标签（':' 后须跟标识符）")
	}
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	return token{kind: tkTag, str: strings.ToLower(l.src[start:l.pos]), line: line}, nil
}

// lexQuoted 解析引号串（§2.4.2：转义仅 \\ 与 \"——「\a 无特殊含义按字面 a」；
// 引号串可跨行——行界入值按 \n 统一）。
func (l *lexer) lexQuoted() (token, error) {
	line := l.line
	l.pos++ // 开引号
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '"':
			l.pos++
			return token{kind: tkString, str: b.String(), line: line}, nil
		case c == '\\':
			if l.pos+1 >= len(l.src) {
				return token{}, syntaxErr(line, "字符串以反斜杠结尾")
			}
			n := l.src[l.pos+1]
			if n == '\\' || n == '"' {
				b.WriteByte(n) // 合法转义还原
				l.pos += 2
			} else {
				b.WriteByte(n) // 未定义转义按无反斜杠字面（§2.4.2 SHOULD NOT 后宽容）
				l.pos += 2
			}
		case c == '\r':
			// CRLF 行界→值内 \n（跨行引号串）
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n' {
				l.pos++
			}
			b.WriteByte('\n')
			l.pos++
			l.line++
		case c == '\n':
			b.WriteByte('\n')
			l.pos++
			l.line++
		case c == 0:
			return token{}, syntaxErr(line, "字符串含 NUL 字节（rfc5228 §2.1 禁止）")
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return token{}, syntaxErr(line, "引号串未闭合")
}

// lexNumber 解析数字（§2.4.1：十进制非负+可选 K/M/G 二进制后缀紧邻；
// 实现义务范围 0..2^31-1 MUST——超界报错）。
func (l *lexer) lexNumber() (token, error) {
	line := l.line
	start := l.pos
	for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
		l.pos++
	}
	digits := l.src[start:l.pos]
	mult := int64(1)
	if l.pos < len(l.src) {
		switch l.src[l.pos] {
		case 'K', 'k':
			mult, l.pos = 1<<10, l.pos+1
		case 'M', 'm':
			mult, l.pos = 1<<20, l.pos+1
		case 'G', 'g':
			mult, l.pos = 1<<30, l.pos+1
		}
	}
	var val int64
	for i := 0; i < len(digits); i++ {
		val = val*10 + int64(digits[i]-'0')
		if val > (1<<62)/10 { // 溢出防护
			return token{}, syntaxErr(line, "数字超出可表示范围")
		}
	}
	// F18④/C19④（2026-10-10 C级债务收尾批）：后缀乘法溢出预检——累积值虽受
	// 上界防护（≤约 4.6e17），×K/M/G 仍可越 int64 回绕为负值绕过下方终检
	// （溢出值可能 ≤2^31-1 假通过）；乘前按上限预检（mult=1 纯数字无需预检，
	// 终检兜底）。
	if mult > 1 && val > (1<<31-1)/mult {
		return token{}, syntaxErr(line, "数字超出 MUST 支持范围 0..2^31-1（rfc5228 §2.4.1）")
	}
	val *= mult
	if val > 1<<31-1 {
		return token{}, syntaxErr(line, "数字超出 MUST 支持范围 0..2^31-1（rfc5228 §2.4.1）")
	}
	return token{kind: tkNumber, num: val, line: line}, nil
}

// lexIdentOrText 解析标识符或 text: 多行串开头（§8.1：identifier 或 "text:" 多行形态）。
func (l *lexer) lexIdentOrText() (token, error) {
	line := l.line
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	word := l.src[start:l.pos]
	// text: 多行串（§2.4.2：keyword "text:" 后至行尾可有空白/行注释，然后
	// CRLF.CRLF 终止的 dot-stuffed 正文——「text:」词后必须紧跟 ':'）
	if strings.EqualFold(word, "text") && l.pos < len(l.src) && l.src[l.pos] == ':' {
		l.pos++ // ':'
		return l.lexMultiline(line)
	}
	return token{kind: tkIdent, str: strings.ToLower(word), line: line}, nil
}

// lexMultiline 解析 text: 多行串（§2.4.2 L437-457：CRLF 后正文至 CRLF.CRLF；
// dot-stuff 还原——行首「..」剥一成「.」，行首「.x」按字面保留；text: 与 CRLF
// 之间允许 hash 注释与空白、不允许块注释）。
func (l *lexer) lexMultiline(line int) (token, error) {
	// 跳过 text: 至行尾的空白与 hash 注释（§2.4.2 L459-461）
	for l.pos < len(l.src) && (l.src[l.pos] == ' ' || l.src[l.pos] == '\t' || l.src[l.pos] == '\r') {
		l.pos++
	}
	if l.pos < len(l.src) && l.src[l.pos] == '#' {
		for l.pos < len(l.src) && l.src[l.pos] != '\n' {
			l.pos++
		}
	}
	// 消费行界（\r\n 或 \n）
	if l.pos < len(l.src) && l.src[l.pos] == '\n' {
		l.pos++
		l.line++
	} else {
		return token{}, syntaxErr(line, "text: 后须换行开始多行正文")
	}
	var b strings.Builder
	for {
		// 读一行（至 \n）
		lineStart := l.pos
		end := strings.IndexByte(l.src[lineStart:], '\n')
		var raw string
		if end < 0 {
			raw = l.src[lineStart:]
			l.pos = len(l.src)
		} else {
			raw = l.src[lineStart : lineStart+end]
			l.pos = lineStart + end + 1
		}
		l.line++
		// 去 \r 尾（CRLF 行界）
		raw = strings.TrimSuffix(raw, "\r")
		// 终止判定：单独一行 "."（CRLF . CRLF——§2.4.2 结束序列，终止前的 CRLF 属于值）
		if raw == "." {
			return token{kind: tkString, str: b.String(), line: line}, nil
		}
		// dot-unstuff（§2.4.2：行首 ".." 剥一；行首 ".x"（x 非 '.'）按字面——
		// 但 SHOULD properly dot-stuffed，实现取剥一逻辑：行首 '.' 且次字符 '.' 剥一；
		// 行首 '.' 且非 '.' —— 按字面保留（潜在歧义由脚本作者负责，规范同款口径）
		if len(raw) >= 2 && raw[0] == '.' && raw[1] == '.' {
			raw = raw[1:]
		}
		b.WriteString(raw)
		b.WriteByte('\n')
		if end < 0 {
			return token{}, syntaxErr(line, "text: 多行串未以独行 '.' 终止")
		}
	}
}

// isDigit 十进制数字判定。
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isIdentStart 标识符首字符（§8.1：ALPHA / "_"）。
func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isIdentPart 标识符后续字符（ALPHA / DIGIT / "_"）。
func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }
