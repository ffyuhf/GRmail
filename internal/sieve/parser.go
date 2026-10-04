// sieve 语法器：rfc5228 §8.2 文法的递归下降实现（R1-A 全自研）。
// 规范锚点：§2.6（位置/标签/可选参数序——标签先于位置参数，同标签禁重复）；§2.7
// （MATCH-TYPE/COMPARATOR/ADDRESS-PART 语法元素）；§2.9（三类命令——动作以 ';' 终止、
// 控制结构以块终止）；§2.10.5+§3.2（require MUST 前置于一切非 require 命令；未 require
// 的扩展不可用）；§2.10.7（嵌套 15 层 MUST——块与测试列表双计数）；§3.1（elsif/else
// 仅可链随 if/elsif——「else if」序列禁止）；§3.3（stop）；§4（fileinto/redirect/keep/
// discard 动作参数形态）；§5（九测试参数形态——size :over/:under 恰一、envelope 同
// address 形态）；rfc5232 §3/§4（setflag/addflag/removeflag/hasflag 参数——无 variables
// 支持口径：显式变量名形态不识别，全部字符串并入标志列表/单列表）。
// 修改历史：
//
//	2026-09-21 00:48:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 5）
//	2026-09-29 17:16:00 | 修正 | RFC候选修正批次 RF-F：F-S1 header/address/envelope 两列表 Names/Keys 边界承载+F-S14 fileinto :flags 文法对齐与标签白名单（计划书 1.1 单元 RF-F）
package sieve

import (
	"fmt"
	"strings"
)

// maxNesting 嵌套上限（rfc5228 §2.10.7：块与测试列表各 MUST 支持 15 层）。
const maxNesting = 15

// 支持的能力集（SIEVE 能力通告同源——U12 计划书 1.5⑥：
// "fileinto envelope imap4flags encoded-character"；base 语言无需 require）。
var supportedCapabilities = map[string]bool{
	"fileinto":          true,
	"envelope":          true,
	"imap4flags":        true,
	"encoded-character": true,
}

// Parse 解析脚本源（编译期校验全量：词法+语法+require 前置+能力声明+嵌套计数）。
// 参数：src 脚本源文本。返回：AST；错误为 *SyntaxError（行号定位——
// PUTSCRIPT/CHECKSCRIPT/Web 保存的拒绝依据）。
func Parse(src string) (*Script, error) {
	lx := newLexer(src)
	p := &parser{}
	// 预读全量 token（词法错误在此期拦截；语法期纯 token 流递归下降）
	for {
		tok, err := lx.next()
		if err != nil {
			return nil, err
		}
		p.tokens = append(p.tokens, tok)
		if tok.kind == tkEOF {
			break
		}
	}

	script := &Script{Requires: map[string]bool{}}
	seenNonRequire := false
	for {
		t := p.cur()
		if t.kind == tkEOF {
			break
		}
		if t.kind != tkIdent {
			return nil, syntaxErr(t.line, "期望命令名，得 %s", tokenDesc(t))
		}
		if t.str == "require" {
			if seenNonRequire {
				return nil, syntaxErr(t.line, "require 必须先于其他命令（rfc5228 §3.2）")
			}
			cmd, err := p.parseRequire()
			if err != nil {
				return nil, err
			}
			for _, cap := range cmd.Strings {
				if !supportedCapabilities[cap] && !strings.HasPrefix(cap, "comparator-") {
					return nil, syntaxErr(t.line, "不支持的能力 %q（require 拒绝——rfc5228 §2.10.5）", cap)
				}
				script.Requires[cap] = true
			}
			continue
		}
		seenNonRequire = true
		break // 其余命令（含 if/elsif/else 链折叠）统一经 parseStatementSeq 承载——
		// 顶层链与块内链同径（§3.1）
	}
	if seenNonRequire {
		cmds, err := p.parseStatementSeq(1)
		if err != nil {
			return nil, err
		}
		script.Commands = append(script.Commands, cmds...)
	}
	return script, nil
}

// parser 递归下降语法器（token 预读全量）。
type parser struct {
	tokens []token
	pos    int
}

// cur 当前 token。
func (p *parser) cur() token { return p.tokens[p.pos] }

// advance 前进并返回前一 token。
func (p *parser) advance() token {
	t := p.tokens[p.pos]
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
	return t
}

// expect 消费指定类别 token（失配报错）。
func (p *parser) expect(k tokenKind, what string) (token, error) {
	t := p.cur()
	if t.kind != k {
		return token{}, syntaxErr(t.line, "期望 %s，得 %s", what, tokenDesc(t))
	}
	return p.advance(), nil
}

// tokenDesc token 的人类可读描述（错误消息）。
func tokenDesc(t token) string {
	switch t.kind {
	case tkEOF:
		return "脚本结尾"
	case tkIdent:
		return fmt.Sprintf("标识符 %q", t.str)
	case tkTag:
		return fmt.Sprintf("标签 :%s", t.str)
	case tkNumber:
		return fmt.Sprintf("数字 %d", t.num)
	case tkString:
		return fmt.Sprintf("字符串 %q", truncateStr(t.str))
	case tkLParen:
		return "'('"
	case tkRParen:
		return "')'"
	case tkLBrace:
		return "'{'"
	case tkRBrace:
		return "'}'"
	case tkComma:
		return "','"
	case tkSemicolon:
		return "';'"
	}
	return "未知 token"
}

// truncateStr 错误消息截断（长串不打爆）。
func truncateStr(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}

// parseRequire 解析 require 命令（§3.2：字符串列表+分号）。
func (p *parser) parseRequire() (CommandNode, error) {
	t := p.advance() // 'require'
	node := CommandNode{Name: "require", Line: t.line}
	strs, err := p.parseStringOrList()
	if err != nil {
		return node, err
	}
	node.Strings = strs
	if _, err = p.expect(tkSemicolon, "';'（require 结束）"); err != nil {
		return node, err
	}
	return node, nil
}

// parseCommand 解析单命令（depth=当前块嵌套深度——§2.10.7 计数）。
func (p *parser) parseCommand(depth int) (CommandNode, error) {
	t := p.cur()
	if t.kind != tkIdent {
		return CommandNode{}, syntaxErr(t.line, "期望命令名，得 %s", tokenDesc(t))
	}
	p.advance()
	node := CommandNode{Name: t.str, Line: t.line}
	switch t.str {
	case "if":
		test, err := p.parseTest(1)
		if err != nil {
			return node, err
		}
		node.Test = test
		blk, err := p.parseBlock(depth)
		if err != nil {
			return node, err
		}
		node.Block = blk
	case "elsif", "else":
		return node, syntaxErr(t.line, "%q 仅可链随 if/elsif 块（rfc5228 §3.1——else if 序列禁止）", t.str)
	case "require":
		return node, syntaxErr(t.line, "require 仅可出现于脚本最前部（rfc5228 §3.2）")
	case "stop", "keep", "discard":
		if _, err := p.expect(tkSemicolon, "';'"); err != nil {
			return node, err
		}
	case "fileinto":
		tags, err := p.parseTags()
		if err != nil {
			return node, err
		}
		node.Tags = tags
		// RF-F/F-S14：fileinto 文法=[:flags <flags-list>] <mailbox>（rfc5228 §4.1+
		// rfc5232 §3 L380——参数序=标志列表在前+邮箱名在后）；标签白名单仅 :flags
		// （文法外标签=语法错误——rfc5228 §2.6.3）
		hasFlags := false
		for _, tg := range tags {
			if tg.Tag != "flags" {
				return node, syntaxErr(t.line, "fileinto 未知标签 :%s（rfc5228 §2.6.3——仅 :flags）", tg.Tag)
			}
			hasFlags = true
		}
		strs, err := p.parseStringOrList()
		if err != nil {
			return node, err
		}
		if hasFlags {
			// :flags <flags-list> <mailbox>：两参数形态——flags 列表+邮箱名（恰一）
			mbox, err := p.parseStringOrList()
			if err != nil {
				return node, err
			}
			if len(mbox) != 1 {
				return node, syntaxErr(t.line, "fileinto 恰一个邮箱名参数（rfc5228 §4.1）")
			}
			node.Strings = append(strs, mbox...) // [flags..., mailbox]——求值侧取末元素为邮箱
		} else {
			if len(strs) != 1 {
				return node, syntaxErr(t.line, "fileinto 恰一个邮箱名参数（rfc5228 §4.1）")
			}
			node.Strings = strs
		}
		if _, err = p.expect(tkSemicolon, "';'"); err != nil {
			return node, err
		}
	case "redirect":
		strs, err := p.parseStringOrList()
		if err != nil {
			return node, err
		}
		if len(strs) != 1 {
			return node, syntaxErr(t.line, "redirect 恰一个地址参数（rfc5228 §4.2）")
		}
		node.Strings = strs
		if _, err = p.expect(tkSemicolon, "';'"); err != nil {
			return node, err
		}
	case "setflag", "addflag", "removeflag":
		// rfc5232 §3：[<变量名>] <flags 列表>——无 variables 支持口径：
		// 显式变量名形态不识别，全部字符串并入标志列表（工程宽容，登记已知限制）
		strs, err := p.parseStringOrList()
		if err != nil {
			return node, err
		}
		if len(strs) == 0 {
			return node, syntaxErr(t.line, "%s 至少一个标志参数（rfc5232 §3）", t.str)
		}
		node.Strings = strs
		if _, err = p.expect(tkSemicolon, "';'"); err != nil {
			return node, err
		}
	default:
		return node, syntaxErr(t.line, "未知命令 %q", t.str)
	}
	return node, nil
}

// parseBlock 解析命令块（§2.8：'{' 命令序列 '}'；嵌套深度计数——§2.10.7）。
// 块内 elsif/else 链随语义：if 块后的 elsif/else 由 parseStatementSeq 消费。
func (p *parser) parseBlock(depth int) ([]CommandNode, error) {
	if _, err := p.expect(tkLBrace, "'{'"); err != nil {
		return nil, err
	}
	cmds, err := p.parseStatementSeq(depth + 1) // 块内层+1（§2.10.7 逐块计数）
	if err != nil {
		return nil, err
	}
	if _, err = p.expect(tkRBrace, "'}'"); err != nil {
		return nil, err
	}
	return cmds, nil
}

// parseStatementSeq 命令序列（含 if/elsif/else 链折叠——elsif/else 挂接前一 if 节点）。
func (p *parser) parseStatementSeq(depth int) ([]CommandNode, error) {
	if depth > maxNesting {
		t := p.cur()
		return nil, syntaxErr(t.line, "块嵌套超过 %d 层（rfc5228 §2.10.7）", maxNesting)
	}
	var cmds []CommandNode
	for {
		t := p.cur()
		if t.kind == tkRBrace || t.kind == tkEOF {
			return cmds, nil
		}
		if t.kind != tkIdent {
			return nil, syntaxErr(t.line, "期望命令名，得 %s", tokenDesc(t))
		}
		// require 块内禁止（§3.2「before anything other than a require」）
		if t.str == "require" {
			return nil, syntaxErr(t.line, "require 不可出现于块内（rfc5228 §3.2）")
		}
		cmd, err := p.parseCommand(depth)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, cmd)
		// elsif/else 链（§3.1：仅随 if/elsif）
		for p.cur().kind == tkIdent && (p.cur().str == "elsif" || p.cur().str == "else") {
			kt := p.advance()
			if cmd.Name != "if" && cmd.Name != "elsif" {
				return nil, syntaxErr(kt.line, "%s 必须紧随 if/elsif 块（rfc5228 §3.1）", kt.str)
			}
			chain := CommandNode{Name: kt.str, Line: kt.line}
			if kt.str == "elsif" {
				test, err := p.parseTest(1)
				if err != nil {
					return nil, err
				}
				chain.Test = test
			}
			blk, err := p.parseBlock(depth)
			if err != nil {
				return nil, err
			}
			chain.Block = blk
			cmd = chain
			cmds = append(cmds, chain)
			// 链节点挂接：扁平序列形态——求值器按 Name+前驱关系处理链（elsif/else
			// 仅当前驱 if/elsif 测试为假时进入——扁平序列+求值器链状态机，等价文法树）
		}
	}
}

// parseTest 解析测试（depth=测试列表嵌套深度——§2.10.7 双计数）。
func (p *parser) parseTest(depth int) (*TestNode, error) {
	if depth > maxNesting {
		t := p.cur()
		return nil, syntaxErr(t.line, "测试列表嵌套超过 %d 层（rfc5228 §2.10.7）", maxNesting)
	}
	t := p.cur()
	if t.kind != tkIdent {
		return nil, syntaxErr(t.line, "期望测试名，得 %s", tokenDesc(t))
	}
	p.advance()
	node := &TestNode{Name: t.str, Line: t.line}
	tags, err := p.parseTags()
	if err != nil {
		return nil, err
	}
	node.Tags = tags
	switch t.str {
	case "true", "false":
		// 无参数
	case "not":
		sub, err := p.parseTest(depth + 1)
		if err != nil {
			return nil, err
		}
		node.Tests = []*TestNode{sub}
	case "allof", "anyof":
		if _, err = p.expect(tkLParen, "'('（测试列表）"); err != nil {
			return nil, err
		}
		for {
			sub, err := p.parseTest(depth + 1)
			if err != nil {
				return nil, err
			}
			node.Tests = append(node.Tests, sub)
			if p.cur().kind == tkComma {
				p.advance()
				continue
			}
			break
		}
		if _, err = p.expect(tkRParen, "')'"); err != nil {
			return nil, err
		}
	case "exists":
		strs, err := p.parseStringOrList()
		if err != nil {
			return nil, err
		}
		node.Strings = strs
	case "size":
		// §5.9：:over/:under 恰一 + 数字
		hasTag := ""
		for _, tg := range tags {
			if tg.Tag == "over" || tg.Tag == "under" {
				if hasTag != "" {
					return nil, syntaxErr(t.line, "size 恰一个 :over/:under（rfc5228 §5.9）")
				}
				hasTag = tg.Tag
			}
		}
		if hasTag == "" {
			return nil, syntaxErr(t.line, "size 须 :over 或 :under（rfc5228 §5.9）")
		}
		nt, err := p.expect(tkNumber, "数字（size 上限）")
		if err != nil {
			return nil, err
		}
		node.Number = &nt.num
	case "header", "address", "envelope":
		// header §5.7：<header-names> <keys>；address §5.1/[ADDRESS-PART]/envelope
		// §5.4 同形态两列表（值×键任一命中即真）——RF-F/F-S1：两列表边界经
		// Names/Keys 结构化承载（rfc5228 §5.7 双列表全量语义——修正扁平拼接丢失）
		first, err := p.parseStringOrList()
		if err != nil {
			return nil, err
		}
		second, err := p.parseStringOrList()
		if err != nil {
			return nil, err
		}
		if len(first) == 0 || len(second) == 0 {
			return nil, syntaxErr(t.line, "%s 须两个字符串列表参数（names+keys——rfc5228 §5）", t.str)
		}
		node.Names, node.Keys = first, second
	case "hasflag":
		// rfc5232 §4：单列表=flags（内部变量形态——无 variables 支持口径；
		// 双列表变量形态因第二 parseStringOrList 遇 '{' 失败自然拒绝）
		first, err := p.parseStringOrList()
		if err != nil {
			return nil, err
		}
		node.Strings = first
	default:
		return nil, syntaxErr(t.line, "未知测试 %q", t.str)
	}
	return node, nil
}

// parseTags 解析标签参数序列（§2.6.2/2.6.3：标签先于位置参数、任意序、同标签禁重复；
// :comparator 携带字符串值）。
func (p *parser) parseTags() ([]TagArg, error) {
	var tags []TagArg
	seen := map[string]bool{}
	for p.cur().kind == tkTag {
		t := p.advance()
		if seen[t.str] {
			return nil, syntaxErr(t.line, "标签 :%s 重复（rfc5228 §2.7.x——同标签禁重复）", t.str)
		}
		seen[t.str] = true
		tag := TagArg{Tag: t.str}
		if t.str == "comparator" {
			v, err := p.expect(tkString, "比较器名（:comparator 的值）")
			if err != nil {
				return nil, err
			}
			tag.Value = v.str
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// parseStringOrList 解析字符串或字符串列表（§2.4.2.1：单串等价单元素列表；
// 列表形态 '(' 串 ',' 串... ')'）。
func (p *parser) parseStringOrList() ([]string, error) {
	if p.cur().kind == tkLBracket { // string-list = "[" ... "]"（§8.2 文法）
		p.advance()
		var out []string
		for {
			s, err := p.expect(tkString, "字符串")
			if err != nil {
				return nil, err
			}
			out = append(out, s.str)
			if p.cur().kind == tkComma {
				p.advance()
				continue
			}
			break
		}
		if _, err := p.expect(tkRBracket, "']'"); err != nil {
			return nil, err
		}
		return out, nil
	}
	s, err := p.expect(tkString, "字符串")
	if err != nil {
		return nil, err
	}
	return []string{s.str}, nil
}
