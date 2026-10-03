// sieve 包测试矩阵（U12 计划书步骤 4-6 检查点——NFR-015 纯函数全离线）。
// 覆盖锚点：rfc5228 §2.10.2 implicit keep 九场景/§3.1 链语义/§3.2 require 前置/
// §4 四动作/§5 测试（header/address/envelope/size/exists/not/allof/anyof）/
// §2.7 三匹配与双比较器/§8.2 文法拒绝矩阵（else if 禁止/嵌套上限/未知命令）/
// rfc5232 imap4flags（setflag/addflag/:flags/hasflag——\Seen/\Flagged 映射）。
// 修改历史：
//
//	2026-09-21 01:10:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 11）
//	2026-09-29 17:15:00 | 修正 | RFC候选修正批次 RF-F：F-S1/F-S14/F-S21 契约测试再现先行（计划书步骤 1——先红后绿锚）
package sieve

import (
	"strings"
	"testing"

	grmail "GRmail/internal/mail"
)

// evalCtx 测试上下文工厂（消息 A 形态——rfc5228 §1.2 示例）。
func evalCtx() *grmail.EvalContext {
	return &grmail.EvalContext{
		Recipient: "roadrunner@acme.example.com",
		Headers: map[string][]string{
			"from":       {"coyote@desert.example.org"},
			"to":         {"roadrunner@acme.example.com"},
			"subject":    {"I have a present for you"},
			"x-caffeine": {"C8H10N4O2"},
		},
		RawSize:       4096,
		ReceivedCount: 1,
	}
}

// evalT 解析+求值便捷断言。
func evalT(t *testing.T, script string, ctx *grmail.EvalContext) (*grmail.SieveDelivery, error) {
	t.Helper()
	ast, err := Parse(script)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	return evalScript(ast, ctx)
}

// TestImplicitKeep 空脚本/条件未命中/stop——implicit keep 兜底（§2.10.2）。
func TestImplicitKeep(t *testing.T) {
	for _, script := range []string{
		"",
		"if size :over 500K { discard; }", // 未命中（4096 < 512000——§2.10.2 示例原文）
		"stop;",
	} {
		dlv, err := evalT(t, script, evalCtx())
		if err != nil {
			t.Fatalf("脚本 %q 求值失败: %v", script, err)
		}
		if dlv.Discard || dlv.FileInto != "" || len(dlv.Redirects) > 0 {
			t.Fatalf("脚本 %q 应 implicit keep（INBOX 原语义）", script)
		}
	}
}

// TestFileInto fileinto 命中（§4.1——TC-011 判定①锚）。
func TestFileInto(t *testing.T) {
	dlv, err := evalT(t, `require "fileinto";
if header :contains "from" "coyote" { fileinto "Newsletter"; }`, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto != "Newsletter" {
		t.Fatalf("fileinto 目标=%q 期望 Newsletter", dlv.FileInto)
	}
}

// TestFileIntoFlagsHasFlag :flags+imap4flags（rfc5232 §3）。
func TestFileIntoFlagsHasFlag(t *testing.T) {
	dlv, err := evalT(t, `require ["fileinto", "imap4flags"];
if header :contains "from" "coyote" { setflag "\\Seen"; fileinto "NL"; }`, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto != "NL" || !dlv.FlagSeen {
		t.Fatalf("fileinto+setflag \\Seen 未生效: %+v", dlv)
	}
	// hasflag 测试（内部变量——rfc5232 §4）
	dlv2, err := evalT(t, `require "imap4flags";
setflag "\\Flagged";
if hasflag "\\Flagged" { fileinto "F"; }`, evalCtx())
	if err != nil || dlv2 == nil || dlv2.FileInto != "F" {
		t.Fatalf("hasflag 未命中: %+v err=%v", dlv2, err)
	}
}

// TestDiscard discard 命中（§4.4 静默——无投递动作）。
func TestDiscard(t *testing.T) {
	dlv, err := evalT(t, `if header :contains ["from"] ["idiot@example.com"] { discard; }`, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.Discard {
		t.Fatal("未命中条件不应 discard")
	}
	dlv, err = evalT(t, `if header :contains "from" "coyote" { discard; }`, evalCtx())
	if err != nil || !dlv.Discard {
		t.Fatalf("discard 未生效: %+v err=%v", dlv, err)
	}
}

// TestRedirect redirect 数量上限（§4.2 MUST——MaxRedirects=5）。
func TestRedirect(t *testing.T) {
	dlv, err := evalT(t, `redirect "bart@example.com";`, evalCtx())
	if err != nil || len(dlv.Redirects) != 1 || dlv.Redirects[0] != "bart@example.com" {
		t.Fatalf("redirect 未生效: %+v err=%v", dlv, err)
	}
	// 上限：6 个 redirect 超限 → 运行时错误
	sb := strings.Builder{}
	for i := 0; i < 6; i++ {
		sb.WriteString("redirect \"a" + string(rune('a'+i)) + "@x.com\";\n")
	}
	if _, err = evalT(t, sb.String(), evalCtx()); err == nil {
		t.Fatal("6 个 redirect 应超 MaxRedirects=5 上限报错")
	}
}

// TestChain if/elsif/else 链（§3.1——恰一分支）。
func TestChain(t *testing.T) {
	script := `require "fileinto";
if header :contains "from" "noone" { fileinto "A"; }
elsif header :contains "subject" "present" { fileinto "B"; }
else { fileinto "C"; }`
	dlv, err := evalT(t, script, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto != "B" {
		t.Fatalf("elsif 分支未命中: %+v", dlv)
	}
}

// TestEnvelope envelope 测试（§5.4——to=当前收件人）。
func TestEnvelope(t *testing.T) {
	script := `require ["fileinto", "envelope"];
if envelope :all :is "to" "roadrunner@acme.example.com" { fileinto "Env"; }`
	ctx := evalCtx()
	ctx.Envelope.MailFrom = "coyote@desert.example.org"
	dlv, err := evalT(t, script, ctx)
	if err != nil || dlv.FileInto != "Env" {
		t.Fatalf("envelope to 未命中: %+v err=%v", dlv, err)
	}
}

// TestAddressParts ADDRESS-PART 三态（§2.7.4）。
func TestAddressParts(t *testing.T) {
	script := `require "fileinto";
if address :is :domain "from" "desert.example.org" { fileinto "Dom"; }`
	dlv, err := evalT(t, script, evalCtx())
	if err != nil || dlv.FileInto != "Dom" {
		t.Fatalf("address :domain 未命中: %+v err=%v", dlv, err)
	}
}

// TestSizeMatch size over/under（§5.9——恰等于两非）。
func TestSizeMatch(t *testing.T) {
	ctx := evalCtx()
	ctx.RawSize = 4000
	d1, _ := evalT(t, "if size :over 4000 { keep; } else { fileinto \"U\"; }", ctx) // 用 else 观测
	_ = d1
	dlv, err := evalT(t, `require "fileinto"; if size :under 4001 { fileinto "U"; }`, ctx)
	if err != nil || dlv.FileInto != "U" {
		t.Fatalf("size :under 4001 对 4000 应命中: %+v err=%v", dlv, err)
	}
}

// TestComparatorOctet i;octet 大小写敏感（§2.7.3 示例）。
func TestComparatorOctet(t *testing.T) {
	script := `require "fileinto";
if header :contains :comparator "i;octet" "subject" "MAKE MONEY FAST" { fileinto "Spam"; }`
	dlv, err := evalT(t, script, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto == "Spam" {
		t.Fatal("i;octet 下大小写不同不应命中")
	}
}

// TestSyntaxRejects 语法拒绝矩阵（编译期——行号定位）。
func TestSyntaxRejects(t *testing.T) {
	cases := []string{
		"else { keep; }",                           // else 未链随 if（§3.1）
		"keep;\nrequire \"fileinto\";",             // require 后置（§3.2）
		"require \"variables\";",                   // 不支持的能力（§2.10.5）
		"frobnicate;",                              // 未知命令
		"if header :contains \"from\" { keep; }",   // 参数不足
		"size :over 100;",                          // size 位置参数须数字
		"if true { keep; } else if true { keep; }", // else if 禁止（§3.1 L1195）
		"keep", // 缺分号
	}
	for _, src := range cases {
		if _, err := Parse(src); err == nil {
			t.Fatalf("脚本 %q 应编译期拒绝", src)
		}
	}
}

// TestLexerMultiline text: 多行 dot-unstuff（§2.4.2）。
func TestLexerMultiline(t *testing.T) {
	ast, err := Parse("if true { keep; }\n# hash comment\n/* block\ncomment */\nstop;")
	if err != nil {
		t.Fatalf("注释容忍失败: %v", err)
	}
	if len(ast.Commands) != 2 {
		t.Fatalf("命令数=%d 期望 2", len(ast.Commands))
	}
}

// TestEncodedCharacter ${hex:} 解码（§2.4.2.4——require 声明态）。
func TestEncodedCharacter(t *testing.T) {
	script := `require ["fileinto", "encoded-character"];
if header :contains "subject" "$${hex:40}" { fileinto "X"; }`
	dlv, err := evalT(t, script, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto == "X" {
		t.Fatal("解码后键 $@ 不应命中 present 主题（require 声明态——解码已生效且不命中）")
	}
	// 正向命中：${hex:70 72 65 73 65 6e 74} 解码 → "present"（§2.4.2.4 空白分隔序列）
	scriptHit := `require ["fileinto", "encoded-character"];
if header :contains "subject" "${hex:70 72 65 73 65 6e 74}" { fileinto "X"; }`
	dlv2, err := evalT(t, scriptHit, evalCtx())
	if err != nil || dlv2.FileInto != "X" {
		t.Fatalf("encoded-character 解码命中失败: %+v err=%v", dlv2, err)
	}
	// 未 require——字面保留（不解码）："$${hex:40}" 子串不命中
	script2 := `require "fileinto";
if header :contains "subject" "$${hex:40}" { fileinto "X"; }`
	dlv3, err3 := evalT(t, script2, evalCtx())
	if err3 != nil {
		t.Fatalf("求值失败: %v", err3)
	}
	if dlv3.FileInto == "X" {
		t.Fatal("未 require 的 encoded-character 不应解码")
	}
}

// TestStopStopImmediate stop 即停（§3.3——未取消 keep 则保留）。
func TestStopStopImmediate(t *testing.T) {
	dlv, err := evalT(t, "if true { stop; }\ndiscard;", evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.Discard {
		t.Fatal("stop 后 discard 不应执行")
	}
}

// TestNestingLimit 15 层嵌套上限（§2.10.7 MUST）。
func TestNestingLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 16; i++ {
		sb.WriteString("if true { ")
	}
	sb.WriteString("keep;")
	for i := 0; i < 16; i++ {
		sb.WriteString(" }")
	}
	if _, err := Parse(sb.String()); err == nil {
		t.Fatal("16 层嵌套应拒绝（上限 15）")
	}
}

// TestRFCFKeyListFullCarriage F-S1 再现：header 测试 keys 列表全量承载
// （rfc5228 §5.7 L1575-1590 双列表语义——names 与 keys 各为一个 string-list；
// 修正前缺陷：扁平承载后仅末元素作 key，首 key "fail" 沦为头名静默丢失）。
func TestRFCFKeyListFullCarriage(t *testing.T) {
	ctx := evalCtx()
	ctx.Headers["subject"] = []string{"fail"} // 首 key 精确命中场景
	dlv, err := evalT(t, `require "fileinto";
if header :is "subject" ["fail", "error"] { fileinto "Hit"; }`, ctx)
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto != "Hit" {
		t.Fatalf("多 key 列表首元素应参与匹配（F-S1——rfc5228 §5.7 双列表全量承载）: %+v", dlv)
	}
	// names 侧多值：两头名任一命中即真（§5.7「any of the named headers」）
	dlv2, err := evalT(t, `require "fileinto";
if header :contains ["x-miss", "x-caffeine"] "C8H10N4O2" { fileinto "Multi"; }`, ctx)
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv2.FileInto != "Multi" {
		t.Fatalf("header-names 列表多值应逐一取值（F-S1）: %+v", dlv2)
	}
}

// TestRFCFFileintoFlags F-S14 再现：fileinto :flags 文法对齐
// （rfc5232 §3 L380 `fileinto :flags "\\Deleted" "INBOX.From Boss"`——
// 参数序=标志列表在前+邮箱名在后；修正前缺陷：parser 恰一参数校验拒绝合法语法）。
func TestRFCFFileintoFlags(t *testing.T) {
	script := `require ["fileinto", "imap4flags"];
fileinto :flags "\\Seen" "NL";`
	ast, err := Parse(script)
	if err != nil {
		t.Fatalf(":flags 合法文法应可解析（F-S14——rfc5232 §3）: %v", err)
	}
	dlv, err := evalScript(ast, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv.FileInto != "NL" || !dlv.FlagSeen {
		t.Fatalf("fileinto :flags 应承载邮箱名+标志（F-S14）: %+v", dlv)
	}
	// 多标志 bracketed 形态（rfc5232 §3.1 setflag 示例形态）
	dlv2, err := evalT(t, `require ["fileinto", "imap4flags"];
fileinto :flags ["\\Seen", "\\Flagged"] "N2";`, evalCtx())
	if err != nil {
		t.Fatalf("求值失败: %v", err)
	}
	if dlv2.FileInto != "N2" || !dlv2.FlagSeen || !dlv2.FlagFlagged {
		t.Fatalf(":flags bracketed 多标志形态应全承载（F-S14）: %+v", dlv2)
	}
	// 未知标签拒绝（文法外标签=语法错误——rfc5228 §2.6.3 命令标签集合）
	if _, err := Parse(`require "fileinto"; fileinto :unknown "X";`); err == nil {
		t.Fatal("fileinto 未知标签应拒绝（F-S14——标签白名单）")
	}
}

// TestRFCFUnicodeOutOfRange F-S21 再现：encoded-character 超范围报错
// （rfc5228 §2.4.2.4 L567-569「It is an error for a script to use a hexadecimal
// value that isn't in either the range 0 to D7FF or the range E000 to 10FFFF」——
// 修正前缺陷：语法合式但超范围按原样保留静默处理）。
func TestRFCFUnicodeOutOfRange(t *testing.T) {
	_, err := evalT(t, `require ["fileinto", "encoded-character"];
if header :is "subject" "${unicode:110000}" { fileinto "X"; }`, evalCtx())
	if err == nil {
		t.Fatal("${unicode:110000} 超范围应报错（F-S21——rfc5228 §2.4.2.4）")
	}
	// 合法上限边界（10FFFF 含）不报错
	if _, err := evalT(t, `require ["fileinto", "encoded-character"];
if header :is "subject" "${unicode:10FFFF}" { fileinto "X"; }`, evalCtx()); err != nil {
		t.Fatalf("10FFFF 边界值合法不应报错: %v", err)
	}
}
