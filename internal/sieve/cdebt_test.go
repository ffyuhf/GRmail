// C级债务收尾批测试（F8/F9/F18③④——2026-10-10，G2 批准 15:45:40）。
// 覆盖：header 测试 rfc2047 解码+首尾空白忽略（rfc5228 §2.4.2.2/§5.7）、
// address 测试白名单（§5.1 MUST restrict）、lexNumber 后缀乘法溢出预检、
// 能力声明单源列表。
// 修改历史：
//
//	2026-10-10 16:15:00 | 新建 | C级债务收尾批（计划书步骤 3/7）
package sieve

import (
	"strings"
	"testing"

	grmail "GRmail/internal/mail"
)

// evalCtxOf 构造最小求值上下文（Headers+RawSize——本批测试仅涉及）。
func evalCtxOf(headers map[string][]string) *grmail.EvalContext {
	return &grmail.EvalContext{Headers: headers, RawSize: 100}
}

// TestCDebtHeaderEncodedWord F8/C19②：encoded-word 头值解码后与明文 key 匹配
// （rfc5228 §2.4.2.2「Interpretation of header data SHOULD be done according
// to [MIME3] section 6.2」——"你好" UTF-8 base64 形态）。
func TestCDebtHeaderEncodedWord(t *testing.T) {
	ast, err := Parse(`if header :contains "subject" "你好" { discard; }`)
	if err != nil {
		t.Fatalf("解析: %v", err)
	}
	// 编码头值：解码后命中
	ctx := evalCtxOf(map[string][]string{"subject": {"=?UTF-8?B?5L2g5aW9?="}})
	dlv, err := evalScript(ast, ctx)
	if err != nil {
		t.Fatalf("求值: %v", err)
	}
	if !dlv.Discard {
		t.Fatal("encoded-word 头值解码后应命中 contains")
	}
	// 未编码头值行为回归：明文同命中
	ctx2 := evalCtxOf(map[string][]string{"subject": {" Prefix 你好 Suffix "}})
	dlv2, err := evalScript(ast, ctx2)
	if err != nil {
		t.Fatalf("求值(明文): %v", err)
	}
	if !dlv2.Discard {
		t.Fatal("明文头值既有 contains 行为应保持")
	}
}

// TestCDebtHeaderWhitespaceTrim rfc5228 §5.7「ignoring leading and trailing
// whitespace」：头值首尾空白忽略后 :is 匹配（F8 顺路承载）。
func TestCDebtHeaderWhitespaceTrim(t *testing.T) {
	ast, err := Parse(`if header :is "x-test" "hello" { discard; }`)
	if err != nil {
		t.Fatalf("解析: %v", err)
	}
	dlv, err := evalScript(ast, evalCtxOf(map[string][]string{"x-test": {"  hello  "}}))
	if err != nil {
		t.Fatalf("求值: %v", err)
	}
	if !dlv.Discard {
		t.Fatal("首尾空白应忽略后 :is 命中（§5.7）")
	}
}

// TestCDebtAddressHeaderWhitelist F18③/C19③：address 测试限定地址结构头
// （rfc5228 §5.1 MUST restrict）——白名单外头名运行时错误即停（与未知 envelope
// 部分同款处置）；白名单内（From）正常求值不匹配返回 false。
func TestCDebtAddressHeaderWhitelist(t *testing.T) {
	ast, err := Parse(`if address :is "x-custom" "a@b.c" { discard; }`)
	if err != nil {
		t.Fatalf("解析: %v", err)
	}
	_, err = evalScript(ast, evalCtxOf(nil))
	if err == nil || !strings.Contains(err.Error(), "MUST restrict") {
		t.Fatalf("白名单外头名应报错即停: %v", err)
	}
	astOK, err := Parse(`if address :is "from" "a@b.c" { discard; }`)
	if err != nil {
		t.Fatalf("解析(from): %v", err)
	}
	dlv, err := evalScript(astOK, evalCtxOf(map[string][]string{"from": {"z@y.x"}}))
	if err != nil {
		t.Fatalf("求值(from): %v", err)
	}
	if dlv.Discard {
		t.Fatal("from 值不匹配应 false（白名单内正常求值锚）")
	}
}

// TestCDebtLexerSuffixOverflow F18④/C19④：后缀乘法溢出预检——4e17×G 越 int64
// 回绕路径拦截；边界值 1G/2047M 通过、2048M 越界拒绝（rfc5228 §2.4.1 0..2^31-1）。
func TestCDebtLexerSuffixOverflow(t *testing.T) {
	if _, err := Parse("if size :over 400000000000000000G { discard; }"); err == nil {
		t.Fatal("4e17G 乘法溢出应报错（回绕防护）")
	}
	ast, err := Parse("if size :over 1G { discard; }")
	if err != nil {
		t.Fatalf("1G 合法: %v", err)
	}
	if got := *ast.Commands[0].Test.Number; got != 1073741824 {
		t.Fatalf("1G 应展开 1073741824: %d", got)
	}
	if _, err := Parse("if size :over 2047M { discard; }"); err != nil {
		t.Fatalf("2047M 边界内应通过: %v", err)
	}
	if _, err := Parse("if size :over 2048M { discard; }"); err == nil {
		t.Fatal("2048M 越 2^31-1 应报错")
	}
}

// TestCDebtCapabilitiesSingleSource F9/C20：能力有序列表内容与派生校验集一致
// （parser require 校验与 managesieve 通告的同一事实来源；managesieve 侧产物
// 一致性经其包内既有 SASL 通告断言承载）。
func TestCDebtCapabilitiesSingleSource(t *testing.T) {
	want := []string{"fileinto", "envelope", "imap4flags", "encoded-character"}
	if len(SupportedCapabilities) != len(want) {
		t.Fatalf("能力列表长度: %v", SupportedCapabilities)
	}
	for i, c := range want {
		if SupportedCapabilities[i] != c {
			t.Fatalf("能力序 [%d]: 得 %q 期望 %q", i, SupportedCapabilities[i], c)
		}
		if !supportedCapabilities[c] {
			t.Fatalf("派生校验集缺 %q", c)
		}
	}
}
