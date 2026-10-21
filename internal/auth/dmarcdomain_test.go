// DMARC域批 测试承载（G2 批准 2026-10-21 23:20:02 逐字「E-1 B 正常域名，他妈谁会
// 放测试模式给别人发信/E-2 B/ E-3 A/ E-4 A/E-5 B/E-6 A/E-7 A/E-8 A/」四实施四登记）：
// E-3-A 同域去重＋共享缓存查询计数锚（GRM-017）/E-4-A 非法 Sender 拒收锚（GRM-018）/
// E-6-A temperror 裸条目直测（GRM-020）/dedupeDomains 保序去重单元锚；
// E-8-A（GRM-022）anyPerm 分支为防御位完整性（dmarc.Evaluate 返 permerror 仅防御
// 分支——queryLevel 已消化语法坏，Verify 级不可构造），既有三态聚合锚经
// TestVerifyMultiFromWithSenderStrictest 族全量回归承载（16 包 -count=1 全绿实证）；
// 登记不处理四项（E-1-B/E-2-B/E-5-B/E-7-A）零代码零断言。
// SRS：FR-008 判定②（A-R 四项结论）＋判定③（DMARC 处置与豁免面——TC-033 判定
// 原文零触碰）；NFR-004/NFR-015（stub DNS 离线驱动）。
// 既有文件零 diff（沿 permerror批 F-1-B 独立文件先例）。
// 修改历史：
//
//	2026-10-21 23-35-00 | 新建 | DMARC域批（计划书步骤 3/4/6）
package auth

import (
	"context"
	"net"
	"strings"
	"testing"

	"GRmail/internal/config"
)

// countDmarcQueries 统计查询审计中指定域的 _dmarc TXT 查询次数（E-3-A 计数口径）。
func countDmarcQueries(log []string, domain string) int {
	n := 0
	for _, q := range log {
		if q == "_dmarc."+domain {
			n++
		}
	}
	return n
}

// TestDedupeDomainsOrderStable E-3-A 单元锚：保序去重（同域仅保留首见；输入序稳定）。
func TestDedupeDomainsOrderStable(t *testing.T) {
	in := []string{"b.com", "a.com", "b.com", "c.com", "a.com", "b.com"}
	got := dedupeDomains(in)
	want := []string{"b.com", "a.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("去重长度: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("去重保序: got %v want %v", got, want)
		}
	}
}

// TestVerifyMultiFromDedupSharesCache E-3-A（GRM-017）：8 同域地址的多地址 From
// 经去重＋共享缓存后，_dmarc.<域> 查询次数与单地址单域评估完全一致（去重前每域
// 独立 cachedTXT 实例——Discover 首查逐域重复，报告实测 8 同域 65 次 vs 单域 9 次）。
// 断言口径：相对锚（N8==N1）——精确绝对次数依赖内部 Tree Walk 链，等价性即修复目标。
func TestVerifyMultiFromDedupSharesCache(t *testing.T) {
	newService := func() (*VerifierService, *stubResolver) {
		resolver := newStubResolver().
			withTXT("x.com", "v=spf1 ip4:192.0.2.0/24 -all").
			withTXT("_dmarc.x.com", "v=DMARC1; p=none; adkim=r; aspf=r")
		return NewVerifierService(resolver, "mx.local", allOnStack()), resolver
	}

	// 基线：单地址（单域路径——一次 Evaluate 一次缓存实例）
	svc1, res1 := newService()
	if _, err := svc1.Verify(context.Background(),
		incoming("mail.x.com", net.ParseIP("192.0.2.1"), "user@x.com", sampleMessage("x.com"))); err != nil {
		t.Fatalf("单地址验证失败: %v", err)
	}
	n1 := countDmarcQueries(res1.queryLog(), "x.com")

	// 8 同域地址（多域路径——去重后应与单域评估等价）
	addrs := make([]string, 8)
	for i := range addrs {
		addrs[i] = string(rune('a'+i)) + "@x.com"
	}
	svc8, res8 := newService()
	r8, err := svc8.Verify(context.Background(),
		incoming("mail.x.com", net.ParseIP("192.0.2.1"), "user@x.com",
			multiFromMessage(strings.Join(addrs, ", "), "s@x.com")))
	if err != nil {
		t.Fatalf("多地址验证失败: %v", err)
	}
	n8 := countDmarcQueries(res8.queryLog(), "x.com")

	if n8 != n1 {
		t.Fatalf("E-3-A：8 同域地址查询数(%d)应与单域基线(%d)一致（去重＋共享缓存）", n8, n1)
	}
	// 全域无 DMARC fail（p=none 照收）——结论不因去重改变（既有语义零变化锚）
	if r8.DMARC != "pass" && r8.DMARC != "none" {
		t.Fatalf("p=none 域结论应照收族（pass/none）: %s", r8.DMARC)
	}
	if r8.FromHeaderViolation {
		t.Fatalf("合法 Sender（s@x.com）多地址不应 violation")
	}
}

// TestVerifyMultiFromInvalidSenderRejected E-4-A（GRM-018）：Sender 头存在但取值
// 非法（not-an-address——不可解析为邮箱地址）＝无有效 Sender→violation 置位
// （V批 E-3② 批准面旁路收口）：DMARC=permerror＋处置不预计算＋拒收归管道。
// 对照锚：TestVerifyMultiFromNoSenderViolation（完全无 Sender 头）同终态。
func TestVerifyMultiFromInvalidSenderRejected(t *testing.T) {
	resolver := newStubResolver().withTXT("_dmarc.example.com", "v=DMARC1; p=reject")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com",
			multiFromMessage("a@other.net, b@example.com", "not-an-address")))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if !res.FromHeaderViolation {
		t.Fatalf("E-4-A：非法 Sender 取值应视为无有效 Sender→violation 置位（DMARC: %s）", res.DMARC)
	}
	if res.DMARC != "permerror" {
		t.Fatalf("violation 档应 DMARC=permerror（rfc9989 §5.3.1 验证不可能终止）: %s", res.DMARC)
	}
	if res.DMARCDisposition != "" {
		t.Fatalf("violation 档处置不预计算（恒空）: %q", res.DMARCDisposition)
	}
}

// TestBuildAuthResultsTemperrorBareEntry E-6-A（GRM-020）直测：temperror 无签名
// 上下文（dkimDomain 空）时以裸 resinfo 呈现（rfc8601 §2.2 propspec 可选——与
// permerror 裸条目形态对齐；原整条丢失致「未评估」与「查询故障」不可区分收口）。
func TestBuildAuthResultsTemperrorBareEntry(t *testing.T) {
	stack := config.AuthStack{DKIMEnabled: true}
	res := &VerifyResults{DKIM: "temperror"}
	h := buildAuthResultsHeader("mx.local", stack, res,
		"", "smtp.mailfrom", "", "example.com", 0)
	if !strings.Contains(h, ";\r\n\tdkim=temperror") {
		t.Fatalf("E-6-A：A-R 应含裸 dkim=temperror 条目: %s", h)
	}
	if strings.Contains(h, "dkim=temperror header.d=") {
		t.Fatalf("无签名上下文应为裸条目（无 header.d）: %s", h)
	}
}

// TestVerifyMultiFromValidSenderStillAccepted E-4-A 对照锚：合法 Sender 地址
// （s@other.net——可解析）多地址 From 不因校验升级而翻转（既有
// TestVerifyMultiFromWithSenderStrictest 语义的直连回归锚）。
func TestVerifyMultiFromValidSenderStillAccepted(t *testing.T) {
	resolver := newStubResolver().
		withTXT("other.net", "v=spf1 ip4:192.0.2.0/24 -all").
		withTXT("_dmarc.other.net", "v=DMARC1; p=none")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.other.net", net.ParseIP("192.0.2.1"), "user@other.net",
			multiFromMessage("a@other.net, b@other.net", "s@other.net")))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if res.FromHeaderViolation {
		t.Fatalf("合法 Sender 不应 violation（校验升级零翻转锚）: %s", res.DMARC)
	}
}
