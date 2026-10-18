// permerror可见性批 测试承载（F-1-B——G2 批准 2026-10-18 10:28:07「F-1 B」）：
// aggregateDKIM permerror 聚合口径直测（E-1-A/E-3-A）＋Verify 级 A-R 呈现锚（E-2-A）。
// SRS：FR-008 判定③「验证临时故障（temperror）与 permerror 不触发拒收」实施态
// （硬档误拒与 soft 档误拒双路径收口——checkRejectionPolicy case 集〔fail/none〕
// 零 permerror 命中，档位照收由结论值结构性保证）；NFR-004（A-R 按 rfc8601 生成——
// permerror 为 §2.2 注册结果值）；NFR-015（stub DNS 离线驱动）。
// 既有文件零 diff（F-1-B 获批落点）；V批遗留登记①收口锚。
// 修改历史：
//
//	2026-10-18 10-33-00 | 新建 | permerror可见性批（计划书步骤 3）
package auth

import (
	"context"
	"net"
	"strings"
	"testing"

	ravendkim "github.com/synqronlabs/raven/dkim"
)

// TestAggregateDKIMPermerrorParseFailure 解析失败路径（Signature=nil——raven
// ParseSignature 错误形态，如 b= 非法 base64）：结论 permerror 而非 none（原口径
// 四分支全不命中落 none——硬档误拒+可见性缺口）；无签名上下文报告域空（呈现层
// 裸条目承载，E-2-A）。
func TestAggregateDKIMPermerrorParseFailure(t *testing.T) {
	results := []ravendkim.Result{
		{Status: ravendkim.StatusPermerror, Signature: nil},
	}
	conclusion, reportDomain := aggregateDKIM(results)
	if conclusion != "permerror" {
		t.Fatalf("解析失败应聚合为 permerror（原缺陷落 none）: %s", conclusion)
	}
	if reportDomain != "" {
		t.Fatalf("无签名上下文报告域应为空（裸条目呈现承载）: %q", reportDomain)
	}
}

// TestAggregateDKIMPermerrorWithSignature 公钥/参数永久错误路径（Signature 非 nil
// ——raven checkSignatureParams/lookup 永久错/公钥吊销等形态）：结论 permerror 而非
// fail（原口径「存在签名即 fail」——soft 档误拒）；报告域取该签名 d=（沿 B-S批 F5
// temperror 先例——消费者可见）。
func TestAggregateDKIMPermerrorWithSignature(t *testing.T) {
	results := []ravendkim.Result{
		{Status: ravendkim.StatusPermerror, Signature: &ravendkim.Signature{Domain: "broken.example.com"}},
	}
	conclusion, reportDomain := aggregateDKIM(results)
	if conclusion != "permerror" {
		t.Fatalf("带签名永久错误应聚合为 permerror（原缺陷落 fail 误拒）: %s", conclusion)
	}
	if reportDomain != "broken.example.com" {
		t.Fatalf("报告域应取签名 d=（可见性）: %q", reportDomain)
	}
}

// TestAggregateDKIMFailBeatsPermerror E-1-A 聚合优先级：验签失败（fail——伪造 b=
// verifyWithKey 路径）优先于 permerror——拒收臂输入最大化（TC-029「有签名且验证
// 失败拒收」语义输入面保持；混合场景 fail 邮件仍可被档位拒收）。
func TestAggregateDKIMFailBeatsPermerror(t *testing.T) {
	results := []ravendkim.Result{
		{Status: ravendkim.StatusPermerror, Signature: nil},
		{Status: ravendkim.StatusPermerror, Signature: &ravendkim.Signature{Domain: "broken.example.com"}},
		{Status: ravendkim.StatusFail, Signature: &ravendkim.Signature{Domain: "forged.example.com"}},
	}
	conclusion, reportDomain := aggregateDKIM(results)
	if conclusion != "fail" {
		t.Fatalf("E-1-A：fail 应优先于 permerror（拒收臂输入最大化）: %s", conclusion)
	}
	if reportDomain != "forged.example.com" {
		t.Fatalf("fail 报告域应取 fail 签名 d=: %q", reportDomain)
	}
}

// TestAggregateDKIMPassBeatsPermerror pass 优先保持：任一签名通过即 pass（既有
// 口径第一优先级——permerror 分支不降级 pass）。
func TestAggregateDKIMPassBeatsPermerror(t *testing.T) {
	results := []ravendkim.Result{
		{Status: ravendkim.StatusPermerror, Signature: &ravendkim.Signature{Domain: "broken.example.com"}},
		{Status: ravendkim.StatusPass, Signature: &ravendkim.Signature{Domain: "good.example.com"}},
	}
	conclusion, reportDomain := aggregateDKIM(results)
	if conclusion != "pass" {
		t.Fatalf("pass 应保持第一优先级: %s", conclusion)
	}
	if reportDomain != "good.example.com" {
		t.Fatalf("pass 报告域应取通过签名 d=: %q", reportDomain)
	}
}

// TestAggregateDKIMTemperrorBeatsPermerror temperror 优先保持（B-S批 F5 锚——
// permerror 分支插入不降级 temperror 既有优先级与报告域形态）。
func TestAggregateDKIMTemperrorBeatsPermerror(t *testing.T) {
	results := []ravendkim.Result{
		{Status: ravendkim.StatusPermerror, Signature: nil},
		{Status: ravendkim.StatusTemperror, Signature: &ravendkim.Signature{Domain: "slow.example.com"}},
	}
	conclusion, reportDomain := aggregateDKIM(results)
	if conclusion != "temperror" {
		t.Fatalf("temperror 应保持既有优先级（B-S批 F5 锚）: %s", conclusion)
	}
	if reportDomain != "slow.example.com" {
		t.Fatalf("temperror 报告域沿 F5 先例: %q", reportDomain)
	}
}

// brokenSignatureMessage 构造带指定 b= 值的 DKIM-Signature 头测试消息（其余头
// 最小集——From 可解析供 DMARC 块消费；bh= 为空 body SHA-256 既有形态）。
func brokenSignatureMessage(bValue string) []byte {
	return []byte("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selx;\r\n" +
		"\th=From:To:Subject:Date:Message-ID; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n" +
		"\tb=" + bValue + "\r\n" +
		"From: sender@example.com\r\n" +
		"To: rcpt@example.org\r\n" +
		"Subject: broken\r\n" +
		"Date: Sat, 18 Oct 2026 10:00:00 +0800\r\n" +
		"Message-ID: <t1@example.com>\r\n" +
		"\r\n" +
		"body\r\n")
}

// TestVerifyDKIMPermerrorParseFailureVisible Verify 级锚①（V批渗透方实测同款构造
// ——342 字符非法 base64：342%4=2 解码失败）：结论 permerror（原缺陷 none）＋A-R
// 裸条目呈现（E-2-A——全 nil 无签名上下文，无 header.d；rfc8601 §2.2 propspec
// 可选）——「无签名」与「签名损坏」消费者可区分（缺口收口锚）。
func TestVerifyDKIMPermerrorParseFailureVisible(t *testing.T) {
	resolver := newStubResolver().
		withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all").
		withTXT("_dmarc.example.com", "v=DMARC1; p=none; adkim=r; aspf=r")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com",
			brokenSignatureMessage(strings.Repeat("A", 342))))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if res.DKIM != "permerror" {
		t.Fatalf("解析失败（非法 base64 b=）应 permerror（原缺陷落 none）: %s（A-R: %s）", res.DKIM, res.AuthResultsHeader)
	}
	if !strings.Contains(res.AuthResultsHeader, ";\r\n\tdkim=permerror") {
		t.Fatalf("A-R 应含裸 dkim=permerror 条目（E-2-A 可见性）: %s", res.AuthResultsHeader)
	}
	if strings.Contains(res.AuthResultsHeader, "dkim=permerror header.d=") {
		t.Fatalf("无签名上下文应为裸条目（无 header.d）: %s", res.AuthResultsHeader)
	}
}

// TestVerifyDKIMPermerrorLookupVisible Verify 级锚②（公钥查询永久失败——签名头
// 可解析〔b= 344 字符合法 base64〕+选择器公钥 NXDOMAIN〔stub 未登记〕）：结论
// permerror（原缺陷 fail 误拒）＋A-R 呈现 header.d（有签名上下文——沿 B-S批 F5
// 先例）；对照区分锚：同形态合法构造+真实公钥+伪造 b= 为 fail 拒收路径
// （TestVerifyDKIMForgedSignatureFails 既有锚——验签失败≠解析/查询失败）。
func TestVerifyDKIMPermerrorLookupVisible(t *testing.T) {
	resolver := newStubResolver().
		withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all").
		withTXT("_dmarc.example.com", "v=DMARC1; p=none; adkim=r; aspf=r")
	// selx._domainkey.example.com 未登记→LookupTXT ErrDNSNotFound→raven lookup
	// ErrNoRecord（非临时）→StatusPermerror 携 Signature
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com",
			brokenSignatureMessage(strings.Repeat("A", 344))))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if res.DKIM != "permerror" {
		t.Fatalf("公钥 NXDOMAIN 应 permerror（原缺陷落 fail 误拒）: %s（A-R: %s）", res.DKIM, res.AuthResultsHeader)
	}
	if !strings.Contains(res.AuthResultsHeader, "dkim=permerror header.d=example.com") {
		t.Fatalf("A-R 应含 header.d 呈现（有签名上下文——F5 先例）: %s", res.AuthResultsHeader)
	}
}
