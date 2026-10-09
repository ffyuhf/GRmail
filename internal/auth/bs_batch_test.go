// B-S安全域批 F5/F6/F9 新用例（计划书 v2.0.0 步骤 2/5/6 检查点承载）。
// 依据：B-S安全域批_计划_20261009_13-36-00_v2.0.0 1.2（F5/F6/F9）+第三章步骤 2/5/6；
// 规范锚：rfc8601 §2.7.2 L1051-1054（smtp.helo 属性）/rfc9989 §4.10 L1211-1233+§4.10.2
// L1351-1352（Tree Walk 多次执行的重复查询面——缓存覆盖对象）/rfc6376 §3.6（键管理伴随）。
// 修改历史：
//
//	2026-10-09 21:35:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package auth

import (
	"context"
	"os"
	"strings"
	"testing"

	"GRmail/internal/config"

	ravendkim "github.com/synqronlabs/raven/dkim"
)

// TestBSF5NullSenderSPFUsesHeloProperty 空反向路径（MAIL FROM <>）来信的 A-R SPF
// 属性域为 smtp.helo（rfc8601 §2.7.2——B-S批 F5 修复锚；原恒 smtp.mailfrom）。
func TestBSF5NullSenderSPFUsesHeloProperty(t *testing.T) {
	stub := newStubResolver().
		withTXT("helo.example.com", "v=spf1 -all") // HELO 判定域 SPF（fail 结论——属性断言独立于结果）
	v := NewVerifierService(stub, "mx.grmail.test", config.AuthStack{
		SPFEnabled: true, DKIMEnabled: false, DMARCEnabled: false, ARCEnabled: false,
	})
	msg := &IncomingMail{
		Envelope: Envelope{Helo: "helo.example.com", MailFrom: ""}, // 空反向路径（退信形态）
		Raw:      []byte("From: a@example.com\r\nSubject: t\r\n\r\nbody\r\n"),
	}
	res, err := v.Verify(context.Background(), msg)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	if !strings.Contains(res.AuthResultsHeader, "smtp.helo=helo.example.com") {
		t.Fatalf("空反向路径 SPF 属性应为 smtp.helo（rfc8601 §2.7.2）: %q", res.AuthResultsHeader)
	}
	if strings.Contains(res.AuthResultsHeader, "smtp.mailfrom=") {
		t.Fatalf("空反向路径不应呈现 smtp.mailfrom 属性: %q", res.AuthResultsHeader)
	}
}

// TestBSF5TemperrorReportsSignatureDomain DKIM temperror 且存在签名上下文时报告域取
// 首个含签名结果的 d=（B-S批 F5 修复锚——原空串致 resinfo 判空丢弃）。
func TestBSF5TemperrorReportsSignatureDomain(t *testing.T) {
	results := []ravendkim.Result{
		{Status: ravendkim.StatusTemperror, Signature: nil},
		{Status: ravendkim.StatusFail, Signature: &ravendkim.Signature{Domain: "signed.example.com"}},
	}
	conclusion, reportDomain := aggregateDKIM(results)
	if conclusion != "temperror" {
		t.Fatalf("结论应 temperror: %q", conclusion)
	}
	if reportDomain != "signed.example.com" {
		t.Fatalf("temperror 报告域应取首个含签名结果的 d=（B-S批 F5）: %q", reportDomain)
	}
	// 无签名上下文维持空（调用方按现状不呈现该条）
	none := []ravendkim.Result{{Status: ravendkim.StatusTemperror, Signature: nil}}
	if _, d := aggregateDKIM(none); d != "" {
		t.Fatalf("无签名上下文 temperror 报告域应维持空串: %q", d)
	}
}

// TestBSF6TreeWalkQueryDeduplicated DMARC Tree Walk 请求级缓存（B-S批 F6 裁决 B——
// 仅缓存无总预算）：同域 _dmarc TXT 查询在 Verify 单次调用内去重（Discover 与
// OrganizationalDomain 共享——stub 查询审计计数断言；rfc9989 §4.10.2 L1351-1352
// 对齐评估多次 Tree Walk 的重复查询面即缓存覆盖对象）。
func TestBSF6TreeWalkQueryDeduplicated(t *testing.T) {
	stub := newStubResolver().
		withTXT("_dmarc.example.com", "v=DMARC1; p=none")
	v := NewVerifierService(stub, "mx.grmail.test", config.AuthStack{
		SPFEnabled: false, DKIMEnabled: false, DMARCEnabled: true, ARCEnabled: false,
	})
	msg := &IncomingMail{
		Envelope: Envelope{Helo: "h", MailFrom: "b@example.com"},
		Raw:      []byte("From: a@example.com\r\nSubject: t\r\n\r\nbody\r\n"),
	}
	if _, err := v.Verify(context.Background(), msg); err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	count := 0
	for _, q := range stub.queryLog() {
		if q == "_dmarc.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Tree Walk 同域 _dmarc 查询应经缓存去重为 1 次（实际 %d 次——B-S批 F6）", count)
	}
}

// TestBSF9WideKeyPermissionsWarnNotReject 私钥文件权限过宽（0644）告警不拒绝
// （B-S批 F9——加载与签名正常路径保持；告警面由 slog 承载不阻断）。
func TestBSF9WideKeyPermissionsWarnNotReject(t *testing.T) {
	privPEM, _, _, err := GenerateDKIMKeyPair("rsa-2048")
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	keyPath := t.TempDir() + "/dkim-wide.pem"
	if err := os.WriteFile(keyPath, privPEM, 0o644); err != nil {
		t.Fatalf("测试私钥落盘失败: %v", err)
	}
	svc, cerr := NewSignerService(config.DKIMConf{
		Selector: "grmail", KeyPath: keyPath, Algorithm: "rsa-sha256",
	})
	if cerr != nil || svc == nil {
		t.Fatalf("0644 私钥加载应成功（告警不拒绝——B-S批 F9）: %v", cerr)
	}
	signed, serr := svc.Sign(context.Background(), []byte("From: a@x.com\r\n\r\nb\r\n"), "x.com")
	if serr != nil || len(signed) == 0 {
		t.Fatalf("0644 私钥签名应正常: signed=%d err=%v", len(signed), serr)
	}
}
