// VerifierService 集成测试（NFR-015：stub DNS 离线驱动，零网络端点）。
// 覆盖：SPF pass/fail、DKIM 签名往返（rsa）、DMARC 联动、A-R 头格式、
// 开关热加载（TC-009 语义）、temperror 注入、From 域解析。
// 修改历史：
//
//	2026-09-17 02:50:00 | 新建 | U3 auth 基础（计划书步骤 8）
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GRmail/internal/config"
)

// sampleMessage 构造最小 RFC5322 测试消息（fromDomain 可控）。
func sampleMessage(fromDomain string) []byte {
	return []byte("From: sender@" + fromDomain + "\r\n" +
		"To: rcpt@example.org\r\n" +
		"Subject: test\r\n" +
		"Date: Wed, 17 Sep 2026 02:00:00 +0800\r\n" +
		"Message-ID: <t1@" + fromDomain + ">\r\n" +
		"\r\n" +
		"body\r\n")
}

// incoming 构造验证输入（信封+消息）。
func incoming(helo string, ip net.IP, mailFrom string, raw []byte) *IncomingMail {
	return &IncomingMail{
		Envelope: Envelope{Helo: helo, RemoteIP: ip, MailFrom: mailFrom},
		Raw:      raw,
	}
}

// allOnStack 四开关全开的认证栈配置。
func allOnStack() config.AuthStack {
	return config.AuthStack{SPFEnabled: true, DKIMEnabled: true, DMARCEnabled: true, ARCEnabled: true}
}

// TestVerifySPFPass SPF ip4 机制命中（rfc7208 路径；A-R 含 smtp.mailfrom 属性）
func TestVerifySPFPass(t *testing.T) {
	resolver := newStubResolver().withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", sampleMessage("example.com")))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if res.SPF != "pass" {
		t.Fatalf("SPF 应 pass: %s", res.SPF)
	}
	if !strings.Contains(res.AuthResultsHeader, "spf=pass smtp.mailfrom=example.com") {
		t.Fatalf("A-R 头 SPF 项缺失或格式错: %s", res.AuthResultsHeader)
	}
	if !strings.HasPrefix(res.AuthResultsHeader, "Authentication-Results: mx.local;") {
		t.Fatalf("A-R 头前缀不符（authserv-id）: %s", res.AuthResultsHeader)
	}
}

// TestVerifySPFFail SPF 全拒绝记录+不匹配 IP → fail
func TestVerifySPFFail(t *testing.T) {
	resolver := newStubResolver().withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, _ := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("198.51.100.9"), "user@example.com", sampleMessage("example.com")))
	if res.SPF != "fail" {
		t.Fatalf("SPF 应 fail: %s", res.SPF)
	}
}

// TestVerifyDKIMSignRoundTripRSA 签名→验证闭环（rsa-sha256；DKIM pass + DMARC pass 联动）
func TestVerifyDKIMSignRoundTripRSA(t *testing.T) {
	key, keyPath := generateRSAKeyPEM(t)
	conf := config.DKIMConf{Selector: "test", KeyPath: keyPath, Algorithm: "rsa-sha256"}
	signer, err := NewSignerService(conf)
	if err != nil {
		t.Fatalf("签名器构造: %v", err)
	}
	msg := sampleMessage("example.com")
	signed, err := signer.Sign(context.Background(), msg, "example.com")
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// DKIM 公钥记录（v=DKIM1; k=rsa; p=<PKIX DER b64>）+ SPF + DMARC 记录
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	resolver := newStubResolver().
		withTXT("test._domainkey.example.com", "v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(pubDER)).
		withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all").
		withTXT("_dmarc.example.com", "v=DMARC1; p=none; adkim=r; aspf=r")

	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", signed))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	if res.DKIM != "pass" {
		t.Fatalf("DKIM 应 pass: %s（A-R: %s）", res.DKIM, res.AuthResultsHeader)
	}
	if res.DMARC != "pass" {
		t.Fatalf("DMARC 应 pass（dkim 对齐快捷①）: %s", res.DMARC)
	}
	if !strings.Contains(res.AuthResultsHeader, "dkim=pass header.d=example.com") {
		t.Fatalf("A-R 头 DKIM 项不符: %s", res.AuthResultsHeader)
	}
	if !strings.Contains(res.AuthResultsHeader, "dmarc=pass header.from=example.com") {
		t.Fatalf("A-R 头 DMARC 项不符: %s", res.AuthResultsHeader)
	}
}

// TestVerifySwitchOffARC TC-009 语义：热加载关闭 ARC 后 A-R 头不再含 arc 项（其余项保留）
func TestVerifySwitchOffARC(t *testing.T) {
	resolver := newStubResolver().withTXT("example.com", "v=spf1 -all")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, _ := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", sampleMessage("example.com")))
	// 断言用 ";\r\n\tarc=" 定界（裸 "arc=" 会误命中 "dmarc=" 子串；RF-E F-A1 后
	// resinfo 分隔为 CRLF+HTAB 折叠——rfc8601 §2.2）
	if !strings.Contains(res.AuthResultsHeader, ";\r\n\tarc=none") {
		t.Fatalf("全开态 A-R 应含 arc 项: %s", res.AuthResultsHeader)
	}

	off := allOnStack()
	off.ARCEnabled = false
	v.OnConfigChange(&config.Config{Auth: off})

	res2, _ := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", sampleMessage("example.com")))
	if strings.Contains(res2.AuthResultsHeader, ";\r\n\tarc=") {
		t.Fatalf("关闭态 A-R 不应含 arc 项: %s", res2.AuthResultsHeader)
	}
	if !strings.Contains(res2.AuthResultsHeader, ";\r\n\tspf=") {
		t.Fatalf("关闭 ARC 不应影响 SPF 项: %s", res2.AuthResultsHeader)
	}
}

// TestVerifyTemperror DNS 瞬时故障注入 → SPF/DKIM 结论 temperror（不虚假成功）
func TestVerifyTemperror(t *testing.T) {
	resolver := newStubResolver().withTemp("example.com")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, _ := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", sampleMessage("example.com")))
	if res.SPF != "temperror" {
		t.Fatalf("SPF 应 temperror: %s", res.SPF)
	}
}

// TestVerifyFromDomainMissing From 头缺失 → DMARC permerror（ErrMissingFrom 定档）
func TestVerifyFromDomainMissing(t *testing.T) {
	resolver := newStubResolver().withTXT("example.com", "v=spf1 -all")
	v := NewVerifierService(resolver, "mx.local", allOnStack())
	raw := []byte("To: rcpt@example.org\r\nSubject: no from\r\n\r\nbody\r\n")
	res, _ := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", raw))
	if res.DMARC != "permerror" {
		t.Fatalf("From 缺失 DMARC 应 permerror: %s", res.DMARC)
	}
}

// TestFromDomain From 域提取：正常/大小写规范化/缺失/畸形
func TestFromDomain(t *testing.T) {
	if d, err := FromDomain(sampleMessage("Example.COM")); err != nil || d != "example.com" {
		t.Fatalf("正常提取+小写失败: %s %v", d, err)
	}
	if _, err := FromDomain([]byte("Subject: x\r\n\r\n")); err == nil {
		t.Fatal("From 缺失应报错")
	}
	if _, err := FromDomain([]byte("From: 畸形 <bad>\r\n\r\n")); err == nil {
		t.Fatal("From 畸形应报错")
	}
}

// TestEnvelopeMailFromDomain 信封域提取辅助（空路径→空串；本地部分 postmaster 化）
func TestEnvelopeMailFromDomain(t *testing.T) {
	e := Envelope{MailFrom: "User@Sub.Example.COM"}
	if e.MailFromDomain() != "sub.example.com" {
		t.Fatalf("信封域提取: %s", e.MailFromDomain())
	}
	if e.MailFromLocal() != "User" {
		t.Fatalf("信封本地部分: %s", e.MailFromLocal())
	}
	empty := Envelope{}
	if empty.MailFromDomain() != "" || empty.MailFromLocal() != "postmaster" {
		t.Fatalf("空路径语义: %q %q", empty.MailFromDomain(), empty.MailFromLocal())
	}
}

// generateRSAKeyPEM 生成 2048 位测试私钥并写 PKCS#8 PEM（Q1-A 键形态）。
func generateRSAKeyPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 键: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("PKCS8 序列化: %v", err)
	}
	path := filepath.Join(t.TempDir(), "dkim.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("写 PEM: %v", err)
	}
	return key, path
}
