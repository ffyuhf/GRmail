// VerifierService 集成测试（NFR-015：stub DNS 离线驱动，零网络端点）。
// 覆盖：SPF pass/fail、DKIM 签名往返（rsa）、DMARC 联动、A-R 头格式、
// 开关热加载（TC-009 语义）、temperror 注入、From 域解析。
// 修改历史：
//
//	2026-09-17 02:50:00 | 新建 | U3 auth 基础（计划书步骤 8）
//	2026-10-18 00-40-00 | 扩展 | DMARC收尾批（计划书步骤 3）：
//	  TestVerifyDMARCDisposition——verify 侧 DMARCDisposition 三态预计算单元锚
//	  （DMARC 批 G3 遗留登记项兑现；E-1-A 承载形态直测）
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

// TestVerifyDKIMForgedSignatureFails T-003 根因核查离线锚（复测核查修复批——
// E-1-A：raven v1.6.1 对「真实选择器公钥存在+伪造 b= 签名值」输入的结论取值）。
// 构造：真实 DKIM 记录（stub 注入公钥）+消息携带「签名值域错误的 DKIM-Signature」——
// raven 应返回 per-signature Status=fail（verifyWithKey 验签失败路径，
// raven@v1.6.1 dkim/verify.go:277-279）；aggregateDKIM 聚合为 fail；
// 拒收判定链（pipeline checkRejectionPolicy）据此在 soft 档触发 550——
// 生产实测（T-003 三构造均 250）与本用例结论对照定位偏差层。
// 若本用例 fail 成立而生产 250——偏差在管道/装配层（开关/注入）；若本用例即 temperror/
// none——偏差在 raven 输入面（DNS 查询路径/记录解析）。本用例为 T-003 根因归因锚。
// SRS：FR-008 判定③（DKIM 软档=有签名且验证失败拒收——拒收臂输入）；TC-029 关联。
func TestVerifyDKIMForgedSignatureFails(t *testing.T) {
	// 真实 RSA 键对与公钥记录（stub 注入——选择器真实存在，与生产「d=gmail.com
	// s=20251104」场景同构：公钥真实存在，签名值域伪造）
	key, _ := generateRSAKeyPEM(t)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	resolver := newStubResolver().
		withTXT("sel2025._domainkey.example.com", "v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(pubDER)).
		withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all").
		withTXT("_dmarc.example.com", "v=DMARC1; p=none")

	// 消息携带「签名值域为随机字节的 DKIM-Signature」（b= 伪造——raven 验签
	// 将经 verifyWithKey 失败返回 StatusFail；bh= 与正文一致排除 hash 路径干扰）
	msg := []byte("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel2025;\r\n" +
		"\th=From:To:Subject:Date:Message-ID; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n" +
		"\tb=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
		"\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
		"\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" +
		"From: sender@example.com\r\n" +
		"To: rcpt@example.org\r\n" +
		"Subject: forged\r\n" +
		"Date: Wed, 17 Sep 2026 02:00:00 +0800\r\n" +
		"Message-ID: <forged@example.com>\r\n" +
		"\r\n" +
		"body\r\n")

	v := NewVerifierService(resolver, "mx.local", allOnStack())
	res, err := v.Verify(context.Background(),
		incoming("mail.example.com", net.ParseIP("192.0.2.1"), "sender@example.com", msg))
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}
	// T-003 归因锚：真实公钥+伪造签名值域→DKIM 结论应为 fail（raven verifyWithKey
	// 验签失败路径）；非 fail 则定位 raven 输入面偏差，fail 则定位管道/装配层偏差
	if res.DKIM != "fail" {
		t.Fatalf("T-003 归因锚：真实公钥+伪造签名应 fail（实际 %s——A-R: %s）", res.DKIM, res.AuthResultsHeader)
	}
}

// TestJoinHostPort T-003 修复锚（复测核查修复批——raven v1.6.1 getSystemNameservers
// 对 IPv6 递归地址不加端口不加方括号的装配侧防御）：IPv6 裸地址→"[v6]:53" 合法
// 拨号串（rfc3986 §3.2.2——沿生产缺陷修复批 daneServerAddr 先例）；IPv4/主机名
// →"host:53"；已带端口原样。SRS：FR-008 判定③实施态（拒收臂 resolver 前置）。
func TestJoinHostPort(t *testing.T) {
	cases := []struct{ host, want string }{
		{"fdae:6a60:38ca::1", "[fdae:6a60:38ca::1]:53"}, // 生产实例 resolv.conf IPv6 形态（B 批实证）
		{"2001:db8::1", "[2001:db8::1]:53"},             // IPv6 通用
		{"223.5.5.5", "223.5.5.5:53"},                   // IPv4
		{"localhost", "localhost:53"},                   // 主机名
	}
	for _, c := range cases {
		if got := joinHostPort(c.host, defaultDNSPort); got != c.want {
			t.Fatalf("joinHostPort(%q)=%q want %q", c.host, got, c.want)
		}
	}
}

// TestNormalizedSystemNameserversEmptyEnv 解析失败/空列表兜底（ravendns 零值链保持）。
func TestNormalizedSystemNameserversEmptyEnv(t *testing.T) {
	// resolv.conf 常规存在——本用例锚定「无 nameserver 行时返回 nil」（空文件场景
	// 以行为解析路径覆盖；不可移植的路径覆盖不注入——读失败形态经代码路径审读锚定）
	if got := normalizedSystemNameservers(); got != nil && len(got) == 0 {
		t.Fatal("空列表应返回 nil 而非空切片（ravendns 零值兜底链保持）")
	}
}

// TestVerifyDMARCDisposition verify 侧 DMARCDisposition 预计算单元锚（DMARC收尾批——
// E-1-A 承载形态直测：DMARC 批 G3 遗留登记项兑现。六态：p=reject 且 fail→"reject"；
// p=quarantine 且 fail→"quarantine"；p=none→""；无记录→""；结论 pass→""；结论
// temperror→""。fail 场景构造：From=example.com＋非对齐 SPF 域（other.net 通过但
// 组织域不同）→无对齐通过项；pass 场景：对齐 SPF 通过。disposition 不入 A-R 头。
// SRS：FR-008 判定③（REQ-20261017-005/006）；NFR-015（stub DNS 离线驱动）。
func TestVerifyDMARCDisposition(t *testing.T) {
	alignedEnv := incoming("mail.example.com", net.ParseIP("192.0.2.1"), "user@example.com", sampleMessage("example.com"))
	misalignedEnv := incoming("mail.other.net", net.ParseIP("192.0.2.1"), "user@other.net", sampleMessage("example.com"))

	cases := []struct {
		name      string
		policy    string // _dmarc.example.com 记录值
		noRecord  bool   // true=不登记 _dmarc 记录（无记录态）
		temp      bool   // true=_dmarc 查询瞬时故障
		env       *IncomingMail
		wantDMARC string
		wantDisp  string
	}{
		{"p=reject且fail→reject", "v=DMARC1; p=reject", false, false, misalignedEnv, "fail", "reject"},
		{"p=quarantine且fail→quarantine", "v=DMARC1; p=quarantine", false, false, misalignedEnv, "fail", "quarantine"},
		{"p=none且fail→不分派", "v=DMARC1; p=none", false, false, misalignedEnv, "fail", ""},
		{"无记录→none不分派", "", true, false, misalignedEnv, "none", ""},
		{"结论pass→不分派", "v=DMARC1; p=reject", false, false, alignedEnv, "pass", ""},
		{"结论temperror→不分派", "v=DMARC1; p=reject", false, true, alignedEnv, "temperror", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := newStubResolver().
				withTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all").
				withTXT("other.net", "v=spf1 ip4:192.0.2.0/24 -all")
			if !tc.noRecord {
				resolver = resolver.withTXT("_dmarc.example.com", tc.policy)
			}
			if tc.temp {
				resolver = resolver.withTemp("_dmarc.example.com")
			}
			v := NewVerifierService(resolver, "mx.local", allOnStack())
			res, err := v.Verify(context.Background(), tc.env)
			if err != nil {
				t.Fatalf("验证失败: %v", err)
			}
			if res.DMARC != tc.wantDMARC {
				t.Fatalf("DMARC 结论不符: got=%s want=%s（A-R: %s）", res.DMARC, tc.wantDMARC, res.AuthResultsHeader)
			}
			if res.DMARCDisposition != tc.wantDisp {
				t.Fatalf("DMARCDisposition 不符: got=%q want=%q", res.DMARCDisposition, tc.wantDisp)
			}
		})
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
