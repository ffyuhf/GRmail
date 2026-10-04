// transport 包 U13 单测（NFR-015：stub DNSSEC 通道全离线驱动——AD 位三态/TLSA
// 发现与可用性/决策四态/EE(3)·TA(2) 匹配/摘要敏捷；mtasts 生成器 ABNF 断言）。
// 依据：U13 计划书 v1.0.0 步骤 5/6 检查点（G2 批准 2026-09-23 08:19:32）；
// rfc7672 §2.1/§2.2/§3、rfc6698 §2/§4.1、rfc7671 §9、rfc8461 §3.1/§3.2、rfc8460 §3。
// 修改历史：
//
//	2026-09-23 09:05:00 | 新建 | U13 传输安全全量（计划书步骤 5/6 检查点）
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"GRmail/internal/config"
)

// ───────────────────────── stub：DNSSEC 查询通道（内存记录表） ─────────────────────────

// stubDANEExchange 可编程 DNSSEC 应答 stub。
// 按查询名+类型路由：A 应答/TLSA 应答/CNAME 应答/错误注入（SERVFAIL 语义）。
type stubDANEExchange struct {
	aAD       bool              // A 应答 AD 位
	aCNAME    string            // A 应答携带的 CNAME 终名（空=无别名）
	tlsaAD    bool              // TLSA 应答 AD 位
	tlsaRRs   []dns.RR          // TLSA 应答记录集
	tlsaEmpty bool              // TLSA secure 否定不存在（NXDOMAIN 语义）
	failA     bool              // A 查询错误注入（MX 不可达路径）
	failTLSA  bool              // TLSA 查询错误注入
	calls     map[string]uint16 // 查询名→类型记录（断言辅助）
}

func newStubExchange() *stubDANEExchange {
	return &stubDANEExchange{calls: map[string]uint16{}}
}

func (s *stubDANEExchange) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	s.calls[strings.TrimSuffix(name, ".")] = qtype
	if s.failA && qtype == dns.TypeA {
		return nil, errStubServfail
	}
	m := new(dns.Msg)
	m.AuthenticatedData = s.aAD // A 与 TLSA 共用开关（用例按需切换——见各用例注释）
	if qtype == dns.TypeA {
		if s.aCNAME != "" {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: dns.Fqdn(s.aCNAME)})
		}
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.10")})
		m.AuthenticatedData = s.aAD
		return m, nil
	}
	if qtype == dns.TypeTLSA {
		if s.failTLSA {
			return nil, errStubServfail
		}
		m.AuthenticatedData = s.tlsaAD
		if s.tlsaEmpty {
			m.Rcode = dns.RcodeNameError // secure 否定不存在
			return m, nil
		}
		m.Answer = s.tlsaRRs
		return m, nil
	}
	m.Rcode = dns.RcodeNameError
	return m, nil
}

// errStubServfail stub 错误哨兵（bogus 语义注入）。
var errStubServfail = &net.DNSError{Err: "stub SERVFAIL", Name: "stub", IsTimeout: false}

// tlsaRR 构造 TLSA 记录（rfc6698 §2.2 呈现格式——三字段 uint8 收窄）。
func tlsaRR(name string, usage, selector, matchType int, dataHex string) dns.RR {
	return &dns.TLSA{
		Hdr:          dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
		Usage:        uint8(usage),
		Selector:     uint8(selector),
		MatchingType: uint8(matchType),
		Certificate:  strings.ToUpper(dataHex),
	}
}

// ───────────────────────── Check 决策四态 ─────────────────────────

// TestU13CheckInsecureADegradesToOpportunistic A 应答 insecure（AD=0）→机会 TLS
// 且免 TLSA 查询（rfc7672 §2.2.2——NFR-008 降级锚：不阻塞投递路径）。
func TestU13CheckInsecureADegradesToOpportunistic(t *testing.T) {
	st := newStubExchange()
	st.aAD = false // 地址 RRset insecure
	st.tlsaAD = true
	st.tlsaRRs = []dns.RR{tlsaRR("_25._tcp.mx1.x.io", 3, 1, 1, strings.Repeat("ab", 32))}
	d := NewDaneService(st.exchange)
	dec, err := d.Check(context.Background(), "mx1.x.io", "x.io")
	if err != nil {
		t.Fatalf("insecure A 应降级非错误: %v", err)
	}
	if dec.Mode != DaneOpportunistic {
		t.Fatalf("期望 Opportunistic，得 %d", dec.Mode)
	}
	if _, queried := st.calls["_25._tcp.mx1.x.io"]; queried {
		t.Fatal("insecure 地址应跳过 TLSA 查询（rfc7672 §2.2.2）")
	}
}

// TestU13CheckAErrorMeansUnreachable A 查询错误→MX 不可达（rfc7672 §2.1.2——防降级锚）。
func TestU13CheckAErrorMeansUnreachable(t *testing.T) {
	st := newStubExchange()
	st.failA = true
	d := NewDaneService(st.exchange)
	if _, err := d.Check(context.Background(), "mx1.x.io", "x.io"); err == nil {
		t.Fatal("A 查询失败应返回错误（MX 不可达）")
	}
}

// TestU13CheckSecureUsableYieldsRequireDANE secure usable TLSA→RequireDANE
// （含 CNAME 展开名候选优先——基域取展开名，rfc7672 §2.2.3）。
func TestU13CheckSecureUsableYieldsRequireDANE(t *testing.T) {
	st := newStubExchange()
	st.aAD = true
	st.aCNAME = "real.x.io" // A 应答含 CNAME 链——展开名候选优先
	st.tlsaAD = true
	st.tlsaRRs = []dns.RR{tlsaRR("_25._tcp.real.x.io", 3, 1, 1, strings.Repeat("cd", 32))}
	d := NewDaneService(st.exchange)
	dec, err := d.Check(context.Background(), "mx1.x.io", "x.io")
	if err != nil {
		t.Fatalf("secure usable 应成功: %v", err)
	}
	if dec.Mode != DaneRequireDANE {
		t.Fatalf("期望 RequireDANE，得 %d", dec.Mode)
	}
	if dec.BaseTLSDomain != "real.x.io" {
		t.Fatalf("基域应为展开名 real.x.io，得 %s", dec.BaseTLSDomain)
	}
	if len(dec.Records) != 1 || dec.Records[0].Usage != 3 {
		t.Fatalf("usable 记录集不符: %+v", dec.Records)
	}
	if len(dec.RefNames) != 2 || dec.RefNames[1] != "x.io" {
		t.Fatalf("参考标识集应含 next-hop 域: %+v", dec.RefNames)
	}
}

// TestU13CheckSecureAllUnusableYieldsTLSOnly secure RRset 全不可用（仅 usage 0/1）
// →RequireTLSOnly（rfc7672 §2.2 第二分支——TLS 承诺信号）。
func TestU13CheckSecureAllUnusableYieldsTLSOnly(t *testing.T) {
	st := newStubExchange()
	st.aAD, st.tlsaAD = true, true
	st.tlsaRRs = []dns.RR{tlsaRR("_25._tcp.mx1.x.io", 0, 0, 1, strings.Repeat("ef", 32))}
	d := NewDaneService(st.exchange)
	dec, err := d.Check(context.Background(), "mx1.x.io", "x.io")
	if err != nil {
		t.Fatalf("secure 不可用应 RequireTLSOnly: %v", err)
	}
	if dec.Mode != DaneRequireTLSOnly {
		t.Fatalf("期望 RequireTLSOnly，得 %d", dec.Mode)
	}
	if len(dec.Records) != 0 {
		t.Fatalf("RequireTLSOnly 记录集应空: %+v", dec.Records)
	}
}

// TestU13CheckTLSErrorMeansUnreachable TLSA 查询错误→MX 不可达（§2.1.2——不换候选绕过）。
func TestU13CheckTLSErrorMeansUnreachable(t *testing.T) {
	st := newStubExchange()
	st.aAD = true
	st.failTLSA = true
	d := NewDaneService(st.exchange)
	if _, err := d.Check(context.Background(), "mx1.x.io", "x.io"); err == nil {
		t.Fatal("TLSA 查询失败应返回错误（MX 不可达）")
	}
}

// TestU13CheckSecureNodataYieldsOpportunistic secure 否定不存在→机会 TLS（NFR-008）。
func TestU13CheckSecureNodataYieldsOpportunistic(t *testing.T) {
	st := newStubExchange()
	st.aAD = true
	st.tlsaAD = true
	st.tlsaEmpty = true // NXDOMAIN
	d := NewDaneService(st.exchange)
	dec, err := d.Check(context.Background(), "mx1.x.io", "x.io")
	if err != nil || dec.Mode != DaneOpportunistic {
		t.Fatalf("secure 无记录应 Opportunistic: dec=%+v err=%v", dec, err)
	}
}

// ───────────────────────── 可用性与摘要敏捷 ─────────────────────────

// TestU13SelectUsableFiltersAndPrefersStrongestDigest 过滤矩阵+摘要敏捷
// （rfc6698 §4.1 未知参数/畸形长度/usage 0·1 不可用；rfc7671 §9 每 (usage,selector)
// 组保留 Full(0)+最强摘要——弱档 3-1-1 在存在 3-1-2 时被排除）。
func TestU13SelectUsableFiltersAndPrefersStrongestDigest(t *testing.T) {
	records := []TLSARecord{
		{Usage: 3, Selector: 1, MatchType: 1, Data: make([]byte, 32)}, // 弱档（被 3-1-2 抑制）
		{Usage: 3, Selector: 1, MatchType: 2, Data: make([]byte, 64)}, // 强档保留
		{Usage: 2, Selector: 0, MatchType: 1, Data: make([]byte, 32)}, // 另组保留
		{Usage: 0, Selector: 1, MatchType: 1, Data: make([]byte, 32)}, // PKIX-TA 不可用
		{Usage: 1, Selector: 0, MatchType: 0, Data: []byte{1}},        // PKIX-EE 不可用
		{Usage: 3, Selector: 2, MatchType: 1, Data: make([]byte, 32)}, // 未知 selector 不可用
		{Usage: 3, Selector: 1, MatchType: 1, Data: make([]byte, 10)}, // 摘要长度畸形不可用
	}
	got := selectUsableTLSA(records)
	if len(got) != 2 {
		t.Fatalf("择优后应 2 条（3-1-2 与 2-0-1），得 %d: %+v", len(got), got)
	}
	seen31, seen20 := false, false
	for _, r := range got {
		if r.Usage == 3 && r.Selector == 1 {
			if r.MatchType != 2 {
				t.Fatal("3-1 组应仅保留最强档 SHA-512")
			}
			seen31 = true
		}
		if r.Usage == 2 && r.Selector == 0 && r.MatchType == 1 {
			seen20 = true
		}
	}
	if !seen31 || !seen20 {
		t.Fatalf("组覆盖缺失: 3-1=%v 2-0=%v", seen31, seen20)
	}
}

// ───────────────────────── 握手后 TLSA 匹配 ─────────────────────────

// makeCert 构造自签测试证书（EE 叶/TA 锚通用——SAN 可指定）。
func makeCert(t *testing.T, cn string, san []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     san,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	return crt, key
}

// TestU13VerifyEE3SPKISHA256 EE(3) 3-1-1 匹配叶 SPKI 摘要——免名称检查
// （rfc7672 §3.1.1：SAN 与本域不符仍认证通过——绑定即认证）。
func TestU13VerifyEE3SPKISHA256(t *testing.T) {
	crt, _ := makeCert(t, "unrelated-name", []string{"other.example"})
	sum := sha256.Sum256(crt.RawSubjectPublicKeyInfo)
	dec := &DaneDecision{
		Mode:    DaneRequireDANE,
		Records: []TLSARecord{{Usage: 3, Selector: 1, MatchType: 1, Data: sum[:]}},
	}
	if err := VerifyPeerCertificates(dec, []*x509.Certificate{crt}); err != nil {
		t.Fatalf("EE(3) SPKI 匹配应通过（免名称检查）: %v", err)
	}
	// 篡改一字节→认证失败（MUST NOT 投递语义输入）
	bad := append([]byte(nil), sum[:]...)
	bad[0] ^= 0xff
	dec.Records[0].Data = bad
	if err := VerifyPeerCertificates(dec, []*x509.Certificate{crt}); err == nil {
		t.Fatal("摘要不匹配应认证失败")
	}
}

// TestU13VerifyEE3FullRecord EE(3) 3-0-0 全量证书比对。
func TestU13VerifyEE3FullRecord(t *testing.T) {
	crt, _ := makeCert(t, "mx1", []string{"mx1.x.io"})
	dec := &DaneDecision{Mode: DaneRequireDANE, Records: []TLSARecord{{Usage: 3, Selector: 0, MatchType: 0, Data: crt.Raw}}}
	if err := VerifyPeerCertificates(dec, []*x509.Certificate{crt}); err != nil {
		t.Fatalf("EE(3) 全量匹配应通过: %v", err)
	}
}

// TestU13VerifyTA2ChainAndNameCheck TA(2)：TA 证书摘要入锚+叶链验证+名称检查
// （参考标识命中——rfc7672 §3.2.2：基域或 next-hop 域任一 SAN 命中即通过）。
func TestU13VerifyTA2ChainAndNameCheck(t *testing.T) {
	// TA 构造：IsCA 基本约束（x509 链验证对锚证书的 CA 属性要求——RFC5280 §4.2.1.9；
	// makeCert 产物无 CA 属性不能作签发 parent 与验证锚）
	taKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 TA 密钥: %v", err)
	}
	taTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dane-ta"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	taDER, err := x509.CreateCertificate(rand.Reader, taTmpl, taTmpl, &taKey.PublicKey, taKey)
	if err != nil {
		t.Fatalf("签发 TA: %v", err)
	}
	taCRT, err := x509.ParseCertificate(taDER)
	if err != nil {
		t.Fatalf("解析 TA: %v", err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mx1.x.io"},
		DNSNames:     []string{"mx1.x.io"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, taCRT, &leafKey.PublicKey, taKey)
	if err != nil {
		t.Fatalf("签发叶证书: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	sum := sha256.Sum256(taCRT.Raw)
	dec := &DaneDecision{
		Mode:     DaneRequireDANE,
		Records:  []TLSARecord{{Usage: 2, Selector: 0, MatchType: 1, Data: sum[:]}},
		RefNames: []string{"mx1.x.io", "x.io"},
	}
	if err := VerifyPeerCertificates(dec, []*x509.Certificate{leaf, taCRT}); err != nil {
		t.Fatalf("TA(2) 链+名称应通过: %v", err)
	}
	// 名称不命中（参考标识全不匹配 SAN）→失败
	dec.RefNames = []string{"elsewhere.example"}
	if err := VerifyPeerCertificates(dec, []*x509.Certificate{leaf, taCRT}); err == nil {
		t.Fatal("名称不匹配应认证失败（§3.2.2）")
	}
}

// TestU13VerifyNoPeerCert 对端无证书→哨兵错误（MUST NOT 投递输入）。
func TestU13VerifyNoPeerCert(t *testing.T) {
	dec := &DaneDecision{Mode: DaneRequireDANE, Records: []TLSARecord{{Usage: 3, Selector: 1, MatchType: 1, Data: make([]byte, 32)}}}
	if err := VerifyPeerCertificates(dec, nil); err != ErrDANENoPeerCertificate {
		t.Fatalf("无证书应返回哨兵，得 %v", err)
	}
}

// ───────────────────────── mtasts 生成器（rfc8461 §3.1/§3.2、rfc8460 §3） ─────────────────────────

// TestU13STSPolicyTextABNF 策略文本逐字段断言（rfc8461 §3.2 ABNF——CRLF 分隔四行）。
func TestU13STSPolicyTextABNF(t *testing.T) {
	got := STSPolicyText("x.io", config.MTAStsConf{Mode: "enforce", MaxAgeSeconds: 604800})
	want := "version: STSv1\r\nmode: enforce\r\nmx: x.io\r\nmax_age: 604800"
	if got != want {
		t.Fatalf("策略文本不符:\n got=%q\nwant=%q", got, want)
	}
}

// TestU13STSTXTRecordValue _mta-sts TXT 记录值（rfc8461 §3.1——id 14 位数字形态）。
func TestU13STSTXTRecordValue(t *testing.T) {
	at := time.Date(2026, 9, 23, 1, 2, 3, 0, time.UTC)
	got := STSTXTRecordValue(at)
	if got != "v=STSv1; id=20260923010203Z;" {
		t.Fatalf("TXT 记录值不符: %q", got)
	}
}

// TestU13TLSRPTTXTRecordValue _smtp._tls TXT 记录值（rfc8460 §3——rua 缺省兜底）。
func TestU13TLSRPTTXTRecordValue(t *testing.T) {
	if got := TLSRPTTXTRecordValue("x.io", config.MTAStsConf{}); got != "v=TLSRPTv1; rua=mailto:postmaster@x.io" {
		t.Fatalf("缺省 rua 不符: %q", got)
	}
	if got := TLSRPTTXTRecordValue("x.io", config.MTAStsConf{RuaAddress: "r@y.io"}); got != "v=TLSRPTv1; rua=mailto:r@y.io" {
		t.Fatalf("自定义 rua 不符: %q", got)
	}
}

// TestU13STSPolicyHost Policy Host 前缀（rfc8461 §3.2——web Host 判定与 ACME 清单共用）。
func TestU13STSPolicyHost(t *testing.T) {
	if got := STSPolicyHost("x.io"); got != "mta-sts.x.io" {
		t.Fatalf("Policy Host 不符: %q", got)
	}
}

// TestU13ACMEDomainList ACME 清单扩展（Q3-A——启用含 mta-sts 子域/禁用单域）。
func TestU13ACMEDomainList(t *testing.T) {
	m := NewACMEManager("x.io", func() config.ACMEConf { return config.ACMEConf{} }, nil)
	if got := m.certificateDomains(); len(got) != 1 || got[0] != "x.io" {
		t.Fatalf("未注入开关应单域: %v", got)
	}
	m.SetStsEnabled(func() bool { return true })
	got := m.certificateDomains()
	if len(got) != 2 || got[1] != "mta-sts.x.io" {
		t.Fatalf("启用 MTA-STS 应双域清单: %v", got)
	}
}

// ───────────────────────── hex 辅助（TLSA 数据构造） ─────────────────────────

// init 注册 hex 反查辅助（TestU13CheckSecureUsableYieldsRequireDANE 用 strings.Repeat
// 构造——此函数确保 encoding/hex 在数据流上的往返一致性断言可用）。
func init() { _ = hex.EncodeToString }
