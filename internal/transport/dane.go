// Package transport 追加发送侧 DANE 验证器：DNSSEC 判定（Q1-A AD 位信任）+
// TLSA 发现（rfc7672 §2.2.2/§2.2.3——A/AAAA 先行+两候选基域+CNAME 链）+
// 四态决策（§2.2：RequireDANE/RequireTLSOnly/Opportunistic/错误=MX 不可达）+
// 握手后 TLSA 匹配（EE(3) §3.1.1 免名称检查/TA(2) §3.1.2 信任锚链+名称检查）。
// 依据：U13 计划书 v1.0.0 步骤 5/6/7（G2 批准 2026-09-23 08:19:32；契约 v1.9.0
// 2.3 DaneValidator 窄接口——mail 经构造注入不 import transport，main 桥接）；
// SRS FR-010（发送侧 DANE）+NFR-008（insecure 降级不阻塞）+NFR-006（认证失败不投递）；
// rfc7672 §2.1.3（安全感知 stub+可信递归解析器合法形态——Q1-A 裁决 2026-09-23 08:16:33）；
// rfc6698 §2（TLSA RDATA 三字段）/§4.1（可用性判定）；rfc7671 §9（摘要敏捷——
// 每 usage+selector 取 Full(0)+最强摘要档）。MX 优先级保持归调用方（sender 遍历序不变）。
// 修改历史：
//
//	2026-09-23 08:30:00 | 新建 | U13 传输安全全量（计划书步骤 5/6）
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ───────────────────────── 契约接口（契约 v1.9.0 2.3 逐字） ─────────────────────────

// DaneValidator 发送侧 DANE 决策器（出站投递链注入，U13）。
type DaneValidator interface {
	// Check 对单台 MX 主机产出 DANE 决策。
	// 参数：ctx 上下文；mxHost MX 主机名；nextHopDomain 原始下一跳域（TA(2) 名称检查
	// 第二参考标识——rfc7672 §3.2.2）。返回：决策；错误=查询失败（调用方按 MX 不可达跳过）。
	Check(ctx context.Context, mxHost, nextHopDomain string) (*DaneDecision, error)
}

// DaneMode DANE 三态决策（rfc7672 §2.2 四分支的调用方语义归并——错误态经 error 返回）。
type DaneMode int

const (
	DaneOpportunistic  DaneMode = iota // insecure/无 secure TLSA→机会 TLS（NFR-008 降级锚）
	DaneRequireTLSOnly                 // secure RRset 全 unusable→MUST TLS 免认证（§2.2 第二分支）
	DaneRequireDANE                    // secure RRset 含 usable→MUST TLS+TLSA 认证（§2.2 第一分支）
)

// TLSARecord TLSA 资源记录解析形态（rfc6698 §2 三字段+关联数据）。
type TLSARecord struct {
	Usage     uint8  // 0 PKIX-TA/1 PKIX-EE/2 DANE-TA/3 DANE-EE（0/1 在 SMTP 机会态不可用——rfc7672 §3.1.3）
	Selector  uint8  // 0 Full cert/1 SPKI（rfc6698 §2.1.2）
	MatchType uint8  // 0 Full/1 SHA-256/2 SHA-512（rfc6698 §2.1.3）
	Data      []byte // 关联数据（摘要或全量——按 MatchType）
}

// DaneDecision DANE 决策结果（U13：transport 域代码层结构——纯数据无依赖）。
type DaneDecision struct {
	Mode          DaneMode     // 三态决策
	BaseTLSDomain string       // TLSA 基域（RequireDANE 态 SNI 与参考标识——rfc7672 §8.1）
	Records       []TLSARecord // usable 记录集（已过滤不可用+摘要敏捷择优）；RequireTLSOnly 态为空
	RefNames      []string     // TA(2) 名称检查参考标识集（基域+next-hop 域——rfc7672 §3.2.2）
}

// 编译期断言。
var _ DaneValidator = (*DaneService)(nil)

// ───────────────────────── 窄接口（stub 注入位，NFR-015） ─────────────────────────

// dnssecExchange DNSSEC 判定查询通道（生产=miekg/dns DO 位+AD 位读取；测试=内存 stub）。
// 语义：查询 name/qtype（name 为完整查询名）；返回应答消息（AD 位与记录由调用方读取）；
// SERVFAIL/超时/网络错误→错误（bogus 语义——rfc7672 §2.1.1/§2.1.2）。
type dnssecExchange func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// ───────────────────────── 生产实现 ─────────────────────────

// daneQueryTimeout 单查询超时（rfc7672 无强制值；对齐 raven 解析库缺省档 5s）。
const daneQueryTimeout = 5 * time.Second

// NewProdDNSSECExchange 生产 DNSSEC 查询闭包（miekg/dns：resolv.conf 递归服务器+
// DO 位 EDNS0——Q1-A AD 位信任形态；UDP 优先、截断回退 TCP）。
// 返回：查询闭包（每次调用构造消息——server 列表轮选无状态）。
func NewProdDNSSECExchange() (dnssecExchange, error) {
	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("读取 resolv.conf: %w", err)
	}
	if len(cc.Servers) == 0 {
		return nil, errors.New("resolv.conf 无递归服务器")
	}
	udp := &dns.Client{Timeout: daneQueryTimeout}
	tcp := &dns.Client{Net: "tcp", Timeout: daneQueryTimeout}
	return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = true
		m.SetEdns0(4096, true) // DO 位——请求 DNSSEC 记录与 AD 位判定（rfc7672 §2.1.3）
		server := cc.Servers[rand.Intn(len(cc.Servers))] + ":" + cc.Port
		resp, _, err := udp.ExchangeContext(ctx, m, server)
		if err == nil && resp.Truncated { // UDP 截断→TCP 重试（大 TLSA RRset 场景）
			resp, _, err = tcp.ExchangeContext(ctx, m, server)
		}
		if err != nil {
			return nil, err
		}
		if resp.Rcode == dns.RcodeServerFailure {
			return nil, errors.New("SERVFAIL") // bogus 语义（rfc7672 §2.1.1）
		}
		return resp, nil
	}, nil
}

// ───────────────────────── 域服务 ─────────────────────────

// DaneService 发送侧 DANE 决策域服务。
type DaneService struct {
	exchange dnssecExchange
}

// NewDaneService 构造 DANE 决策器。
// 参数：exchange DNSSEC 查询通道（生产 NewProdDNSSECExchange；测试 stub 注入）。
func NewDaneService(exchange dnssecExchange) *DaneService {
	return &DaneService{exchange: exchange}
}

// Check 对单台 MX 主机产出 DANE 决策（契约 2.3 语义）。
// 流程（rfc7672 §2.2.2/§2.2.3）：A 先行（insecure→跳过 TLSA=Opportunistic）→
// TLSA 两候选基域查询（展开名优先/原名次之）→四态判定。
func (s *DaneService) Check(ctx context.Context, mxHost, nextHopDomain string) (*DaneDecision, error) {
	// 1. A 先行（§2.2.2：地址 RRset insecure→该主机免 TLSA 查询——防问题域名服务器
	// 的 TLSA 查询挂死；查询错误→MX 不可达语义沿 rfc7672 §2.1.2）
	addrResp, err := s.exchange(ctx, mxHost, dns.TypeA)
	if err != nil {
		return nil, fmt.Errorf("A 查询失败（MX 视为不可达）: %w", err)
	}
	if !addrResp.AuthenticatedData {
		// insecure 地址（含否定不存在）：无 DNSSEC 保护→DANE 不适用（NFR-008 降级）
		return &DaneDecision{Mode: DaneOpportunistic}, nil
	}

	// 2. TLSA 两候选基域（§2.2.3：展开名优先、未展开名次之——展开名自 A 应答的
	// CNAME 链提取（§2.1.3：递归应答整链返回，AD 位覆盖全链））
	expanded := expandedHost(addrResp)
	candidates := []string{mxHost}
	if expanded != "" && expanded != mxHost {
		candidates = []string{expanded, mxHost} // 展开名优先（§2.2.3）
	}
	tlsaResp, tlsaBase, err := s.queryTLSA(ctx, candidates)
	if err != nil {
		return nil, fmt.Errorf("TLSA 查询失败（MX 视为不可达）: %w", err)
	}

	// 3. 判定（§2.2 四分支）
	if tlsaResp == nil || !tlsaResp.AuthenticatedData {
		// insecure TLSA（含否定不存在）→DANE 不适用（机会 TLS，NFR-008）
		return &DaneDecision{Mode: DaneOpportunistic}, nil
	}
	records := parseTLSARRset(tlsaResp)
	if len(records) == 0 {
		// secure 否定不存在（NXDOMAIN/NODATA）→机会 TLS（NFR-008）
		return &DaneDecision{Mode: DaneOpportunistic}, nil
	}
	usable := selectUsableTLSA(records) // rfc6698 §4.1 可用性+rfc7671 §9 摘要敏捷
	if len(usable) == 0 {
		// secure 非空 RRset 全 unusable→MUST TLS 免认证（§2.2 第二分支——TLS 承诺信号）
		return &DaneDecision{Mode: DaneRequireTLSOnly, BaseTLSDomain: tlsaBase}, nil
	}
	return &DaneDecision{
		Mode:          DaneRequireDANE,
		BaseTLSDomain: tlsaBase,
		Records:       usable,
		RefNames:      []string{tlsaBase, nextHopDomain}, // §3.2.2：基域主参考+next-hop 第二
	}, nil
}

// queryTLSA 候选基域逐查（rfc7672 §2.2.3：展开名优先、未展开名次之）。
// 语义：secure 且含 TLSA 记录→命中返回；insecure 或 secure 否定不存在→次候选；
// 查询错误→直接返回错误（§2.1.2——MX 不可达，禁止换候选绕过防降级）。
// 参数：ctx 上下文；candidates 候选基域集（≥1）。返回：最终应答（nil=全候选未命中
// secure 记录）；命中基域；错误。
func (s *DaneService) queryTLSA(ctx context.Context, candidates []string) (*dns.Msg, string, error) {
	var lastResp *dns.Msg
	for _, base := range candidates {
		resp, err := s.exchange(ctx, tlsaQueryName(base), dns.TypeTLSA)
		if err != nil {
			return nil, "", err // bogus/超时——MX 不可达（§2.1.2，不换候选）
		}
		if resp.AuthenticatedData && containsRRType(resp, dns.TypeTLSA) {
			return resp, base, nil // secure 命中
		}
		lastResp = resp // insecure（含否定不存在）→次候选（§2.2.3）
	}
	return lastResp, "", nil // 未命中（调用方按 insecure/无记录→Opportunistic）
}

// tlsaQueryName TLSA 查询名构造（rfc6698 §3/§2.2.3：_<port>._tcp.<host>——出站恒 25）。
func tlsaQueryName(host string) string { return "_25._tcp." + host }

// expandedHost 从 A/AAAA 应答提取 CNAME 展开终名（rfc7672 §2.1.3：递归应答整链
// 返回——末条 CNAME 的 Target 即链尾；AD 位覆盖全应答，链任一 insecure 整体降级已由
// 调用方 AD 判定承载）。返回：展开终名（无 CNAME 时空串）。
func expandedHost(m *dns.Msg) string {
	target := ""
	for _, rr := range m.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			target = strings.TrimSuffix(cn.Target, ".")
		}
	}
	return target
}

// containsRRType 应答是否含指定类型记录。
func containsRRType(m *dns.Msg, t uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}

// parseTLSARRset 解析应答中全部 TLSA 记录（rfc6698 §2.2 呈现格式 hex→字节）。
func parseTLSARRset(m *dns.Msg) []TLSARecord {
	var out []TLSARecord
	for _, rr := range m.Answer {
		t, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		data, err := hex.DecodeString(t.Certificate)
		if err != nil {
			continue // 比较数据 malformed→不可用（rfc6698 §4.1）
		}
		out = append(out, TLSARecord{Usage: uint8(t.Usage), Selector: uint8(t.Selector), MatchType: uint8(t.MatchingType), Data: data})
	}
	return out
}

// selectUsableTLSA 可用性过滤+摘要敏捷择优（rfc6698 §4.1：未知 usage/selector/
// matching type 或畸形长度→不可用；rfc7672 §3.1.3：usage 0/1 在 SMTP 机会态不可用；
// rfc7671 §9：每 (usage,selector) 组保留 Full(0)+最强摘要档 SHA-512>SHA-256）。
func selectUsableTLSA(records []TLSARecord) []TLSARecord {
	type groupKey struct{ usage, selector uint8 }
	groups := make(map[groupKey][]TLSARecord)
	for _, r := range records {
		if r.Usage > 3 || r.Selector > 1 || r.MatchType > 2 {
			continue // 未知参数→不可用
		}
		if r.Usage == 0 || r.Usage == 1 {
			continue // PKIX-TA/PKIX-EE：SMTP 机会态不支持（rfc7672 §3.1.3）
		}
		if (r.MatchType == 1 && len(r.Data) != sha256.Size) || (r.MatchType == 2 && len(r.Data) != sha512.Size) {
			continue // 摘要长度畸形→不可用（rfc6698 §4.1）
		}
		k := groupKey{r.Usage, r.Selector}
		groups[k] = append(groups[k], r)
	}
	var usable []TLSARecord
	for _, rs := range groups {
		bestDigest := uint8(0) // 该组内出现的最强摘要档（0=无/1=256/2=512）
		for _, r := range rs {
			if r.MatchType > bestDigest {
				bestDigest = r.MatchType
			}
		}
		for _, r := range rs {
			if r.MatchType == 0 || r.MatchType == bestDigest { // Full(0)+最强档（rfc7671 §9）
				usable = append(usable, r)
			}
		}
	}
	return usable
}

// ───────────────────────── 握手后 TLSA 匹配（sender RequireDANE 分支调用） ─────────────────────────

// ErrDANENoPeerCertificate 对端未出示证书（DANE 认证不可能成功——MUST NOT 投递语义输入）。
var ErrDANENoPeerCertificate = errors.New("dane: 对端未出示证书")

// VerifyPeerCertificates 对握手所得证书链执行 TLSA 匹配认证（rfc7672 §3）。
// 参数：d RequireDANE 决策；certs 对端链（leaf 在前——tls.Conn.ConnectionState().
// PeerCertificates）。返回：认证通过为 nil；失败=认证失败（调用方 MUST NOT 投递——§3.2）。
// 语义：EE(3)（§3.1.1）叶证书 SPKI/全量比对——免名称检查免有效期；
// TA(2)（§3.1.2）信任锚链验证+名称检查（RefNames——DNS-ID 优先，§3.2.3）。
func VerifyPeerCertificates(d *DaneDecision, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return ErrDANENoPeerCertificate
	}
	leaf := certs[0]
	hasEE, hasTA := false, false
	for _, r := range d.Records {
		switch r.Usage {
		case 3: // DANE-EE：叶证书直接比对（绑定即认证——名称与有效期由 TLSA RRSIG 生命周期承载）
			hasEE = true
			if daneMatchRecord(r, selectorBytes(r.Selector, leaf)) {
				return nil // EE(3) 命中即整体通过（rfc7672 §3.1.1）
			}
		case 2: // DANE-TA：信任锚（数据=TA 证书全量或其摘要）→链验证+名称检查
			hasTA = true
			if verifyTA(r, d.RefNames, leaf, certs) {
				return nil
			}
		}
	}
	if hasEE && !hasTA {
		return fmt.Errorf("DANE-EE(3) 全部记录不匹配叶证书")
	}
	if hasTA {
		return fmt.Errorf("DANE-TA(2) 信任锚验证未通过（任一参考标识）")
	}
	return fmt.Errorf("决策无可验证 TLSA 记录")
}

// selectorBytes 按记录 Selector 取叶证书比对素材（rfc6698 §2.1.2：0=完整证书/1=SPKI）。
func selectorBytes(selector uint8, leaf *x509.Certificate) []byte {
	if selector == 0 {
		return leaf.Raw
	}
	return leaf.RawSubjectPublicKeyInfo
}

// daneMatchRecord 单记录比对（MatchType 0 全量相等/1 SHA-256/2 SHA-512）。
func daneMatchRecord(r TLSARecord, material []byte) bool {
	switch r.MatchType {
	case 0:
		return string(r.Data) == string(material)
	case 1:
		sum := sha256.Sum256(material)
		return string(r.Data) == string(sum[:])
	case 2:
		sum := sha512.Sum512(material)
		return string(r.Data) == string(sum[:])
	}
	return false
}

// verifyTA DANE-TA(2) 信任锚验证（rfc7672 §3.1.2/§3.2.2）：
// Full(0) 记录数据=TA 证书 DER→直接入 Roots；摘要记录→在服务端出示链中按摘要定位
// TA 证书（发布者义务 MUST 携带 TA 于链中）；leaf 经 x509 PKIX 验证+名称检查
// （逐 RefNames 尝试——DNS-ID 语义由 x509 DNSName 承载，通配符最左标签）。
func verifyTA(r TLSARecord, refNames []string, leaf *x509.Certificate, chain []*x509.Certificate) bool {
	roots := x509.NewCertPool()
	added := false
	if r.MatchType == 0 && r.Selector == 0 {
		if crt, err := x509.ParseCertificate(r.Data); err == nil {
			roots.AddCert(crt)
			added = true
		}
	} else {
		for _, crt := range chain { // 链内定位 TA 证书（摘要或 SPKI 摘要形态）
			if daneMatchRecord(r, selectorBytes(r.Selector, crt)) {
				roots.AddCert(crt)
				added = true
				break
			}
		}
	}
	if !added {
		return false
	}
	now := time.Now()
	for _, name := range refNames { // 任一参考标识通过即可（§3.2.2 参考标识集）
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:       roots,
			DNSName:     name,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			CurrentTime: now,
		}); err == nil {
			return true
		}
	}
	return false
}
