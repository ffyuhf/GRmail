// transport 域传输安全合规批定向测试（F7 策略快照/F8① ACME 回写重试/F9① DANE
// 中间链/F9② RCODE 分类——NFR-015 纯函数与 stub 离线驱动）。
// 依据：传输安全合规批_计划_20261007_15-10-00_v1.0.0 步骤 7/8/9 检查点
// （G2 批准 2026-10-07 15:13:06；rfc8460 §4.4/§4.5、rfc6698 §2.1.1、rfc7672 §2.1.2）。
// 修改历史：
//
//	2026-10-07 15:45:00 | 新建 | 传输安全合规批 F7/F8①/F9①②（计划书步骤 7-9 定向锚）
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// ───────────────────────── F7：TLS-RPT 策略快照（B-T2②） ─────────────────────────

// TestTLSRPTPolicySnapshotFirstSeen F7：策略快照按域首见记录（后续 nil 调用不覆盖）
// ——SnapshotAndReset 携带 PolicyType/PolicyString/MXHostPatterns（rfc8460 §4.4/§4.5
// 报告结构完整化的聚合侧锚）。
func TestTLSRPTPolicySnapshotFirstSeen(t *testing.T) {
	agg := NewTLSRPTAggregator()
	snap := &TLSPolicySnapshot{
		PolicyType:     "sts",
		PolicyString:   []string{"version: STSv1", "mode: enforce", "mx: mx1.ext.io", "max_age: 3600"},
		MXHostPatterns: []string{"mx1.ext.io"},
	}
	agg.Record("ext.io", "mx1.ext.io", TLSRPTSuccess, snap)
	agg.Record("ext.io", "mx2.ext.io", TLSRPTStarttlsNotSupported, nil) // 后续 nil 不覆盖首见
	out := agg.SnapshotAndReset()
	st, ok := out["ext.io"]
	if !ok {
		t.Fatal("域应存在")
	}
	if st.PolicyType != "sts" || len(st.PolicyString) != 4 || st.PolicyString[1] != "mode: enforce" || len(st.MXHostPatterns) != 1 {
		t.Fatalf("首见快照应完整保持（§4.5 策略行数组）: %+v", st)
	}
	if st.Success != 1 || len(st.Failures) != 1 {
		t.Fatalf("计数应正确: success=%d failures=%d", st.Success, len(st.Failures))
	}
}

// TestTLSRPTPolicySnapshotDaneForm F7：DANE 快照形态（tlsa+RDATA presentation 数组
// ——wire.go 适配器构造格式的聚合侧消费锚；nil 域零值兜底 no-policy-found 归报告构造侧）。
func TestTLSRPTPolicySnapshotDaneForm(t *testing.T) {
	agg := NewTLSRPTAggregator()
	agg.Record("dane.io", "mx1.dane.io", TLSRPTSuccess, &TLSPolicySnapshot{
		PolicyType:   "tlsa",
		PolicyString: []string{"3 0 1 abc123"},
	})
	st := agg.SnapshotAndReset()["dane.io"]
	if st.PolicyType != "tlsa" || len(st.PolicyString) != 1 || st.PolicyString[0] != "3 0 1 abc123" {
		t.Fatalf("tlsa 快照形态不符（§4.5 RDATA presentation）: %+v", st)
	}
	// 无策略域：零值（报告构造侧兜底 no-policy-found）
	agg.Record("plain.io", "mx1.plain.io", TLSRPTSuccess, nil)
	if st := agg.SnapshotAndReset()["plain.io"]; st.PolicyType != "" {
		t.Fatalf("无策略域应零值: %+v", st)
	}
}

// ───────────────────────── F8①：ACME 回写失败强制重试（B-T3①） ─────────────────────────

// TestACMEWriteBackPendingForcesRetry F8①：writeBackPending 置位后 EnsureIssued 绕过
// needsRenewal 窗口（90 天新证书场景原跳过→现强制进入 obtain 重试链——离线在
// lego 网络步失败返回非 nil 即证明未跳过）；对照组未置位+90 天直接跳过（nil）。
func TestACMEWriteBackPendingForcesRetry(t *testing.T) {
	dir := t.TempDir()
	conf := config.ACMEConf{CertsDir: dir, Enabled: true}
	newMgr := func() *ACMEManager {
		return NewACMEManager("example.com", func() config.ACMEConf { return conf }, func(string, string) error { return nil })
	}

	// 对照组：90 天证书+未置位 → 窗口内直接跳过（零动作 nil）
	m1 := newMgr()
	writeTestCert(t, filepath.Join(dir, "example.com", "fullchain.pem"), 90*24*time.Hour)
	if err := m1.EnsureIssued(context.Background()); err != nil {
		t.Fatalf("90 天未置位应跳过: %v", err)
	}

	// 置位组：同 90 天证书+writeBackPending → 绕过窗口进入 obtain（离线 lego 网络步
	// 失败非 nil——重试链激活证明；B-T3①「30d 窗内不再触发→长期不接入」收口锚）
	m2 := newMgr()
	m2.writeBackPending = true
	if err := m2.EnsureIssued(context.Background()); err == nil {
		t.Fatal("writeBackPending 置位应绕过窗口进入 obtain（离线失败非 nil 证明）")
	}
}

// ───────────────────────── F9①：DANE TA(2) 跨中间链验证（B-S11①） ─────────────────────────

// signCertBy 测试辅助：以 issuer 证书签发一张新证书（ECDSA P-256；模板可选定制）。
func signCertBy(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, dnsName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true, // 链内证书需 CA 基本约束（路径构建）
		BasicConstraintsValid: true,
	}
	parent, priv := issuer, any(issuerKey)
	if issuer == nil {
		parent, priv = tmpl, key // 自签：parent=template 自身（writeTestCert 同款先例形态）+ 自身私钥
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, priv)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	return crt, key
}

// TestDaneVerifyTAViaIntermediates F9①：TA(2) 全量记录锚定 root、服务端出示
// [leaf, intermediate]（不含 root）——leaf→intermediate→root 路径构建依赖
// Intermediates 池（rfc6698 §2.1.1；修复前仅 Roots 单锚无中间池致跨中间链失败）。
func TestDaneVerifyTAViaIntermediates(t *testing.T) {
	// 三级链构造：root 自签（issuer=nil 形态）→ intermediate 由 root 签 → leaf 由 intermediate 签
	root, rootKey := signCertBy(t, nil, nil, "test-root")
	interCrt, interKey := signCertBy(t, root, rootKey, "test-intermediate")
	leafCrt, _ := signCertBy(t, interCrt, interKey, "mx.example.com")

	// TA(2) 全量记录（Usage=2/Selector=0/MatchType=0/Data=root DER）——wire 适配器
	// 同源形态；服务端链 [leaf, intermediate]（root 不出示——跨中间路径场景）
	d := &DaneDecision{
		Mode:     DaneRequireDANE,
		Records:  []TLSARecord{{Usage: 2, Selector: 0, MatchType: 0, Data: root.Raw}},
		RefNames: []string{"mx.example.com"},
	}
	// F9① 修复后：Intermediates={intermediate}（chain[1:]）→ 路径构建通过
	if err := VerifyPeerCertificates(d, []*x509.Certificate{leafCrt, interCrt}); err != nil {
		t.Fatalf("跨中间链 TA(2) 验证应通过（Intermediates 池承载）: %v", err)
	}
}

// ───────────────────────── F9②：RCODE 查询失败分类（B-S11②） ─────────────────────────

// TestDNSRcodeIsQueryError F9②：NOERROR/NXDOMAIN 非错误（否定不存在——rfc7672 §2.1.1）
// 与异常 RCODE 全族错误（SERVFAIL/FORMERR/REFUSED/NOTIMP/NOTAUTH——§2.1.2 etc. 涵盖，
// §2.2.2 L876-877 NOTIMP 点名）的表驱动锚。
func TestDNSRcodeIsQueryError(t *testing.T) {
	cases := []struct {
		name  string
		rcode int
		want  bool
	}{
		{"NOERROR 成功", 0, false},
		{"NXDOMAIN 否定不存在", 3, false},
		{"SERVFAIL", 2, true},
		{"FORMERR", 1, true},
		{"REFUSED", 5, true},
		{"NOTIMP", 4, true},
		{"NOTAUTH", 9, true},
	}
	for _, c := range cases {
		if got := dnsRcodeIsQueryError(c.rcode); got != c.want {
			t.Errorf("%s: dnsRcodeIsQueryError(%d)=%v want %v", c.name, c.rcode, got, c.want)
		}
	}
}

// （占位哨兵使用——errors import 保持编译完整）
var _ = errors.New
