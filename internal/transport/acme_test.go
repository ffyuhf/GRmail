// transport 包 U10 ACME 离线测试（NFR-015：零外部网络依赖——真签发不可离线，
// 部署后判定登记计划书第六章；离线覆盖挑战表/续期判定/账户密钥持久化/手动模式零动作）。
// 修改历史：
//
//	2026-09-20 01:55:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 9）
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// TestACMEChallengeStoreRoundtrip 挑战表 Present/Lookup/CleanUp 往返（rfc8555 HTTP-01
// 资源语义的内存承载——lego challenge.Provider 契约）。
func TestACMEChallengeStoreRoundtrip(t *testing.T) {
	s := &ChallengeStore{vals: make(map[string]string)}
	if err := s.Present("example.com", "tok", "key-auth"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if v, ok := s.Lookup("tok"); !ok || v != "key-auth" {
		t.Fatalf("Lookup 应命中，得 %q %v", v, ok)
	}
	if _, ok := s.Lookup("other"); ok {
		t.Fatal("未存 token 不应命中")
	}
	if err := s.CleanUp("example.com", "tok", "key-auth"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if _, ok := s.Lookup("tok"); ok {
		t.Fatal("CleanUp 后应清除")
	}
}

// TestACMENeedsRenewalWindow 续期窗口判定（Q6-A：缺失=待签发/剩余<30 天=续期/充足=跳过）。
func TestACMENeedsRenewalWindow(t *testing.T) {
	dir := t.TempDir()
	conf := config.ACMEConf{CertsDir: dir}
	m := NewACMEManager("example.com", func() config.ACMEConf { return conf }, nil)

	if !m.needsRenewal(conf) {
		t.Fatal("证书缺失应判定需要签发")
	}
	// 自签证书剩余 90 天（>30 窗口）→false
	writeTestCert(t, filepath.Join(dir, "example.com", "fullchain.pem"), 90*24*time.Hour)
	if m.needsRenewal(conf) {
		t.Fatal("剩余 90 天不应续期")
	}
	// 剩余 10 天（<30 窗口）→true
	writeTestCert(t, filepath.Join(dir, "example.com", "fullchain.pem"), 10*24*time.Hour)
	if !m.needsRenewal(conf) {
		t.Fatal("剩余 10 天应触发续期")
	}
	// 损坏 PEM→true（自愈重签）
	if err := os.WriteFile(filepath.Join(dir, "example.com", "fullchain.pem"), []byte("not-pem"), 0o600); err != nil {
		t.Fatalf("写坏证书: %v", err)
	}
	if !m.needsRenewal(conf) {
		t.Fatal("损坏证书应判定重签")
	}
}

// TestACMEAccountKeyPersist 账户私钥持久化往返（生成→落盘→复载一致；ECDSA P-256）。
func TestACMEAccountKeyPersist(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "acme-account.key")
	m := NewACMEManager("example.com", func() config.ACMEConf { return config.ACMEConf{} }, nil)
	k1, err := m.loadOrCreateAccountKey(keyPath)
	if err != nil {
		t.Fatalf("生成账户密钥: %v", err)
	}
	// 复载：同文件同钥
	k2, err := m.loadOrCreateAccountKey(keyPath)
	if err != nil {
		t.Fatalf("复载账户密钥: %v", err)
	}
	e1, e2 := k1.(*ecdsa.PrivateKey), k2.(*ecdsa.PrivateKey)
	if e1.X.Cmp(e2.X) != 0 || e1.Y.Cmp(e2.Y) != 0 {
		t.Fatal("复载密钥应与生成一致")
	}
	if e1.Curve != elliptic.P256() {
		t.Fatal("账户密钥曲线应为 P-256")
	}
}

// TestACMEManualModeNoAction 手动模式（Enabled=false）：EnsureIssued 零动作零网络。
func TestACMEManualModeNoAction(t *testing.T) {
	m := NewACMEManager("example.com",
		func() config.ACMEConf { return config.ACMEConf{Enabled: false} }, nil)
	if err := m.EnsureIssued(context.Background()); err != nil {
		t.Fatalf("手动模式 EnsureIssued 应零动作成功: %v", err)
	}
}

// writeTestCert 生成自签证书 PEM 落盘（指定 NotAfter 剩余时长；needsRenewal 判定输入）。
func writeTestCert(t *testing.T, path string, remaining time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "acme-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(remaining),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("建目录: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("落盘测试证书: %v", err)
	}
}
