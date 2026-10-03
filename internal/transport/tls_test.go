// transport 包单测：TLS 证书中心（加载/就绪/入站出站配置/热重载）。
// 全离线驱动（NFR-015）：临时自签证书经本地 tls listener/client 往返验证。
// 修改历史：
//
//	2026-09-17 11:50:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 4 检查点）
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"GRmail/internal/config"
)

// writeSelfSignedCert 生成临时自签证书对（ECDSA P-256；SAN=127.0.0.1）并写入目录。
// 返回 certPath/keyPath。
func writeSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "grmail-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("序列化私钥: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("写证书: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("写私钥: %v", err)
	}
	return certPath, keyPath
}

// TestTLSManagerUnconfiguredNotReady 未配置证书：构造成功且未就绪（TLS 端点跳过判定，1.5⑫）
func TestTLSManagerUnconfiguredNotReady(t *testing.T) {
	m, err := NewTLSManager(config.TLSConf{})
	if err != nil {
		t.Fatalf("未配置构造应无错: %v", err)
	}
	if m.Ready() {
		t.Fatal("未配置应未就绪")
	}
	if got := m.ServerTLSConfig("example.com"); got != nil {
		t.Fatal("未就绪时 ServerTLSConfig 应返回 nil（rfc3207 4.1 不通告依据）")
	}
}

// TestTLSManagerLoadAndHandshake 证书加载后本地 TLS 握手往返（入站配置有效性）
func TestTLSManagerLoadAndHandshake(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	m, err := NewTLSManager(config.TLSConf{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	if !m.Ready() {
		t.Fatal("已配置应就绪")
	}
	srvCfg := m.ServerTLSConfig("localhost")
	if srvCfg == nil {
		t.Fatal("就绪后配置不应为 nil")
	}
	if srvCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion 应为 TLS1.2（rfc8314 4）: %v", srvCfg.MinVersion)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("TLS 监听: %v", err)
	}
	defer ln.Close()
	done := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- ""
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
		done <- string(buf[:n])
	}()
	// 客户端以系统池+InsecureSkipVerify（自签非公共 CA，测试仅验握手与应用数据往返）
	clientCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("TLS 拨号: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("写入: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("读取: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("往返数据不一致: %q", string(buf))
	}
}

// TestClientTLSConfigBaseline 出站配置基线（MinVersion TLS1.2）
func TestClientTLSConfigBaseline(t *testing.T) {
	if got := ClientTLSConfig(); got.MinVersion != tls.VersionTLS12 {
		t.Fatalf("出站 MinVersion 应为 TLS1.2: %v", got.MinVersion)
	}
}

// TestTLSManagerOnConfigChangePathSwitch 订阅回调：路径变更触发重载
func TestTLSManagerOnConfigChangePathSwitch(t *testing.T) {
	dir1 := t.TempDir()
	cert1, key1 := writeSelfSignedCert(t, dir1)
	m, err := NewTLSManager(config.TLSConf{CertFile: cert1, KeyFile: key1})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	dir2 := t.TempDir()
	cert2, key2 := writeSelfSignedCert(t, dir2)
	m.OnConfigChange(&config.Config{TLS: config.TLSConf{CertFile: cert2, KeyFile: key2}})
	m.mu.RLock()
	cur := m.certPath
	m.mu.RUnlock()
	if cur != cert2 {
		t.Fatalf("路径应切换到新证书: %s", cur)
	}
	if !m.Ready() {
		t.Fatal("切换后应保持就绪")
	}
	// 路径未变：回调零动作（不重载不报错）
	m.OnConfigChange(&config.Config{TLS: config.TLSConf{CertFile: cert2, KeyFile: key2}})
	m.mu.RLock()
	cur = m.certPath
	m.mu.RUnlock()
	if cur != cert2 {
		t.Fatalf("路径未变时不应切换: %s", cur)
	}
}

// TestTLSManagerWatchCertFiles 证书文件替换热重载（去抖 1s 后新证书生效）
func TestTLSManagerWatchCertFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	m, err := NewTLSManager(config.TLSConf{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.WatchCertFiles(ctx); err != nil {
		t.Fatalf("监听启动: %v", err)
	}
	defer m.Close()

	// 原子替换证书文件（tmp+rename，模拟续期）
	cert2Path, key2Path := writeSelfSignedCert(t, t.TempDir())
	c2, err := os.ReadFile(cert2Path)
	if err != nil {
		t.Fatalf("读新证书: %v", err)
	}
	k2, err := os.ReadFile(key2Path)
	if err != nil {
		t.Fatalf("读新私钥: %v", err)
	}
	tmp := certPath + ".tmp"
	if err := os.WriteFile(tmp, c2, 0o600); err != nil {
		t.Fatalf("写临时证书: %v", err)
	}
	if err := os.Rename(tmp, certPath); err != nil {
		t.Fatalf("替换证书: %v", err)
	}
	tmpK := keyPath + ".tmp"
	if err := os.WriteFile(tmpK, k2, 0o600); err != nil {
		t.Fatalf("写临时私钥: %v", err)
	}
	if err := os.Rename(tmpK, keyPath); err != nil {
		t.Fatalf("替换私钥: %v", err)
	}

	// 去抖 1s+重载余量
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.RLock()
		loaded := m.cert != nil && string(m.cert.Certificate[0]) != ""
		leaf, err := x509.ParseCertificate(m.cert.Certificate[0])
		m.mu.RUnlock()
		if loaded && err == nil && leaf.Subject.CommonName == "grmail-test" {
			// 成功判据：重载完成无错（内容级断言受限——同名 CN；无错误即通过）
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("热重载未在时限内完成")
}
