// smtp 包 U10 25 端口 STARTTLS 离线测试（NFR-015：net.Pipe+本地自签证书，零网络端点）。
// 覆盖：rfc3207 §4 原文锚点——无证书不通告（8314 §4 L374-376）/证书就绪通告/可选升级
// 全流程（220→握手→协议重置→重 EHLO）/带参 501/未配置 454/明文收信不强制（§4 L129-136）。
// 修改历史：
//
//	2026-09-20 02:00:00 | 新建 | U10 STARTTLS 收口（计划书步骤 5 检查点）
package smtp

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// starttlsConn 测试 harness：net.Pipe 驱动单会话（25 收信端点；pipeline/accounts 零注入——
// STARTTLS 前置命令不触投递路径）。
type starttlsConn struct {
	t      *testing.T
	client net.Conn
	reader *bufio.Reader
	srv    *Server
}

// dialStarttls 建立管道会话并读取横幅。
// 参数：t 测试；cfg 服务端配置。返回：harness（Cleanup 关闭）。
func dialStarttls(t *testing.T, cfg ServerConfig) *starttlsConn {
	t.Helper()
	cfg.Domain = "test.local"
	srv := NewServer(cfg, nil, nil) // pipeline/accounts=nil：本测试不触 MAIL/RCPT 后续链
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go srv.serveConn(server)
	h := &starttlsConn{t: t, client: client, reader: bufio.NewReader(client), srv: srv}
	h.expectLine("220") // 横幅
	return h
}

// send 发送命令行。
func (h *starttlsConn) send(line string) {
	h.t.Helper()
	if _, err := h.client.Write([]byte(line + "\r\n")); err != nil {
		h.t.Fatalf("发送 %q: %v", line, err)
	}
}

// expectLine 读取一行并断言前缀。
func (h *starttlsConn) expectLine(prefix string) string {
	h.t.Helper()
	_ = h.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := h.reader.ReadString('\n')
	if err != nil {
		h.t.Fatalf("读取行（期望 %s*）: %v", prefix, err)
	}
	if len(line) < len(prefix) || line[:len(prefix)] != prefix {
		h.t.Fatalf("应答前缀期望 %s*，得 %q", prefix, line)
	}
	return line
}

// expectMulti 读取多行应答至末行（250 末行/250- 续行），返回拼接全文（通告断言用）。
func (h *starttlsConn) expectMulti(code string) string {
	h.t.Helper()
	var all string
	for {
		line := h.expectLine(code)
		all += line
		if len(line) > 3 && line[3] == ' ' {
			return all // 末行
		}
	}
}

// genSelfSigned 生成内存自签证书对（STARTTLS 升级用）。
func genSelfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ServerName:   "test.local",
	}
}

// TestU10STARTTLSNoCertNoAdvertise 无证书：不通告 STARTTLS（rfc8314 §4 L374-376）+
// 命令 454 + 明文收信能力保持（rfc3207 §4 L129-136——不强制升级）。
func TestU10STARTTLSNoCertNoAdvertise(t *testing.T) {
	h := dialStarttls(t, ServerConfig{})
	h.send("EHLO client.test")
	caps := h.expectMulti("250")
	if containsFold(caps, "STARTTLS") {
		t.Fatal("无证书不应通告 STARTTLS")
	}
	h.send("STARTTLS")
	h.expectLine("454") // 未配置——临时不可用（不崩溃兜底）
	// 明文继续可用（可选升级语义——EHLO 重发正常）
	h.send("NOOP")
	h.expectLine("250")
}

// TestU10STARTTLSUpgradeFlow 证书就绪：通告→升级→协议重置→TLS 会话中禁再通告/503。
func TestU10STARTTLSUpgradeFlow(t *testing.T) {
	tlsCfg := genSelfSigned(t)
	h := dialStarttls(t, ServerConfig{TLSConfig: func() *tls.Config { return tlsCfg }})
	h.send("EHLO client.test")
	caps := h.expectMulti("250")
	if !containsFold(caps, "STARTTLS") {
		t.Fatalf("证书就绪应通告 STARTTLS，得 %q", caps)
	}
	// 带参 501（rfc3207 §4：无参数）
	h.send("STARTTLS extra")
	h.expectLine("501")
	// 正常升级：220 → 握手（客户端侧 tls.Client）→ 重 EHLO（协议重置后能力行无 STARTTLS）
	h.send("STARTTLS")
	h.expectLine("220")
	tlsClient := tls.Client(h.client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, ServerName: "test.local"}) //nolint:gosec // 测试自签
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS 握手: %v", err)
	}
	h.client = tlsClient
	h.reader = bufio.NewReader(tlsClient)
	// rfc3207 §4.2：协议重置——必须先 EHLO（未 EHLO 时 MAIL 503）
	h.send("MAIL FROM:<a@test.local>")
	h.expectLine("503")
	// 重 EHLO：TLS 会话中不得再通告 STARTTLS（§4.2）
	h.send("EHLO client.test")
	caps2 := h.expectMulti("250")
	if containsFold(caps2, "STARTTLS") {
		t.Fatal("TLS 会话中不得再通告 STARTTLS（rfc3207 §4.2）")
	}
	// TLS 中重复 STARTTLS→503
	h.send("STARTTLS")
	h.expectLine("503")
}

// containsFold 子串包含（大小写不敏感）。
func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if equalFold(s[i:i+len(sub)], sub) {
				return true
			}
		}
		return false
	})()
}

// equalFold ASCII 大小写不敏感相等。
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
