// SignerService 单测（NFR-015 离线）：rsa/ed25519 签名往返、未配置/算法不符哨兵、
// selector 热重载（Q1-A）。
// 修改历史：
//
//	2026-09-17 02:52:00 | 新建 | U3 auth 基础（计划书步骤 8）
//	2026-09-29 17:21:00 | 修正 | RFC候选修正批次 RF-G：F-A4 弱 RSA 密钥拒绝测试（rfc8301 §3 ≥1024 bits）
package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GRmail/internal/config"

	ravendkim "github.com/synqronlabs/raven/dkim"
)

// generateEd25519KeyPEM 生成 ed25519 测试私钥并写 PKCS#8 PEM。
func generateEd25519KeyPEM(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 ed25519 键: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("PKCS8 序列化: %v", err)
	}
	path := filepath.Join(t.TempDir(), "dkim-ed.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("写 PEM: %v", err)
	}
	return key, path
}

// TestSignWeakRSAKeyRejected F-A4：弱 RSA 私钥（<1024 位）构造即拒绝
// （rfc8301 §3 L148-149「Signers MUST use RSA keys of at least 1024 bits」）。
func TestSignWeakRSAKeyRejected(t *testing.T) {
	// Go 1.24+ crypto/rsa 拒绝生成 <1024 位钥——GODEBUG 开关放开仅限本测试
	// 生成弱钥样本（t.Setenv 作用域内；校验对象是本实现的位长防线非标准库）
	t.Setenv("GODEBUG", "rsa1024min=0")
	key, err := rsa.GenerateKey(rand.Reader, 512) // 512 位弱钥（下限 1024）
	if err != nil {
		t.Fatalf("生成 512 位弱钥: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("PKCS8 序列化: %v", err)
	}
	path := filepath.Join(t.TempDir(), "dkim-weak.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("写 PEM: %v", err)
	}
	if _, err := NewSignerService(config.DKIMConf{Selector: "s", KeyPath: path, Algorithm: "rsa-sha256"}); !errors.Is(err, ErrKeyTooWeak) {
		t.Fatalf("512 位弱钥应 ErrKeyTooWeak 拒绝（rfc8301 §3）: %v", err)
	}
	// 既有 2048 位合格钥路径保持通过（generateRSAKeyPEM 固定 2048——verify_test.go）
	_, okPath := generateRSAKeyPEM(t)
	if _, err := NewSignerService(config.DKIMConf{Selector: "s", KeyPath: okPath, Algorithm: "rsa-sha256"}); err != nil {
		t.Fatalf("2048 位合格钥应通过: %v", err)
	}
}

// verifySignedWithStub 用 stub DNS 对签名后消息执行 raven dkim.Verify（往返校验）。
// keyType：公钥记录 k= 标签（实测修正 2026-09-17 02:50：缺省 k=rsa 时 raven 按
// SubjectPublicKeyInfo 解析，ed25519 原始 32 字节公钥必须显式 k=ed25519——rfc6376 3.6.1）。
func verifySignedWithStub(t *testing.T, signed []byte, selector, keyType, pubB64 string) []ravendkim.Result {
	t.Helper()
	resolver := newStubResolver().withTXT(selector+"._domainkey.example.com",
		"v=DKIM1; k="+keyType+"; p="+pubB64)
	results, err := ravendkim.Verify(context.Background(), resolver, signed)
	if err != nil {
		t.Fatalf("dkim 验证执行失败: %v", err)
	}
	return results
}

// TestSignRoundTripEd25519 ed25519-sha256 签名往返（rfc8463 路径；签名头算法标签断言）
func TestSignRoundTripEd25519(t *testing.T) {
	key, keyPath := generateEd25519KeyPEM(t)
	signer, err := NewSignerService(config.DKIMConf{Selector: "ed", KeyPath: keyPath, Algorithm: "ed25519-sha256"})
	if err != nil {
		t.Fatalf("签名器构造: %v", err)
	}
	signed, err := signer.Sign(context.Background(), sampleMessage("example.com"), "example.com")
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if !strings.Contains(string(signed), "a=ed25519-sha256") {
		t.Fatalf("签名头应含 ed25519-sha256 算法标签")
	}
	pubB64 := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	results := verifySignedWithStub(t, signed, "ed", "ed25519", pubB64)
	if len(results) == 0 || results[0].Status != ravendkim.StatusPass {
		t.Fatalf("ed25519 往返验证应 pass: %+v", results)
	}
}

// TestSignNotConfigured 零值配置构造即失败（缺省未配置态显式报错，不静默）
func TestSignNotConfigured(t *testing.T) {
	if _, err := NewSignerService(config.DKIMConf{}); !errors.Is(err, ErrKeyNotConfigured) {
		t.Fatalf("零值配置应 ErrKeyNotConfigured: %v", err)
	}
	key, keyPath := generateRSAKeyPEM(t)
	_ = key
	signer, err := NewSignerService(config.DKIMConf{Selector: "s", KeyPath: keyPath, Algorithm: "rsa-sha256"})
	if err != nil {
		t.Fatalf("正常构造: %v", err)
	}
	// 热加载清空配置 → Sign 显式报错
	signer.OnConfigChange(&config.Config{Auth: config.AuthStack{}})
	if _, err := signer.Sign(context.Background(), sampleMessage("example.com"), "example.com"); !errors.Is(err, ErrKeyNotConfigured) {
		t.Fatalf("清空后 Sign 应 ErrKeyNotConfigured: %v", err)
	}
}

// TestSignAlgorithmMismatch 配置算法与私钥类型不符（ed25519 键配 rsa-sha256）
func TestSignAlgorithmMismatch(t *testing.T) {
	_, keyPath := generateEd25519KeyPEM(t)
	_, err := NewSignerService(config.DKIMConf{Selector: "s", KeyPath: keyPath, Algorithm: "rsa-sha256"})
	if !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("应 ErrAlgorithmMismatch: %v", err)
	}
}

// TestSignUnsupportedAlgorithm 不在支持集的算法（rsa-sha1 已被 rfc8301 废止）
func TestSignUnsupportedAlgorithm(t *testing.T) {
	_, keyPath := generateRSAKeyPEM(t)
	_, err := NewSignerService(config.DKIMConf{Selector: "s", KeyPath: keyPath, Algorithm: "rsa-sha1"})
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("应 ErrUnsupportedAlgorithm: %v", err)
	}
}

// TestSignerHotReloadSelector Q1-A 热加载：selector 变更换键即时生效（s= 标签断言）
func TestSignerHotReloadSelector(t *testing.T) {
	_, keyPath := generateRSAKeyPEM(t)
	conf := config.DKIMConf{Selector: "s1", KeyPath: keyPath, Algorithm: "rsa-sha256"}
	signer, err := NewSignerService(conf)
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	signed1, err := signer.Sign(context.Background(), sampleMessage("example.com"), "example.com")
	if err != nil {
		t.Fatalf("签名1: %v", err)
	}
	if !strings.Contains(string(signed1), "s=s1") {
		t.Fatal("首轮签名应含 s=s1")
	}
	conf.Selector = "s2"
	signer.OnConfigChange(&config.Config{Auth: config.AuthStack{DKIM: conf}})
	signed2, err := signer.Sign(context.Background(), sampleMessage("example.com"), "example.com")
	if err != nil {
		t.Fatalf("签名2: %v", err)
	}
	if !strings.Contains(string(signed2), "s=s2") {
		t.Fatal("热加载后签名应含 s=s2")
	}
}

// TestSignPrependsHeader 签名输出=DKIM-Signature 头前置+原消息（契约 signed 语义）
func TestSignPrependsHeader(t *testing.T) {
	key, keyPath := generateRSAKeyPEM(t)
	_ = key
	signer, _ := NewSignerService(config.DKIMConf{Selector: "s", KeyPath: keyPath, Algorithm: "rsa-sha256"})
	msg := sampleMessage("example.com")
	signed, err := signer.Sign(context.Background(), msg, "example.com")
	if err != nil {
		t.Fatalf("签名: %v", err)
	}
	if !strings.HasPrefix(string(signed), "DKIM-Signature:") {
		t.Fatal("签名输出应以 DKIM-Signature 头起始")
	}
	if !strings.HasSuffix(string(signed), string(msg)) {
		t.Fatal("签名输出应保留原消息尾部完整")
	}
	if len(signed) <= len(msg) {
		t.Fatal("签名输出应长于原消息")
	}
}
