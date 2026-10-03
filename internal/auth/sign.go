// auth 出站 DKIM 签名器：键加载（PEM）+ raven 签名 + DKIM-Signature 头前置组装。
// 依据：SRS FR-008（发信时系统执行 DKIM 签名）；
// 模块接口契约 v1.0.0 2.2 节（Signer 签名逐字落地，compile-time 断言锁定）；
// 用户裁决 Q1-A（2026-09-17 02:08:38）：config.json 扩展 selector/私钥路径/算法，
// U3 实现键加载+签名，阶段二 transport 仅接管证书；
// rfc8301（rsa-sha256 现行档）/rfc8463（ed25519-sha256）——RFC 库 04 类。
// 修改历史：
//
//	2026-09-17 02:44:00 | 新建 | U3 auth 基础（计划书步骤 7，Q1-A 落码）
//	2026-09-29 17:20:00 | 修正 | RFC候选修正批次 RF-G：F-A4 RSA 私钥位长下限校验（rfc8301 §3——Signers MUST ≥1024 bits，启动期/热重载期双路径拒绝）
package auth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"

	"GRmail/internal/config"

	ravendkim "github.com/synqronlabs/raven/dkim"
)

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrKeyNotConfigured DKIM 签名未配置（selector/私钥路径/算法任一为空——Q1-A 缺省零值态；
	// 签名失败显式报错，不静默跳过：FR-008 判定要求发信必签名）
	ErrKeyNotConfigured = errors.New("auth: DKIM 签名未配置")
	// ErrKeyUnreadable 私钥文件不可读或 PEM 解析失败
	ErrKeyUnreadable = errors.New("auth: DKIM 私钥不可读")
	// ErrAlgorithmMismatch 配置算法与私钥类型不符（如 rsa-sha256 配了 ed25519 键）
	ErrAlgorithmMismatch = errors.New("auth: DKIM 算法与私钥类型不符")
	// ErrUnsupportedAlgorithm 配置算法不在支持集（rsa-sha256|ed25519-sha256）
	ErrUnsupportedAlgorithm = errors.New("auth: DKIM 算法不支持")
	// ErrKeyTooWeak RSA 私钥位长低于规范下限（RF-G/F-A4——rfc8301 §3
	// 「Signers MUST use RSA keys of at least 1024 bits for all keys」）
	ErrKeyTooWeak = errors.New("auth: DKIM RSA 私钥位长不足")
)

// minRSAKeyBits RSA 私钥位长下限（rfc8301 §3——Signers MUST ≥1024 bits）。
const minRSAKeyBits = 1024

// ───────────────────────── 契约接口（模块接口契约 2.2 逐字） ─────────────────────────

// Signer 出站签名（DKIM，键管理 transport 域——阶段二仅接管证书，键经 Q1-A 裁决归本实现）。
type Signer interface {
	Sign(ctx context.Context, msg []byte, domain string) (signed []byte, err error)
}

// ───────────────────────── 签名器服务 ─────────────────────────

// SignerService DKIM 出站签名域服务（U5 提交管道注入消费）。
type SignerService struct {
	mu      sync.RWMutex
	conf    config.DKIMConf
	key     crypto.Signer // 已解析私钥（构造时加载；配置变更经 OnConfigChange 重载）
	keyAlgo string        // 私钥实际类型（"rsa"|"ed25519"）
}

// NewSignerService 构造签名器并加载私钥。
// 参数：conf DKIM 配置（Q1-A）。返回：服务实例；未配置返回 ErrKeyNotConfigured；
// 私钥不可读/算法不符返回对应哨兵（启动期显式失败，禁止带病运行）。
func NewSignerService(conf config.DKIMConf) (*SignerService, error) {
	s := &SignerService{conf: conf}
	if err := s.reloadKey(); err != nil {
		return nil, err
	}
	return s, nil
}

// 编译期断言：契约接口实现锁定 + config.Subscriber 实现
var (
	_ Signer            = (*SignerService)(nil)
	_ config.Subscriber = (*SignerService)(nil)
)

// reloadKey 按当前 conf 加载私钥（读文件→PEM 解析→算法校验）。
// 返回：ErrKeyNotConfigured / ErrKeyUnreadable / ErrAlgorithmMismatch / ErrUnsupportedAlgorithm。
func (s *SignerService) reloadKey() error {
	c := s.conf
	if c.Selector == "" || c.KeyPath == "" || c.Algorithm == "" {
		return ErrKeyNotConfigured
	}
	data, err := os.ReadFile(c.KeyPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyUnreadable, err)
	}
	key, algo, err := parsePrivateKeyPEM(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyUnreadable, err)
	}
	want := ""
	switch c.Algorithm {
	case "rsa-sha256":
		want = "rsa"
	case "ed25519-sha256":
		want = "ed25519"
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, c.Algorithm)
	}
	if algo != want {
		return fmt.Errorf("%w: 配置 %s 但私钥为 %s", ErrAlgorithmMismatch, c.Algorithm, algo)
	}
	// RF-G/F-A4：RSA 私钥位长下限校验（rfc8301 §3——弱密钥双路径拒绝：
	// 构造期 NewSignerService 与热重载 OnConfigChange 均经本函数）
	if rsaKey, isRSA := key.(*rsa.PrivateKey); isRSA && rsaKey.N.BitLen() < minRSAKeyBits {
		return fmt.Errorf("%w: %d 位 < 下限 %d 位（rfc8301 §3）", ErrKeyTooWeak, rsaKey.N.BitLen(), minRSAKeyBits)
	}
	s.key, s.keyAlgo = key, algo
	return nil
}

// parsePrivateKeyPEM 解析 PEM 私钥（支持 PKCS#1 RSA / PKCS#8 RSA·Ed25519）。
// 参数：data PEM 文件内容。返回：私钥；类型（"rsa"|"ed25519"）。
func parsePrivateKeyPEM(data []byte) (crypto.Signer, string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", errors.New("非 PEM 格式")
	}
	switch block.Type {
	case "RSA PRIVATE KEY": // PKCS#1
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		return key, "rsa", nil
	case "PRIVATE KEY": // PKCS#8（RSA 或 Ed25519）
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, "rsa", nil
		case ed25519.PrivateKey:
			return k, "ed25519", nil
		default:
			return nil, "", fmt.Errorf("不支持的私钥类型 %T", key)
		}
	default:
		return nil, "", fmt.Errorf("不支持的 PEM 块类型 %q", block.Type)
	}
}

// OnConfigChange 实现 config.Subscriber（CON-003 订阅侧）：
// DKIMConf 变更时重载（selector/算法即时生效；KeyPath 变更重读键——
// 重载失败保留旧键并返回错误告警语义，禁止半配置态）。
func (s *SignerService) OnConfigChange(newCfg *config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conf = newCfg.Auth.DKIM
	err := s.reloadKey()
	switch {
	case err == nil:
		return // 重载成功，新键生效
	case errors.Is(err, ErrKeyNotConfigured):
		s.key = nil // 显式清空配置：签名进入未配置态（后续 Sign 显式报错）
	default:
		// 键重载失败：保留旧键（订阅回调约定：错误仅记录告警——config.Subscriber 注释）；
		// 失败原因经日志输出，下一轮变更重试
		fmt.Fprintf(os.Stderr, "auth: DKIM 键热重载失败，保留旧键: %v\n", err)
	}
}

// Sign 对完整 RFC5322 消息执行 DKIM 签名（FR-008：发信必签名）。
// raven Signer 产出 DKIM-Signature 头后前置注入原消息（relaxed/relaxed 规范化、
// sha256 哈希——rfc8301 现行档；签名头集取 raven DefaultSignedHeaders）。
// 参数：ctx 上下文；msg 完整消息字节；domain 签名域（d= 标签，U5 以发件身份域传入）。
// 返回：签名后完整消息（DKIM-Signature 头 + 原消息）；未配置/键缺失返回显式错误。
func (s *SignerService) Sign(ctx context.Context, msg []byte, domain string) ([]byte, error) {
	s.mu.RLock()
	conf, key := s.conf, s.key
	s.mu.RUnlock()
	if key == nil {
		return nil, ErrKeyNotConfigured
	}
	signer := &ravendkim.Signer{
		Domain:                 domain,
		Selector:               conf.Selector,
		PrivateKey:             key,
		Hash:                   "sha256",
		HeaderCanonicalization: ravendkim.CanonRelaxed,
		BodyCanonicalization:   ravendkim.CanonRelaxed,
	}
	header, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("auth: DKIM 签名失败: %w", err)
	}
	// 实测修正（2026-09-17 02:46 定位）：raven Signer.Sign 返回的头已自带 \r\n 结尾，
	// 此处不得再补 CRLF——双 CRLF 会在头与消息间插入空行，破坏 bh/b= 覆盖的字节流
	// （症状：验证器报 crypto/rsa: verification error）。
	signed := make([]byte, 0, len(header)+len(msg))
	signed = append(signed, header...)
	signed = append(signed, msg...)
	return signed, nil
}
