// auth 出站 DKIM 签名器：键加载（PEM）+ raven 签名 + DKIM-Signature 头前置组装。
// 依据：SRS FR-008（发信时系统执行 DKIM 签名）；
// 模块接口契约 v1.37.0 2.2 节（Signer 签名逐字落地，compile-time 断言锁定）；
// 用户裁决 Q1-A（2026-09-17 02:08:38）：config.json 扩展 selector/私钥路径/算法，
// U3 实现键加载+签名，阶段二 transport 仅接管证书；
// rfc8301（rsa-sha256 现行档）/rfc8463（ed25519-sha256）——RFC 库 04 类。
// 修改历史：
//
//	2026-09-17 02:44:00 | 新建 | U3 auth 基础（计划书步骤 7，Q1-A 落码）
//	2026-09-29 17:20:00 | 修正 | RFC候选修正批次 RF-G：F-A4 RSA 私钥位长下限校验（rfc8301 §3——Signers MUST ≥1024 bits，启动期/热重载期双路径拒绝）
//	2026-10-04 15:05:00 | 扩展 | 向导占位符与布局修复批次：GenerateDKIMKeyPair/DKIMPublicKeyDNSValue
//	（Setup 向导步 3 密钥生成+步 4 公钥呈现——FR-015「无需手工编辑任何配置文件」收口；
//	强度四档干系人裁决 2026-10-04 15:01 三a；SPKI 公钥格式裁决六a；依据：向导占位符与
//	布局修复计划书 v1.0.0 1.2-DKIM 组，G2 批准 2026-10-04 15:03:25；SRS FR-008/FR-015）
//	2026-10-08 13:10:00 | 修正 | 文档治理批 C1：头注契约版本引用刷新 v1.0.0→v1.37.0（注释漂移收口；纯注释零行为变更）
package auth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
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
	// B-S批 F9①：私钥文件权限校验——组/其他可读写（mode&0o066≠0）即告警（告警不
	// 拒绝：umask 环境差异容忍+管理员自治；rfc6376 §6 键保密义务的运维提示面）
	if fi, serr := os.Stat(c.KeyPath); serr == nil && fi.Mode().Perm()&0o066 != 0 {
		slog.Warn("DKIM 私钥文件权限过宽（建议 0600）",
			"path", c.KeyPath, "mode", fi.Mode().Perm().String())
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
		// 失败原因经结构化日志输出（B-S批 F9③——原 fmt.Fprintf(os.Stderr) 绕过
		// slog 装配，LogID 链断；热重载为全局事件无请求 ctx，走默认 logger——
		// observability.SetupLogger 已 SetDefault）下一轮变更重试
		slog.Warn("auth: DKIM 键热重载失败，保留旧键", "error", err)
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

// ───────────────────────── 向导密钥生成（向导占位符与布局修复批次） ─────────────────────────

// DKIMStrengths 向导密钥强度档位（干系人裁决 2026-10-04 15:01 三a——四档，
// rsa-2048 缺省；rsa 档位为位长、ed25519 为固定曲线）。
var DKIMStrengths = []string{"rsa-2048", "rsa-3072", "rsa-4096", "ed25519"}

// DefaultDKIMStrength 缺省强度档（三a裁决）。
const DefaultDKIMStrength = "rsa-2048"

// GenerateDKIMKeyPair 按强度档生成 DKIM 密钥对（Setup 向导步 3 消费——FR-015
// 判定标准「无需手工编辑任何配置文件」收口：密钥原需管理员 openssl 手工生成）。
// 参数：strength 档位（DKIMStrengths 值域，非法值返回 ErrUnsupportedAlgorithm）。
// 返回：私钥 PKCS#8 PEM（parsePrivateKeyPEM/reloadKey 消费兼容——同格式闭环）；
// 公钥 DNS TXT 值（v=DKIM1; k=rsa|ed25519; p=Base64(SPKI)——rfc6376 §3.6.1，
// SPKI 格式对齐 Gmail/Fastmail 同构，裁决六a）；算法标识（config.DKIMConf.Algorithm
// 写入值：rsa-sha256|ed25519-sha256）。
func GenerateDKIMKeyPair(strength string) (privPEM []byte, dnsTXT string, algorithm string, err error) {
	var signer crypto.Signer
	var spki any
	ktag := ""
	switch strength {
	case "rsa-2048", "rsa-3072", "rsa-4096":
		bits := map[string]int{"rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096}[strength]
		key, gerr := rsa.GenerateKey(rand.Reader, bits)
		if gerr != nil {
			return nil, "", "", fmt.Errorf("auth: RSA %d 密钥生成失败: %w", bits, gerr)
		}
		signer, spki, ktag, algorithm = key, &key.PublicKey, "rsa", "rsa-sha256"
	case "ed25519":
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, "", "", fmt.Errorf("auth: Ed25519 密钥生成失败: %w", gerr)
		}
		signer, spki, ktag, algorithm = priv, priv.Public(), "ed25519", "ed25519-sha256"
	default:
		return nil, "", "", fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, strength)
	}
	der, merr := x509.MarshalPKCS8PrivateKey(signer)
	if merr != nil {
		return nil, "", "", fmt.Errorf("auth: PKCS#8 编码失败: %w", merr)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	txt, terr := DKIMDNSTXTFromPublic(spki, ktag)
	if terr != nil {
		return nil, "", "", terr
	}
	return privPEM, txt, algorithm, nil
}

// DKIMDNSTXTFromPublic 公钥 → DNS TXT 值（v=DKIM1; k=<tag>; p=<Base64(SPKI)>）。
// 参数：pub crypto.PublicKey（*rsa.PublicKey 或 ed25519.PublicKey）；ktag "rsa"|"ed25519"。
func DKIMDNSTXTFromPublic(pub any, ktag string) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("auth: 公钥 SPKI 编码失败: %w", err)
	}
	return "v=DKIM1; k=" + ktag + "; p=" + base64.StdEncoding.EncodeToString(der), nil
}

// DKIMPublicKeyDNSValue 读既有私钥文件构造公钥 DNS TXT 值（向导步 4 呈现——
// 设置页换键后 DNS 建议按 config 现值呈现，1.3-4 边界）。
// 参数：keyPath 私钥 PEM 路径（空=未配置）。返回：DNS TXT 值；未配置返回空串
// （调用方该记录行不呈现——无占位语义）；不可读/类型不支持返回错误。
func DKIMPublicKeyDNSValue(keyPath string) (string, error) {
	if keyPath == "" {
		return "", nil
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyUnreadable, err)
	}
	key, algo, err := parsePrivateKeyPEM(data)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeyUnreadable, err)
	}
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		return "", fmt.Errorf("auth: 不支持的私钥类型 %T", key)
	}
	return DKIMDNSTXTFromPublic(pub, algo)
}
