// Package transport 追加 ACME 证书管理：Let's Encrypt 类 CA 自动签发与续期（HTTP-01）。
// 依据：U10 计划书 v1.0.0 步骤 4（裁决 Q5-A/Q6-A，G2 批准 2026-09-20 00:32:33）——
// 签发/续期产物原子落盘 data/certs/<domain>/{fullchain,privkey}.pem 并经回调回写
// config.json TLS 路径（全程复用 TLSManager 既有双热重载链路：OnConfigChange+WatchCertFiles，
// 零 TLSManager 新接口）；续期=常驻 goroutine 每日 tick，剩余有效期<30 天触发（lego 惯例窗口）；
// rfc8314 §4.4「MSP MUST maintain valid server certificates」政策依据。
// 协议承载：rfc8555 未入 RFC 库（110 份清单核验）——ACME 协议细节由 lego v4.35.2 承载
// （选型 #12/Q9-A）；lego API 形态经 go doc 实测落档 U10 修改文档第三章（计划书 1.5⑬）：
// challenge.Provider={Present,CleanUp}、registration.User 三方法、certificate.Resource
// 字段 PEM 直落盘、SetHTTP01Provider 注入自研 provider（80 挑战由 web 路由直答——端口共用零冲突）。
// 依赖方向：transport→{config,observability}（架构第四章合法；不 import web——token 表经
// Store() 暴露由 main 装配桥接 web 挑战路由）。
// U13（G2 批准 2026-09-23 08:19:32；Q3-A 裁决）：签发域名清单扩展——MTA-STS 启用时
// 增 mta-sts.<主域>（SAN 覆盖策略宿主——rfc8461 §3.3 证书有效性前提；HTTP-01 对
// 两域名分别挑战，80 挑战路由全站既有承载零新增设施）；清单经 stsEnabled 快照注入
// （热加载——关闭 MTA-STS 后下一次续期收窄为单域）。
// 修改历史：
//
//	2026-09-20 00:48:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 4）
//	2026-09-23 08:50:00 | 扩展 | U13 传输安全全量：域名清单扩展（计划书步骤 8/1.5④）
package transport

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"

	"GRmail/internal/config"
	"GRmail/internal/observability"
)

// renewWindow 续期触发窗口（Q6-A：剩余有效期<30 天；工程常量，G2 批复生效）
const renewWindow = 30 * 24 * time.Hour

// renewTickInterval 续期检查周期（每日一次；真签发/续期动作仅在窗口内触发）
const renewTickInterval = 24 * time.Hour

// ChallengeStore ACME HTTP-01 挑战 token 内存表（challenge.Provider 实现）。
// Present 由 lego 在授权期回调存入 token→keyAuth 映射；web 80 端口挑战路由经
// Lookup 按 token 直答 keyAuth（/.well-known/acme-challenge/{token}——rfc8555
// HTTP-01 资源语义，经 lego 承载）；CleanUp 授权完成后清除。
type ChallengeStore struct {
	mu   sync.RWMutex
	vals map[string]string // token → keyAuth
}

// Present 实现 challenge.Provider：存入挑战应答值。
// 参数：domain/_ 授权域名（单域部署未用）；token 挑战令牌；keyAuth 应答正文。
func (s *ChallengeStore) Present(_, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vals[token] = keyAuth
	return nil
}

// CleanUp 实现 challenge.Provider：清除挑战应答值。
func (s *ChallengeStore) CleanUp(_, token, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.vals, token)
	return nil
}

// Lookup 挑战路由查询：按 token 取应答正文。
// 参数：token 挑战令牌。返回：keyAuth 与存在性（不存在由调用方 404）。
func (s *ChallengeStore) Lookup(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.vals[token]
	return v, ok
}

// acmeUser ACME 账户身份（registration.User 实现——lego 实测三方法）。
type acmeUser struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ACMEManager ACME 签发与续期管理器（Q6-A 落盘回写链承载）。
// 生命周期：NewACMEManager（无 IO）→ main 桥接 Store() 至 web 挑战路由 →
// Setup 第六步完成后 EnsureIssued 首签（异步）→ Run 每日 tick 续期。
type ACMEManager struct {
	domain       string
	confSnapshot func() config.ACMEConf               // 配置快照（热加载；CADirURL 变更重启生效——client 构造期绑定）
	saveTLSPaths func(certFile, keyFile string) error // 回写 config.json TLS 路径（main 注入：Current→改→Save→Watcher 广播→TLSManager 重载）
	stsEnabled   func() bool                          // U13：MTA-STS 开关快照（清单扩展判定；nil=恒 false——单域既有形态）
	store        *ChallengeStore
}

// NewACMEManager 构造 ACME 管理器。
// 参数：domain 主域名（签发目标，Setup 第三步落定）；confSnapshot ACME 配置快照函数；
// saveTLSPaths 证书路径回写回调（nil=不回写——测试/手动模式场景）。
// 可选注入：SetStsEnabled（U13——MTA-STS 开关快照；未注入=单域既有形态，测试零适配）。
func NewACMEManager(domain string, confSnapshot func() config.ACMEConf, saveTLSPaths func(certFile, keyFile string) error) *ACMEManager {
	return &ACMEManager{
		domain:       domain,
		confSnapshot: confSnapshot,
		saveTLSPaths: saveTLSPaths,
		store:        &ChallengeStore{vals: make(map[string]string)},
	}
}

// SetStsEnabled 注入 MTA-STS 开关快照（U13 Q3-A——清单扩展判定；main 装配期调用一次）。
// 参数：enabled 快照函数（返回 true 时签发/续期清单含 mta-sts.<主域>）。
func (m *ACMEManager) SetStsEnabled(enabled func() bool) { m.stsEnabled = enabled }

// certificateDomains 签发域名清单（U13：MTA-STS 启用→[主域, mta-sts.主域]——SAN 覆盖
// 策略宿主；禁用→单域既有形态）。
func (m *ACMEManager) certificateDomains() []string {
	if m.stsEnabled != nil && m.stsEnabled() {
		return []string{m.domain, STSPolicyHost(m.domain)}
	}
	return []string{m.domain}
}

// Store 暴露挑战表（main 桥接 web 80 挑战路由）。
func (m *ACMEManager) Store() *ChallengeStore { return m.store }

// EnsureIssued 确保证书存在（不存在即签发；已存在且未到窗口则跳过）。
// Setup 第六步完成后异步调用；内部复用 needsRenewal 判定避免重复签发。
// 参数：ctx 取消上下文（日志）。返回：签发/落盘/回写任一失败的原样错误（调用方记日志，
// 每日 tick 会重试——计划书 1.5⑥ 重试语义）。
func (m *ACMEManager) EnsureIssued(ctx context.Context) error {
	conf := m.confSnapshot()
	if !conf.Enabled {
		return nil // 手动模式（Q5-A 双模式之另一态——证书经向导手动导入路径）
	}
	if !m.needsRenewal(conf) {
		return nil
	}
	return m.obtain(ctx, conf)
}

// Run 续期循环：每日 tick 检查剩余窗口（<30 天触发重签）；ctx 取消即退出。
// 手动模式（Enabled=false）下空转（零网络动作——热加载切回自动模式下一 tick 生效）。
func (m *ACMEManager) Run(ctx context.Context) {
	logger := observability.LoggerFromContext(ctx)
	ticker := time.NewTicker(renewTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conf := m.confSnapshot()
			if !conf.Enabled {
				continue
			}
			if !m.needsRenewal(conf) {
				continue
			}
			if err := m.obtain(ctx, conf); err != nil {
				logger.Error("ACME 续期失败（下一 tick 重试）", "error", err, "domain", m.domain)
				continue
			}
			logger.Info("ACME 续期完成", "domain", m.domain)
		}
	}
}

// obtain 签发全链：账户密钥加载/生成 → 客户端构造（目录端点构造期绑定）→
// 账户注册/解析 → HTTP-01 provider 注入 → Obtain → 落盘 → 回写。
func (m *ACMEManager) obtain(ctx context.Context, conf config.ACMEConf) error {
	logger := observability.LoggerFromContext(ctx)

	key, err := m.loadOrCreateAccountKey(conf.AccountKeyPath)
	if err != nil {
		return fmt.Errorf("ACME 账户密钥: %w", err)
	}
	user := &acmeUser{email: conf.Email, key: key}

	dirURL := conf.CADirURL
	if dirURL == "" {
		dirURL = config.ACMEDirectoryProduction // 零值兜底（旧配置兼容）
	}
	if conf.Staging {
		dirURL = config.ACMEDirectoryStaging // staging 覆盖（测试签发——计划书 1.5⑥）
	}
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = dirURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("ACME 客户端构造: %w", err)
	}
	// 挑战模式注入（D8#12——FR-015 判定标准「HTTP-01/DNS-01」双模式；S4-W Q1-A
	// 裁决仅 Cloudflare：lego providers/dns/cloudflare API Token 凭证形态，DNS-01
	// 免 80 端口依赖〔txt 记录经提供商 API 写删——挑战生命周期由 lego 承载〕；
	// DNSProvider 空=HTTP-01 既有缺省——80 挑战路由承载不变）
	if conf.DNSProvider == "cloudflare" {
		if conf.DNSApiToken == "" {
			return fmt.Errorf("DNS-01（cloudflare）缺少 dnsApiToken 凭证（config.json acme 节）")
		}
		dnsCfg := cloudflare.NewDefaultConfig()
		dnsCfg.AuthToken = conf.DNSApiToken
		provider, err := cloudflare.NewDNSProviderConfig(dnsCfg)
		if err != nil {
			return fmt.Errorf("Cloudflare DNS provider 构造: %w", err)
		}
		if err := client.Challenge.SetDNS01Provider(provider); err != nil {
			return fmt.Errorf("DNS-01 provider 注入: %w", err)
		}
	} else if err := client.Challenge.SetHTTP01Provider(m.store); err != nil {
		return fmt.Errorf("HTTP-01 provider 注入: %w", err)
	}

	// 账户注册：优先解析既有账户（密钥复用），失败回退注册（TermsOfServiceAgreed）
	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("ACME 账户注册: %w", err)
		}
	}
	user.reg = reg

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: m.certificateDomains(), // U13：MTA-STS 启用时含 mta-sts.<主域>（Q3-A）
		Bundle:  true,                   // fullchain 捆绑（PEM 直落盘——certificate.Resource 实测语义）
	})
	if err != nil {
		return fmt.Errorf("ACME 证书签发: %w", err)
	}

	certFile, keyFile, err := m.persistCert(conf, res)
	if err != nil {
		return err
	}
	logger.Info("ACME 证书已签发并落盘", "domain", m.domain, "cert", certFile)

	if m.saveTLSPaths != nil {
		if err := m.saveTLSPaths(certFile, keyFile); err != nil {
			// 落盘成功但回写失败：证书文件在位（TLSManager 下次重启/路径变更时拾取），
			// 返回错误促上层记录并由 tick 重试（重复签发前 needsRenewal 先生效——回写成功前 NotAfter 未到窗口会跳过重签，
			// 极端窗口内重复签发受 CA 配额限制可容忍，登记修改文档第三章）
			return fmt.Errorf("回写 config.json TLS 路径: %w", err)
		}
	}
	return nil
}

// persistCert 证书产物原子落盘（Q6-A：<CertsDir>/<domain>/{fullchain,privkey}.pem，0600）。
// 返回：证书/私钥文件路径（回写 config.json 用）。
func (m *ACMEManager) persistCert(conf config.ACMEConf, res *certificate.Resource) (string, string, error) {
	dir := conf.CertsDir
	if dir == "" {
		dir = "data/certs" // 零值兜底
	}
	certDir := filepath.Join(dir, m.domain)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", "", fmt.Errorf("创建证书目录: %w", err)
	}
	certFile := filepath.Join(certDir, "fullchain.pem")
	keyFile := filepath.Join(certDir, "privkey.pem")
	if err := writeFileAtomic(certFile, res.Certificate); err != nil {
		return "", "", fmt.Errorf("落盘证书: %w", err)
	}
	if err := writeFileAtomic(keyFile, res.PrivateKey); err != nil {
		return "", "", fmt.Errorf("落盘私钥: %w", err)
	}
	return certFile, keyFile, nil
}

// writeFileAtomic 原子写（临时文件+rename——沿 config.Save 同语义，崩溃安全）。
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// needsRenewal 续期判定：证书缺失=true（待首签/补签）；解析失败=true（重签自愈）；
// 剩余有效期<30 天=true（Q6-A 窗口）。
func (m *ACMEManager) needsRenewal(conf config.ACMEConf) bool {
	dir := conf.CertsDir
	if dir == "" {
		dir = "data/certs"
	}
	certFile := filepath.Join(dir, m.domain, "fullchain.pem")
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return true // 缺失→需要签发
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return true // 损坏→重签自愈
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < renewWindow
}

// loadOrCreateAccountKey ACME 账户私钥持久化（ECDSA P-256；存在即加载，缺失即生成落盘）。
// 参数：path 密钥文件路径（缺省档 data/certs/acme-account.key 由 Default 提供；空值兜底同值）。
// 返回：私钥；生成/解析/落盘失败返回 error（签发前置失败——调用方记日志重试）。
func (m *ACMEManager) loadOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	if path == "" {
		path = "data/certs/acme-account.key"
	}
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("ACME 账户密钥 PEM 损坏")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取 ACME 账户密钥: %w", err)
	}
	// 生成新密钥并落盘（目录保障——首启场景）
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ACME 账户密钥: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("序列化 ACME 账户密钥: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建 ACME 密钥目录: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(path, pemData); err != nil {
		return nil, fmt.Errorf("落盘 ACME 账户密钥: %w", err)
	}
	slog.Default().Info("ACME 账户密钥已生成", "path", path)
	return key, nil
}
