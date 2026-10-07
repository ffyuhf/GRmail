// Package transport 实现传输安全基础设施：TLS 配置中心最小集（证书加载、
// 入站/出站 tls.Config 构造、证书热重载）。MTA-STS/TLS-RPT/DANE 与 ACME 证书
// 管理归阶段二/U10（架构总览第三章 transport 条目「阶段二全量」的分批落地）。
// 依据：U5 计划书 v1.0.0 步骤 4（Q2-A 裁决 2026-09-17 11:28:56：提交端口 TLS
// 全量一步到位——465 隐式 TLS/587 STARTTLS；手动证书路径即可用，ACME 归 U10）；
// rfc8314 4 节「MUST support TLS 1.2 or later」；rfc3207 4.1（服务器无证书配置
// 不应通告 STARTTLS——本包 Ready() 为该判定的唯一依据）；CON-003 订阅者清单
// 「TLS 重建」（架构总览 5.2）。
// 修改历史：
//
//	2026-09-17 11:48:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 4）
//	2026-10-07 15:35:00 | 修正 | 传输安全合规批 F8③（B-T3）：OnConfigChange 换路径
//	后重建证书监听（原 watcher 绑定初始目录——新路径文件替换不热重载收口；
//	G2 批准 2026-10-07 15:13:06）
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"GRmail/internal/config"
)

// TLSManager TLS 证书中心：持有服务端证书并构造入站/出站 TLS 配置。
// 生命周期：NewTLSManager（初始加载，未配置证书返回未就绪态不报错）→
// 订阅 config.Watcher（路径变更重载）→ WatchCertFiles（证书文件替换热重载）。
type TLSManager struct {
	mu       sync.RWMutex
	cert     *tls.Certificate // 当前服务端证书（Ready 判定依据）
	certPath string
	keyPath  string
	watcher  *fsnotify.Watcher
	// watchCtx F8③（传输安全合规批）：首次 WatchCertFiles 注入的生命周期上下文
	// ——OnConfigChange 换路径重建监听时复用（事件循环取消联动）。
	watchCtx context.Context
	closed   bool
}

// NewTLSManager 构造 TLS 证书中心并尝试初始加载。
// 参数：conf TLS 配置（零值=未配置，返回未就绪管理器——调用方据此跳过 TLS 端点，
// U5 计划书 1.5⑫）。
// 返回：管理器；证书已配置但加载失败时返回错误（启动期 fail-fast）。
func NewTLSManager(conf config.TLSConf) (*TLSManager, error) {
	m := &TLSManager{certPath: conf.CertFile, keyPath: conf.KeyFile}
	if conf.CertFile == "" || conf.KeyFile == "" {
		return m, nil // 未配置：未就绪态合法（TLS 端点跳过+告警归调用方）
	}
	if err := m.load(); err != nil {
		return nil, fmt.Errorf("初始证书加载: %w", err)
	}
	return m, nil
}

// load 从当前路径加载证书对（调用方持写锁或初始化期单线程）。
func (m *TLSManager) load() error {
	cert, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return err
	}
	m.cert = &cert
	return nil
}

// Ready 证书是否就绪（STARTTLS 通告与 465 端点启动的判定依据，rfc3207 4.1）。
func (m *TLSManager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert != nil
}

// ServerTLSConfig 构造入站服务端 TLS 配置（465 隐式包裹与 587 STARTTLS 升级共用）。
// 参数：serverName 证书 ServerName（主域名）；未就绪时返回 nil（调用方禁止通告/启动 TLS）。
func (m *TLSManager) ServerTLSConfig(serverName string) *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*m.cert},
		MinVersion:   tls.VersionTLS12, // rfc8314 4：MUST TLS1.2+（自动含 TLS1.3 能力，NFR-006）
		ServerName:   serverName,
	}
}

// ClientTLSConfig 构造出站投递客户端 TLS 配置（验证对端：系统根 CA+MX 主机名，
// U5 计划书 1.5⑤ Opportunistic TLS 策略的验证侧）。
func ClientTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// OnConfigChange 实现 config.Subscriber：config.json 中证书路径变更时重载。
// 新路径未配置（清空）时保持当前证书不卸载（运行中的 TLS 端点不中断，重启后收窄）。
func (m *TLSManager) OnConfigChange(newCfg *config.Config) {
	if newCfg == nil || newCfg.TLS.CertFile == "" || newCfg.TLS.KeyFile == "" {
		return
	}
	m.mu.Lock()
	samePath := newCfg.TLS.CertFile == m.certPath && newCfg.TLS.KeyFile == m.keyPath
	if samePath {
		m.mu.Unlock()
		return // 路径未变（证书文件本身的替换经 WatchCertFiles 收敛）
	}
	m.certPath = newCfg.TLS.CertFile
	m.keyPath = newCfg.TLS.KeyFile
	err := m.load()
	watchCtx := m.watchCtx
	m.mu.Unlock()
	if err != nil {
		slog.Default().Error("证书路径变更后重载失败，保持原证书", "error", err, "certFile", newCfg.TLS.CertFile)
		return
	}
	// F8③（B-T3）：路径变更后重建监听——原 watcher 绑定初始目录，新路径文件替换
	// 不触发事件（手动证书续期热重载在新路径下失效的原缺陷收口；锁外重建——
	// WatchCertFiles 自持锁）。
	if watchCtx != nil {
		m.rebuildWatcher(watchCtx)
	}
	slog.Default().Info("TLS 证书已按新路径重载", "certFile", newCfg.TLS.CertFile)
}

// rebuildWatcher 重建证书文件监听（F8③：Close 旧 watcher→按当前 certPath 重挂
// 新目录+重启事件循环；旧循环随 Events 通道关闭自然退出）。失败 Warn（重启生效兜底）。
// 参数：ctx 生命周期上下文（首次 WatchCertFiles 注入值）。
func (m *TLSManager) rebuildWatcher(ctx context.Context) {
	m.mu.Lock()
	old := m.watcher
	m.watcher = nil
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if err := m.WatchCertFiles(ctx); err != nil {
		slog.Default().Warn("证书监听重建失败（新路径文件替换暂不热重载——重启生效兜底）", "error", err)
	}
}

// WatchCertFiles 监听证书文件替换（手动证书续期场景：文件 rename 原子替换后
// 下一连接即用新证书——PMail 全景 D3 手动模式先例；ACME 自动续期归 U10）。
// 参数：ctx 生命周期上下文（取消即退出监听）。
func (m *TLSManager) WatchCertFiles(ctx context.Context) error {
	m.mu.Lock()
	if m.closed || m.certPath == "" {
		m.mu.Unlock()
		return nil // 未配置证书无需监听
	}
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("创建证书 fsnotify: %w", err)
	}
	m.watcher = fw
	m.watchCtx = ctx // F8③：记录生命周期上下文（OnConfigChange 换路径重建复用）
	m.mu.Unlock()

	// 监听证书所在目录（rename 替换 inode，目录监听才持续收事件——沿 config.Watch 同口径）
	if err := fw.Add(filepath.Dir(m.certPath)); err != nil {
		_ = fw.Close()
		return fmt.Errorf("监听证书目录: %w", err)
	}
	go m.certWatchLoop(ctx, fw)
	slog.Default().Info("证书文件热重载监听已启动", "dir", filepath.Dir(m.certPath))
	return nil
}

// certWatchLoop 证书文件事件循环：目标文件 Write/Create → 去抖 1s → 重载
func (m *TLSManager) certWatchLoop(ctx context.Context, fw *fsnotify.Watcher) {
	logger := slog.Default()
	target, _ := filepath.Abs(m.certPath)
	var debounce *time.Timer
	for {
		select {
		case <-ctx.Done():
			_ = fw.Close()
			return
		case event, ok := <-fw.Events:
			if !ok {
				return
			}
			eventPath, _ := filepath.Abs(event.Name)
			if eventPath != target || !(event.Has(fsnotify.Write) || event.Has(fsnotify.Create)) {
				continue
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(time.Second, func() { // 去抖：原子写双事件合并
				m.mu.Lock()
				err := m.load()
				m.mu.Unlock()
				if err != nil {
					logger.Error("证书热重载失败，保持原证书", "error", err)
					return
				}
				logger.Info("TLS 证书热重载完成", "certFile", m.certPath)
			})
		case err, ok := <-fw.Errors:
			if !ok {
				return
			}
			logger.Error("证书监听异常", "error", err)
		}
	}
}

// Close 停止证书监听（幂等）
func (m *TLSManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}
