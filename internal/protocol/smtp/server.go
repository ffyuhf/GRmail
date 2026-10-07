// Package smtp 自研 SMTP 服务端（25 端口收信；Q4 裁决 2026-09-15 11:01:24：
// 收信管道/防丢信需字节级深度控制）。
// 依据：SRS v1.0.0 FR-005（收信侧）/CON-004/NFR-007；
// 模块接口契约 v1.1.0 2.3 节（InboundPipeline 注入）；
// 架构总览 v1.0.0 第三章（接入层仅协议编解码与会话管理，禁止业务逻辑——
// 投递判定经管道，应答码语义由管道返回值决定）＋第四章（smtp→mail 单向依赖）。
// 协议对照：draft-ietf-emailcore-rfc5321bis-44（命令集/顺序/限值/超时/点透明性）、
// rfc1870（SIZE）、rfc6152（8BITMIME）、rfc6531（SMTPUTF8）、rfc2920（PIPELINING）、
// rfc3463（ENHANCEDSTATUSCODES）——RFC 标准库索引 v1.1.0 01 类。
// U4 范围（Q3-B 裁决 2026-09-17 03:06:39）：明文收信，EHLO 不通告 STARTTLS
// （TLS 归 U10 证书就绪后统一挂载，NFR-006 闭环时点 U10）。
// U10 落地（Q8-A 裁决 2026-09-20 00:29，G2 批准含契约 v1.6.0 升版授权）：
// ServerConfig 增 TLSConfig 快照注入——证书就绪时 EHLO 通告 STARTTLS（rfc3207 §4.1/
// rfc8314 §4 L374-376）、可选升级不强制本地投递（rfc3207 §4 L129-136 公开引用服务器
// MUST NOT 条款——25 端口保持明文收信能力）。
// U21 增量（可观测性增强——H5 等价）：ServerConfig 增 ProtocolDebug 快照注入位+
// protocolDebug 快照读取方法（命令应答面 debug 条件输出——埋点归 session.go）。
// 修改历史：
//
//	2026-09-17 03:45:00 | 新建 | U4 SMTP 收信（计划书步骤 9）
//	2026-09-20 00:52:00 | 扩展 | U10 STARTTLS 收口：ServerConfig 增 TLSConfig（计划书步骤 5）
//	2026-09-27 06:19:00 | 扩展 | U21 可观测性增强：ProtocolDebug 注入位+快照方法
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 4）
package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// MailboxResolver RCPT 三态判定的账号查询窄接口（消费侧最小化；account.Service 满足）。
type MailboxResolver interface {
	GetMailbox(ctx context.Context, addr string) (*storage.Mailbox, error)
}

// ServerConfig SMTP 服务端配置（快照函数承载热加载语义——U4 计划书 1.5⑪：
// MaxMessageSize 每连接读取快照生效；Domain/端口启动期绑定）。
type ServerConfig struct {
	Domain          string             // 主域名（横幅/本域 RCPT 判定）
	MaxMessageSize  func() int64       // SIZE 通告与 DATA 超限阈值（快照，Q2-A；nil=35MiB 缺省档）
	CatchAllEnabled func() bool        // FR-003 条件开关快照（nil=true 缺省）
	MaxRecipients   int                // 单信 RCPT 上限（rfc5321bis 4.5.3.1 建议值 100；0=100）
	TLSConfig       func() *tls.Config // 服务端 TLS 快照（U10 Q8-A；nil 或返回 nil=证书未就绪——
	// EHLO 不通告 STARTTLS 且 STARTTLS 命令 454，明文收信照常——rfc3207 §4/§4.1 与
	// rfc8314 §4 L374-376「无证书 SHOULD NOT 通告」；旧装配形态零行为变化）
	ProtocolDebug func() bool // 协议 debug 快照（U21——config Log.ProtocolDebug；nil=false 缺省热生效）
}

// protocolDebug 协议 debug 快照读取（U21；nil 注入=禁用——缺省零输出零行为变化）。
func (s *Server) protocolDebug() bool {
	return s.cfg.ProtocolDebug != nil && s.cfg.ProtocolDebug()
}

// Server SMTP 收信服务端（单监听多连接；接入层零业务逻辑——投递编排全在管道侧）。
type Server struct {
	cfg      ServerConfig
	pipeline mail.InboundPipeline // 收信管道注入（契约 v1.1.0 2.3；架构第四章 smtp→mail 单向依赖）
	accounts MailboxResolver

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

// NewServer 构造 SMTP 服务端。
// 参数：cfg 服务端配置；pipeline 收信管道（注入）；accounts 邮箱查询（RCPT 三态判定）。
func NewServer(cfg ServerConfig, pipeline mail.InboundPipeline, accounts MailboxResolver) *Server {
	if cfg.MaxMessageSize == nil {
		cfg.MaxMessageSize = func() int64 { return 36700160 } // 35MiB（Q2-A 缺省档兜底）
	}
	if cfg.CatchAllEnabled == nil {
		cfg.CatchAllEnabled = func() bool { return true }
	}
	if cfg.MaxRecipients <= 0 {
		cfg.MaxRecipients = 100 // rfc5321bis 4.5.3.1.6
	}
	return &Server{cfg: cfg, pipeline: pipeline, accounts: accounts, conns: make(map[net.Conn]struct{})}
}

// ListenAndServe 监听并循环接受连接（阻塞直至 Shutdown 或监听器关闭）。
// 参数：addr 监听地址（如 ":25"）。返回：监听或接受阶段的不可恢复错误。
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SMTP 监听失败: %w", err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("SMTP 服务端已关闭")
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil // Shutdown 触发的关闭：正常退出
			}
			return fmt.Errorf("SMTP 接受连接: %w", err)
		}
		// F8（访问协议资源限制批）：连接上限——复用 track 登记集判定（锁内
		// 长度判定+登记原子完成，避免独立计数器与登记集双源漂移）；超限即时
		// 关闭（NFR-002 资源面防御，256/端点档）。
		s.mu.Lock()
		overLimit := len(s.conns) >= smtpMaxConns
		if !overLimit {
			s.conns[conn] = struct{}{}
		}
		s.mu.Unlock()
		if overLimit {
			_ = conn.Close()
			slog.Warn("SMTP 连接超上限拒绝", "max", smtpMaxConns, "remote", conn.RemoteAddr().String())
			continue
		}
		go func() {
			defer s.track(conn, false)
			s.serveConn(conn) // 每连接一会话（状态机见 session.go）
		}()
	}
}

// smtpMaxConns 单端点连接数上限（F8——NFR-002：连接风暴下 goroutine/内存
// 无界防御；单管理员自托管+512MB 场景 256/端点最坏 ~15MB 受控）。
const smtpMaxConns = 256

// Shutdown 优雅停止：关闭监听器与全部活动连接（先停新连接再收口旧连接）。
func (s *Server) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.ln != nil {
		if err := s.ln.Close(); err != nil {
			return fmt.Errorf("关闭 SMTP 监听: %w", err)
		}
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
	return nil
}

// track 连接登记/注销（Shutdown 收口用）。
func (s *Server) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
		return
	}
	delete(s.conns, conn)
}
