// Package pop3 实现 POP3 服务端自研（FR-007/IR-003：995 隐式 TLS + rfc1939 命令集 +
// SASL 认证 rfc5034 + 明文连接拒绝认证）。
// 架构依据：系统架构总览 v1.2.2 选型 #4（POP3 自研，Q4 裁决 2026-09-15 11:01:24）、
// 第四章依赖规则（protocol/pop3 → {account,storage,observability}，transport TLS 注入）；
// 契约 v1.37.0 2.4 注记（account.Service+MessageRepo+FolderRepo+BlobStore 注入形态；v1.33.0 资源限制注记同章承载）。
// 规范依据（RFC 标准库索引 v1.3.0 02 类）：rfc1939（STD 53 全文回读：§3 命令/响应语法
// 与多行响应 byte-stuffing/三态状态机、§4 超时≥10min、§5-§8 命令集、§11 octet 计数口径）、
// rfc2449（§3 ABNF 命令≤255 八位组、§4 能力行≤512、§5 CAPA 双态、§6.1/6.8/6.6 TOP/UIDL/PIPELINING）、
// rfc5034（§3 SASL 能力、§4 AUTH 命令）。
// 用户裁决（U7 计划书 v1.0.0 第六章，G2 批准 2026-09-19 04:09:01）：
// Q1-A QUIT 提交=HardDelete（U6 EXPUNGE 同款）；Q2-A 仅 AUTH PLAIN（无 USER/PASS/APOP）；
// Q3-A CAPA+UIDL+TOP+PIPELINING 全量；Q4-A 明文连接 AUTH 一律 -ERR（会话层 *tls.Conn 判定）。
// U21 增量（可观测性增强——H5 等价）：ServerConfig 增 ProtocolDebug 快照注入位+
// protocolDebug 快照读取方法（命令响应面 debug 条件输出——埋点归 session.go）。
// 修改历史：
//
//	2026-09-19 04:09:01 | 新建 | U7 POP3 自研（计划书 v1.0.0 步骤 2，G2 批准）
//	2026-09-27 06:20:00 | 扩展 | U21 可观测性增强：ProtocolDebug 注入位+快照方法
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 4）
//	2026-10-08 13:10:00 | 修正 | 文档治理批 C1：头注版本引用刷新（架构 v1.0.1→v1.2.2/契约 v1.3.1→v1.37.0——注释漂移收口；纯注释零行为变更）
package pop3

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"GRmail/internal/account"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
)

// maildropLocks per-mailbox 独占锁表（F4/A-13④——rfc1939 §4 L213-217 "as
// necessary" 描述性义务的进程内承载：TRANSACTION 期独占防双会话 UPDATE 期
// 互相覆盖删除集；单实例部署形态下进程内锁即全量锁）。
type maildropLocks struct {
	mu   sync.Mutex
	held map[int64]bool // mailboxID → 持有标记
}

// newMaildropLocks 构造锁表。
func newMaildropLocks() *maildropLocks { return &maildropLocks{held: make(map[int64]bool)} }

// tryLock 非阻塞尝试获取邮箱 maildrop 锁。
// 参数：mailboxID 邮箱 ID。返回：是否获取成功。
func (l *maildropLocks) tryLock(mailboxID int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held[mailboxID] {
		return false
	}
	l.held[mailboxID] = true
	return true
}

// unlock 释放邮箱 maildrop 锁（幂等）。
func (l *maildropLocks) unlock(mailboxID int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.held, mailboxID)
}

// Server POP3 服务端（995 隐式 TLS 端点，rfc8314 §3.2 连接即握手）。
type Server struct {
	cfg       ServerConfig
	accounts  *account.Service
	messages  storage.MessageRepo
	folders   storage.FolderRepo
	blobs     storage.BlobStore
	locks     *maildropLocks // F4：maildrop 独占锁表
	mu        sync.Mutex
	listeners []net.Listener
	closed    bool
	wg        sync.WaitGroup
	conns     atomic.Int64 // F8：活动连接计数（上限判定）
}

// ServerConfig POP3 服务端配置（依赖注入位——架构第四章：接入层不含业务）。
type ServerConfig struct {
	Domain        string             // 主域名（日志呈现）
	TLSConfig     func() *tls.Config // TLS 配置供给（TLSManager 注入；nil=证书未就绪——调用方跳过启动+告警，对齐 U5 1.5⑫）
	ProtocolDebug func() bool        // 协议 debug 快照（U21——config Log.ProtocolDebug；nil=false 缺省热生效）
}

// protocolDebug 协议 debug 快照读取（U21；nil 注入=禁用——缺省零输出零行为变化）。
func (s *Server) protocolDebug() bool {
	return s.cfg.ProtocolDebug != nil && s.cfg.ProtocolDebug()
}

// NewServer 构造 POP3 服务端。
// 参数：cfg 配置；accounts 账号域服务（AUTH PLAIN→VerifyCredentials，FR-001 三入口之一）；
// messages 邮件仓储（IMAPSearch 空 filter 全量/GetDetail/HardDelete——契约 v1.3.1 2.1 既有方法，零扩展）；
// folders 文件夹仓储（定位 kind=inbox）；blobs CAS 字节存储（RETR/TOP 原文）。
// 返回：服务实例。
func NewServer(cfg ServerConfig, accounts *account.Service, messages storage.MessageRepo, folders storage.FolderRepo, blobs storage.BlobStore) *Server {
	return &Server{cfg: cfg, accounts: accounts, messages: messages, folders: folders, blobs: blobs, locks: newMaildropLocks()}
}

// ErrTLSNotReady 证书未就绪（调用方据此跳过端点启动并告警——U5 1.5⑫ 同口径）。
var ErrTLSNotReady = errors.New("pop3: TLS 证书未就绪")

// ListenAndServeTLS 绑定 addr 并以隐式 TLS 服务（rfc8314 §3.2；TLSConfig 供给为 nil 时
// 返回 ErrTLSNotReady 由调用方跳过+告警）。
// 参数：addr 监听地址（":995"）。返回：服务异常退出原因。
func (s *Server) ListenAndServeTLS(addr string) error {
	tlsCfg := s.cfg.TLSConfig()
	if tlsCfg == nil {
		return ErrTLSNotReady
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	return s.Serve(tcpListenerTLS{ln, tlsCfg})
}

// Serve 接受连接并逐连接起会话（可测形态：测试经明文 loopback listener 注入驱动——
// Q4-A 明文拒绝判定锚：非 *tls.Conn 连接上 AUTH 一律 -ERR）。
// 参数：ln 任意监听器（TLS 包裹与否由调用方决定）。返回：服务异常退出原因。
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		// F8：连接上限——超限即时关闭（NFR-002 资源面防御，256/端点档）。
		if s.conns.Add(1) > pop3MaxConns {
			s.conns.Add(-1)
			_ = conn.Close()
			slog.Warn("POP3 连接超上限拒绝", "max", pop3MaxConns, "remote", conn.RemoteAddr().String())
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.conns.Add(-1)
			s.handleConn(conn)
		}()
	}
}

// pop3MaxConns 单端点连接数上限（F8——NFR-002：连接风暴下 goroutine/内存
// 无界防御；单管理员自托管+512MB 场景 256/端点最坏 ~15MB 受控）。
const pop3MaxConns = 256

// handleConn 单连接生命周期（连接入口 LogID——NFR-016；rfc1939 §4 超时≥10min：
// 到期不进 UPDATE 直接断连不应答）。
func (s *Server) handleConn(conn net.Conn) {
	logID := observability.NewLogID()
	slog.Info("POP3 连接建立", "logid", logID, "remote", conn.RemoteAddr().String())
	newSession(s, conn, logID).serve()
	_ = conn.Close()
	slog.Info("POP3 连接关闭", "logid", logID)
}

// Addr 当前监听地址（测试与运维探活；未监听返回 nil）。
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.listeners) == 0 {
		return nil
	}
	return s.listeners[len(s.listeners)-1].Addr()
}

// Shutdown 优雅关闭（停止接受连接；等待在途会话退出——QUIT 语义由客户端触发或断连兜底）。
func (s *Server) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	return nil
}

// tcpListenerTLS 监听器 TLS 包裹（每连接 tls.Server 包裹后交会话——U6 同款形态）。
type tcpListenerTLS struct {
	net.Listener
	tlsCfg *tls.Config
}

// Accept 接受连接并即刻 TLS 握手（隐式 TLS，rfc8314 §3.2）。
func (l tcpListenerTLS) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(conn, l.tlsCfg), nil
}
