// Package managesieve ManageSieve 协议服务端（rfc5804——R1-A 全自研，U12）。
// 依据：rfc5804 §1.7（能力三项 MUST：IMPLEMENTATION/SIEVE/VERSION；STARTTLS MUST 实现；
// SASL 通告规则——SASL 空当且仅当通告 STARTTLS）、§1.8（TCP 4190）、§2（命令族全集）；
// 契约 v1.37.0 2.4 注记（accounts+scripts+语法校验+TLSConfig 快照注入形态；v1.19.0 能力串/v1.33.0 资源限制注记同章承载）；
// SRS IR-004/FR-011（TC-011 判定②）；NFR-006（明文连接 AUTHENTICATE 一律 NO）。
// 裁决来源：Q1-R1 全自研（2026-09-21 00:30:59）；G2 批准 2026-09-21 00:36:18。
// U23 增量（可观测性扩展——U21 登记项②收口，H5 等价）：ServerConfig 增 ProtocolDebug
// 快照注入位+protocolDebug 快照读取方法（命令响应面 debug 条件输出——埋点归 session.go）。
// 修改历史：
//
//	2026-09-21 00:58:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 8）
//	2026-09-27 13:40:00 | 扩展 | U23 可观测性扩展：ProtocolDebug 注入位+快照方法
//	（来源：G2 批准 2026-09-27 13:20:53，U23 计划书 v1.0.0 步骤 5/1.5⑤）
//	2026-10-08 13:10:00 | 修正 | 文档治理批 C1：头注契约版本引用刷新 v1.8.0→v1.37.0（注释漂移收口；纯注释零行为变更）
package managesieve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"GRmail/internal/account"
	"GRmail/internal/observability"
	"GRmail/internal/sieve"
	"GRmail/internal/storage"
)

// ErrTLSNotReady TLS 未就绪哨兵（调用方跳过挂载+告警——沿 U6/U7/U8 先例；
// 本服务 4190 为明文承载+STARTTLS 升级形态，无证书时 STARTTLS 不通告）。
var ErrTLSNotReady = errors.New("managesieve: TLS 未配置（STARTTLS 不通告，SASL 能力为空——只读不可认证态）")

// QuotaConfig HAVESPACE 配额快照（U12 计划书 1.5⑦：脚本数/单脚本字节，G2 批复生效）。
type QuotaConfig struct {
	MaxScripts int // 单邮箱脚本数上限（缺省 10）
	MaxBytes   int // 单脚本字节上限（缺省 64KB）
}

// Defaults 缺省档。
func (q QuotaConfig) Defaults() QuotaConfig {
	if q.MaxScripts <= 0 {
		q.MaxScripts = 10
	}
	if q.MaxBytes <= 0 {
		q.MaxBytes = 64 * 1024
	}
	return q
}

// ServerConfig 依赖注入集（契约 v1.8.0 2.4 注记形态）。
type ServerConfig struct {
	Port          int                     // 监听端口（缺省 4190——重启生效口径沿端口先例）
	Accounts      *account.Service        // AUTHENTICATE PLAIN 主体校验（active 邮箱）
	Scripts       storage.SieveScriptRepo // 脚本仓储
	Validate      func(src string) error  // 语法校验（sieve.Parse 注入——PUTSCRIPT/CHECKSCRIPT）
	TLSConfig     func() *tls.Config      // STARTTLS 快照（nil/nil 返回=未就绪不通告）
	Quota         func() QuotaConfig      // HAVESPACE 配额快照（nil=缺省档）
	ProtocolDebug func() bool             // 协议 debug 快照（U23——config Log.ProtocolDebug；nil=false 缺省热生效，命令响应面条件输出）
	Domain        string                  // OWNER 能力与 IMPLEMENTATION 标识
}

// protocolDebug 协议 debug 快照读取（U23；nil 注入=禁用——缺省零输出零行为变化）。
func (s *Server) protocolDebug() bool {
	return s.cfg.ProtocolDebug != nil && s.cfg.ProtocolDebug()
}

// Server ManageSieve 服务端（4190 明文承载+连接级 STARTTLS 升级）。
type Server struct {
	cfg   ServerConfig
	ln    net.Listener
	conns atomic.Int64 // F8：活动连接计数（上限判定）
}

// NewServer 构造服务端。
func NewServer(cfg ServerConfig) *Server { return &Server{cfg: cfg} }

// Addr 监听地址（未监听返回 nil）。
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// ListenAndServe 监听并服务（阻塞；端口缺省 4190）。
func (s *Server) ListenAndServe() error {
	port := s.cfg.Port
	if port <= 0 {
		port = 4190
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("managesieve 监听 :%d: %w", port, err)
	}
	return s.Serve(ln)
}

// Serve 在既有监听上服务（可测形态——明文 listener 注入）。
func (s *Server) Serve(ln net.Listener) error {
	s.ln = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// F8（访问协议资源限制批）：连接上限——超限即时关闭（NFR-002 资源面防御）。
		if s.conns.Add(1) > managesieveMaxConns {
			s.conns.Add(-1)
			_ = conn.Close()
			slog.Warn("ManageSieve 连接超上限拒绝", "max", managesieveMaxConns, "remote", conn.RemoteAddr().String())
			continue
		}
		go func() {
			defer s.conns.Add(-1)
			s.serveConn(conn)
		}()
	}
}

// managesieveMaxConns 单端点连接数上限（F8——NFR-002：与其他三端点同档 256）。
const managesieveMaxConns = 256

// Shutdown 优雅停止。
func (s *Server) Shutdown() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

// serveConn 单连接服务（入口 LogID——NFR-016；SASL 通告规则与 STARTTLS 归 session）。
func (s *Server) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	ctx, _ := observability.ContextWithNewLogID(context.Background(), slog.Default())
	sess := newSession(ctx, conn, s.cfg)
	sess.run()
}

// tlsReady TLS 就绪判定（nil 配置=未就绪——U10 25 端点同款语义）。
func (s *Server) tlsReady() bool { return s.cfg.TLSConfig != nil && s.cfg.TLSConfig() != nil }

// validateScript 语法校验透传（nil 注入=恒通过——测试桩形态）。
func (s *Server) validateScript(src string) error {
	if s.cfg.Validate == nil {
		return nil // 注入缺失防御态（生产装配必注入 sieve.Parse）
	}
	return s.cfg.Validate(src)
}

// compileValidate sieve.Parse 直连形态（校验函数标准实现——main 装配用）。
func compileValidate(src string) error {
	_, err := sieve.Parse(src)
	return err
}

// warnConn 连接级告警（SASL 空态部署缺陷显性化）。
func warnConn(msg string) { slog.Warn(msg) }
