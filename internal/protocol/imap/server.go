// Package imap 实现 IMAP4rev2 服务端（FR-006）：emersion/go-imap v2 封装（架构总览
// 选型 #5，Q4 裁决）——993 隐式 TLS 端点（Q1-A 2026-09-18 00:00:04，rfc8314 §1/§3.2
// 推荐 Implicit TLS 优先；无明文端口即无 STARTTLS/LOGINDISABLED 义务链，rfc9051 §5）、
// v2 Session 体系映射 account/storage（契约 v1.37.0 2.4——U6 以来历版注记承载）、
// IDLE 事件驱动推送（Q2-A 2026-09-18 00:01:30，rfc2177 §3）。
// 能力集：IMAP4rev2/IDLE/LITERAL+(rfc7888)/UTF8=ACCEPT(rfc6855)/MOVE(rfc6851)/NAMESPACE；
// CONDSTORE(rfc7162)/QUOTA(rfc9208) 非 FR-006 判定必需不实现（计划书 1.2 不改清单，阶段二）。
// FLAGS 五系统标志映射（契约 v1.16.0 2.4 终态——Q2-A 2026-09-29 五标志 RFC 化，v1.3.0 三标志口径废止）：\Seen↔is_read、\Flagged↔is_flagged、
// \Deleted↔status=deleted、\Answered↔is_answered、\Draft↔is_draft（五标志全部持久化）。
// UIDVALIDITY 固定值 1（Q4-A 2026-09-18 00:07:22：uid 经 DB 持久+mailbox 域全局 MAX+1
// 不复用，rfc9051 2.3.1.1 递增义务不触发；§9 示例值 1 合法）。
// 修改历史：
//
//	2026-09-18 00:28:00 | 新建 | U6 IMAP 集成（计划书步骤 5，G2 批准 2026-09-18 00:09:22）
//	2026-09-27 06:18:00 | 扩展 | U21 可观测性增强：Options.DebugWriter 挂接条件 Writer
//	（H5 等价——快照控制开闭热生效；ServerConfig 增 ProtocolDebug 注入位）
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 4/1.5①⑤；双源核对：
//	go-imap v2 imapserver.Options 原生 DebugWriter io.Writer 字段——go doc 实录）
//	2026-10-08 13:10:00 | 修正 | 文档治理批 C1：头注契约版本引用刷新 v1.3.0→v1.37.0+FLAGS
//	口径按 v1.16.0 五标志终态改写（原三标志口径已废止——裁决索引覆盖链 2；纯注释零行为变更）
package imap

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"GRmail/internal/account"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
)

// debugWriter 协议 debug 条件 Writer（U21——H5 IMAP debug 输出等价承载）。
// go-imap v2 经 Options.DebugWriter 输出 raw ingress/egress 帧；本类型每次 Write 读
// 快照决定输出与否（false=静默丢弃——恒返回 len(p) 保持消费语义）。
// B-S批 F4（裁决 A 2026-10-09 13:34）：认证帧凭据掩码——行缓冲状态机：
// ①AUTHENTICATE 命令行（任意 tag 后跟 AUTHENTICATE token）的 initial-response
// 参数掩码 [REDACTED]；②SASL continuation 轮（上一完整行为 "+" 前缀 challenge——
// rfc9051 §7.5 continuation 数据形态）的下一客户端行整行掩码（base64 凭据无命令
// 词可判，行级状态承载）；非认证帧原样；非 debug 模式零输出零行为变化。
// 多连接共享同一 Writer 实例（Options 全局单份）——互斥锁保护行缓冲状态。
type debugWriter struct {
	enabled func() bool // 快照供给（ServerConfig.ProtocolDebug 注入；nil=禁用）

	mu             sync.Mutex
	buf            []byte // 行缓冲（Write 可能半行——拼至行界逐行处理）
	afterChallenge bool   // 上一完整行为 "+" 前缀 continuation challenge（下一行掩码）
}

// Write 条件输出（行缓冲掩码后逐行输出；Debug 级；行尾空白剥除）。
func (w *debugWriter) Write(p []byte) (int, error) {
	if w.enabled == nil || !w.enabled() {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i+1])
		w.buf = w.buf[i+1:]
		out, masked := w.maskLine(line)
		slog.Debug("imap_debug", "proto", "imap", "data", strings.TrimRight(out, "\r\n"))
		w.afterChallenge = masked
	}
	return len(p), nil
}

// maskLine 单行掩码判定（B-S批 F4）。
// 返回：输出行；该行是否为服务端 continuation challenge（"+" 前缀——下一客户端行掩码）。
func (w *debugWriter) maskLine(line string) (string, bool) {
	if strings.HasPrefix(line, "+") {
		return line, true // continuation challenge——下一行（客户端凭据应答）掩码
	}
	if w.afterChallenge {
		return "[REDACTED]\r\n", false // challenge 后的客户端行=base64 凭据——整行掩码
	}
	trimmed := strings.TrimRight(line, "\r\n")
	fields := strings.Fields(trimmed)
	if len(fields) >= 2 && strings.EqualFold(fields[1], "AUTHENTICATE") && len(fields) >= 3 {
		// tag AUTHENTICATE mech [initial-response]——保留 tag+命令+机制，掩第四段起
		return fields[0] + " " + fields[1] + " " + fields[2] + " [REDACTED]\r\n", false
	}
	return line, false
}

// uidValidity 固定 UIDVALIDITY（Q4-A：零 schema 承载；rfc9051 2.3.1.1 递增义务
// 仅触发于 UID 不持久场景——本项目 uid DB 持久且全局不复用）。
const uidValidity uint32 = 1

// Server IMAP4rev2 服务端（go-imap v2 封装；993 隐式 TLS）。
type Server struct {
	cfg       ServerConfig
	accounts  *account.Service
	messages  storage.MessageRepo
	blobs     storage.BlobStore
	notifier  *Notifier
	inner     *imapserver.Server
	connCount atomic.Int64 // F8：活动连接计数（connLimitListener 消费）
	mu        sync.Mutex
	listeners []net.Listener
	closed    bool
}

// ServerConfig IMAP 服务端配置（依赖注入位——架构第四章：接入层不含业务）。
type ServerConfig struct {
	Domain        string             // 主域名（日志与 Namespace 呈现）
	TLSConfig     func() *tls.Config // TLS 配置供给（TLSManager 注入；nil=证书未就绪——调用方跳过启动+告警，对齐 U5 1.5⑫）
	MaxAppendSize func() int64       // APPEND 大小上限供给（config Mail.MaxMessageSizeBytes 快照热生效；nil=缺省 35MiB）
	ProtocolDebug func() bool        // 协议 debug 快照（U21——config Log.ProtocolDebug；nil=false 缺省，Write 时读取热生效）
}

// NewServer 构造 IMAP 服务端。
// 参数：cfg 配置；accounts 账号域服务（Login→VerifyCredentials/folder 映射）；
// messages 邮件仓储（契约 v1.3.0 2.1 十一方法）；blobs CAS 字节存储（FETCH BODY 原文）。
// 返回：服务实例。
func NewServer(cfg ServerConfig, accounts *account.Service, messages storage.MessageRepo, blobs storage.BlobStore) *Server {
	s := &Server{cfg: cfg, accounts: accounts, messages: messages, blobs: blobs, notifier: NewNotifier()}
	s.inner = imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return s.newSession(conn)
		},
		// U21 协议 debug：原生 DebugWriter 挂接条件 Writer（每次 Write 读快照——热加载
		// 生效；false 时丢弃返回——零输出零行为变化）。注：raw 帧含凭据等敏感信息，
		// 仅排障时开启（go-imap v2 Options 字段原文警示）。
		DebugWriter: &debugWriter{enabled: cfg.ProtocolDebug},
		// 能力集：IMAP4rev2 为基线（必需其一）；IDLE/MOVE/UTF8=ACCEPT/LITERAL+ 为
		// FR-006 判定扩展；NAMESPACE 为 IMAP4rev2 内含能力（v2 Options 注释口径）
		Caps: imap.CapSet{
			imap.CapIMAP4rev2:   {},
			imap.CapIdle:        {},
			imap.CapLiteralPlus: {},
			imap.CapUTF8Accept:  {},
			imap.CapMove:        {},
			imap.CapNamespace:   {},
		},
	})
	return s
}

// ErrTLSNotReady 证书未就绪（调用方据此跳过端点启动并告警——U5 1.5⑫ 同口径）。
var ErrTLSNotReady = errors.New("imap: TLS 证书未就绪")

// Notifier IDLE 事件广播器（Q2-A：mail.DeliverObserver 桥接位——cmd 装配层注入
// InboundPipeline.SetObserver；订阅-通知模型，落库事件实时唤醒 IDLE 会话）。
type Notifier struct {
	mu   sync.Mutex
	subs map[int64][]chan struct{} // mailboxID → 订阅通道集
}

// NewNotifier 构造广播器。
func NewNotifier() *Notifier {
	return &Notifier{subs: make(map[int64][]chan struct{})}
}

// maxAppendSize APPEND 大小上限（快照供给；缺省 35MiB 与 SMTP DATA 同档——Q2-A 缺省口径）。
func (s *Server) maxAppendSize() int64 {
	if s.cfg.MaxAppendSize != nil {
		if n := s.cfg.MaxAppendSize(); n > 0 {
			return n
		}
	}
	return 36700160 // 35MiB 缺省档
}

// OnDelivered 实现 mail.DeliverObserver（落库成功回调→逐邮箱非阻塞唤醒）。
// 尽力语义：无订阅者/通道满直接跳过（IDLE 会话在下轮事件或客户端轮询收敛）。
func (n *Notifier) OnDelivered(mailboxIDs []int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, id := range mailboxIDs {
		for _, ch := range n.subs[id] {
			select {
			case ch <- struct{}{}:
			default: // 满则丢弃（事件合并语义：待唤醒会话刷新时读最新计数）
			}
		}
	}
}

// Subscribe 订阅邮箱事件。
// 参数：mailboxID 邮箱 ID。返回：事件通道、注销函数。
func (n *Notifier) Subscribe(mailboxID int64) (<-chan struct{}, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ch := make(chan struct{}, 1)
	n.subs[mailboxID] = append(n.subs[mailboxID], ch)
	return ch, func() { n.unsubscribe(mailboxID, ch) }
}

// unsubscribe 注销订阅（幂等）。
func (n *Notifier) unsubscribe(mailboxID int64, ch chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list := n.subs[mailboxID]
	for i, c := range list {
		if c == ch {
			n.subs[mailboxID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(n.subs[mailboxID]) == 0 {
		delete(n.subs, mailboxID)
	}
}

// NotifierAccessor 暴露广播器（cmd 装配层取用注入 mail 管道）。
func (s *Server) NotifierAccessor() *Notifier { return s.notifier }

// ListenAndServeTLS 绑定 addr 并以隐式 TLS 服务（rfc8314 3.2：连接即握手；
// TLSConfig 供给为 nil 时返回 ErrTLSNotReady 由调用方跳过+告警）。
// 参数：addr 监听地址（":993"）。返回：服务异常退出原因。
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
	// F8（访问协议资源限制批）：经 connLimitListener 注入连接上限（IMAP 连接
	// 由库层 inner.Serve 承载，Accept 循环不可直接注入判定逻辑）。计数包装
	//（countedConn）位于 TLS 内层、tls.Server 外层包裹——库层 *tls.Conn 类型
	// 断言保持成立（外层包装会破坏断言致 PRIVACYREQUIRED 拒认证，u6 e2e 实证）；
	// Close 经 TLS 层传导释放计数。
	return s.inner.Serve(&connLimitListener{Listener: ln, count: &s.connCount, tlsCfg: tlsCfg})
}

// imapMaxConns 单端点连接数上限（F8——NFR-002：连接风暴下 goroutine/内存
// 无界防御；单管理员自托管+512MB 场景 256/端点最坏 ~15MB 受控）。
const imapMaxConns = 256

// connLimitListener 连接上限注入监听器（F8——Accept 层拦截：超限连接即时
// 关闭后仍返回已关连接（库层读取即错会话即终；Accept 错误形态会终止库层
// Serve 监听循环，不可采用）。计数包装（countedConn）位于 TLS 内层、
// tls.Server 外层包裹——库层 *tls.Conn 类型断言保持成立；Close 经 TLS 层
// 传导释放计数。
type connLimitListener struct {
	net.Listener // 原始 TCP 监听（TLS 包装由本层承担）
	count        *atomic.Int64
	tlsCfg       *tls.Config
}

// Accept 接受连接并执行上限判定与 TLS 包裹。
func (l *connLimitListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc := &countedConn{Conn: conn, count: l.count}
	if l.count.Add(1) > imapMaxConns {
		_ = cc.Close() // 计数经 once 即时释放；库层对已关连接会话即终
		slog.Warn("IMAP 连接超上限拒绝", "max", imapMaxConns, "remote", conn.RemoteAddr().String())
	}
	return tls.Server(cc, l.tlsCfg), nil // 外层 *tls.Conn——库层 TLS 断言成立
}

// countedConn 计数连接（Close 时递减——once 保证幂等）。
type countedConn struct {
	net.Conn
	count *atomic.Int64
	once  sync.Once
}

// Close 关闭连接并释放计数（幂等）。
func (c *countedConn) Close() error {
	c.once.Do(func() { c.count.Add(-1) })
	return c.Conn.Close()
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

// Shutdown 优雅关闭（停止接受连接；关闭既有监听器）。
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
	return s.inner.Close()
}

// tcpListenerTLS 监听器 TLS 包裹（每连接 tls.Server 包裹后交 go-imap Serve）。
type tcpListenerTLS struct {
	net.Listener
	tlsCfg *tls.Config
}

// Accept 接受连接并即刻 TLS 握手（隐式 TLS，rfc8314 3.2）。
func (l tcpListenerTLS) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(conn, l.tlsCfg), nil
}

// newSession 构造会话（连接入口 LogID——NFR-016）。
func (s *Server) newSession(_ *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	logID := observability.NewLogID()
	slog.Info("IMAP 连接建立", "logid", logID)
	return &Session{server: s, logID: logID}, &imapserver.GreetingData{}, nil
}
