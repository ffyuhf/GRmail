// Package smtp 追加提交端点：465 隐式 TLS（rfc8314 3.3）/587 STARTTLS（rfc3207）
// U23 增量（协议 debug——U21 登记项①收口，H5 等价）：readLine/replyRaw 命令应答面
// 逐行条件输出（快照控制热生效；AUTH challenge 应答经 replyRaw 汇聚点覆盖；DATA 体
// 直读 rw.Reader 不经 readLine 天然不输出——防刷屏口径与三协议一致）。
// +AUTH PLAIN/LOGIN（rfc4954）+提交会话（未认证 MAIL 530/授权 550 5.7.1 由管道判定）。
// 依据：U5 计划书 v1.0.0 步骤 10（Q2-A 裁决：提交端口 TLS 全量一步到位；Q3-B 对
// 25 收信端点继续有效——本文件不触碰 25 端点行为）；
// rfc4954 第 4 章原文锚点：AUTH 后重复/事务中 503、334 challenge 纯 base64、'*' 取消
// 501、535 拒绝、235 成功、504 未支持、明文会话禁止明文密码机制（本端点明文 587
// 不通告 AUTH——MUST 条款；客户端须 STARTTLS 后重 EHLO）；
// rfc3207 第 4 章：STARTTLS 无参（501 拒参）/220/454、握手后协议重置（丢弃 EHLO 知识，
// 4.2）、TLS 会话中不再通告与执行 STARTTLS；
// rfc6409 4.3 未认证 MAIL→530；5.3 提交服务器 2 分钟内应答；
// 契约 v1.2.0 2.3 SubmissionPipeline 注入；架构第四章 smtp→mail 单向依赖。
// 修改历史：
//
//	2026-09-17 23:30:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 10）
//	2026-09-27 13:36:00 | 扩展 | U23 可观测性扩展：提交端点协议 debug 收口
//	（快照注入位+ctx 字段+debugFrame 辅助+readLine/replyRaw 两埋点）
//	（来源：G2 批准 2026-09-27 13:20:53，U23 计划书 v1.0.0 步骤 4/1.5④）
//	2026-09-30 18:32:00 | 修正 | RFCSHOULD修正批次 RF-A（F-5）：明文连接 AUTH
//	防御性应答 538→530 5.7.11——rfc4954 L630-639「538 documented here for
//	historical purposes only」废弃该码（§6 L992-993 同载），增强码 5.7.11 保留
//	（L641-648）搭配现行基础码 530（L623）承载「加密要求」语义
//	（依据：RFCSHOULD修正计划书 v1.0.0 步骤 3，G2 批准 2026-09-30 18:28:20）
//	2026-10-06 19:50:00 | 修正 | 提交端点对齐批（评审修复批次 2/8）：F1/A-11
//	DATA 大小终判（tooBig+552，rfc1870 §6.1 L231-233）；F2/A-12 终止检测复用
//	indexDataTerminator（空消息前缀特判 rfc5321bis §4.1.1.4 L2206-2207）；
//	F3/B-S10①②③ AUTH 限流（LoginAttemptRepo 联动 421）+SASLprep 消费
//	（rfc4954 §4 L261-268）+AUTH 行超限 500 5.5.6（L255-259）；F4/B-F8
//	STARTTLS 带参 501（rfc3207 §4 L108）+EHLO 空域 501（rfc5321bis §4.1.4）+
//	收件人上限常量化（§4.5.3.1.8 MUST ≥100）+per-command 超时（§4.5.3.2
//	L3846-3848 MUST）；F5/B-F9 NOTIFY/ORCPT 重复+值域校验（rfc3461 §4.1/
//	§4.2/§4.5 L533-536）；F6/B-F10 VerifyCredentials/Submit 改传 ss.ctx
//	（LogID 链闭环）（依据：提交端点对齐批计划书 v1.0.0，G2 批准
//	2026-10-06 19:43:56；SRS FR-005/NFR-004/005/007/016、FR-013 伴随）
package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	"GRmail/internal/observability"
)

// CredentialVerifier 提交认证窄接口（account.Service.VerifyCredentials 满足；
// 返回 *storage.Mailbox 供授权对齐——本接口窄化为错误形态）。
type CredentialVerifier interface {
	VerifyCredentials(ctx context.Context, addr, password string) error
}

// ── 提交端点对齐批（B-S10①/③）常量与窄接口 ──

const (
	// rcptMaxRecipients 单事务收件人上限（F4/B-F8：rfc5321bis §4.5.3.1.8 L3771-3773
	// 「MUST 缓冲≥100」——本值=MUST 最小值，超限应答 452（§4.5.3.1.10 L3833-3835）。
	// 原魔数 100 常量化命名，行为零变化。
	rcptMaxRecipients = 100
	// authLineLimit AUTH 交换行读上限（F3/B-S10③：rfc4954 §4 L246-254——BASE64 挑战
	// 响应可远超命令行限，12288 octets 为规范参考值；超限 500 5.5.6，L255-259）。
	authLineLimit = 12288
)

// errAuthLineTooLong AUTH 交换行超限哨兵（应答 500 5.5.6 已在 readAuthLine 内发出，
// 上层按错误返回终止本次 AUTH——rfc4954 §4 L255-259）。
var errAuthLineTooLong = errors.New("smtp: AUTH 交换行超长")

// AttemptRecorder AUTH 失败计数窄接口（F3/B-S10①：storage.LoginAttemptRepo 前
// 三方法隐式满足——窄接口形态沿本文件 CredentialVerifier 先例，smtp 包零 storage
// import，架构第四章依赖方向保持）。nil=限流关闭（渐进态，沿 U14 Tokens nil 先例）。
type AttemptRecorder interface {
	RecordAttempt(ctx context.Context, subjectKey, ip string, success bool, at time.Time) error
	CountRecentFails(ctx context.Context, subjectKey string, since time.Time) (int64, error)
	ClearSubject(ctx context.Context, subjectKey string) error
}

// SubmissionConfig 提交端点配置。
type SubmissionConfig struct {
	Domain         string             // 主域名（EHLO 应答/横幅）
	MaxMessageSize func() int64       // SIZE 通告（快照；nil=35MiB）
	TLSConfig      func() *tls.Config // 服务端 TLS（动态快照；nil=证书未就绪——TLS 端点不启动且 587 不通告 STARTTLS，rfc3207 4.1）
	ProtocolDebug  func() bool        // 协议 debug 快照（U23——config Log.ProtocolDebug；nil=false 缺省热生效，命令应答面条件输出）
	// Attempts AUTH 失败计数仓储（F3/B-S10①——提交端点对齐批；nil=限流关闭）。
	Attempts AttemptRecorder
	// AttemptLimit 限流参数快照（窗口/阈值——与 web 登录限流同源 config.LoginLimitConf；
	// nil=15min/5 次兜底档，沿 web limitConf 形态）。
	AttemptLimit func() (window time.Duration, threshold int64)
}

// SubmissionServer 提交端点服务端（465 隐式+587 STARTTLS 双端口；接入层零业务）。
type SubmissionServer struct {
	cfg      SubmissionConfig
	pipeline mail.SubmissionPipeline // 提交管道注入（契约 v1.2.0）
	verifier CredentialVerifier      // AUTH 凭据校验（U2）

	mu     sync.Mutex
	lns    []net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

// NewSubmissionServer 构造提交端点。
// 参数：cfg 配置；pipeline 提交管道；verifier 凭据校验。
func NewSubmissionServer(cfg SubmissionConfig, pipeline mail.SubmissionPipeline, verifier CredentialVerifier) *SubmissionServer {
	if cfg.MaxMessageSize == nil {
		cfg.MaxMessageSize = func() int64 { return 36700160 }
	}
	return &SubmissionServer{cfg: cfg, pipeline: pipeline, verifier: verifier, conns: make(map[net.Conn]struct{})}
}

// ListenAndServe 启动双端口：465（隐式 TLS，证书就绪时）与 587（明文+STARTTLS）。
// 证书未就绪（TLSConfig nil）时 465 跳过并日志告警（U5 计划书 1.5⑫）。
// 参数：implicitAddr 形如 ":465"（空=跳过）；explicitAddr 形如 ":587"。
func (s *SubmissionServer) ListenAndServe(implicitAddr, explicitAddr string) error {
	if explicitAddr != "" {
		if err := s.serveListener(explicitAddr, false); err != nil {
			return err
		}
	}
	if implicitAddr != "" {
		if s.cfg.TLSConfig() == nil {
			slog.Default().Warn("TLS 证书未配置：465 提交端点跳过启动（手动放置证书或 U10 ACME 后生效）")
			return nil
		}
		if err := s.serveListener(implicitAddr, true); err != nil {
			return err
		}
	}
	return nil
}

// serveListener 单端口监听循环。
func (s *SubmissionServer) serveListener(addr string, implicitTLS bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("提交端点监听失败 %s: %w", addr, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("提交端点已关闭")
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("提交端点接受连接: %w", err)
		}
		if implicitTLS {
			if tc := s.cfg.TLSConfig(); tc != nil {
				conn = tls.Server(conn, tc)
			}
		}
		s.track(conn, true)
		go func() {
			defer s.track(conn, false)
			s.serveSubmission(conn, implicitTLS)
		}()
	}
}

// protocolDebug 协议 debug 快照读取（U23；nil 注入=禁用——缺省零输出零行为变化）。
func (s *SubmissionServer) protocolDebug() bool {
	return s.cfg.ProtocolDebug != nil && s.cfg.ProtocolDebug()
}

// track 连接登记/摘除（Shutdown 收口依据）。
func (s *SubmissionServer) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[conn] = struct{}{}
		return
	}
	delete(s.conns, conn)
}

// Shutdown 优雅停止。
func (s *SubmissionServer) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, ln := range s.lns {
		_ = ln.Close()
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
	return nil
}

// submitSession 提交会话状态（U4 session 语义子集+提交扩展位）。
type submitSession struct {
	srv       *SubmissionServer
	conn      net.Conn // 底层连接（F-9——RemoteIP/TLS cipher 提取；STARTTLS 升级时同步更新）
	rw        *bufio.ReadWriter
	inTLS     bool   // 当前会话是否已处 TLS 层（隐式包裹或 STARTTLS 升级）
	heloDone  bool   // EHLO/HELO 完成（MAIL 前置）
	authUser  string // 认证身份（空=未认证）
	mailFrom  string // 信封发件人（空=事务外或 null path）
	rcpts     []string
	inTx      bool // 事务中（MAIL 已接受）
	dsnParams []mail.DSNParam
	ctx       context.Context // 会话级上下文（U23 协议 debug 输出携带 logid——serveSubmission 一次赋值）
}

// serveSubmission 单连接提交会话循环。
func (s *SubmissionServer) serveSubmission(conn net.Conn, implicitTLS bool) {
	defer func() { _ = conn.Close() }()
	// F4/B-F8（提交端点对齐批）：per-command 超时——每命令循环头重置 idle deadline
	// （rfc5321bis §4.5.3.2 L3846-3848「MUST per-command timeouts」；idleTimeout
	// =5min 同包常量对齐 §4.5.3.2.7；DATA 收流期由 data() 内 dataIdleTimeout
	// 3min 逐块承载 §4.5.3.2.5——原单次绝对 5min 缺陷修正）。
	// U23：LogID 会话锚点（proto=submission 与 25 端点 smtp 区分——NFR-016 观测链）
	ctx := observability.LoggerIntoContext(context.Background(),
		slog.Default().With("logid", observability.NewLogID(), "proto", "submission", "remote", conn.RemoteAddr().String()))
	sess := &submitSession{
		srv:   s,
		conn:  conn, // F-9：连接引用（STARTTLS 升级时同步替换为 tls.Conn）
		rw:    bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		inTLS: implicitTLS,
		ctx:   ctx,
	}
	sess.reply(220, s.cfg.Domain+" ESMTP submission ready")
	for {
		_ = conn.SetDeadline(time.Now().Add(idleTimeout)) // F4：每命令重置（见上注）
		line, err := sess.readLine()
		if err != nil {
			if errors.Is(err, errLineTooLong) { // F4：命令行超长 500 后会话继续（rfc5321bis §4.5.3.1.4/.9——行已整读流同步）
				sess.reply(500, "5.5.6 Line too long")
				continue
			}
			return
		}
		verb, arg := splitVerb(line)
		switch verb {
		case "EHLO":
			sess.helo(arg)
		case "HELO":
			sess.heloDone = true
			sess.resetTx()
			sess.reply(250, "ok")
		case "STARTTLS":
			sess.startTLS(conn, arg) // F4：arg 传入校验（rfc3207 §4 L108 带参 501）
		case "AUTH":
			sess.auth(arg)
		case "MAIL":
			sess.mail(arg)
		case "RCPT":
			sess.rcpt(arg)
		case "DATA":
			sess.data()
		case "RSET":
			sess.resetTx()
			sess.reply(250, "ok")
		case "NOOP":
			sess.reply(250, "ok")
		case "QUIT":
			sess.reply(221, "bye")
			return
		case "VRFY":
			sess.reply(252, "cannot verify")
		default:
			sess.reply(500, "command not recognized")
		}
	}
}

// remoteIP 提交会话对端 IP（F-9——MSA Received trace 头 from 子句输入）。
func (ss *submitSession) remoteIP() net.IP {
	if ta, ok := ss.conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP
	}
	return nil
}

// tlsCipherName 会话 TLS 加密套件注册名（F-9——rfc8314 §4.3 tls 子句；
// 非 TLS 连接返回空（提交端点认证强制 TLS，理论不可达的防御分支））。
func (ss *submitSession) tlsCipherName() string {
	if tc, ok := ss.conn.(*tls.Conn); ok {
		return tls.CipherSuiteName(tc.ConnectionState().CipherSuite)
	}
	return ""
}

// helo EHLO 处理：能力行按 TLS 状态差异化（1.5④；rfc3207 4.2 TLS 后列表可变）。
func (ss *submitSession) helo(arg string) {
	if strings.TrimSpace(arg) == "" {
		// F4/B-F8（提交端点对齐批）：EHLO 需域名参数——空域 501（rfc5321bis
		// §4.1.1.1/§4.1.4 命令语法要求；HELO 分支保持原口径零触碰）。
		ss.reply(501, "5.5.4 domain required")
		return
	}
	ss.heloDone = true
	ss.resetTx()
	caps := []string{ss.srv.cfg.Domain + " hello"}
	caps = append(caps, "SIZE "+strconv.FormatInt(ss.srv.cfg.MaxMessageSize(), 10))
	caps = append(caps, "8BITMIME", "SMTPUTF8", "PIPELINING", "ENHANCEDSTATUSCODES")
	if !ss.inTLS {
		if ss.srv.cfg.TLSConfig() != nil {
			caps = append(caps, "STARTTLS") // 仅明文 587 通告（TLS 会话中不得再通告，rfc3207 4.2）
		}
	} else {
		caps = append(caps, "AUTH PLAIN LOGIN") // 明文会话不通告（rfc4954 明文密码 MUST 条款）
	}
	for i, c := range caps {
		sep := "-"
		if i == len(caps)-1 {
			sep = " "
		}
		ss.replyRaw("250" + sep + c)
	}
}

// startTLS STARTTLS 升级（rfc3207 第 4 章：无参 501/220/握手/重置；TLS 中禁重复）。
func (ss *submitSession) startTLS(conn net.Conn, arg string) {
	if strings.TrimSpace(arg) != "" {
		// F4/B-F8（提交端点对齐批）：STARTTLS 不带参数——带参 501
		// （rfc3207 §4 L108「501 Syntax error (no parameters allowed)」）。
		ss.reply(501, "5.5.4 syntax error (no parameters allowed)")
		return
	}
	if ss.inTLS {
		ss.reply(503, "TLS already active") // rfc3207 4.2：TLS 会话中不得再 STARTTLS
		return
	}
	tc := ss.srv.cfg.TLSConfig()
	if tc == nil {
		ss.reply(454, "TLS not available") // 无证书临时不可用（rfc3207 4）
		return
	}
	ss.reply(220, "Ready to start TLS")
	tlsConn := tls.Server(conn, tc)
	if err := tlsConn.Handshake(); err != nil {
		return // 握手失败断连（rfc3207 4.1）
	}
	ss.inTLS = true
	// 协议重置（rfc3207 4.2：丢弃 EHLO 等先验知识）
	ss.heloDone = false
	ss.authUser = ""
	ss.resetTx()
	ss.rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
	ss.conn = tlsConn // F-9：连接引用升级（cipher 提取面）；关闭仍走外层原 conn（同底层传导）
	// 注意：外层 serveSubmission 仍持旧 conn 引用——升级后读写经 ss.rw（Deadline 由
	// tlsConn 继承原 conn；serveSubmission 循环只分发 ss.rw 读写，连接关闭走 defer 原
	// conn（tls.Server 包装同底层，Close 传导））
}

// auth AUTH 命令（rfc4954 第 4 章逐条：503 重复/事务中、504 未支持、334/235/535、
// '*' 取消 501、initial-response 与 '=' 空响应）。
func (ss *submitSession) auth(arg string) {
	if ss.authUser != "" {
		ss.reply(503, "already authenticated") // rfc4954 4：成功后不得再 AUTH
		return
	}
	if ss.inTx {
		ss.reply(503, "not permitted during mail transaction")
		return
	}
	parts := strings.Fields(arg)
	if len(parts) == 0 {
		ss.reply(501, "mechanism required")
		return
	}
	mechanism, initial := parts[0], ""
	if len(parts) > 1 {
		initial = parts[1]
	}
	if !ss.inTLS {
		// F-5：538 已废弃（rfc4954 L636-639 historical purposes only）——改 530 搭配
		// 保留增强码 5.7.11（L648）承载「加密要求」语义（ENHANCEDSTATUSCODES 通告一致）
		ss.reply(530, "5.7.11 Encryption required for authentication")
		return
	}
	var user, pass string
	var err error
	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		user, pass, err = ss.authPLAIN(initial)
	case "LOGIN":
		user, pass, err = ss.authLOGIN(initial)
	default:
		ss.reply(504, "mechanism not supported") // rfc4954 4：未支持 504（5.5.4）
		return
	}
	if err != nil {
		return // 应答已在内部发出（取消/解码失败/行超限 500 5.5.6）
	}
	// F3②/B-S10（提交端点对齐批）：SASLprep 身份准备（rfc4954 §4 L261-268——
	// 授权身份 SHOULD use SASLprep；准备失败或结果空串 MUST fail the
	// authentication；沿 POP3 cmdAuth F-P7 先例——auth.SASLprep 承载）。
	prepared, serr := auth.SASLprep(user)
	if serr != nil || prepared == "" {
		ss.reply(535, "authentication failed") // MUST fail 承载（防枚举统一口径）
		return
	}
	user = strings.ToLower(prepared)
	// F3①/B-S10：AUTH 失败限流——LoginAttemptRepo 联动（工程防线沿 web 登录限流
	// 同源同参；421 临时语义保留对端重试协商；nil=渐进态关闭）。
	subjectKey := "submission:" + user // 命名空间前缀沿 web recordFail 键形态
	if locked := ss.authLocked(subjectKey); locked {
		ss.reply(421, "4.7.0 too many failed attempts, try again later")
		return
	}
	// F6/B-F10：改传 ss.ctx（会话 LogID 链闭环——NFR-016；原 context.Background 断链修正）。
	if err = ss.srv.verifier.VerifyCredentials(ss.ctx, user, pass); err != nil {
		ss.recordAuthFail(subjectKey)
		ss.reply(535, "authentication failed") // rfc4954 4：535（防枚举统一口径归 U2）
		return
	}
	ss.clearAuthFails(subjectKey)
	ss.authUser = user
	ss.reply(235, "authenticated") // rfc4954 4：235
}

// authLocked AUTH 失败限流判定（F3①/B-S10①——提交端点对齐批）。
// 参数：subjectKey 计数键（"submission:"+地址）。返回：锁定判定（仓储未注入/
// 查询故障一律 false 放行——限流为防线非通路，故障不阻断认证主链）。
func (ss *submitSession) authLocked(subjectKey string) bool {
	if ss.srv.cfg.Attempts == nil {
		return false
	}
	window, threshold := ss.authLimitConf()
	fails, err := ss.srv.cfg.Attempts.CountRecentFails(ss.ctx, subjectKey, time.Now().UTC().Add(-window))
	if err != nil {
		return false // 查询故障放行（尽力语义——沿 web locked 母版精神反向容错）
	}
	return fails >= threshold
}

// authLimitConf 限流参数快照（nil=15min/5 次兜底档——沿 web limitConf 形态）。
func (ss *submitSession) authLimitConf() (window time.Duration, threshold int64) {
	if ss.srv.cfg.AttemptLimit != nil {
		if w, t := ss.srv.cfg.AttemptLimit(); w > 0 && t > 0 {
			return w, t
		}
	}
	return 15 * time.Minute, 5
}

// recordAuthFail 记录一次 AUTH 失败（尽力语义——记录故障不改变拒绝应答）。
func (ss *submitSession) recordAuthFail(subjectKey string) {
	if ss.srv.cfg.Attempts == nil {
		return
	}
	ip := ""
	if ss.remoteIP() != nil {
		ip = ss.remoteIP().String()
	}
	_ = ss.srv.cfg.Attempts.RecordAttempt(ss.ctx, subjectKey, ip, false, time.Now().UTC())
}

// clearAuthFails 认证成功清零（尽力语义）。
func (ss *submitSession) clearAuthFails(subjectKey string) {
	if ss.srv.cfg.Attempts == nil {
		return
	}
	_ = ss.srv.cfg.Attempts.ClearSubject(ss.ctx, subjectKey)
}

// authPLAIN PLAIN 机制（initial-response 或 334 追问；解码 authzid\0authcid\0passwd）。
func (ss *submitSession) authPLAIN(initial string) (user, pass string, err error) {
	resp := initial
	if resp == "" {
		ss.reply(334, "")             // 空挑战
		resp, err = ss.readAuthLine() // F3③：AUTH 交换行读（12288 上限——rfc4954 §4 L246-259）
		if err != nil {
			return
		}
	}
	if resp == "*" {
		ss.reply(501, "cancelled") // rfc4954 4：'*' 取消
		return "", "", fmt.Errorf("cancelled")
	}
	raw, derr := base64.StdEncoding.DecodeString(resp)
	if derr != nil {
		ss.reply(501, "invalid base64") // 5.5.2
		return "", "", derr
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		ss.reply(501, "malformed PLAIN")
		return "", "", fmt.Errorf("malformed")
	}
	return parts[1], parts[2], nil
}

// authLOGIN LOGIN 机制（334 Username:/334 Password:/base64 两轮）。
func (ss *submitSession) authLOGIN(initial string) (user, pass string, err error) {
	user = initial
	if user == "" {
		ss.reply(334, base64.StdEncoding.EncodeToString([]byte("Username:")))
		user, err = ss.readAuthLine() // F3③：AUTH 交换行读（rfc4954 §4 L246-259）
		if err != nil {
			return
		}
	}
	if user == "*" {
		ss.reply(501, "cancelled")
		return "", "", fmt.Errorf("cancelled")
	}
	if raw, derr := base64.StdEncoding.DecodeString(user); derr == nil {
		user = string(raw)
	}
	ss.reply(334, base64.StdEncoding.EncodeToString([]byte("Password:")))
	pass, err = ss.readAuthLine() // F3③：AUTH 交换行读（rfc4954 §4 L246-259）
	if err != nil {
		return
	}
	if pass == "*" {
		ss.reply(501, "cancelled")
		return "", "", fmt.Errorf("cancelled")
	}
	raw, derr := base64.StdEncoding.DecodeString(pass)
	if derr != nil {
		ss.reply(501, "invalid base64")
		return "", "", derr
	}
	return user, string(raw), nil
}

// mail MAIL FROM（rfc6409 4.3 未认证 530；DSN RET/ENVID 参数解析透传）。
func (ss *submitSession) mail(arg string) {
	if ss.authUser == "" {
		ss.reply(530, "5.7.0 Authentication required") // rfc6409 4.3 MUST
		return
	}
	if !ss.heloDone {
		ss.reply(503, "send EHLO first")
		return
	}
	if ss.inTx {
		ss.reply(503, "nested MAIL")
		return
	}
	from, paramsStr, ok := parsePathArg(arg) // session.go 既有辅助（params 为空格串）
	if !ok {
		ss.reply(501, "syntax error in address")
		return
	}
	ss.dsnParams = ss.dsnParams[:0]
	for _, p := range strings.Fields(paramsStr) {
		kv := strings.SplitN(p, "=", 2)
		key := strings.ToUpper(kv[0])
		val := ""
		if len(kv) == 2 {
			val = kv[1]
		}
		switch key {
		case "RET", "ENVID": // rfc3461 4.3/4.4（重复 501）
			for _, exist := range ss.dsnParams {
				if exist.Keyword == key {
					ss.reply(501, "duplicate parameter") // rfc3461 4.5
					return
				}
			}
			if len(kv) == 2 {
				ss.dsnParams = append(ss.dsnParams, mail.DSNParam{Keyword: key, Value: kv[1]})
			}
		case "SIZE": // F-1：rfc1870 §4/§7——EHLO 通告 SIZE 即须接受扩展 MAIL 参数（口径沿 25 端口 parseMailParams）
			n, serr := strconv.ParseInt(val, 10, 64)
			if serr != nil || n < 0 {
				ss.reply(501, "5.5.4 SIZE 参数非法")
				return
			}
			if n > ss.srv.cfg.MaxMessageSize() {
				ss.reply(552, "5.3.4 声明大小超过上限（SIZE 预检）") // rfc1870 6.2
				return
			}
		case "BODY": // F-1：rfc6152 §3——8BITMIME 通告即须接受 BODY 参数（值域同 25 端口）
			if val != "8BITMIME" && val != "7BIT" {
				ss.reply(501, "5.5.4 BODY 参数非法（7BIT|8BITMIME）")
				return
			}
		case "SMTPUTF8": // F-1：rfc6531 §3.1——通告即须接受（无值参数）
		case "AUTH": // F-7：rfc4954 §5 L491-493——通告 AUTH 即 MUST 支持 MAIL FROM AUTH= 参数（空参数容忍，值不消费）
		default:
			ss.reply(555, "unsupported parameter") // 沿 U4 555 口径
			return
		}
	}
	ss.mailFrom = from
	ss.inTx = true
	ss.reply(250, "ok")
}

// rcpt RCPT TO（DSN NOTIFY/ORCPT 参数校验与透传；上限常量化）。
func (ss *submitSession) rcpt(arg string) {
	if !ss.inTx {
		ss.reply(503, "need MAIL first")
		return
	}
	to, paramsStr, ok := parsePathArg(arg)
	if !ok {
		ss.reply(501, "syntax error in address")
		return
	}
	if len(ss.rcpts) >= rcptMaxRecipients {
		// F4/B-F8：上限常量化（rfc5321bis §4.5.3.1.8 L3771-3773 MUST ≥100——本值即
		// MUST 最小值；应答 452 §4.5.3.1.10 L3833-3835——原有口径保持，行为零变化）。
		ss.reply(452, "too many recipients")
		return
	}
	rcptKey := strings.ToLower(to)
	for _, p := range strings.Fields(paramsStr) {
		kv := strings.SplitN(p, "=", 2)
		key := strings.ToUpper(kv[0])
		switch key {
		case "NOTIFY", "ORCPT":
			// F5/B-F9（提交端点对齐批）：重复检查——同 RCPT 内同参数 MUST NOT 超一次，
			// 超过 SHOULD 501（rfc3461 §4.5 L533-536；对齐 RET/ENVID 既有 mail() 形态）。
			for _, exist := range ss.dsnParams {
				if exist.Keyword == key && exist.Rcpt == rcptKey {
					ss.reply(501, "5.5.4 duplicate parameter")
					return
				}
			}
			if len(kv) != 2 || kv[1] == "" {
				ss.reply(501, "5.5.4 parameter value required")
				return
			}
			if key == "NOTIFY" && !validNotifyValue(kv[1]) {
				// rfc3461 §4.1 L355-363：NEVER 独占或 SUCCESS/FAILURE/DELAY 逗号列表（大小写任意）。
				ss.reply(501, "5.5.4 NOTIFY 参数非法（NEVER 或 SUCCESS,FAILURE,DELAY 列表）")
				return
			}
			if key == "ORCPT" && !validOrcptValue(kv[1]) {
				// rfc3461 §4.2 L412-422：addr-type;xtext 形态，整参 ≤500 字符。
				ss.reply(501, "5.5.4 ORCPT 参数非法（addr-type;xtext ≤500 octets）")
				return
			}
			ss.dsnParams = append(ss.dsnParams, mail.DSNParam{Keyword: key, Value: kv[1], Rcpt: rcptKey})
		default:
			ss.reply(555, "unsupported parameter")
			return
		}
	}
	ss.rcpts = append(ss.rcpts, rcptKey)
	ss.reply(250, "ok")
}

// validNotifyValue NOTIFY 参数值域校验（F5——rfc3461 §4.1 L355-363）：
// "NEVER" 独占（不得与列表混用）或 SUCCESS/FAILURE/DELAY 逗号列表（至少一项）；
// 关键字大小写任意（L365-366）。
func validNotifyValue(v string) bool {
	u := strings.ToUpper(v)
	if u == "NEVER" {
		return true
	}
	seen := false
	for _, el := range strings.Split(u, ",") {
		switch el {
		case "SUCCESS", "FAILURE", "DELAY":
			seen = true
		default:
			return false // 含 NEVER 混用/未知元素/空元素均拒
		}
	}
	return seen
}

// validOrcptValue ORCPT 参数值域校验（F5——rfc3461 §4.2 L412-422）：
// addr-type";"xtext 形态——恰一个分号且两侧非空（addr-type=atom 非空；xtext 非空），
// 整参 ≤500 字符（L421-422）。
func validOrcptValue(v string) bool {
	if len(v) > 500 {
		return false
	}
	return strings.Count(v, ";") == 1 && !strings.HasPrefix(v, ";") && !strings.HasSuffix(v, ";")
}

// data DATA 收流（<CRLF>.<CRLF> 终止；大小终判；dot 还原；Submit→250/451/550 映射）。
// F2/A-12（提交端点对齐批）：终止检测改复用 25 端点共享辅助 indexDataTerminator
// （位置 0 前缀特判——空消息首包 ".\r\n" 的前导 CRLF 由 354 应答行充当，
// rfc5321bis §4.1.1.4 L2206-2207；跨块回退扫描对齐 readData 母版——原
// bytesHasTerminator 尾缀匹配 len<5 恒假致空消息挂死缺陷修正）；
// F1/A-11：DATA 面大小终判（tooBig 标记+继续消费至终止序列保持协议同步+552
// ——rfc1870 §6.1 L231-233；SIZE 参数不用于判定内容结束 L201-202，终止检测
// 独立承载；实际大于声明未超上限仍接受——L235-238 permitted 宽容保持）。
func (ss *submitSession) data() {
	if !ss.inTx || len(ss.rcpts) == 0 {
		ss.reply(503, "need RCPT first")
		return
	}
	ss.reply(354, "End data with <CR><LF>.<CR><LF>")
	limit := ss.srv.cfg.MaxMessageSize()
	var raw []byte
	scanned := 0 // 已扫描偏移（终止序列跨块边界回退重扫——母版形态）
	tooBig := false
	for {
		_ = ss.conn.SetReadDeadline(time.Now().Add(dataIdleTimeout)) // F4：数据块 3min 逐块（rfc5321bis §4.5.3.2.5）
		chunk := make([]byte, readChunk)
		n, err := ss.rw.Reader.Read(chunk)
		if n > 0 {
			raw = append(raw, chunk[:n]...)
			// 自上次扫描点-3 回退扫描（终止序列最长跨块 4 字节——readData 母版同款）
			start := scanned - len(dataTerminator) + 1
			if start < 0 {
				start = 0
			}
			if idx := indexDataTerminator(raw, start); idx >= 0 {
				body := unstuffDots(raw[:idx])
				if tooBig || int64(len(body)) > limit {
					// F1：实际长度终判（超限标记或超限事实——552 rfc1870 §6.1 L231-233）
					ss.reply(552, "5.3.4 message size exceeds fixed maximum")
					ss.resetTx()
					return
				}
				// F6/B-F10：改传 ss.ctx（会话 LogID 链闭环——NFR-016）。
				res := ss.srv.pipeline.Submit(ss.ctx, &mail.Submission{
					// F-9：RemoteIP+TLSCipher 承载（MSA 接收 trace 头构造输入——rfc8314 §7.4）
					Envelope:   auth.Envelope{MailFrom: ss.mailFrom, Helo: "submission", RemoteIP: ss.remoteIP()},
					AuthUser:   ss.authUser,
					Recipients: ss.rcpts,
					DSNParams:  ss.dsnParams,
					TLSCipher:  ss.tlsCipherName(),
				}, body)
				// U15：插件拒绝识别（提交客户端可见——计划偏离裁决 A；纯增量 case）
				var pluginRej *mail.PluginRejectError
				switch {
				case res == nil:
					ss.reply(250, "ok: queued as accepted") // 已接受非已投递（流程设计 3.1）
				case errors.As(res, &pluginRej):
					ss.reply(pluginRej.Code, pluginRej.Message) // 插件给定码（4xx/5xx）
				case errors.Is(res, mail.ErrUnauthorized):
					ss.reply(550, "5.7.1 sender not authorized") // rfc6409 6.1/FR-002
				default:
					ss.reply(451, "temporary failure, try again") // ErrRetryable（CON-004 提交侧）
				}
				ss.resetTx()
				return
			}
			scanned = len(raw)
			if !tooBig && int64(len(raw)) > limit {
				tooBig = true // 标记后继续消费至终止序列（协议同步——母版语义）
			}
		}
		if err != nil {
			return
		}
	}
}

// resetTx 事务复位（RSET/EHLO/提交完成共用）。
func (ss *submitSession) resetTx() {
	ss.mailFrom = ""
	ss.rcpts = nil
	ss.inTx = false
	ss.dsnParams = nil
}

// ───────────────────────── 会话读写辅助 ─────────────────────────

func (ss *submitSession) readLine() (string, error) {
	line, err := ss.rw.Reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	ss.debugFrame("C", line) // U23 协议 debug（开启时输出——命令面）
	if len(line) > cmdLineLimit {
		// F4/B-F8（提交端点对齐批）：命令行超长哨兵（rfc5321bis §4.5.3.1.4/.9——
		// 行已整读保持流同步，调用方 500 后会话继续；cmdLineLimit=4096 同包常量）。
		return "", errLineTooLong
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readAuthLine AUTH 交换行读取（F3③/B-S10③——提交端点对齐批）。
// BASE64 挑战响应可远超命令行限（rfc4954 §4 L246-254——12288 octets 规范参考
// 上限 authLineLimit）；超限即 500+5.5.6（L255-259「fails the AUTH command with
// the 500 reply」+§6 L607-612「Authentication Exchange line is too long」），
// 哨兵由上层终止本次 AUTH。
// 参数：无（读一行）。返回：剥 CRLF 后的行；超限返回 errAuthLineTooLong（500 已发）。
func (ss *submitSession) readAuthLine() (string, error) {
	line, err := ss.rw.Reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	ss.debugFrame("C", line) // U23 协议 debug（开启时输出——AUTH 交换面）
	if len(line) > authLineLimit {
		ss.reply(500, "5.5.6 Authentication Exchange line is too long")
		return "", errAuthLineTooLong
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (ss *submitSession) reply(code int, text string) {
	ss.replyRaw(fmt.Sprintf("%d %s", code, text))
}

func (ss *submitSession) replyRaw(line string) {
	ss.debugFrame("S", line) // U23 协议 debug（开启时输出——应答面汇聚点，reply 委托此处）
	_, _ = ss.rw.Writer.WriteString(line + "\r\n")
	_ = ss.rw.Writer.Flush()
}

// debugFrame 协议 debug 条件输出（U23——H5 等价；快照关闭时零开销跳过）。
// 参数：dir 方向前缀（C=客户端来向/S=服务端去向）；line 原始行（不含行尾）。
// 说明：与 25 端点 session.debugFrame 平行实现（绑定类型不同——srv 为 *SubmissionServer，
// 禁止跨类型重构共用，保持最小侵入）；输出经 LoggerFromContext 显式取 ctx 内绑定 logger
// （slog-context 语义——标准门面不消费 ctx 内绑定，勿混用）。
func (ss *submitSession) debugFrame(dir, line string) {
	if ss.ctx == nil || !ss.srv.protocolDebug() {
		return
	}
	observability.LoggerFromContext(ss.ctx).Debug("submission_debug",
		"dir", dir, "frame", strings.TrimRight(line, "\r\n"))
}

// splitVerb 命令动词与参数切分。
func splitVerb(line string) (verb, arg string) {
	i := strings.IndexAny(line, " ")
	if i < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:i]), line[i+1:]
}

// （parsePathArg/unstuffDots/indexDataTerminator 复用 session.go U4 既有共享辅助，
// 不重复定义——F2/A-12 提交端点对齐批：终止检测并入单点共享，原
// bytesHasTerminator/stripTerminator 尾缀匹配实现随缺陷修正废除。）
