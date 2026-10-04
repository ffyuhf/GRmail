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

// SubmissionConfig 提交端点配置。
type SubmissionConfig struct {
	Domain         string             // 主域名（EHLO 应答/横幅）
	MaxMessageSize func() int64       // SIZE 通告（快照；nil=35MiB）
	TLSConfig      func() *tls.Config // 服务端 TLS（动态快照；nil=证书未就绪——TLS 端点不启动且 587 不通告 STARTTLS，rfc3207 4.1）
	ProtocolDebug  func() bool        // 协议 debug 快照（U23——config Log.ProtocolDebug；nil=false 缺省热生效，命令应答面条件输出）
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
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute)) // rfc5321bis 4.5.3.2 idle
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
		line, err := sess.readLine()
		if err != nil {
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
			sess.startTLS(conn)
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
func (ss *submitSession) startTLS(conn net.Conn) {
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
		return // 应答已在内部发出（取消/解码失败）
	}
	if err = ss.srv.verifier.VerifyCredentials(context.Background(), strings.ToLower(user), pass); err != nil {
		ss.reply(535, "authentication failed") // rfc4954 4：535（防枚举统一口径归 U2）
		return
	}
	ss.authUser = strings.ToLower(user)
	ss.reply(235, "authenticated") // rfc4954 4：235
}

// authPLAIN PLAIN 机制（initial-response 或 334 追问；解码 authzid\0authcid\0passwd）。
func (ss *submitSession) authPLAIN(initial string) (user, pass string, err error) {
	resp := initial
	if resp == "" {
		ss.reply(334, "") // 空挑战
		resp, err = ss.readLine()
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
		user, err = ss.readLine()
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
	pass, err = ss.readLine()
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

// rcpt RCPT TO（DSN NOTIFY/ORCPT 参数透传；上限）。
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
	if len(ss.rcpts) >= 100 {
		ss.reply(452, "too many recipients") // rfc5321bis 4.5.3.1.8
		return
	}
	for _, p := range strings.Fields(paramsStr) {
		kv := strings.SplitN(p, "=", 2)
		switch strings.ToUpper(kv[0]) {
		case "NOTIFY", "ORCPT":
			if len(kv) == 2 {
				ss.dsnParams = append(ss.dsnParams, mail.DSNParam{Keyword: strings.ToUpper(kv[0]), Value: kv[1], Rcpt: strings.ToLower(to)})
			}
		default:
			ss.reply(555, "unsupported parameter")
			return
		}
	}
	ss.rcpts = append(ss.rcpts, strings.ToLower(to))
	ss.reply(250, "ok")
}

// data DATA 收流（<CRLF>.<CRLF> 终止；dot 还原；Submit→250/451/550 映射）。
func (ss *submitSession) data() {
	if !ss.inTx || len(ss.rcpts) == 0 {
		ss.reply(503, "need RCPT first")
		return
	}
	ss.reply(354, "End data with <CR><LF>.<CR><LF>")
	var raw []byte
	buf := make([]byte, 4096)
	lineStart := true
	for {
		n, err := ss.rw.Reader.Read(buf)
		if err != nil {
			return
		}
		raw = append(raw, buf[:n]...)
		// 终止序列检测：尾部 ".\r\n" 且其前为行首（简化扫描——数据完整性由终止点判定）
		if n > 0 && bytesHasTerminator(raw) {
			body := stripTerminator(raw)
			body = unstuffDots(body)
			res := ss.srv.pipeline.Submit(context.Background(), &mail.Submission{
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
		_ = lineStart
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

// （parsePathArg/unstuffDots 复用 session.go U4 既有辅助，不重复定义）

// bytesHasTerminator 数据尾部 <CRLF>.<CRLF> 检测。
func bytesHasTerminator(raw []byte) bool {
	if len(raw) < 5 {
		return false
	}
	return strings.HasSuffix(string(raw), "\r\n.\r\n")
}

// stripTerminator 剥除尾部终止序列。
func stripTerminator(raw []byte) []byte {
	return raw[:len(raw)-5]
}
