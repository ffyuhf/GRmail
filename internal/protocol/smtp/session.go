// SMTP 会话状态机：连接生命周期、命令解析与应答、DATA 收流（严格 CRLF/点透明性）、
// RCPT 三态判定、超时与限值。
// 依据：draft-ietf-emailcore-rfc5321bis-44 原文逐节对照（2026-09-17 规范纠偏后重写）——
// 4.1.1.2（MAIL 清空反向/前向/数据缓冲后置入反向路径）、4.1.1.4（DATA：终止序列
// <CRLF>.<CRLF>；裸 LF 行 MUST NOT 作为行终止；<LF>.<LF> MUST NOT 等价终止；
// 部分成功仍 MUST 250——本项目单事务原子无部分态）、4.1.4（MAIL 前必须 EHLO；
// VRFY/NOOP/RSET/HELP 不要求初始化；EHLO 重置如 RSET；顺序违规 503 且状态不变；
// QUIT 为最后命令）、4.5.2（点透明性：单点行终止、行首点剥一）、4.5.3.1.4（命令行
// 512 下限，扩展可增）、4.5.3.1.6（文本行 1000 不计透明点）、4.5.3.1.8（收件人
// 缓冲 ≥100，超限拒绝新增而非丢弃已接受）、4.5.3.1.9（超限应答 500/501/452/552）、
// 4.5.3.2.5（数据块 3 分钟）、4.5.3.2.7（命令等待 ≥5 分钟）；
// rfc1870 6.2（SIZE 声明超限 552 预检）、rfc3463（增强状态码）、rfc2920（PIPELINING：
// 逐行读逐行答满足批量发送客户端）。
//
//	U10 增量（Q8-A 裁决 2026-09-20 00:29）：25 收信端点 STARTTLS 可选升级——rfc3207 §4
//	原文锚点（STARTTLS 无参 501/220/454 临时不可用；§4.2 握手后协议重置至初始态、服务器
//	MUST 丢弃 EHLO 先验知识、TLS 会话中 MUST NOT 再通告；§4 L129-136 公开引用服务器
//	MUST NOT 强制 STARTTLS 才允许本地投递——明文收信能力保持）。
//
// U21 增量（协议 debug——H5 等价）：readLine/reply/replyMulti 命令应答面逐行条件输出
// （快照控制热生效；DATA 体不输出防刷屏）；范围口径见 debugFrame 注释。
// 修改历史：
//
//	2026-09-17 03:50:00 | 新建 | U4 SMTP 收信（计划书步骤 9）
//	2026-09-17 03:58:00 | 重写 | 规范纠偏：DATA 收流改字节级 <CRLF>.<CRLF> 终止扫描
//	（裸 LF 宽容违反 4.1.1.4 MUST NOT）；数据块超时 5→3 分钟（4.5.3.2.5）；
//	超长行 500 应答后会话继续（4.5.3.1.9）；MAIL 成功清空前向缓冲（4.1.1.2）
//	2026-09-20 00:53:00 | 扩展 | U10 STARTTLS 收口：inTLS 状态+命令分支+EHLO 条件通告（计划书步骤 5）
//	2026-09-27 06:19:00 | 扩展 | U21 可观测性增强：命令应答面协议 debug 条件输出
//	（readLine/reply/replyMulti 三埋点+session.ctx 字段+debugFrame 辅助——H5 等价）
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 4/1.5⑤）
//	2026-09-29 18:32:00 | 修正 | RFC候选修正批次 RF-I：F-8 无域 <Postmaster> 特判
//	（rfc5321bis §2.3.5 ABNF 无域形态+§4.5.1「MUST be supported」——映射本主域）
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
)

// 会话级常量（rfc5321bis 4.5.3；U4 计划书 1.5⑧⑨）。
const (
	cmdLineLimit    = 4096            // 命令行读缓冲上限（512 为规范下限，扩展放宽；超长 500）
	textLineLimit   = 1075            // DATA 文本行上限（1000+SMTPUTF8 余量，4.5.3.1.6）
	idleTimeout     = 5 * time.Minute // 命令间空闲（4.5.3.2.7 ≥5min）
	dataIdleTimeout = 3 * time.Minute // DATA 数据块间隔（4.5.3.2.5：3 Minutes）
	readChunk       = 8192            // DATA 字节扫描块大小
)

// dataTerminator DATA 终止序列（rfc5321bis 4.1.1.4：<CRLF>.<CRLF>）。
var dataTerminator = []byte("\r\n.\r\n")

// session 单连接会话状态（命令循环内独占，无并发竞争）。
type session struct {
	srv   *Server
	conn  net.Conn
	r     *bufio.Reader
	w     *bufio.Writer
	inTLS bool            // 是否已处 TLS 层（U10：STARTTLS 升级后置位——EHLO 通告与重复升级判定，rfc3207 §4.2）
	ctx   context.Context // 会话级上下文（U21 协议 debug 输出携带 log_id——serveConn 一次性赋值）

	// 会话状态（rfc5321bis 4.1.4 顺序表）
	helo     string     // EHLO/HELO 参数
	mailFrom string     // MAIL FROM 反向路径（""=空路径 <>）
	mailOpts mailParams // MAIL 参数（SIZE/BODY/SMTPUTF8）与事务标记
	rcpts    []string   // 已接受收件人（上限 MaxRecipients，4.5.3.1.8）
}

// serveConn 服务单连接：横幅→命令循环→QUIT/关闭。
func (s *Server) serveConn(conn net.Conn) {
	// LogID 全链路锚点（NFR-016：连接入口生成，ctx 贯穿会话→管道→落库日志）
	ctx := observability.LoggerIntoContext(context.Background(),
		slog.Default().With("logid", observability.NewLogID(), "proto", "smtp", "remote", conn.RemoteAddr().String()))

	sess := &session{srv: s, conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn), ctx: ctx}
	defer func() { _ = conn.Close() }()
	slog.InfoContext(ctx, "SMTP 连接建立")

	sess.reply(ctx, 220, fmt.Sprintf("%s ESMTP GRmail", s.cfg.Domain))
	sess.commandLoop(ctx)
	slog.InfoContext(ctx, "SMTP 连接关闭")
}

// commandLoop 命令循环：逐行读取并分发（PIPELINING 兼容：客户端批量发送时逐行逐答）。
func (sess *session) commandLoop(ctx context.Context) {
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		line, err := sess.readLine()
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				// 4.5.3.1.9：超长行应答 500，会话可继续（行剩余部分已被 readLine 消费）
				sess.reply(ctx, 500, "5.5.2 行超长")
				continue
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				sess.reply(ctx, 421, "4.4.2 超时未收到命令，连接关闭")
			}
			return // 对端关闭/IO 错误/超时：结束会话
		}
		verb, arg := splitCommand(line)
		switch verb {
		case "EHLO":
			sess.cmdEhlo(ctx, arg, true)
		case "HELO":
			sess.cmdEhlo(ctx, arg, false)
		case "STARTTLS":
			sess.cmdStartTLS(ctx, arg) // U10：可选升级（rfc3207 §4——明文收信照常，不强制）
		case "MAIL":
			sess.cmdMail(ctx, arg)
		case "RCPT":
			sess.cmdRcpt(ctx, arg)
		case "DATA":
			if done := sess.cmdData(ctx); done {
				return
			}
		case "RSET":
			sess.resetTransaction()
			sess.reply(ctx, 250, "2.0.0 OK")
		case "NOOP":
			sess.reply(ctx, 250, "2.0.0 OK")
		case "QUIT":
			sess.reply(ctx, 221, "2.0.0 再见")
			return
		case "VRFY":
			sess.reply(ctx, 252, "2.5.2 无法验证用户，但将尝试投递")
		case "HELP":
			sess.reply(ctx, 214, "支持：EHLO HELO MAIL RCPT DATA RSET NOOP QUIT VRFY")
		case "":
			sess.reply(ctx, 500, "5.5.2 空命令")
		default:
			sess.reply(ctx, 500, fmt.Sprintf("5.5.2 未识别命令：%s", verb))
		}
	}
}

// ───────────────────────── 命令实现 ─────────────────────────

// cmdEhlo EHLO/HELO 处理：登记 helo 并如 RSET 重置事务（4.1.4），返回能力通告
// （1.5⑦：SIZE/8BITMIME/SMTPUTF8/PIPELINING/ENHANCEDSTATUSCODES；U10 Q8-A：证书就绪
// 且未处 TLS 时增通告 STARTTLS——Q3-B「无 TLS」经 U10 收口为「证书未就绪不通告」；
// 无认证——25 收信端点恒不通告 AUTH）。
func (sess *session) cmdEhlo(ctx context.Context, arg string, esmtp bool) {
	if arg == "" {
		sess.reply(ctx, 501, "5.5.4 域名参数缺失")
		return
	}
	sess.helo = arg
	sess.resetTransaction() // 4.1.4：EHLO MUST 如 RSET 清缓冲
	domain := sess.srv.cfg.Domain
	if !esmtp {
		sess.reply(ctx, 250, fmt.Sprintf("%s 你好", domain))
		return
	}
	// 多行能力通告（rfc5321bis 4.1.1.1：末行 250，余行 250-）
	caps := []string{
		fmt.Sprintf("%s 你好", domain),
		fmt.Sprintf("SIZE %d", sess.srv.cfg.MaxMessageSize()),
		"8BITMIME",
		"SMTPUTF8",
		"PIPELINING",
		"ENHANCEDSTATUSCODES",
	}
	// U10：STARTTLS 条件通告——证书就绪（TLSConfig 非 nil 且返回非 nil）且未处 TLS 会话
	// （rfc3207 §4.2 TLS 会话中 MUST NOT 再通告；rfc8314 §4 L374-376 无证书 SHOULD NOT 通告）
	if !sess.inTLS && sess.srv.cfg.TLSConfig != nil && sess.srv.cfg.TLSConfig() != nil {
		caps = append(caps, "STARTTLS")
	}
	sess.replyMulti(ctx, 250, caps...)
}

// cmdStartTLS STARTTLS 可选升级（U10 Q8-A；rfc3207 §4 原文锚点：
// 已处 TLS→503 禁重复（§4.2）；带参→501（无参数）；证书未就绪→454 临时不可用（§4）；
// 220→TLS 握手→握手失败断连（§4.1）；成功后协议重置至初始态——服务器 MUST 丢弃 EHLO
// 等先验知识（§4.2）；DATA 前不强制 TLS——公开引用服务器 MUST NOT 强制 STARTTLS 才许
// 本地投递（§4 L129-136），本命令全程可选）。
func (sess *session) cmdStartTLS(ctx context.Context, arg string) {
	if sess.inTLS {
		sess.reply(ctx, 503, "5.5.1 TLS 已激活，禁止重复 STARTTLS")
		return
	}
	if arg != "" {
		sess.reply(ctx, 501, "5.5.4 STARTTLS 不接受参数")
		return
	}
	if sess.srv.cfg.TLSConfig == nil {
		sess.reply(ctx, 454, "4.7.0 TLS 暂不可用（未配置）") // 旧装配形态（U10 前构造）零崩溃兜底
		return
	}
	tc := sess.srv.cfg.TLSConfig()
	if tc == nil {
		sess.reply(ctx, 454, "4.7.0 TLS 暂不可用（证书未就绪）")
		return
	}
	sess.reply(ctx, 220, "2.0.0 准备启动 TLS")
	tlsConn := tls.Server(sess.conn, tc)
	if err := tlsConn.Handshake(); err != nil {
		slog.InfoContext(ctx, "STARTTLS 握手失败，断开连接", "error", err)
		return // 握手失败断连（rfc3207 §4.1——后续读写已无意义）
	}
	sess.inTLS = true
	// 协议重置（rfc3207 §4.2）：丢弃先验知识+事务缓冲
	sess.helo = ""
	sess.resetTransaction()
	// 连接层替换：deadline/读写/close 全走 TLS 层（Close 传导底层；沿提交端点先例）
	sess.conn = tlsConn
	sess.r = bufio.NewReader(tlsConn)
	sess.w = bufio.NewWriter(tlsConn)
	slog.InfoContext(ctx, "STARTTLS 升级完成（25 端口可选 TLS）")
}

// cmdMail MAIL FROM 处理：顺序校验（4.1.4 MAIL 前必须 EHLO；事务中 MAIL 禁止）→
// 路径与参数解析→SIZE 预检（rfc1870 6.2）→成功清空前向/数据缓冲（4.1.1.2）。
func (sess *session) cmdMail(ctx context.Context, arg string) {
	if sess.helo == "" {
		sess.reply(ctx, 503, "5.5.1 需要 EHLO/HELO 先行")
		return
	}
	if sess.mailOpts.started {
		sess.reply(ctx, 503, "5.5.1 已有 MAIL 事务，需 RSET")
		return
	}
	path, params, ok := parsePathArg(arg)
	if !ok {
		sess.reply(ctx, 501, "5.5.4 语法错误（应为 MAIL FROM:<path> [参数]）")
		return
	}
	opts, code, msg := parseMailParams(params, sess.srv.cfg.MaxMessageSize())
	if code != 0 {
		sess.reply(ctx, code, msg)
		return
	}
	// 4.1.1.2：MAIL 清空反向/前向/数据缓冲后置入反向路径（防御：清残留前向路径）
	sess.rcpts = nil
	sess.mailFrom = path
	sess.mailOpts = opts
	sess.reply(ctx, 250, "2.1.0 发件人确认")
}

// cmdRcpt RCPT TO 处理：顺序校验→地址规范化→本域判定（防开放中继）→三态判定
// （关键流程设计第二章；disabled 拒绝/CatchAll 关闭拒绝均为 1.5⑥ 口径）。
func (sess *session) cmdRcpt(ctx context.Context, arg string) {
	if !sess.mailOpts.started {
		sess.reply(ctx, 503, "5.5.1 需要 MAIL FROM 先行")
		return
	}
	if len(sess.rcpts) >= sess.srv.cfg.MaxRecipients {
		// 4.5.3.1.8：超限拒绝新增（不丢弃已接受地址）；4.5.3.1.9：452
		sess.reply(ctx, 452, "4.5.3 收件人过多，请分批提交")
		return
	}
	addr, _, ok := parsePathArg(arg)
	if !ok || addr == "" {
		sess.reply(ctx, 501, "5.5.4 语法错误（应为 RCPT TO:<地址>）")
		return
	}
	// RF-I/F-8：无域 <Postmaster> 特判（rfc5321bis §2.3.5 L2176-2177 ABNF
	// "<Postmaster>" 无域形态+§4.5.1 L3628-3630「MUST be supported」；大小写
	// 不敏感——L2179-2180；映射本主域后走既有三态判定全链）
	if strings.EqualFold(strings.TrimSpace(addr), "postmaster") {
		addr = "postmaster@" + sess.srv.cfg.Domain
	}
	local, domain, err := normalizeAddress(addr)
	if err != nil {
		sess.reply(ctx, 501, "5.5.4 邮箱地址非法")
		return
	}
	if !strings.EqualFold(domain, sess.srv.cfg.Domain) {
		slog.WarnContext(ctx, "RCPT 非本域拒绝（防开放中继）", "addr", addr)
		sess.reply(ctx, 550, "5.7.1 非本域收件人，拒绝中继")
		return
	}
	m, err := sess.srv.accounts.GetMailbox(ctx, local+"@"+domain)
	switch {
	case err == nil && m.Status == storage.MailboxStatusActive:
		sess.rcpts = append(sess.rcpts, m.Address)
		sess.reply(ctx, 250, "2.1.5 收件人确认")
	case err == nil && m.Status == storage.MailboxStatusShadow:
		sess.rcpts = append(sess.rcpts, m.Address) // 影子归档（FR-004）
		sess.reply(ctx, 250, "2.1.5 收件人确认")
	case err == nil:
		sess.reply(ctx, 550, "5.2.1 邮箱当前不可用（已禁用）")
	case errors.Is(err, storage.ErrMailboxNotFound):
		if !sess.srv.cfg.CatchAllEnabled() {
			sess.reply(ctx, 550, "5.1.1 邮箱不存在")
			return
		}
		// 不存在+CatchAll 开启：接受（DATA 后管道建影子归档——FR-004 判定①）
		sess.rcpts = append(sess.rcpts, local+"@"+domain)
		sess.reply(ctx, 250, "2.1.5 收件人确认")
	default:
		slog.ErrorContext(ctx, "RCPT 查询失败", "addr", addr, "error", err)
		sess.reply(ctx, 451, "4.4.3 临时目录故障，请稍后重试")
	}
}

// cmdData DATA 处理：字节级收流（<CRLF>.<CRLF> 终止+点透明还原+SIZE 累计双闸）→
// 管道投递→应答映射（451/250——CON-004；部分成功场景因单事务原子而不存在，4.1.1.4）。
// 返回 true 表示会话终止（仅 DATA 阶段 IO 失败）。
func (sess *session) cmdData(ctx context.Context) bool {
	if len(sess.rcpts) == 0 {
		sess.reply(ctx, 503, "5.5.1 需要 RCPT TO 先行")
		return false
	}
	sess.reply(ctx, 354, "开始邮件输入，以 <CRLF>.<CRLF> 结束")

	raw, tooBig, err := sess.readData()
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			sess.reply(ctx, 421, "4.4.2 数据接收超时，连接关闭")
		}
		return true // IO 层失败：会话不可继续
	}
	if tooBig {
		sess.reply(ctx, 552, "5.3.4 邮件超过大小上限")
		sess.resetTransaction()
		return false
	}

	// 管道投递（契约 v1.1.0 2.3）：应答码语义由返回值决定（451/250——CON-004）
	deliverErr := sess.srv.pipeline.Deliver(ctx, &mail.Delivery{
		Envelope: auth.Envelope{
			Helo:     sess.helo,
			RemoteIP: remoteIP(sess.conn),
			MailFrom: sess.mailFrom,
		},
		Recipients: sess.rcpts,
	}, raw)
	sess.resetTransaction()
	// U15：插件拒绝识别（对端可见——计划偏离裁决 A 2026-09-24 10:53:12；纯增量
	// case：无 PluginRejectError 时完全走原路径，行为与 U14b 末态一致）
	var pluginRej *mail.PluginRejectError
	switch {
	case deliverErr == nil:
		sess.reply(ctx, 250, "2.0.0 OK：投递已受理")
	case errors.As(deliverErr, &pluginRej):
		slog.InfoContext(ctx, "插件拒绝投递（对端可见）", "plugin", pluginRej.Plugin, "code", pluginRej.Code)
		sess.reply(ctx, pluginRej.Code, pluginRej.Message)
	case errors.Is(deliverErr, mail.ErrRetryable):
		slog.WarnContext(ctx, "投递临时失败（451）", "error", deliverErr)
		sess.reply(ctx, 451, "4.3.0 落库临时失败，请稍后重试")
	default:
		// 管道异常同样禁止 250（CON-004 精神）：451 促对端重试
		slog.ErrorContext(ctx, "投递异常（451）", "error", deliverErr)
		sess.reply(ctx, 451, "4.3.0 投递处理异常，请稍后重试")
	}
	return false
}

// readData DATA 阶段字节级收流（rfc5321bis 4.1.1.4/4.5.2 严格语义）：
// - 终止序列 <CRLF>.<CRLF> 字节扫描（流首 ".\r\n" 视为空消息终止）；
// - 裸 LF 不作为行终止（4.1.1.4 MUST NOT——<LF>.<LF> 不触发终止，作为数据字节保留）；
// - 终止序列首 CRLF 即最后一行行尾：消息字节=内容+单次 CRLF 收尾（不加多余空行）；
// - 点透明还原（4.5.2）：CRLF 行界后的行首点剥一（单点行已被终止逻辑消费）；
// - SIZE 累计超限即短路标记，继续消费至终止序列保持协议同步后返回（552 由调用方应答）。
// 返回：消息字节、是否超限、IO 错误。
func (sess *session) readData() ([]byte, bool, error) {
	limit := sess.srv.cfg.MaxMessageSize()
	var buf []byte
	scanned := 0 // 已扫描偏移（终止序列跨块边界回退 4 字节重扫）
	tooBig := false

	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(dataIdleTimeout))
		chunk := make([]byte, readChunk)
		n, err := sess.conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			// 自上次扫描点-3 回退扫描（终止序列最长跨块 4 字节）
			start := scanned - len(dataTerminator) + 1
			if start < 0 {
				start = 0
			}
			if idx := indexDataTerminator(buf, start); idx >= 0 {
				msg := unstuffDots(buf[:idx])
				// 超限以实际消息长度终判（单块读入时累计标记尚未置位的路径——缺陷修正 2026-09-17）
				return msg, tooBig || int64(len(msg)) > limit, nil
			}
			scanned = len(buf)
			if !tooBig && int64(len(buf)) > limit {
				tooBig = true // 标记后继续消费至终止序列（协议同步）
			}
		}
		if err != nil {
			return nil, false, err
		}
	}
}

// indexDataTerminator 自 start 起扫描终止序列 <CRLF>.<CRLF>；
// 位置 0 特例：缓冲以 ".\r\n" 开头（354 后立即终止的空消息，前导 CRLF 由应答行充当）。
func indexDataTerminator(buf []byte, start int) int {
	if idx := bytes.Index(buf[min(start, len(buf)):], dataTerminator); idx >= 0 {
		return idx + start
	}
	if bytes.HasPrefix(buf, []byte(".\r\n")) {
		return 0 // 空消息：终止序列前半（CRLF）即 354 应答行尾
	}
	return -1
}

// unstuffDots 点透明还原（rfc5321bis 4.5.2 接收侧）：仅 CRLF 行界后的行首点剥一
// （裸 LF 后的点为数据字节——4.1.1.4 MUST NOT 语义，缺陷修正 2026-09-17）；
// 消息末行收尾补单次 CRLF（终止序列首 CRLF 为该行行尾——不加多余空行，4.1.1.4）。
func unstuffDots(content []byte) []byte {
	if len(content) == 0 {
		return nil // 空消息
	}
	out := make([]byte, 0, len(content)+2)
	lineStart := true // 缓冲起点视同行首
	prevCR := false   // 前一字节为 CR（CRLF 序列追踪）
	for _, b := range content {
		if lineStart && b == '.' {
			// 行首点剥一（单点行已被终止逻辑消费，此处必有后续内容字节）
			lineStart, prevCR = false, false
			continue
		}
		out = append(out, b)
		lineStart = prevCR && b == '\n' // 仅 CRLF 之后为行首
		prevCR = b == '\r'
	}
	out = append(out, '\r', '\n') // 末行行尾（终止序列首 CRLF 语义）
	return out
}

// ───────────────────────── 会话辅助 ─────────────────────────

// reply 写单行应答。
func (sess *session) reply(ctx context.Context, code int, text string) {
	line := fmt.Sprintf("%d %s\r\n", code, text)
	sess.debugFrame("S", line) // U21 协议 debug（开启时输出）
	if _, err := sess.w.WriteString(line); err != nil {
		slog.WarnContext(ctx, "SMTP 应答写失败", "error", err)
		return
	}
	_ = sess.w.Flush()
}

// replyMulti 多行应答（EHLO 能力通告；rfc5321bis 4.2：非末行 code-，末行 code 空格）。
func (sess *session) replyMulti(ctx context.Context, code int, lines ...string) {
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		line := fmt.Sprintf("%d%s%s\r\n", code, sep, l)
		sess.debugFrame("S", line) // U21 协议 debug（开启时输出）
		if _, err := sess.w.WriteString(line); err != nil {
			slog.WarnContext(ctx, "SMTP 应答写失败", "error", err)
			return
		}
	}
	_ = sess.w.Flush()
}

// readLine 读取一行（剥 CRLF/LF；超长消费行尾后返回哨兵由调用方 500——4.5.3.1.9）。
// F5（B-S8，访问协议资源限制批）：ReadSlice 循环计数形态——原 bufio.ReadLine 依赖
// 默认 4096 缓冲返回 raw ≤4095，`len(raw) > cmdLineLimit(4096)` 恒假、errLineTooLong
// 从未触发（超长命令被静默吞并剩余段、末段按整行处理）。现累计长度超限即标记，
// 继续消费至行尾保持流同步（衔接既有"消费超长行剩余部分"语义），返回哨兵走
// 500 应答实际生效（rfc5321bis §4.5.3.1.9）；零额外内存累积（分块判定）。
func (sess *session) readLine() (string, error) {
	var buf []byte
	tooLong := false
	for {
		seg, err := sess.r.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull {
			return "", err // IO 错误/对端关闭（半行数据丢弃——未完成命令无语义）
		}
		if !tooLong && len(buf)+len(seg) > cmdLineLimit {
			tooLong = true // 超长标记——本行作废，继续消费至行尾（协议同步）
		}
		if !tooLong {
			buf = append(buf, seg...)
		}
		if err == bufio.ErrBufferFull {
			continue // 行未完（缓冲满，seg 已并入）——继续读取
		}
		if err != nil {
			return "", err
		}
		break // 行完成（含 '\n'）
	}
	if tooLong {
		return "", errLineTooLong
	}
	line := strings.TrimRight(string(buf), "\r\n")
	sess.debugFrame("C", line+"\r\n") // U21 协议 debug（开启时输出——命令面）
	return line, nil
}

// debugFrame 协议 debug 条件输出（U21——H5 等价；快照关闭时零开销跳过）。
// 参数：dir 方向前缀（C=客户端来向/S=服务端去向）；line 含 CRLF 的原始行。
// 范围口径：命令/应答面逐行输出；DATA 与多行邮件体不输出（防刷屏——排障对象为交互）。
// logger 取法：经 observability.LoggerFromContext 显式取 ctx 绑定 logger（slog-context
// 语义——slog.DebugContext 标准门面不消费 ctx 内绑定，勿混用）。
func (sess *session) debugFrame(dir, line string) {
	if sess.ctx == nil || !sess.srv.protocolDebug() {
		return
	}
	observability.LoggerFromContext(sess.ctx).Debug("smtp_debug", "proto", "smtp", "dir", dir, "data", strings.TrimRight(line, "\r\n"))
}

// resetTransaction 事务复位（RSET/投递完成/EHLO；rfc5321bis 4.1.1.2/4.1.4）。
func (sess *session) resetTransaction() {
	sess.mailFrom = ""
	sess.mailOpts = mailParams{}
	sess.rcpts = nil
}

// remoteIP 提取对端 IP（TCP RemoteAddr）。
func remoteIP(conn net.Conn) net.IP {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.IP
	}
	return nil
}

// ───────────────────────── 解析辅助（rfc5321bis 4.1.2 宽容解析） ─────────────────────────

// splitCommand 拆分命令动词与参数（动词大写归一；MAIL FROM:/RCPT TO: 冒号归入动词段）。
func splitCommand(line string) (verb, arg string) {
	line = strings.TrimRight(line, "\r\n")
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == ':' {
			return strings.ToUpper(line[:i]), strings.TrimSpace(line[i+1:])
		}
	}
	return strings.ToUpper(line), ""
}

// parsePathArg 解析 "FROM:<path> k=v" / "TO:<addr>" 形态（宽容无尖括号）。
// 返回：地址（空串=空路径 <>）、MAIL 参数段、是否可解析。
func parsePathArg(arg string) (path string, params string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" || !strings.Contains(arg, ":") {
		return "", "", false
	}
	idx := strings.Index(arg, ":")
	rest := strings.TrimSpace(arg[idx+1:])
	if strings.HasPrefix(rest, "<") {
		end := strings.Index(rest, ">")
		if end < 0 {
			return "", "", false
		}
		return strings.TrimSpace(rest[1:end]), strings.TrimSpace(rest[end+1:]), true
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", "", true // <> 空路径无括号宽容（MAIL 合法；RCPT 由调用方拒空地址）
	}
	return fields[0], strings.Join(fields[1:], " "), true
}

// mailParams MAIL 参数承载（rfc1870 SIZE/rfc6152 BODY/rfc6531 SMTPUTF8；
// started=MAIL 事务标记——空路径 <> 时 mailFrom 为空串，事务存在性以此判定）。
type mailParams struct {
	started    bool
	smtpUTF8   bool
	body8Bit   bool
	declaredSZ int64
}

// parseMailParams 解析 MAIL 参数（1.5⑩：参数接受并透传存档；
// SIZE 声明值超上限 552 预检拒绝——rfc1870 6.2）。
// 返回：参数集；code 非 0 表示应答回复（code/msg 就绪）。
func parseMailParams(params string, maxSize int64) (p mailParams, code int, msg string) {
	p.started = true
	for _, kv := range strings.Fields(params) {
		key, val, _ := strings.Cut(strings.ToUpper(kv), "=")
		switch key {
		case "SIZE":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n < 0 {
				return p, 501, "5.5.4 SIZE 参数非法"
			}
			if n > maxSize {
				return p, 552, "5.3.4 声明大小超过上限（SIZE 预检）"
			}
			p.declaredSZ = n
		case "BODY":
			if val == "8BITMIME" {
				p.body8Bit = true
			} else if val != "7BIT" {
				return p, 501, "5.5.4 BODY 参数非法（7BIT|8BITMIME）"
			}
		case "SMTPUTF8":
			p.smtpUTF8 = true
		case "":
			// 空段忽略
		default:
			return p, 555, "5.5.4 不支持的 MAIL 参数"
		}
	}
	return p, 0, ""
}

// normalizeAddress 地址小写规范化与结构校验（与 account.NormalizeAddress 同口径的
// 接入层副本——避免接入层依赖业务包；两处口径由测试对齐锁定）。
func normalizeAddress(addr string) (local, domain string, err error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 || len(addr) > 320 || len(addr[:at]) > 64 || len(addr[at+1:]) > 255 {
		return "", "", fmt.Errorf("地址非法: %s", addr)
	}
	if strings.ContainsAny(addr, " \t\r\n\x00") {
		return "", "", fmt.Errorf("地址含非法字符: %s", addr)
	}
	return addr[:at], addr[at+1:], nil
}

// errLineTooLong 超长行哨兵（调用方按 4.5.3.1.9 以 500 继续）。
var errLineTooLong = errors.New("smtp: 行超长")
