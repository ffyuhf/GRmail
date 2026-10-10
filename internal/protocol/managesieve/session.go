// managesieve 会话（rfc5804 §1-§2——R1-A 自研）。
// 规范锚点：§1.1（命令与响应：OK/NO/BYE 文本；能力协商连接即推+STARTTLS/AUTH 后
// 重推）；§1.7（IMPLEMENTATION/SIEVE/VERSION 三 MUST+STARTTLS+SASL 空 iff STARTTLS
// +认证后 OWNER+MAXREDIRECTS）；§1.2（字面量 {n+}/{n} 与引号串）；§2 命令族
// （AUTHENTICATE/STARTTLS/CAPABILITY/PUTSCRIPT/GETSCRIPT/SETACTIVE/DELETESCRIPT/
// LISTSCRIPTS/HAVESPACE/CHECKSCRIPT/NOOP/RENAMESCRIPT/LOGOUT——VERSION "1.0" 全集）。
// 认证：AUTHENTICATE "PLAIN"（rfc4616 三段式 authzid NUL authcid NUL passwd——
// 沿 U7 AUTH PLAIN 先例；明文连接一律 NO——NFR-006）。
// U23 增量（协议 debug——U21 登记项②收口，H5 等价）：readLine 命令面+writeOK/writeNO/
// writeBye/writeCapabilities 响应面逐帧条件输出（快照控制热生效；字面量 {n+} 脚本体经
// readLiteralBytes 读取不经 readLine 埋点——PUTSCRIPT 大体量防刷屏，与 SMTP DATA 口径一致）。
// SCRAM认证批增量（v1.39.0——G2 批准 2026-10-09 23:37:36 候选全 A）：AUTHENTICATE 增
// SCRAM-SHA-1 机制（rfc5804 §1.6 L692-694「MUST implement the SCRAM-SHA-1」缺口
// 实施——B-S 批 F3「之后做」裁决兑现；rfc5802 §5 四步交换/§5.1 SASLprep 与 =2C/=3D
// 转义/§6 gs2 通道绑定旗标〔n/y 接受、p 拒——服务端无 -PLUS 通告〕/§7 文法）。
// 修改历史：
//
//	2026-09-21 01:00:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 8）
//	2026-09-23 12:56:00 | 修正 | U12b 装配收口：writeCapabilities 补 Flush（连接即推能力
//	滞留 bufio 缓冲致客户端死锁——loopback 测试驱动发现，缺陷修正①）
//	（依据：U12b 计划书 v1.0.0 步骤 3，G2 批准 2026-09-23 12:49:06；rfc5804 §1.1 能力协商）
//
// 2026-09-27 13:42:00 | 扩展 | U23 可观测性扩展：命令响应面协议 debug 条件输出
// （debugFrame 辅助+readLine/writeOK/writeNO/writeBye/writeCapabilities 五埋点）
// （来源：G2 批准 2026-09-27 13:20:53，U23 计划书 v1.0.0 步骤 5/1.5⑤）
// 2026-10-10 16:05:00 | 优化 | C级债务收尾批（G2 批准 2026-10-10 15:45:40）：
//
//	F9/C20 SIEVE 通告串单源化（sieve.SupportedCapabilities 派生——原双源独立
//	字面量分叉根治）+F10/C21 RENAMESCRIPT 改调 storage 原子 RenameScript
//	（原三步非事务中途失败残留双名脚本收口）
package managesieve

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/auth"
	"GRmail/internal/observability"
	"GRmail/internal/sieve"
	"GRmail/internal/storage"
)

// implementationName IMPLEMENTATION 能力值。
const implementationName = "GRmail Sieve (U12 R1-A)"

// sieveCapability SIEVE 能力通告串（F9/C20 单源化——2026-10-10 C级债务收尾批：
// sieve.SupportedCapabilities 有序列表派生+comparator 双值尾接——parser require
// 校验集与协议通告的同一事实来源〔原双源独立字面量分叉根治〕；产物与原串
// 逐字节一致——兼容锚；新增能力仅改 sieve.SupportedCapabilities 一处）。
// comparator 双值按 rfc5228 §6.2.3 初始注册「comparator-*」形态通告（D8#6——
// G2 批准 2026-09-30 23:40:58）。
var sieveCapability = strings.Join(slices.Concat(
	sieve.SupportedCapabilities,
	[]string{"comparator-i;octet", "comparator-i;ascii-casemap"},
), " ")

// session 单连接会话状态机（未认证→已认证两态）。
type session struct {
	ctx      context.Context
	cfg      ServerConfig
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	inTLS    bool   // STARTTLS 已升级
	authed   bool   // AUTHENTICATE 已成功
	mboxID   int64  // 已认证邮箱 ID
	mboxAdr  string // 已认证邮箱地址（OWNER 能力）
	quitting bool
	// B-S批 F4（裁决 A 2026-10-09 13:34）：challenge 轮应答帧掩码标志——
	// cmdAuthenticate 发空 challenge 后置位，下一 readLine 为 base64 凭据应答
	authRedact bool
}

// scramExchange SCRAM-SHA-1 握手会话态（v1.39.0——rfc5802 §5 交换承载）。
// 哈希口径：AuthMessage 各分量用原文逐字拼接（§5.1 n 属性「MUST use it as received
// in hash calculations」——SASLprep 仅作查找键，不改哈希输入）。
type scramExchange struct {
	authcid         string                    // SASLprep 后查找键（库内小写地址）
	clientFirstBare string                    // client-first-message-bare 原文（AuthMessage 首分量）
	gs2Header       string                    // "n,," / "y,,"（c= 期望值的 base64 源——§7 cbind-input）
	clientNonce     string                    // 客户端 nonce 原文（组合 nonce 前缀）
	serverFirst     string                    // server-first 原文（AuthMessage 中分量）
	combinedNonce   string                    // 组合 nonce（client-final r= 须逐字相等——§5.1 MUST verify）
	creds           *storage.SCRAMCredentials // 服务端四元组（伪装态=DummySalt/全零键——proof 恒败防枚举）
}

// newSession 构造会话。
func newSession(ctx context.Context, conn net.Conn, cfg ServerConfig) *session {
	return &session{
		ctx: ctx, cfg: cfg, conn: conn,
		br: bufio.NewReader(conn), bw: bufio.NewWriter(conn),
	}
}

// run 会话主循环（连接即推能力 §1.7；逐行命令循环）。
func (s *session) run() {
	s.writeCapabilities()
	for !s.quitting {
		line, err := s.readLine()
		if err != nil {
			return // 连接结束/IO 错误
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if !s.dispatch(line) {
			return // BYE 后终止
		}
	}
}

// dispatch 命令分派（返回 false=会话终止）。
func (s *session) dispatch(line string) bool {
	tokens := strings.Fields(line)
	cmd := strings.ToLower(tokens[0])
	switch cmd {
	case "capability":
		s.writeCapabilities()
		s.writeOK("能力已重推")
	case "noop":
		s.writeOK("NOOP")
	case "logout":
		s.writeBye("再见")
		return false
	case "starttls":
		s.cmdStartTLS()
	case "authenticate":
		s.cmdAuthenticate(line)
	default:
		if !s.authed {
			s.writeNO("未认证（先 AUTHENTICATE）")
			return true
		}
		return s.dispatchAuthed(cmd, line, tokens)
	}
	return true
}

// dispatchAuthed 已认证态命令族（§2 脚本管理）。
func (s *session) dispatchAuthed(cmd, line string, tokens []string) bool {
	switch cmd {
	case "putscript":
		s.cmdPutScript(line)
	case "getscript":
		s.cmdGetScript(tokens)
	case "setactive":
		s.cmdSetActive(tokens)
	case "deletescript":
		s.cmdDeleteScript(tokens)
	case "listscripts":
		s.cmdListScripts()
	case "havespace":
		s.cmdHaveSpace(tokens)
	case "checkscript":
		s.cmdCheckScript(line)
	case "renamescript":
		s.cmdRenameScript(tokens)
	default:
		s.writeNO("未知命令 %q", tokens[0])
	}
	return true
}

// ───────────────────────── 能力协商（§1.7） ─────────────────────────

// writeCapabilities 推送能力集（连接即推+STARTTLS/AUTH 后重推 §1.1）。
// SASL 通告规则（L380-384）：SASL 空当且仅当通告 STARTTLS——TLS 就绪未升级态
// SASL 空（MUST 先 STARTTLS）；升级后 SASL "PLAIN"；无 TLS 配置态 SASL 空
// 且无 STARTTLS（部署缺陷显性化——只读不可认证，warnConn 告警一次）。
func (s *session) writeCapabilities() {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\"IMPLEMENTATION\" \"%s\"\r\n", implementationName))
	b.WriteString(fmt.Sprintf("\"SIEVE\" \"%s\"\r\n", sieveCapability))
	tlsReady := s.cfg.TLSConfig != nil && s.cfg.TLSConfig() != nil
	if tlsReady {
		b.WriteString("\"STARTTLS\"\r\n")
		if !s.inTLS {
			b.WriteString("\"SASL\" \"\"\r\n") // 先 STARTTLS（§1.7 iff 规则）
		} else {
			// SCRAM认证批（v1.39.0）：机制集扩展——PLAIN 位序在前（既有客户端偏好序零变化）
			b.WriteString("\"SASL\" \"PLAIN SCRAM-SHA-1\"\r\n")
		}
	} else if !s.inTLS {
		b.WriteString("\"SASL\" \"\"\r\n")
		warnConn("managesieve 无 TLS 配置：SASL 空通告（不可认证态——证书就绪后恢复）")
	}
	b.WriteString(fmt.Sprintf("\"MAXREDIRECTS\" \"%d\"\r\n", maxRedirectsValue))
	if s.authed {
		b.WriteString(fmt.Sprintf("\"OWNER\" \"%s\"\r\n", s.mboxAdr)) // 认证后 SHOULD（§1.7 L424-427）
	}
	b.WriteString("\"VERSION\" \"1.0\"\r\n")
	s.debugFrame("S", b.String()) // U23 协议 debug（开启时输出——能力块整体帧，多行原样）
	_, _ = s.bw.WriteString(b.String())
	_ = s.bw.Flush() // 连接即推/重推即时下发（能力块 ~200B 滞留 4096 缓冲将阻塞客户端等能力——U12b 缺陷修正①）
}

// maxRedirectsValue MAXREDIRECTS 能力值（与 mail.MaxRedirects 同源——§1.7 L408-412）。
const maxRedirectsValue = 5

// ───────────────────────── STARTTLS（§2） ─────────────────────────

// cmdStartTLS STARTTLS 升级（220→握手→成功后能力重推+状态重置 §1.7 L358-365；
// 454 不可用/503 TLS 中禁重复）。
func (s *session) cmdStartTLS() {
	if s.inTLS {
		s.writeNO("已在 TLS 中（503——rfc5804 §1.7）")
		return
	}
	if s.cfg.TLSConfig == nil || s.cfg.TLSConfig() == nil {
		s.writeNO("TLS 不可用（454——无证书配置）")
		return
	}
	s.writeOK("开始 TLS 升级")
	_ = s.bw.Flush()
	tlsConn := tls.Server(s.conn, s.cfg.TLSConfig())
	if err := tlsConn.HandshakeContext(s.ctx); err != nil {
		slog.WarnContext(s.ctx, "managesieve STARTTLS 握手失败", "error", err)
		s.quitting = true
		return
	}
	s.conn, s.br, s.bw = tlsConn, bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn)
	s.inTLS = true
	s.authed = false // 状态重置（§1.7：能力 STARTTLS 后变化——认证须重来）
	s.writeCapabilities()
}

// ───────────────────────── AUTHENTICATE（§2+rfc4616） ─────────────────────────

// cmdAuthenticate AUTHENTICATE "PLAIN"（initial-response 可选；'*' 取消；base64
// 三段式 NUL 分隔；明文连接一律 NO——NFR-006；成功后能力重推含 OWNER）。
func (s *session) cmdAuthenticate(line string) {
	if s.authed {
		s.writeNO("已认证（先 LOGOUT）")
		return
	}
	if !s.inTLS {
		s.writeNO("须先 STARTTLS（明文连接拒绝认证——NFR-006）")
		return
	}
	fields := strings.Fields(line)
	var mech, ir string
	if len(fields) >= 2 {
		mech = strings.ToUpper(unquote(fields[1])) // rfc5804 §2 auth-type=string 带引号形态（U12b 缺陷修正②——去引号后比对；宽容无引号）
	}
	if len(fields) >= 3 {
		ir = fields[2]
	}
	switch mech {
	case "PLAIN":
		s.authPLAIN(ir)
	case "SCRAM-SHA-1": // SCRAM认证批（v1.39.0）：rfc5804 §1.6 L692-694 MUST 机制
		s.authSCRAM(ir)
	default:
		s.writeNO("不支持的机制 %q（PLAIN/SCRAM-SHA-1）", mech)
	}
}

// authPLAIN PLAIN 机制主体（rfc4616 三段式——原 cmdAuthenticate 内联体平移，行为零变化）。
func (s *session) authPLAIN(ir string) {
	if ir == "" {
		// F-M9：空 challenge 为空串（rfc5804 §2.1 L582-591——服务端挑战是 string，
		// 空 challenge/response 以空串发送；原中文文本致规范客户端 base64 解码失败）
		_, _ = s.bw.WriteString("\"\"\r\n")
		_ = s.bw.Flush()
		var err error
		s.authRedact = true // B-S批 F4：下一 readLine 为 challenge 应答（base64 凭据）
		ir, err = s.readLine()
		s.authRedact = false
		if err != nil {
			s.quitting = true
			return
		}
		ir = strings.TrimRight(ir, "\r\n")
	}
	if ir == "*" {
		s.writeNO("客户端取消认证")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(ir)
	if err != nil {
		s.writeNO("base64 解码失败")
		return
	}
	parts := strings.Split(string(raw), "\x00") // rfc4616：authzid NUL authcid NUL passwd
	if len(parts) != 3 {
		s.writeNO("PLAIN 凭据格式错误（三段 NUL 分隔）")
		return
	}
	// B-S批 F3（裁决 2026-10-09 13:34）：认证失败限流——窗口内连续失败超阈值拒绝
	// （沿 smtp 提交端点对齐批 F3① 形态；nil=限流关闭渐进态；成功清零）
	subjectKey := "managesieve:" + parts[1]
	if s.authLocked(subjectKey) {
		s.writeNO("认证失败次数过多（稍后再试）")
		return
	}
	m, verr := s.cfg.Accounts.VerifyCredentials(s.ctx, parts[1], parts[2])
	if verr != nil || m == nil {
		s.recordAuthFail(subjectKey)
		s.writeNO("认证失败（凭据无效）") // 统一文本防枚举（U2 口径）
		return
	}
	s.clearAuthFails(subjectKey)
	s.authed, s.mboxID, s.mboxAdr = true, m.ID, m.Address
	s.writeCapabilities()
	s.writeOK("认证成功")
}

// authSCRAM SCRAM-SHA-1 机制主体（SCRAM认证批 v1.39.0——rfc5802 §5 四步交换 +
// rfc5804 §2.1 质询/应答承载：challenge 与应答的 string 内容均为 base64 编码的
// SASL 数据〔L583-585〕；server-final 经 OK (SASL "...") 响应码回发省一轮〔L591-594〕）。
// 安全口径：用户不存在/未配备→伪装盐继续交互（响应形态与真实用户一致——§7 防信息
// 披露口径），最终 proof 验证统一失败；认证失败限流沿 PLAIN 形态（B-S批 F3）。
func (s *session) authSCRAM(ir string) {
	// 第一步 client-first：ir 为空发空 challenge 读应答（与 PLAIN 同形态）
	if ir == "" {
		_, _ = s.bw.WriteString("\"\"\r\n")
		_ = s.bw.Flush()
		var err error
		s.authRedact = true // B-S批 F4 延续：认证交换帧掩码（SCRAM 帧含 proof）
		ir, err = s.readLine()
		s.authRedact = false
		if err != nil {
			s.quitting = true
			return
		}
		ir = strings.TrimRight(ir, "\r\n")
	}
	if ir == "*" {
		s.writeNO("客户端取消认证")
		return
	}
	first, derr := base64.StdEncoding.DecodeString(ir)
	if derr != nil {
		s.writeNO("base64 解码失败")
		return
	}
	ex := parseSCRAMClientFirst(string(first))
	if ex == nil {
		s.writeNO("client-first 格式错误")
		return
	}
	// §5.1 n 属性：服务端 MUST SASLprep 处理 username（query string 口径）
	prep, perr := auth.SASLprep(ex.authcid)
	if perr != nil || prep == "" {
		s.writeNO("认证失败（凭据无效）") // invalid-username-encoding 统一口径
		return
	}
	ex.authcid = prep
	subjectKey := "managesieve:" + ex.authcid
	if s.authLocked(subjectKey) {
		s.writeNO("认证失败次数过多（稍后再试）")
		return
	}
	// 取四元组：两哨兵（不存在/未配备）均转伪装态——防 unknown-user 即时失败暴露
	creds := &storage.SCRAMCredentials{
		StoredKey:  make([]byte, 20),
		ServerKey:  make([]byte, 20),
		Salt:       account.SCRAMDummySalt,
		Iterations: account.SCRAMIterations,
	}
	if real, cerr := s.cfg.Accounts.GetSCRAMCredentials(s.ctx, ex.authcid); cerr == nil {
		creds = real
	}
	ex.creds = creds
	ex.combinedNonce = ex.clientNonce + randomSCRAMNonce()
	ex.serverFirst = fmt.Sprintf("r=%s,s=%s,i=%d",
		ex.combinedNonce, base64.StdEncoding.EncodeToString(creds.Salt), creds.Iterations)
	// 第二步 server-first：quoted base64 challenge（rfc5804 §2.1 L583-584——
	// 挑战 string 内容为 base64 编码的 SASL 数据）；第三步 client-final 在
	// 同函数内同步读取（沿 PLAIN challenge 轮形态——应答不经主循环 dispatch）
	_, _ = s.bw.WriteString(fmt.Sprintf("\"%s\"\r\n",
		base64.StdEncoding.EncodeToString([]byte(ex.serverFirst))))
	_ = s.bw.Flush()
	s.authRedact = true // B-S批 F4 延续：client-final 含 proof——整行掩码
	resp, rerr := s.readLine()
	s.authRedact = false
	if rerr != nil {
		s.quitting = true
		return
	}
	s.authSCRAMFinal(ex, strings.TrimRight(resp, "\r\n"))
}

// authSCRAMFinal client-final 解析与验证（第三/四步——rfc5802 §5：nonce 逐字校验
// 〔§5.1「server MUST verify that the nonce sent by the client in the second
// message is the same as the one sent by the server in its first message」〕；
// c= 通道绑定数据校验〔§6 L805-807「The server MUST always validate the client's
// c= field」——cbind-input=gs2-header〕；proof 经 account.SCRAMServerVerify〔§3
// L424-429〕；成功回发 server-final v= 于 OK (SASL) 响应码——rfc5804 §2.1 L591-594
// 「this data MAY be placed within the data portion of the SASL response code to
// save a round trip」；失败统一文本防枚举+限流计数〔沿 PLAIN 形态〕）。
func (s *session) authSCRAMFinal(ex *scramExchange, ir string) {
	if ir == "*" {
		s.writeNO("客户端取消认证")
		return
	}
	subjectKey := "managesieve:" + ex.authcid
	if s.authLocked(subjectKey) {
		s.writeNO("认证失败次数过多（稍后再试）")
		return
	}
	final, derr := base64.StdEncoding.DecodeString(ir)
	if derr != nil {
		s.recordAuthFail(subjectKey)
		s.writeNO("认证失败（凭据无效）") // base64 层失败统一口径（不泄细节）
		return
	}
	cBind, rNonce, proof, withoutProof, ok := parseSCRAMClientFinal(string(final))
	if !ok || rNonce != ex.combinedNonce {
		s.recordAuthFail(subjectKey)
		s.writeNO("认证失败（凭据无效）")
		return
	}
	if string(cBind) != ex.gs2Header {
		s.recordAuthFail(subjectKey)
		s.writeNO("认证失败（凭据无效）")
		return
	}
	authMessage := ex.clientFirstBare + "," + ex.serverFirst + "," + withoutProof
	pass, serverSig := account.SCRAMServerVerify(ex.creds.StoredKey, ex.creds.ServerKey,
		[]byte(authMessage), proof)
	if !pass {
		s.recordAuthFail(subjectKey)
		s.writeNO("认证失败（凭据无效）")
		return
	}
	// proof 已过：主体态校验（active）——授权层检查（非枚举面；disabled 邮箱拒绝
	// 与 PLAIN VerifyCredentials 同语义）
	m, merr := s.cfg.Accounts.GetMailbox(s.ctx, ex.authcid)
	if merr != nil || m.Status != storage.MailboxStatusActive {
		s.recordAuthFail(subjectKey)
		s.writeNO("认证失败（凭据无效）")
		return
	}
	s.clearAuthFails(subjectKey)
	s.authed, s.mboxID, s.mboxAdr = true, m.ID, m.Address
	s.writeCapabilities()
	// 第四步 server-final：v=base64(ServerSignature)——OK (SASL "<b64(server-final)>")
	// 承载（rfc5804 §2.1 形态——外层 base64 编码 SASL additional data 原文）
	sf := "v=" + base64.StdEncoding.EncodeToString(serverSig)
	s.debugFrame("S", fmt.Sprintf("OK (SASL %q)", base64.StdEncoding.EncodeToString([]byte(sf))))
	_, _ = s.bw.WriteString(fmt.Sprintf("OK (SASL \"%s\")\r\n",
		base64.StdEncoding.EncodeToString([]byte(sf))))
	_ = s.bw.Flush()
}

// parseSCRAMClientFirst 解析 client-first-message（rfc5802 §7 文法：gs2-header +
// client-first-bare）。gs2 旗标：本服务端无 -PLUS 通告（不实现通道绑定）——"n"〔客户
// 端不支持〕与 "y"〔客户端支持但认为服务端不支持——§6 L791-793 仅服务端支持 CB 时
// "y" 须拒，本服务端不支持故接受〕均接受；"p" 拒绝〔§6 L801-803〕；首字符非 n/y/p
// 无效〔§5 L519-522 MUST fail〕。authzid（a=）非空拒绝——单用户语义无代理授权承载；
// m= 保留属性 MUST fail〔§5.1〕；bare 后未知可选扩展忽略〔§5.1 L717〕；username 的
// =2C/=3D 转义解码。参数：msg base64 解码后的 client-first 原文。返回：握手态（nil=
// 格式错误）。
func parseSCRAMClientFirst(msg string) *scramExchange {
	var flag string
	switch {
	case strings.HasPrefix(msg, "n,"):
		flag = "n,"
	case strings.HasPrefix(msg, "y,"):
		flag = "y,"
	default:
		return nil // "p=..."（通道绑定）与非 n/y/p 首字符——均拒
	}
	rest := msg[len(flag):]
	authzEnd := strings.IndexByte(rest, ',')
	if authzEnd < 0 || authzEnd > 0 {
		return nil // gs2-header 第二段缺失 / authzid 非空（"a=..."）——均拒
	}
	gs2 := flag + ","
	bare := rest[authzEnd+1:]
	if strings.HasPrefix(bare, "m=") {
		return nil // §5.1 m 属性存在 MUST fail
	}
	nEnd := strings.IndexByte(bare, ',')
	if nEnd < 3 || !strings.HasPrefix(bare, "n=") {
		return nil
	}
	username := decodeSASLName(bare[2:nEnd])
	if username == "" {
		return nil
	}
	rPart := bare[nEnd+1:]
	if rEnd := strings.IndexByte(rPart, ','); rEnd >= 0 {
		rPart = rPart[:rEnd] // 其后可选扩展忽略
	}
	if !strings.HasPrefix(rPart, "r=") || len(rPart) < 3 {
		return nil
	}
	return &scramExchange{authcid: username, clientFirstBare: bare, gs2Header: gs2, clientNonce: rPart[2:]}
}

// parseSCRAMClientFinal 解析 client-final-message（rfc5802 §7 文法：channel-binding
// "," nonce ["," extensions] "," proof——proof 为最末属性）。返回：c= 解码值、r=
// nonce、p= 解码 proof、without-proof 原文、是否合法。
func parseSCRAMClientFinal(msg string) (cBind []byte, rNonce string, proof []byte, withoutProof string, ok bool) {
	pIdx := strings.LastIndex(msg, ",p=")
	if pIdx < 0 {
		return nil, "", nil, "", false
	}
	withoutProof = msg[:pIdx]
	proofB64 := msg[pIdx+3:]
	cEnd := strings.IndexByte(withoutProof, ',')
	if cEnd < 0 || !strings.HasPrefix(withoutProof, "c=") {
		return nil, "", nil, "", false
	}
	cB64 := withoutProof[2:cEnd]
	rPart := withoutProof[cEnd+1:]
	if rEnd := strings.IndexByte(rPart, ','); rEnd >= 0 {
		rPart = rPart[:rEnd] // 可选扩展忽略
	}
	if !strings.HasPrefix(rPart, "r=") || len(rPart) < 3 {
		return nil, "", nil, "", false
	}
	var err error
	if cBind, err = base64.StdEncoding.DecodeString(cB64); err != nil {
		return nil, "", nil, "", false
	}
	if proof, err = base64.StdEncoding.DecodeString(proofB64); err != nil {
		return nil, "", nil, "", false
	}
	return cBind, rPart[2:], proof, withoutProof, true
}

// decodeSASLName saslname 的 =2C/=3D 转义解码（rfc5802 §5.1 L627-630：','/'=' 在
// username 中以 '=2C'/'=3D' 发送；'=' 不跟随 2C/3D MUST fail——空串承载）。
func decodeSASLName(s string) string {
	if !strings.Contains(s, "=") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			switch {
			case strings.HasPrefix(s[i:], "=2C"):
				b.WriteByte(',')
				i += 2
			case strings.HasPrefix(s[i:], "=3D"):
				b.WriteByte('=')
				i += 2
			default:
				return "" // 非 2C/3D 转义——MUST fail
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// randomSCRAMNonce 服务端 nonce（rfc5802 §5.1 r 属性：printable ASCII 除 ','——
// hex 编码天然满足；CSPRNG 12B→24 字符，§9 L1191 随机性建议承载）。
func randomSCRAMNonce() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// authLocked 认证失败限流判定（B-S批 F3——沿提交端点对齐批先例；nil 注入=关闭；
// 计数故障放行——可用性优先，与提交端点同口径）。
func (s *session) authLocked(subjectKey string) bool {
	if s.cfg.Attempts == nil {
		return false
	}
	window, threshold := s.authLimitConf()
	fails, err := s.cfg.Attempts.CountRecentFails(s.ctx, subjectKey, time.Now().UTC().Add(-window))
	if err != nil {
		return false
	}
	return fails >= threshold
}

// authLimitConf 限流参数快照（nil 注入=兜底档 15min/5 次——沿 web limitConf 形态）。
func (s *session) authLimitConf() (time.Duration, int64) {
	if s.cfg.AttemptLimit != nil {
		if w, t := s.cfg.AttemptLimit(); w > 0 && t > 0 {
			return w, t
		}
	}
	return 15 * time.Minute, 5
}

// recordAuthFail 认证失败计数（尽力语义）。
func (s *session) recordAuthFail(subjectKey string) {
	if s.cfg.Attempts == nil {
		return
	}
	ip := ""
	if ra := s.conn.RemoteAddr(); ra != nil {
		ip = ra.String()
	}
	_ = s.cfg.Attempts.RecordAttempt(s.ctx, subjectKey, ip, false, time.Now().UTC())
}

// clearAuthFails 认证成功清零计数（尽力语义）。
func (s *session) clearAuthFails(subjectKey string) {
	if s.cfg.Attempts == nil {
		return
	}
	_ = s.cfg.Attempts.ClearSubject(s.ctx, subjectKey)
}

// ───────────────────────── 脚本管理命令族（§2） ─────────────────────────

// cmdPutScript PUTSCRIPT <name> <content 字面量>（语法校验先行+HAVESPACE 配额；
// 激活态保持——rfc5804 §2 语义）。
// F3（A-13③，访问协议资源限制批）：配额判定前置至字面量读取前——原
// readLiteralBytes 先 make([]byte,n) 分配后校验配额，n 无上限（OOM 面）；
// 现按声明计数前置拒绝（读后重复判定保留为终态防线）。
func (s *session) cmdPutScript(line string) {
	rest := strings.TrimSpace(line[len("putscript"):])
	name, n, litOK := s.parseNameThenLiteral(rest)
	if !litOK {
		s.writeNO("PUTSCRIPT 须脚本名+字面量内容")
		return
	}
	// B-S批 F3：脚本名校验（长度 ≤128+无控制符——rfc5804 §1.6 name 文法防御；
	// 原 parseNameThenLiteral 原样透传任意串）
	if verr := validScriptName(name); verr != nil {
		s.writeNO("%v", verr)
		return
	}
	if msg, ok := s.checkLiteralCount(n); !ok {
		s.writeNO("%s", msg)
		return
	}
	content, err := s.readLiteralBytes(n)
	if err != nil {
		s.writeNO("字面量读取失败: %v", err)
		return
	}
	// B-S批 F3：零长脚本拒绝（空脚本无过滤语义——PUTSCRIPT 语义防御）
	if len(content) == 0 {
		s.writeNO("脚本内容为空（零长脚本不可保存）")
		return
	}
	quota := s.quota()
	if len(content) > quota.MaxBytes {
		s.writeNOCode("QUOTA/MAXSIZE", "脚本超单脚本上限 %d 字节", quota.MaxBytes) // F-M1：rfc5804 §1.5 L317-319
		return
	}
	scripts, _ := s.cfg.Scripts.ListScripts(s.ctx, s.mboxID)
	if len(scripts) >= quota.MaxScripts {
		// upsert 既有名不占新额度
		exists := false
		for _, sc := range scripts {
			if sc.Name == name {
				exists = true
				break
			}
		}
		if !exists {
			s.writeNOCode("QUOTA/MAXSCRIPTS", "脚本数超上限 %d", quota.MaxScripts) // F-M1：rfc5804 §1.5
			return
		}
	}
	if verr := s.validate(string(content)); verr != nil {
		s.writeNO("脚本语法错误: %v", verr)
		return
	}
	if err = s.cfg.Scripts.PutScript(s.ctx, &storage.SieveScript{
		MailboxID: s.mboxID, Name: name, Content: string(content),
	}); err != nil {
		s.writeNO("保存失败: %v", err)
		return
	}
	s.writeOK("PUTSCRIPT 完成")
}

// cmdGetScript GETSCRIPT <name>（内容以 {n+} 字面量回传）。
func (s *session) cmdGetScript(tokens []string) {
	if len(tokens) < 2 {
		s.writeNO("GETSCRIPT 须脚本名")
		return
	}
	sc, err := s.cfg.Scripts.GetScript(s.ctx, s.mboxID, unquote(tokens[1]))
	if err != nil {
		if errors.Is(err, storage.ErrSieveScriptNotFound) {
			s.writeNO("脚本不存在")
			return
		}
		s.writeNO("查询失败: %v", err)
		return
	}
	_, _ = s.bw.WriteString(fmt.Sprintf("{%d+}\r\n", len(sc.Content)))
	_, _ = s.bw.WriteString(sc.Content)
	if !strings.HasSuffix(sc.Content, "\r\n") {
		_, _ = s.bw.WriteString("\r\n") // 字面量后行界
	}
	s.writeOK("GETSCRIPT 完成")
}

// cmdSetActive SETACTIVE <name>（空名=取消激活——rfc5804 §2 语义）。
func (s *session) cmdSetActive(tokens []string) {
	if len(tokens) < 2 {
		s.writeNO("SETACTIVE 须脚本名（空串取消激活）")
		return
	}
	name := unquote(tokens[1])
	if name == "" {
		if err := s.cfg.Scripts.SetActive(s.ctx, s.mboxID, "\x00none"); err != nil && !errors.Is(err, storage.ErrSieveScriptNotFound) {
			s.writeNO("取消激活失败: %v", err)
			return
		}
		s.writeOK("已取消激活")
		return
	}
	if err := s.cfg.Scripts.SetActive(s.ctx, s.mboxID, name); err != nil {
		if errors.Is(err, storage.ErrSieveScriptNotFound) {
			s.writeNO("脚本不存在")
			return
		}
		s.writeNO("激活失败: %v", err)
		return
	}
	s.writeOK("SETACTIVE 完成")
}

// cmdDeleteScript DELETESCRIPT <name>（激活脚本拒绝——rfc5804 §2.10 L1379-1381
// 「MUST NOT allow the client to delete an active script」：F-M3 删除前查激活态，
// 激活脚本 NO (ACTIVE) 拒绝——连带清激活的 storage 语义不经此路径触发）。
func (s *session) cmdDeleteScript(tokens []string) {
	if len(tokens) < 2 {
		s.writeNO("DELETESCRIPT 须脚本名")
		return
	}
	name := unquote(tokens[1])
	if act, aerr := s.cfg.Scripts.GetActiveScript(s.ctx, s.mboxID); aerr == nil && act != nil && act.Name == name {
		s.writeNOCode("ACTIVE", "激活脚本不可删除（先 SETACTIVE 取消激活）")
		return
	}
	if err := s.cfg.Scripts.DeleteScript(s.ctx, s.mboxID, name); err != nil {
		s.writeNO("删除失败: %v", err)
		return
	}
	s.writeOK("DELETESCRIPT 完成")
}

// cmdListScripts LISTSCRIPTS（每行 "name" [ACTIVE]；末 OK）。
func (s *session) cmdListScripts() {
	scripts, err := s.cfg.Scripts.ListScripts(s.ctx, s.mboxID)
	if err != nil {
		s.writeNO("列举失败: %v", err)
		return
	}
	var b strings.Builder
	for _, sc := range scripts {
		if sc.IsActive {
			b.WriteString(fmt.Sprintf("\"%s\" ACTIVE\r\n", sc.Name))
		} else {
			b.WriteString(fmt.Sprintf("\"%s\"\r\n", sc.Name))
		}
	}
	_, _ = s.bw.WriteString(b.String())
	s.writeOK("%d 个脚本", len(scripts))
}

// cmdHaveSpace HAVESPACE <name> <number>（配额判定——§2）。
func (s *session) cmdHaveSpace(tokens []string) {
	if len(tokens) < 3 {
		s.writeNO("HAVESPACE 须脚本名+字节数")
		return
	}
	n, err := strconv.Atoi(tokens[2])
	if err != nil || n < 0 {
		s.writeNO("字节数无效")
		return
	}
	quota := s.quota()
	scripts, _ := s.cfg.Scripts.ListScripts(s.ctx, s.mboxID)
	nameExists := func() bool {
		for _, sc := range scripts {
			if sc.Name == unquote(tokens[1]) {
				return true
			}
		}
		return false
	}
	if len(scripts)+func() int {
		if nameExists() {
			return 0
		}
		return 1
	}() > quota.MaxScripts {
		s.writeNOCode("QUOTA/MAXSCRIPTS", "脚本数超上限 %d", quota.MaxScripts) // F-M1
		return
	}
	if n > quota.MaxBytes {
		s.writeNOCode("QUOTA/MAXSIZE", "单脚本超上限 %d 字节", quota.MaxBytes) // F-M1
		return
	}
	s.writeOK("配额内")
}

// cmdCheckScript CHECKSCRIPT <content 字面量>（仅语法校验不落库——§2）。
// 直形字面量（无脚本名——rfc5804 §2 checkscript 语法；U12b 缺陷修正③：原误用
// parseNameThenLiteral 致 { 开头的合法形态被 i<=0 拒绝）。
func (s *session) cmdCheckScript(line string) {
	rest := strings.TrimSpace(line[len("checkscript"):])
	var n int
	if strings.HasPrefix(rest, "{") {
		cnt, ok := parseLiteralCount(rest)
		if !ok {
			s.writeNO("CHECKSCRIPT 字面量前缀无效")
			return
		}
		n = cnt
	} else {
		_, n2, ok := s.parseNameThenLiteral(rest) // 宽容兼容「名+字面量」形态
		if !ok {
			s.writeNO("CHECKSCRIPT 须字面量内容")
			return
		}
		n = n2
	}
	// F3（A-13③）：配额前置（同 PUTSCRIPT——读体前按声明计数拒绝）
	if msg, ok := s.checkLiteralCount(n); !ok {
		s.writeNO("%s", msg)
		return
	}
	content, err := s.readLiteralBytes(n)
	if err != nil {
		s.writeNO("字面量读取失败: %v", err)
		return
	}
	if verr := s.validate(string(content)); verr != nil {
		s.writeNO("脚本语法错误: %v", verr)
		return
	}
	s.writeOK("语法校验通过")
}

// cmdRenameScript RENAMESCRIPT <old> <new>（VERSION 1.0 命令——F10/C21 原子承载；
// F-M4：新名已存在 NO (ALREADYEXISTS) 拒绝——rfc5804 §2.11 L1414-1416，
// 原 upsert 覆盖既有脚本违反 MUST。C级债务收尾批 2026-10-10：改调 storage 原子
// RenameScript——原三步非事务〔PutScript→SetActive→DeleteScript〕中途失败残留
// 双名脚本；外部行为等价〔成功应答与激活迁移语义不变〕，仅消中间失败窗口）。
func (s *session) cmdRenameScript(tokens []string) {
	if len(tokens) < 3 {
		s.writeNO("RENAMESCRIPT 须旧名+新名")
		return
	}
	oldN, newN := unquote(tokens[1]), unquote(tokens[2])
	if _, err := s.cfg.Scripts.GetScript(s.ctx, s.mboxID, newN); err == nil {
		s.writeNOCode("ALREADYEXISTS", "新名脚本已存在")
		return
	}
	if err := s.cfg.Scripts.RenameScript(s.ctx, s.mboxID, oldN, newN); err != nil {
		if errors.Is(err, storage.ErrSieveScriptNotFound) {
			s.writeNO("脚本不存在")
			return
		}
		s.writeNO("改名失败: %v", err)
		return
	}
	s.writeOK("RENAMESCRIPT 完成")
}

// ───────────────────────── 字面量与 IO 基元（§1.2） ─────────────────────────

// parseNameThenLiteral 解析「<名> <{n+} 前缀>」形态（PUTSCRIPT 输入切分；
// §1.2：{n+} 非同步字面量——客户端不再等续行确认直接发正文；n 提取自前缀）。
func (s *session) parseNameThenLiteral(rest string) (string, int, bool) {
	i := strings.IndexByte(rest, '{')
	if i <= 0 {
		return "", 0, false
	}
	n, ok := parseLiteralCount(rest[i:])
	if !ok {
		return "", 0, false
	}
	return unquote(strings.TrimSpace(rest[:i])), n, true
}

// parseLiteralCount 字面量前缀 "{n+}"/"{n}" 的长度解析（§1.2；同步形态 {n} 宽容接受）。
// 参数：prefix 形如 {123+} 的前缀串。返回：字节数；形态是否合法。
// F3 常量锚：literalNumberMax（rfc5804 语法章 L1855-1858 number=32-bit unsigned
// 0 ≤ n < 4,294,967,296——超界为语法错误）；readLineMax（单行上限——沿 POP3
// readLineMax=512 先例，命令行+字面量前缀总长 512 充裕）。
const (
	literalNumberMax = 4294967296
	readLineMax      = 512
)

// cmdIdleTimeout 命令面不活动超时（F6/M4——原会话全程无 SetDeadline，挂死
// 客户端/goroutine 长期占用；沿 POP3 inactivityTimeout=10min 先例，rfc5804
// 无强制超时条款属工程防线）。
const cmdIdleTimeout = 10 * time.Minute

// literalIdleTimeout 字面量分块读取的块间超时（F6——大脚本慢速链路逐块续期，
// 不被单次窗口掐断）；literalReadChunk 分块大小。
const (
	literalIdleTimeout = 10 * time.Minute
	literalReadChunk   = 8192
)

// errLineTooLong 超长行哨兵（F3——会话终止承载：流同步确定性优先，超长行
// 无合法协议场景〔字面量体经 readLiteralBytes 独立读取，命令行仅含名字+前缀〕）。
var errLineTooLong = errors.New("managesieve: 行超长")

// checkLiteralCount 字面量声明计数前置校验（F3——读体/分配前的统一防线；
// QUOTA/MAXSIZE 响应码在调用方 writeNO 内平文承载〔与既有 F-M1 码语义一致，
// 此处返回拒绝消息由 writeNO 输出〕）。
// 参数：n 字面量声明字节数。返回：拒绝消息（""=通过）；是否通过。
func (s *session) checkLiteralCount(n int) (string, bool) {
	if n < 0 || n >= literalNumberMax {
		return fmt.Sprintf("字面量计数 %d 超 32 位语法上界（rfc5804 number 文法）", n), false
	}
	if quota := s.quota(); n > quota.MaxBytes {
		return fmt.Sprintf("脚本超单脚本上限 %d 字节（NO (QUOTA/MAXSIZE)）", quota.MaxBytes), false
	}
	return "", true
}

func parseLiteralCount(prefix string) (int, bool) {
	if !strings.HasSuffix(prefix, "+}") {
		if !strings.HasSuffix(prefix, "}") {
			return 0, false
		}
	}
	nStr := strings.TrimSuffix(strings.TrimPrefix(prefix, "{"), "+}")
	nStr = strings.TrimSuffix(nStr, "}")
	n, err := strconv.Atoi(strings.TrimSpace(nStr))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// readLiteralBytes 读取字面量正文 n 字节+行界（§1.2——行内前缀已解析，此处读字节流）。
// F3（A-13③）：分配防御——make 前二次校验 32 位上界与配额上限（调用点已前置
// 判定，此处兜底任何路径不发生无界分配）；F6（M4）：分块读取逐块重置读
// deadline（10min/块——大脚本慢速链路续期不被掐断；原全程零 deadline）。
func (s *session) readLiteralBytes(n int) ([]byte, error) {
	if msg, ok := s.checkLiteralCount(n); !ok {
		return nil, errors.New(msg)
	}
	buf := make([]byte, n)
	for remaining := n; remaining > 0; {
		_ = s.conn.SetReadDeadline(time.Now().Add(literalIdleTimeout))
		chunk := remaining
		if chunk > literalReadChunk {
			chunk = literalReadChunk
		}
		off := n - remaining
		if _, err := io.ReadFull(s.br, buf[off:off+chunk]); err != nil {
			return nil, fmt.Errorf("读取 %d 字节: %w", n, err)
		}
		remaining -= chunk
	}
	// 消费字面量后行界（\r\n 或 \n 宽容）
	if _, err := s.br.ReadString('\n'); err != nil {
		return nil, fmt.Errorf("读取字面量行界: %w", err)
	}
	return buf, nil
}

// quota 配额快照（nil 注入=缺省档）。
func (s *session) quota() QuotaConfig {
	if s.cfg.Quota == nil {
		return QuotaConfig{}.Defaults()
	}
	return s.cfg.Quota().Defaults()
}

// writeNOCode 带响应码的 NO 应答（rfc5804 §1.3 形态 `NO (CODE) "text"`——
// F-M1/M3/M4 修正承载；响应码枚举 QUOTA/MAXSCRIPTS/QUOTA/MAXSIZE/ACTIVE/ALREADYEXISTS）。
// 参数：code 响应码；format 文本模板；args 模板实参。
func (s *session) writeNOCode(code, format string, args ...any) {
	s.debugFrame("S", fmt.Sprintf("NO (%s)", code))
	_, _ = s.bw.WriteString(fmt.Sprintf("NO (%s) \"%s\"\r\n", code, fmt.Sprintf(format, args...)))
	_ = s.bw.Flush()
}

// validScriptName 脚本名防御校验（B-S批 F3）：非空+长度 ≤128+无控制字符
// （rfc5804 §1.6 name 文法——ASCII 可打印形态；路径分隔符等由 URL 承载层既有
// validSieveScriptName 防御，协议侧本函数承载存储前最小面）。
func validScriptName(name string) error {
	if name == "" {
		return errors.New("脚本名为空")
	}
	if len(name) > 128 {
		return fmt.Errorf("脚本名超长（%d > 128）", len(name))
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("脚本名含控制字符")
		}
	}
	return nil
}

// validate 语法校验透传。
func (s *session) validate(src string) error {
	if s.cfg.Validate == nil {
		return nil
	}
	return s.cfg.Validate(src)
}

// readLine 读单行（\r\n 或 \n 行界——宽容口径与词法器一致）。
// F3：超长拒绝——ReadSlice 循环计数（ReadString 无界累积防御：超 readLineMax
// 即停止累积消费至行尾返回哨兵，会话由 run 终止〔超长行无合法协议场景〕）；
// F6（M4）：读取前设置命令面不活动 deadline。
func (s *session) readLine() (string, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(cmdIdleTimeout))
	var buf []byte
	tooLong := false
	for {
		seg, err := s.br.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull {
			return "", err
		}
		if !tooLong && len(buf)+len(seg) > readLineMax {
			tooLong = true
		}
		if !tooLong {
			buf = append(buf, seg...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	if tooLong {
		return "", errLineTooLong
	}
	line := string(buf)
	// B-S批 F4（裁决 A 2026-10-09 13:34）：认证帧凭据掩码——AUTHENTICATE 命令行
	// initial-response 参数与 challenge 轮应答帧（authRedact 置位时整行）替换
	// [REDACTED]（ProtocolDebug 开启时明文口令不落 30 天日志文件；非认证帧原样；
	// 非 debug 模式零输出零行为变化）
	if s.authRedact {
		s.debugFrame("C", "[REDACTED]")
	} else {
		s.debugFrame("C", redactAuthLine(line))
	}
	_ = s.bw.Flush()
	return line, nil
}

// redactAuthLine AUTHENTICATE 命令行凭据掩码（B-S批 F4）：`AUTHENTICATE "PLAIN" <b64>`
// 形态的第三个 token（initial-response，宽容无引号形态同掩）替换 [REDACTED]（保留
// 命令+机制名——排障可见认证交互结构）；无 initial-response 形态原样（凭据走
// challenge 轮，由 authRedact 标志承载）。
func redactAuthLine(line string) string {
	trimmed := strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(strings.ToUpper(trimmed), "AUTHENTICATE ") {
		return line // 非认证命令——原样
	}
	fields := strings.Fields(trimmed)
	if len(fields) >= 3 {
		return fields[0] + " " + fields[1] + " [REDACTED]\r\n"
	}
	return line
}

// writeOK 应答 OK。
func (s *session) writeOK(format string, args ...any) {
	s.debugFrame("S", fmt.Sprintf("OK \"%s\"\r\n", fmt.Sprintf(format, args...))) // U23 协议 debug
	_, _ = fmt.Fprintf(s.bw, "OK \"%s\"\r\n", fmt.Sprintf(format, args...))
	_ = s.bw.Flush()
}

// writeNO 应答 NO。
func (s *session) writeNO(format string, args ...any) {
	s.debugFrame("S", fmt.Sprintf("NO \"%s\"\r\n", fmt.Sprintf(format, args...))) // U23 协议 debug
	_, _ = fmt.Fprintf(s.bw, "NO \"%s\"\r\n", fmt.Sprintf(format, args...))
	_ = s.bw.Flush()
}

// writeBye 应答 BYE（会话终止）。
func (s *session) writeBye(format string, args ...any) {
	s.debugFrame("S", fmt.Sprintf("BYE \"%s\"\r\n", fmt.Sprintf(format, args...))) // U23 协议 debug
	_, _ = fmt.Fprintf(s.bw, "BYE \"%s\"\r\n", fmt.Sprintf(format, args...))
	_ = s.bw.Flush()
}

// debugFrame 协议 debug 条件输出（U23——H5 等价；快照关闭时零开销跳过）。
// 参数：dir 方向前缀（C=客户端来向/S=服务端去向）；line 原始帧（能力块多行原样）。
// 说明：ctx 由 serveConn 经 ContextWithNewLogID 建立（logid 属性随绑定 logger 携带）；
// 输出经 LoggerFromContext 显式取绑定 logger（slog-context 语义——标准门面不消费
// ctx 内绑定，勿混用，沿 U21 缺陷修正⑥ 教训）。
func (s *session) debugFrame(dir, line string) {
	if s.ctx == nil || s.cfg.ProtocolDebug == nil || !s.cfg.ProtocolDebug() {
		return // nil 注入=禁用（缺省装配/测试直构防御——与 Server.protocolDebug 同语义）
	}
	observability.LoggerFromContext(s.ctx).Debug("managesieve_debug",
		"dir", dir, "frame", strings.TrimRight(line, "\r\n"))
}

// unquote 去引号串外层双引号（无引号原样——宽容）。
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
