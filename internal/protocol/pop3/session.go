// pop3 会话：rfc1939 三态状态机（AUTHORIZATION→TRANSACTION→UPDATE）+ 全命令实现。
// U21 增量（协议 debug——H5 等价）：readLine/writeLine 命令响应面逐行条件输出
// （快照控制热生效；多行邮件体不输出防刷屏）；范围口径见 debugFrame 注释。
// 规范锚点（逐条对照原文）：rfc1939 §3（+OK/-ERR 大写/未识别与状态错误 -ERR/多行响应
// byte-stuffing CRLF.CRLF 终止）、§4（超时≥10min 到期不进 UPDATE 直接断连）、
// §5（STAT drop listing "+OK nn mm"/LIST scan listing/RETR/DELE 标记/NOOP/RSET）、
// §6（QUIT UPDATE：删除失败 -ERR some deleted messages not removed，绝不删未标记消息；
// AUTHORIZATION 态 QUIT 不进 UPDATE）、§7（USER/PASS——Q2-A 裁决不实现）、
// §8（TOP 头+空行+体前 n 行/UIDL 1-70 字符 0x21-0x7E 持久唯一）、§11（octet 计数=存储字节）；
// rfc2449 §5（CAPA 双态可用；AUTHORIZATION 态能力必须双态通告）§6.6（PIPELINING 逐条处理）；
// rfc5034 §4（AUTH mechanism [initial-response]/'+ ' challenge/'*' 取消/base64 失败 -ERR/
// 成功后再 AUTH 必须 -ERR/仅 AUTHORIZATION 态/TLS+PLAIN 最低义务/明文会话禁明文密码机制）。
// 用户裁决：Q1-A QUIT=HardDelete；Q2-A 仅 AUTH PLAIN；Q3-A UIDL=uid；Q4-A 非 *tls.Conn 拒 AUTH。
// 修改历史：
//
//	2026-09-19 04:09:01 | 新建 | U7 POP3 自研（计划书 v1.0.0 步骤 3，G2 批准）
//	2026-09-27 06:20:00 | 扩展 | U21 可观测性增强：命令响应面协议 debug 条件输出
//	（readLine/writeLine 两埋点+debugFrame 辅助——H5 等价）
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 4/1.5⑤）
//	2026-10-08 18-30-00 | 修正 | B-FUNC功能缺陷修复批 F3（B-F7）：AUTH 零长
//	initial-response "=" 归一——rfc5034 §4 L245-247「If the client needs to send
//	a zero-length initial response, it MUST transmit the response as a single
//	equals sign ("=")」（§5 ABNF initial-response = base64 / "="）——响应已存在
//	但零数据，非省略形态：不发 challenge 轮，空串直入解码/PLAIN 三段校验链
//	（零长载荷经既有拒绝路径 -ERR invalid PLAIN credentials——替代原 base64
//	解码失败误拒。G2 批准 2026-10-08 18:26:50；SRS FR-007 伴随）
package pop3

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// inactivityTimeout 不活动超时（rfc1939 §4：MAY 实现，MUST ≥10 分钟；到期不进
// UPDATE 直接断连不应答——DELE 标记随之丢弃，符合"非 QUIT 终止不删除"语义）。
const inactivityTimeout = 10 * time.Minute

// readLineMax 单行读取上限（rfc2449 §4：支持 CAPA 的服务器 MUST 支持命令 255 八位组；
// 取 512 与响应行上限对齐，含 CRLF 与余量）。
const readLineMax = 512

// pop3Msg maildrop 快照行（AUTHORIZATION→TRANSACTION 转换时一次载入；rfc1939 §4：
// 服务器打开 maildrop 后指派 message-number 并记录大小）。
type pop3Msg struct {
	id      int64 // mailbox_messages.id（HardDelete 入参）
	uid     int64 // IMAP UID（UIDL 值——数据模型 3.5 持久唯一不复用，满足 rfc1939 §8）
	size    int64 // RawSize（rfc1939 §11：octet 计数=存储字节）
	blobKey string
	deleted bool // rfc1939 §5 DELE：会话内标记，QUIT 才提交（内存态零 DB 触碰）
}

// session POP3 会话（单连接单 goroutine 持有，无并发共享）。
type session struct {
	server *Server
	conn   net.Conn
	r      *bufio.Reader
	w      *bufio.Writer
	logID  string
	// B-S批 F4（裁决 A 2026-10-09 13:34）：challenge 轮应答帧掩码标志——cmdAuth
	// 发 "+ " 后置位，下一 readLine 为 base64 凭据应答（无命令词可判），读毕复位
	authRedact bool

	mbox *storage.Mailbox // 认证后邮箱（nil=AUTHORIZATION 态）
	msgs []pop3Msg        // maildrop 快照（message-number=index+1）

	// lockedMailbox 持有 maildrop 锁的邮箱 ID（0=未持锁）——F4/A-13④。
	lockedMailbox int64
}

// newSession 构造会话。
func newSession(s *Server, conn net.Conn, logID string) *session {
	return &session{
		server: s,
		conn:   conn,
		r:      bufio.NewReaderSize(conn, 4096),
		w:      bufio.NewWriterSize(conn, 4096),
		logID:  logID,
	}
}

// serve 会话主循环（greeting→命令分派→QUIT/断连退出）。
func (ss *session) serve() {
	// F4：会话任意退出路径释放 maildrop 锁（幂等——rfc1939 §4 L213-217 独占
	// 语义的会话生命周期承载：非 QUIT 终止同样释放，"非 QUIT 终止不删除"由
	// UPDATE 提交仅在 QUIT 路径触发的既有语义保证）。
	defer ss.releaseMaildrop()
	// rfc1939 §4：greeting 为单行正响应
	ss.writeLine("+OK POP3 server ready")
	for {
		_ = ss.conn.SetReadDeadline(time.Now().Add(inactivityTimeout))
		line, err := ss.readLine()
		if err != nil {
			// 超时/断连/读取错误：不进 UPDATE 不删除（rfc1939 §4/§6）
			return
		}
		keyword, arg := splitCommand(line)
		if keyword == "" {
			ss.writeLine("-ERR empty command")
			continue
		}
		if ss.mbox == nil {
			if !ss.dispatchAuthorization(keyword, arg) {
				return
			}
			continue
		}
		if !ss.dispatchTransaction(keyword, arg) {
			return
		}
	}
}

// ───────────────────────── AUTHORIZATION 态（rfc1939 §4） ─────────────────────────

// dispatchAuthorization AUTHORIZATION 态命令分派。
// 返回 false=会话结束（QUIT/致命错误）。
func (ss *session) dispatchAuthorization(keyword, arg string) bool {
	switch keyword {
	case "CAPA": // rfc2449 §5：双态可用
		ss.cmdCAPA()
	case "AUTH": // rfc5034 §4：仅 AUTHORIZATION 态
		ss.cmdAuth(arg)
	case "QUIT": // rfc1939 §6：AUTHORIZATION 态 QUIT 不进 UPDATE
		ss.writeLine("+OK POP3 server signing off")
		return false
	default: // rfc1939 §3：状态错误命令 -ERR（含 USER/PASS——Q2-A 不实现）
		ss.writeLine("-ERR command not valid in AUTHORIZATION state")
	}
	return true
}

// cmdCAPA 能力通告（rfc2449 §5；AUTHORIZATION 态能力必须双态通告——TOP/UIDL/
// PIPELINING/SASL/IMPLEMENTATION 均双态）。Q3-A 全量；Q2-A 无 USER tag、SASL 仅 PLAIN。
// F-P5（RFCSHOULD修正批次）：补 EXPIRE NEVER——本服务消息无限期保留（POP3 删除仅经
// 显式 DELE；IMAP 侧同存储），rfc2449 §6.7 L628-629「Sites which permit users to
// retain messages indefinitely SHOULD announce this with the EXPIRE NEVER response」。
func (ss *session) cmdCAPA() {
	ss.writeLine("+OK Capability list follows")
	ss.writeLine("TOP")
	ss.writeLine("UIDL")
	ss.writeLine("PIPELINING")
	ss.writeLine("EXPIRE NEVER") // F-P5：无限期保留策略通告（rfc2449 §6.7 L595-596/L628-629）
	ss.writeLine("SASL PLAIN")
	ss.writeLine("IMPLEMENTATION GRmail-POP3-U7")
	ss.writeLine(".")
}

// cmdAuth AUTH 命令（rfc5034 §4 逐条）。
// Q4-A：非 *tls.Conn 连接一律 -ERR（FR-007 明文连接认证请求一律拒绝——
// 生产形态仅 995 隐式 TLS，本判定为会话层防御义务与测试层判定锚）。
func (ss *session) cmdAuth(arg string) {
	if _, isTLS := ss.conn.(*tls.Conn); !isTLS {
		ss.writeLine("-ERR TLS required before authentication")
		return
	}
	mech, ir, ok := splitAuthArg(arg)
	if !ok {
		ss.writeLine("-ERR syntax error")
		return
	}
	if mech != "PLAIN" { // Q2-A：仅 PLAIN（rfc5034 §4：机制不支持 -ERR）
		ss.writeLine("-ERR unsupported authentication mechanism")
		return
	}
	resp := ir
	// F3（B-F7 修复）：零长 initial-response "="（rfc5034 §4 L245-247 MUST）——
	// 响应已存在但零数据（非省略形态）：不发 challenge 轮，空串直入解码链；
	// 零长载荷经 parsePlain 三段校验拒绝（合法 -ERR 路径）。
	zeroLengthIR := resp == "="
	if zeroLengthIR {
		resp = ""
	}
	if resp == "" && !zeroLengthIR { // 省略形态：challenge 一轮（"+ "，rfc5034 §4 continue-req）
		ss.writeLine("+ ")
		ss.authRedact = true // B-S批 F4：下一 readLine 为 challenge 应答（base64 凭据）
		line, err := ss.readLine()
		ss.authRedact = false
		if err != nil {
			return
		}
		resp = strings.TrimRight(line, "\r\n")
	}
	if resp == "*" { // rfc5034 §4：取消
		ss.writeLine("-ERR authentication cancelled")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(resp)
	if err != nil { // rfc5034 §4：base64 解码失败 MUST -ERR
		ss.writeLine("-ERR invalid base64")
		return
	}
	authcid, passwd, err := parsePlain(raw)
	if err != nil {
		ss.writeLine("-ERR invalid PLAIN credentials")
		return
	}
	// F-P7：SASLprep 身份准备（rfc5034 §4 L287-289「SHOULD use the SASLprep profile
	// of the StringPrep algorithm」——授权身份准备；PLAIN authzid 空=授权身份取 authcid；
	// 禁止字符/双向命中按认证失败处理——方案 A 裁决 2026-09-30 18:54）
	prep, perr := auth.SASLprep(authcid)
	if perr != nil {
		ss.writeLine("-ERR invalid identity (saslprep)")
		return
	}
	authcid = prep
	mbox, err := ss.server.accounts.VerifyCredentials(ss.ctx(), authcid, passwd)
	if err != nil { // U2 统一拒绝防枚举（含不存在/影子/禁用/密码错）
		slog.Warn("POP3 认证失败", "logid", ss.logID)
		ss.writeLine("-ERR authentication failed")
		return
	}
	ss.mbox = mbox
	// F4（A-13④）：maildrop 独占锁——TRANSACTION 期防双会话删除集互覆（原应答
	// 文本宣称 locked 无实际锁）；锁失败按 rfc1939 §4 L221-234 负响应语义拒绝
	//（不进 TRANSACTION、不删消息、可重新认证或 QUIT）。
	if !ss.server.locks.tryLock(mbox.ID) {
		ss.mbox = nil
		ss.writeLine("-ERR unable to lock maildrop")
		return
	}
	ss.lockedMailbox = mbox.ID
	if err := ss.loadMaildrop(); err != nil {
		// maildrop 打开失败：拒绝进入 TRANSACTION（rfc1939 §4）——释放锁后再拒绝
		ss.mbox = nil
		ss.releaseMaildrop()
		slog.Error("POP3 maildrop 载入失败", "logid", ss.logID, "error", err)
		ss.writeLine("-ERR unable to open maildrop")
		return
	}
	slog.Info("POP3 认证成功", "logid", ss.logID, "mailbox", mbox.Address)
	ss.writeLine("+OK maildrop locked and ready")
}

// releaseMaildrop 释放 maildrop 独占锁（F4——幂等；serve defer 与中途失败路径共用）。
func (ss *session) releaseMaildrop() {
	if ss.lockedMailbox != 0 {
		ss.server.locks.unlock(ss.lockedMailbox)
		ss.lockedMailbox = 0
	}
}

// splitAuthArg 拆分 AUTH mechanism [initial-response]。
// 返回：机制（大写归一）、initial-response（缺省空）、语法是否合法。
func splitAuthArg(arg string) (mech, ir string, ok bool) {
	fields := strings.Fields(arg)
	switch len(fields) {
	case 1:
		return strings.ToUpper(fields[0]), "", true
	case 2:
		return strings.ToUpper(fields[0]), fields[1], true
	default:
		return "", "", false
	}
}

// parsePlain 解析 SASL PLAIN 载荷（rfc4616 §3：authzid NUL authcid NUL passwd；
// authzid 非空时须等于 authcid）。
func parsePlain(raw []byte) (authcid, passwd string, err error) {
	parts := bytes.Split(raw, []byte{0})
	if len(parts) != 3 {
		return "", "", errors.New("pop3: PLAIN 需三段 NUL 分隔")
	}
	authzid, cid, pwd := string(parts[0]), string(parts[1]), string(parts[2])
	if cid == "" || pwd == "" {
		return "", "", errors.New("pop3: PLAIN authcid/passwd 为空")
	}
	if authzid != "" && authzid != cid {
		return "", "", errors.New("pop3: PLAIN authzid 不匹配")
	}
	return cid, pwd, nil
}

// loadMaildrop 载入 INBOX 快照（TRANSACTION 进入点；rfc1939 §4：打开 maildrop
// 指派 message-number 1..n 并记录大小）。
// 数据面（契约 v1.3.1 2.1 既有方法零扩展）：FolderRepo.List 定位 kind=inbox →
// IMAPSearch 空 filter（FlagDeleted=false 排除 IMAP \Deleted 残留——与 IMAP 侧
// 删除语义一致）。
// 配置并发批 F10（M3 N+1 消除）：IMAPSearch 列集尾部自本批起含 raw_size/blob_key
// ——maildrop 快照单查询直取（原逐条 GetDetail 取 uid/size/blobKey 为 N+1 查询，
// 十万封级登录 P95 风险；GetDetail 调用计数归零，RETR/TOP 消费快照内 blobKey）。
func (ss *session) loadMaildrop() error {
	folders, err := ss.server.folders.List(ss.ctx(), ss.mbox.ID)
	if err != nil {
		return fmt.Errorf("列举文件夹: %w", err)
	}
	var inboxID int64 = -1
	for _, f := range folders {
		if f.Kind == storage.FolderKindInbox {
			inboxID = f.ID
			break
		}
	}
	if inboxID < 0 {
		return errors.New("pop3: INBOX 文件夹缺失")
	}
	no := false
	items, err := ss.server.messages.IMAPSearch(ss.ctx(), storage.IMAPSearchQuery{
		MailboxID: ss.mbox.ID,
		FolderID:  inboxID,
		Filter:    storage.SearchFilter{FlagDeleted: &no}, // 排除 status=deleted
	})
	if err != nil {
		return fmt.Errorf("检索 maildrop: %w", err)
	}
	ss.msgs = ss.msgs[:0]
	for _, it := range items {
		// F10：单查询直取（GetDetail N+1 消除——id/uid/size/blobKey 均来自本批
		// 扩展的 IMAPSearch 列集）
		ss.msgs = append(ss.msgs, pop3Msg{id: it.ID, uid: it.UID, size: it.Size, blobKey: it.BlobKey})
	}
	return nil
}

// ───────────────────────── TRANSACTION 态（rfc1939 §5） ─────────────────────────

// dispatchTransaction TRANSACTION 态命令分派（PIPELINING 逐条处理——rfc2449 §6.6）。
// 返回 false=会话结束（QUIT）。
func (ss *session) dispatchTransaction(keyword, arg string) bool {
	switch keyword {
	case "STAT":
		ss.cmdSTAT()
	case "LIST":
		ss.cmdLIST(arg)
	case "RETR":
		ss.cmdRETR(arg)
	case "TOP":
		ss.cmdTOP(arg)
	case "UIDL":
		ss.cmdUIDL(arg)
	case "DELE":
		ss.cmdDELE(arg)
	case "NOOP":
		ss.writeLine("+OK")
	case "RSET":
		for i := range ss.msgs { // rfc1939 §5：撤销全部删除标记
			ss.msgs[i].deleted = false
		}
		ss.writeLine("+OK maildrop reset")
	case "CAPA":
		ss.cmdCAPA()
	case "QUIT":
		return ss.cmdUpdateQuit()
	case "AUTH": // rfc5034 §4：成功后 MUST -ERR
		ss.writeLine("-ERR already authenticated")
	default:
		ss.writeLine("-ERR unknown command")
	}
	return true
}

// visible 快照中未标记删除的消息序号集（rfc1939 §5：标记删除的不计入 STAT/LIST/UIDL）。
func (ss *session) visible() []int {
	out := make([]int, 0, len(ss.msgs))
	for i := range ss.msgs {
		if !ss.msgs[i].deleted {
			out = append(out, i)
		}
	}
	return out
}

// msgByNum message-number → 快照下标（1-based；已标记删除视同不存在——rfc1939 §5）。
func (ss *session) msgByNum(num int) (int, bool) {
	if num < 1 || num > len(ss.msgs) {
		return 0, false
	}
	if ss.msgs[num-1].deleted {
		return 0, false
	}
	return num - 1, true
}

// cmdSTAT drop listing（rfc1939 §5："+OK nn mm"——条数与八位组总数，标记删除不计）。
func (ss *session) cmdSTAT() {
	var count, total int64
	for i := range ss.msgs {
		if !ss.msgs[i].deleted {
			count++
			total += ss.msgs[i].size
		}
	}
	ss.writeLine(fmt.Sprintf("+OK %d %d", count, total))
}

// cmdLIST scan listing（rfc1939 §5：单参 "+OK n size"；无参多行；空 maildrop
// 亦 +OK 空列表——附录 A 澄清）。
func (ss *session) cmdLIST(arg string) {
	if arg != "" {
		num, err := strconv.Atoi(strings.Fields(arg)[0])
		if err != nil {
			ss.writeLine("-ERR invalid message number")
			return
		}
		idx, ok := ss.msgByNum(num)
		if !ok {
			ss.writeLine(fmt.Sprintf("-ERR no such message, only %d messages in maildrop", len(ss.msgs)))
			return
		}
		ss.writeLine(fmt.Sprintf("+OK %d %d", num, ss.msgs[idx].size))
		return
	}
	ss.writeLine("+OK scan listing follows")
	for _, i := range ss.visible() {
		ss.writeLine(fmt.Sprintf("%d %d", i+1, ss.msgs[i].size))
	}
	ss.writeLine(".")
}

// cmdRETR 发送邮件原文（rfc1939 §5：多行响应+byte-stuff；§11：octet=存储字节）。
func (ss *session) cmdRETR(arg string) {
	idx, ok := ss.msgNumArg(arg)
	if !ok {
		return
	}
	m := &ss.msgs[idx]
	raw, err := ss.server.blobs.Read(ss.ctx(), m.blobKey)
	if err != nil {
		ss.writeLine("-ERR unable to read message")
		return
	}
	ss.writeLine(fmt.Sprintf("+OK %d octets", m.size))
	ss.writeMultiline(raw)
}

// cmdTOP 头+空行+体前 n 行（rfc1939 §8：n 超体行数则发送整个消息；Q3-A）。
func (ss *session) cmdTOP(arg string) {
	fields := strings.Fields(arg)
	if len(fields) != 2 {
		ss.writeLine("-ERR syntax: TOP msg n")
		return
	}
	num, err1 := strconv.Atoi(fields[0])
	n, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil || n < 0 {
		ss.writeLine("-ERR syntax: TOP msg n")
		return
	}
	idx, ok := ss.msgByNum(num)
	if !ok {
		ss.writeLine(fmt.Sprintf("-ERR no such message, only %d messages in maildrop", len(ss.msgs)))
		return
	}
	raw, err := ss.server.blobs.Read(ss.ctx(), ss.msgs[idx].blobKey)
	if err != nil {
		ss.writeLine("-ERR unable to read message")
		return
	}
	ss.writeLine("+OK top of message follows")
	ss.writeMultiline(truncateTop(raw, n))
}

// cmdUIDL unique-id listing（rfc1939 §8："n uid"格式，uid 后无附加信息；
// Q3-A：uid=mailbox_messages.uid 十进制串——0x21-0x7E 字符集天然满足）。
func (ss *session) cmdUIDL(arg string) {
	if arg != "" {
		num, err := strconv.Atoi(strings.Fields(arg)[0])
		if err != nil {
			ss.writeLine("-ERR invalid message number")
			return
		}
		idx, ok := ss.msgByNum(num)
		if !ok {
			ss.writeLine(fmt.Sprintf("-ERR no such message, only %d messages in maildrop", len(ss.msgs)))
			return
		}
		ss.writeLine(fmt.Sprintf("+OK %d %d", num, ss.msgs[idx].uid))
		return
	}
	ss.writeLine("+OK unique-id listing follows")
	for _, i := range ss.visible() {
		ss.writeLine(fmt.Sprintf("%d %d", i+1, ss.msgs[i].uid))
	}
	ss.writeLine(".")
}

// cmdDELE 标记删除（rfc1939 §5：仅内存标记，后续引用该编号 -ERR；UPDATE 态才真删）。
func (ss *session) cmdDELE(arg string) {
	idx, ok := ss.msgNumArg(arg)
	if !ok {
		return
	}
	ss.msgs[idx].deleted = true
	ss.writeLine(fmt.Sprintf("+OK message %d deleted", idx+1))
}

// msgNumArg 解析单消息编号参数（RETR/DELE 共用；错误应答由本函数给出）。
func (ss *session) msgNumArg(arg string) (int, bool) {
	fields := strings.Fields(arg)
	if len(fields) != 1 {
		ss.writeLine("-ERR syntax: message number required")
		return 0, false
	}
	num, err := strconv.Atoi(fields[0])
	if err != nil {
		ss.writeLine("-ERR invalid message number")
		return 0, false
	}
	idx, ok := ss.msgByNum(num)
	if !ok {
		ss.writeLine(fmt.Sprintf("-ERR no such message, only %d messages in maildrop", len(ss.msgs)))
		return 0, false
	}
	return idx, true
}

// ───────────────────────── UPDATE 态（rfc1939 §6） ─────────────────────────

// cmdUpdateQuit TRANSACTION 态 QUIT：提交删除并告别。
// Q1-A：HardDelete 单事务批量（U6 EXPUNGE 同款，孤儿 blob 归对账任务清理）；
// rfc1939 §6：失败 -ERR some deleted messages not removed（单事务原子性保证
// "或全删或全不删"，绝不删未标记消息）。返回 false 结束会话。
func (ss *session) cmdUpdateQuit() bool {
	ids := make([]int64, 0, len(ss.msgs))
	for i := range ss.msgs {
		if ss.msgs[i].deleted {
			ids = append(ids, ss.msgs[i].id)
		}
	}
	if len(ids) > 0 {
		if err := ss.server.messages.HardDelete(ss.ctx(), ids); err != nil {
			slog.Error("POP3 UPDATE 删除失败", "logid", ss.logID, "error", err)
			ss.writeLine("-ERR some deleted messages not removed")
			return false
		}
		slog.Info("POP3 UPDATE 提交删除", "logid", ss.logID, "count", len(ids))
	}
	ss.writeLine("+OK POP3 server signing off")
	return false
}

// ───────────────────────── 读写原语（rfc1939 §3） ─────────────────────────

// readLine 读一行命令（CRLF/LF 兼容；超长截断按语法错误处理）。
func (ss *session) readLine() (string, error) {
	line, err := ss.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > readLineMax {
		return "", errors.New("pop3: 命令行超长")
	}
	// B-S批 F4（裁决 A 2026-10-09 13:34）：认证帧凭据掩码——AUTH 族命令行
	// initial-response 参数与 challenge 轮应答帧（authRedact 置位时整行）替换
	// [REDACTED]（ProtocolDebug 开启时明文口令不落 30 天日志文件；非认证帧原样；
	// 非 debug 模式零输出零行为变化）
	if ss.authRedact {
		ss.debugFrame("C", "[REDACTED]")
	} else {
		ss.debugFrame("C", redactAuthLine(line))
	}
	return line, nil
}

// redactAuthLine AUTH 命令行凭据掩码（B-S批 F4）：`AUTH PLAIN <base64>` 形态的
// initial-response 参数整段替换 [REDACTED]（保留机制名——排障可见认证交互结构）；
// 无参数形态（省略 initial-response，凭据走 challenge 轮）无凭据可掩原样返回。
func redactAuthLine(line string) string {
	trimmed := strings.TrimRight(line, "\r\n")
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "AUTH ") && !strings.HasPrefix(upper, "AUTH\t") {
		return line // 非认证命令——原样
	}
	fields := strings.SplitN(trimmed, " ", 3)
	if len(fields) == 3 {
		return fields[0] + " " + fields[1] + " [REDACTED]\r\n"
	}
	return line
}

// writeLine 写单行响应（自动补 CRLF）。
func (ss *session) writeLine(line string) {
	ss.debugFrame("S", line+"\r\n") // U21 协议 debug（开启时输出——响应面）
	_, _ = ss.w.WriteString(line + "\r\n")
	_ = ss.w.Flush()
}

// debugFrame 协议 debug 条件输出（U21——H5 等价；快照关闭时零开销跳过）。
// 参数：dir 方向前缀（C=客户端来向/S=服务端去向）；line 原始行（含行尾）。
// 范围口径：命令/单行响应面逐行输出；writeMultiline 邮件体不输出（防刷屏——排障对象
// 为交互；logid 属性经 session.logID 承载关联）。
func (ss *session) debugFrame(dir, line string) {
	if ss.server == nil || !ss.server.protocolDebug() {
		return
	}
	slog.Debug("pop3_debug", "proto", "pop3", "logid", ss.logID, "dir", dir, "data", strings.TrimRight(line, "\r\n"))
}

// writeMultiline 多行响应（rfc1939 §3：以 '.' 开头的行前置填充一个 '.'；
// 五八位组 CRLF.CRLF 终止。原文行尾统一规范化为 CRLF）。
func (ss *session) writeMultiline(raw []byte) {
	data := normalizeCRLF(raw)
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 0 && line[0] == '.' {
			ss.w.WriteByte('.')
		}
		ss.w.Write(line)
		ss.w.WriteString("\r\n")
	}
	ss.w.WriteString(".\r\n")
	_ = ss.w.Flush()
}

// normalizeCRLF 行尾规范化为 LF 便于逐行处理（\r\n→\n；孤行 \r 保留原样）。
func normalizeCRLF(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

// truncateTop 截取头块+空行+体前 n 行（rfc1939 §8；n 超体行数返回原文）。
// 输出形态：头块（含尾换行）+空行+体前 n 行（各含尾换行）。
func truncateTop(raw []byte, n int) []byte {
	data := normalizeCRLF(raw)
	headEnd := findHeaderEnd(data)
	if headEnd < 0 {
		return data // 无空行分隔：整体视作头
	}
	head := data[:headEnd+1] // 头块含尾换行（headEnd 指向首个 \n）
	body := data[headEnd+2:] // 跳过头体分隔的两个换行
	lines := bytes.SplitAfter(body, []byte("\n"))
	if n >= len(lines) {
		return data
	}
	var out []byte
	out = append(out, head...)
	out = append(out, []byte("\n")...) // 头与体之间的空行
	out = append(out, bytes.Join(lines[:n], nil)...)
	return out
}

// findHeaderEnd 定位头块结束（首个空行前的换行位置；-1=未找到）。
func findHeaderEnd(data []byte) int {
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return i
	}
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return i
	}
	return -1
}

// ctx 会话上下文（LogID 经 slog 全局关联；预留 ctx 化演进位）。
func (ss *session) ctx() context.Context { return context.Background() }

// splitCommand 拆分命令关键词与参数（关键词大小写不敏感——rfc1939 附录 A）。
func splitCommand(line string) (keyword, arg string) {
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", ""
	}
	return strings.ToUpper(fields[0]), strings.TrimPrefix(line, fields[0])
}
