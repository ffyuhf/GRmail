// smtp 服务端会话单测（NFR-015：net.Pipe 内存管道驱动，零网络端点）。
// 覆盖锚点：rfc5321bis 4.1.4（顺序 503）、4.1.1.4（<CRLF>.<CRLF> 终止/裸 LF 不终止）、
// 4.5.2（点透明）、rfc1870（SIZE 双闸 552）、PIPELINING（批量逐答）、
// 关键流程设计第二章（RCPT 三态）、TC-021（451 应答）、Q3-B（无 STARTTLS/AUTH 通告）。
// 修改历史：
//
//	2026-09-17 04:25:00 | 新建 | U4 SMTP 收信（计划书步骤 11）
package smtp

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// ───────────────────────── 测试 stub ─────────────────────────

// stubPipeline 记录投递输入（或注入可重试失败——TC-021）。
type stubPipeline struct {
	got     []*mail.Delivery
	raws    [][]byte
	failErr error
}

func (s *stubPipeline) Deliver(_ context.Context, in *mail.Delivery, raw []byte) error {
	if s.failErr != nil {
		return s.failErr
	}
	cp := make([]byte, len(raw))
	copy(cp, raw)
	s.got = append(s.got, in)
	s.raws = append(s.raws, cp)
	return nil
}

// stubResolver 内存邮箱表。
type stubResolver struct {
	mailboxes map[string]storage.MailboxStatus
}

func (s stubResolver) GetMailbox(_ context.Context, addr string) (*storage.Mailbox, error) {
	if st, ok := s.mailboxes[strings.ToLower(addr)]; ok {
		return &storage.Mailbox{ID: 1, Address: strings.ToLower(addr), Status: st}, nil
	}
	return nil, storage.ErrMailboxNotFound
}

// testHarness net.Pipe 会话测试装置。
type testHarness struct {
	client net.Conn
	reader *bufio.Reader // 共享读取器（预读缓冲不跨 expect 丢失——缺陷修正 2026-09-17 04:40）
	pipe   *stubPipeline
	srv    *Server
	t      *testing.T
}

// newHarness 建立管道会话（服务端 goroutine 独立运行；横幅由 expect 消费）。
func newHarness(t *testing.T, mailboxes map[string]storage.MailboxStatus, catchAll bool, maxSz int64) *testHarness {
	t.Helper()
	client, server := net.Pipe()
	pipe := &stubPipeline{}
	resolver := stubResolver{mailboxes: mailboxes}
	cfg := ServerConfig{
		Domain:          "t.io",
		MaxMessageSize:  func() int64 { return maxSz },
		CatchAllEnabled: func() bool { return catchAll },
	}
	srv := NewServer(cfg, pipe, resolver)
	go srv.serveConn(server)
	t.Cleanup(func() { _ = client.Close() })
	h := &testHarness{client: client, reader: bufio.NewReader(client), pipe: pipe, srv: srv, t: t}
	h.expect("220") // 横幅
	return h
}

// send 写一行命令（补 CRLF）。
func (h *testHarness) send(line string) {
	h.t.Helper()
	if _, err := h.client.Write([]byte(line + "\r\n")); err != nil {
		h.t.Fatalf("发送 %q: %v", line, err)
	}
}

// sendRaw 写原始字节（DATA 体，不补行尾）。
func (h *testHarness) sendRaw(data string) {
	h.t.Helper()
	if _, err := h.client.Write([]byte(data)); err != nil {
		h.t.Fatalf("发送原始数据: %v", err)
	}
}

// expect 读取应答直至前缀匹配（多行能力通告循环读完；共享 reader 防预读丢失）。
func (h *testHarness) expect(prefix string) string {
	h.t.Helper()
	var last string
	for {
		line, err := h.reader.ReadString('\n')
		if err != nil {
			h.t.Fatalf("读应答: %v", err)
		}
		last = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(last, prefix+" ") || (last == prefix) {
			return last
		}
		// 多行（code-）继续读
		if len(last) > 4 && last[3] == '-' {
			continue
		}
		h.t.Fatalf("应答 %q 不匹配期望前缀 %q", last, prefix)
	}
}

// dialog 单命令应答快捷（send+expect）。
func (h *testHarness) dialog(sendLine, expectCode string) string {
	h.t.Helper()
	h.send(sendLine)
	return h.expect(expectCode)
}

// deliverMail 完整事务：EHLO→MAIL→RCPT→DATA→体→终止。
func (h *testHarness) deliverMail(rcpt, body string, expectCode string) string {
	h.t.Helper()
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RCPT TO:<"+rcpt+">", "250")
	h.dialog("DATA", "354")
	h.sendRaw(body)
	return h.expect(expectCode)
}

// ───────────────────────── 会话矩阵 ─────────────────────────

// TestEhloCapabilities 能力通告（1.5⑦：五扩展；Q3-B：无 STARTTLS/AUTH）。
func TestEhloCapabilities(t *testing.T) {
	h := newHarness(t, nil, true, 36700160)
	caps := h.dialog("EHLO tester", "250")
	// 多行能力需继续读取（expect 已循环读完；此处校验整体应答流）
	_ = caps
	h.send("EHLO tester")
	r := h.reader // 共享 reader（预读缓冲安全）
	var got []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("读能力行: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		got = append(got, line)
		if len(line) > 3 && line[3] == ' ' {
			break
		}
	}
	joined := strings.Join(got, "\n")
	for _, kw := range []string{"SIZE 36700160", "8BITMIME", "SMTPUTF8", "PIPELINING", "ENHANCEDSTATUSCODES"} {
		if !strings.Contains(joined, kw) {
			t.Fatalf("能力行缺 %s:\n%s", kw, joined)
		}
	}
	if strings.Contains(joined, "STARTTLS") || strings.Contains(joined, "AUTH") {
		t.Fatalf("Q3-B：收信端点不应通告 STARTTLS/AUTH:\n%s", joined)
	}
}

// TestCommandOrderViolations 顺序违规 503（rfc5321bis 4.1.4）。
func TestCommandOrderViolations(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 36700160)
	h.dialog("MAIL FROM:<s@example.com>", "503") // 无 EHLO
	h.dialog("RCPT TO:<a@t.io>", "503")          // 无 MAIL
	h.dialog("DATA", "503")                      // 无 RCPT
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250") // 顺序就绪后成功
	h.dialog("MAIL FROM:<s@example.com>", "503") // 事务中重复 MAIL
}

// TestRcptStates RCPT 三态与拒绝分支（流程设计第二章+1.5⑥）。
// RF-I/F-8 增补：无域 <Postmaster> 特判（rfc5321bis §2.3.5+§4.5.1 MUST be
// supported——大小写不敏感；映射 postmaster@本主域 走三态判定）。
func TestRcptStates(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{
		"active@t.io":     storage.MailboxStatusActive,
		"shadow@t.io":     storage.MailboxStatusShadow,
		"off@t.io":        storage.MailboxStatusDisabled,
		"postmaster@t.io": storage.MailboxStatusActive,
	}, true, 36700160)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RCPT TO:<ACTIVE@T.IO>", "250") // 大写归一
	h.dialog("RCPT TO:<shadow@t.io>", "250")
	h.dialog("RCPT TO:<off@t.io>", "550")   // disabled
	h.dialog("RCPT TO:<new@t.io>", "250")   // 不存在+catchall 开启
	h.dialog("RCPT TO:<x@other.io>", "550") // 非本域（防中继）
	h.dialog("RCPT TO:<Postmaster>", "250") // F-8：无域形态（大小写不敏感）
	h.dialog("RCPT TO:<postmaster>", "250") // F-8：小写同判
}

// TestRcptNoCatchAll CatchAll 关闭：不存在 550（FR-003 条件语义）。
func TestRcptNoCatchAll(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, false, 36700160)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RCPT TO:<a@t.io>", "250")
	h.dialog("RCPT TO:<nobody@t.io>", "550")
}

// TestSizePrecheck MAIL SIZE 声明超限 552（rfc1870 6.2 预检）。
func TestSizePrecheck(t *testing.T) {
	h := newHarness(t, nil, true, 1000)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com> SIZE=2000", "552")
	h.dialog("MAIL FROM:<s@example.com> SIZE=500", "250")
}

// TestDataDeliverSuccess 投递成功 250：点透明还原+信封透传（4.5.2+流程第一章）。
func TestDataDeliverSuccess(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 36700160)
	h.dialog("EHLO mail.example.com", "250")
	h.dialog("MAIL FROM:<s@example.com> BODY=8BITMIME SMTPUTF8", "250")
	h.dialog("RCPT TO:<a@t.io>", "250")
	h.dialog("DATA", "354")
	h.sendRaw("Subject: t\r\n\r\n..dot line\r\n..normal\r\n.\r\n") // 双点 stuffing（4.5.2 客户端侧）；末行 CRLF 后 ".\r\n" 终止
	h.expect("250")

	if len(h.pipe.got) != 1 {
		t.Fatalf("应投递一次: %d", len(h.pipe.got))
	}
	in := h.pipe.got[0]
	if in.Envelope.Helo != "mail.example.com" || in.Envelope.MailFrom != "s@example.com" {
		t.Fatalf("信封透传错: %+v", in.Envelope)
	}
	if in.Recipients[0] != "a@t.io" {
		t.Fatalf("收件人错: %v", in.Recipients)
	}
	// 点透明还原：..dot→.dot；消息 CRLF 收尾
	if string(h.pipe.raws[0]) != "Subject: t\r\n\r\n.dot line\r\n.normal\r\n" {
		t.Fatalf("点透明/行尾还原错: %q", string(h.pipe.raws[0]))
	}
}

// TestDataRetryable451 管道 Retryable→451（TC-021 判定①：非虚假 250）。
func TestDataRetryable451(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 36700160)
	h.pipe.failErr = mail.ErrRetryable
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RCPT TO:<a@t.io>", "250")
	h.dialog("DATA", "354")
	h.sendRaw("body\r\n.\r\n") // 终止序列（失败应答前同样需协议同步收尾）
	h.expect("451")
}

// TestDataTooBig DATA 累计超限 552（rfc1870 6.3 实际超传输）。
func TestDataTooBig(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 64)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RCPT TO:<a@t.io>", "250")
	h.dialog("DATA", "354")
	h.sendRaw(strings.Repeat("x", 100) + "\r\n.\r\n") // 超限后以终止点收尾
	h.expect("552")
}

// TestBareLFNotTerminator 裸 <LF>.<LF> 不终止（4.1.1.4 MUST NOT；数据保留）。
func TestBareLFNotTerminator(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 36700160)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RCPT TO:<a@t.io>", "250")
	h.dialog("DATA", "354")
	h.sendRaw("a\n.\nb\r\n.\r\n") // 中间 \n.\n 为数据；\r\n.\r\n 才终止
	h.expect("250")
	// 数据字节原样保留（裸 LF 不作行终止、不触发点剥离规则歧义——按字节保真）
	if !strings.Contains(string(h.pipe.raws[0]), "a\n.\nb\r\n") {
		t.Fatalf("裸 LF 数据保真失败: %q", string(h.pipe.raws[0]))
	}
}

// TestPipeliningBatch 批量发送逐行应答（rfc2920 服务器义务 1：按序应答）。
func TestPipeliningBatch(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 36700160)
	h.send("EHLO tester\r\nMAIL FROM:<s@example.com>\r\nRCPT TO:<a@t.io>\r\nDATA")
	// 逐个消费：EHLO 多行 250、MAIL 250、RCPT 250、DATA 354
	h.expect("250")
	h.expect("250")
	h.expect("250")
	h.expect("354")
	h.sendRaw("x\r\n.\r\n")
	h.expect("250")
}

// TestMiscCommands NOOP/VRFY/未知/RSET/QUIT（4.1.4：无 EHLO 亦可用）。
func TestMiscCommands(t *testing.T) {
	h := newHarness(t, nil, true, 36700160)
	h.dialog("NOOP", "250")
	h.dialog("VRFY a@t.io", "252")
	h.dialog("BOGUS", "500")
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250")
	h.dialog("RSET", "250")
	h.dialog("MAIL FROM:<s@example.com>", "250") // RSET 后可重新 MAIL
	h.dialog("QUIT", "221")
}

// TestEmptyMailFrom 空路径 <> 合法（退信场景，rfc5321bis 3.6/4.1.2）。
func TestEmptyMailFrom(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"a@t.io": storage.MailboxStatusActive}, true, 36700160)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<>", "250")
	h.dialog("RCPT TO:<a@t.io>", "250")
	h.dialog("DATA", "354")
	h.sendRaw("\r\n.\r\n") // 空消息
	h.expect("250")
	if h.pipe.got[0].Envelope.MailFrom != "" {
		t.Fatalf("空路径应透传空串: %q", h.pipe.got[0].Envelope.MailFrom)
	}
}

// TestMailParamsUnsupported 不支持的 MAIL 参数 555（4.1.1.11）。
func TestMailParamsUnsupported(t *testing.T) {
	h := newHarness(t, nil, true, 36700160)
	h.dialog("EHLO tester", "250")
	h.dialog("MAIL FROM:<s@example.com> FOO=bar", "555")
}

// 编译期 stub 接口锁定（Server 消费 mail.InboundPipeline 与本包 MailboxResolver）。
var (
	_ mail.InboundPipeline = (*stubPipeline)(nil)
	_ MailboxResolver      = stubResolver{}
)
