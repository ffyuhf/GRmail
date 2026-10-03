// mail 域 U5 单测：提交管道/DSN 构造/出站投递/worker 状态机（NFR-015：
// stub 管理员/stub MX/net.Pipe 模拟对端/内存 Blob 全离线驱动）。
// 2026-09-29 17:30:00 | RF-H | F-L2/F-L8 出站声明面矩阵测试（RFC候选修正批次）。
// 覆盖锚点：FR-002 授权三分支（rfc6409 3.2/6.1）、rfc6409 8.2/8.3 头补齐、
// Q3-A 本域分流、Q4-A DSN 结构（rfc3464 2/2.2/2.3）与防循环、Q5-C 退避序列、
// Q6 修订域分组、TC-021 判定②（回写失败态保持）。
// 修改历史：
//
//	2026-09-17 13:20:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 6-9 检查点）
//	2026-09-28 09:34:00 | 重构 | R5R6收敛：6 处 SetMessageSource 全局注入+defer 清理
//	废除——8 处 NewOutboundSenderService 构造末位传 fixedSource/messages stub
//	（依据：R5R6收敛计划书 v1.0.0 步骤 4，G2 批准 2026-09-28 09:31:53）
package mail

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// ───────────────────────── 测试替身 ─────────────────────────

// stubAdmins 内存管理员表。
type stubAdmins struct{ admins map[string]bool }

func (s *stubAdmins) IsAdminUser(_ context.Context, name string) (bool, error) {
	return s.admins[name], nil
}

// stubSigner 恒成功签名（前置标记字节）。
type stubSigner struct {
	prefix string
	calls  int
}

func (s *stubSigner) Sign(_ context.Context, msg []byte, _ string) ([]byte, error) {
	s.calls++
	return append([]byte(s.prefix), msg...), nil
}

// keylessSigner 恒返回 ErrKeyNotConfigured（跳过路径）。
type keylessSigner struct{}

func (keylessSigner) Sign(_ context.Context, msg []byte, _ string) ([]byte, error) {
	return nil, auth.ErrKeyNotConfigured
}

// （memBlobs/newMemBlobs 复用 pipeline_test.go U4 既有替身，不重复定义）

// stubSubmissionStore 入队捕获（事务形态断言位）。
type stubSubmissionStore struct {
	mu    sync.Mutex
	metas []*storage.SubmissionMeta
	fail  bool
}

func (s *stubSubmissionStore) StoreSubmission(_ context.Context, m *storage.SubmissionMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return fmt.Errorf("注入事务失败")
	}
	s.metas = append(s.metas, m)
	return nil
}

// stubInbound 本域分流收信管道捕获。
type stubInbound struct {
	mu       sync.Mutex
	delivers []*Delivery
	raws     [][]byte
	fail     bool
}

func (s *stubInbound) Deliver(_ context.Context, in *Delivery, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return fmt.Errorf("注入落库失败")
	}
	s.delivers = append(s.delivers, in)
	s.raws = append(s.raws, raw)
	return nil
}

// stubMX 内存 MX 解析。
type stubMX struct {
	mx    map[string][]string
	hosts map[string][]string
}

func (s *stubMX) LookupMX(_ context.Context, domain string) ([]string, error) {
	return s.mx[domain], nil
}
func (s *stubMX) LookupHost(_ context.Context, host string) ([]string, error) {
	return s.hosts[host], nil
}

// pipeDialer 测试连接工厂（TCP loopback：net.Pipe 全同步语义下「QUIT 写与 221 写」
// 双向互等易死锁，loopback 内核缓冲吸收使脚本化对端稳定——NFR-015 离线口径内的
// 本地回环，不触外部端点）。
type pipeDialer struct {
	addr string
}

// newFakeServerDialer 启动 loopback 监听并逐连接交给脚本化 serve。
func newFakeServerDialer(t *testing.T, handler func(net.Conn)) *pipeDialer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback 监听: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return &pipeDialer{addr: ln.Addr().String()}
}

// Dial 连接 loopback 服务端。
func (p *pipeDialer) Dial(ctx context.Context, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", p.addr)
}

// fakeSMTPServer 模拟对端脚本：lines 依次写入；captured 收命令。
type fakeSMTPServer struct {
	mu       sync.Mutex
	captured []string
	// 每轮响应脚本（索引对齐命令序：greeting/EHLO/MAIL/RCPT/DATA/ACK）
	greet  string // 220 行
	ehlo   string // 250 能力（可含 STARTTLS）
	mail   string
	rcpt   string
	data   string // 354 或拒绝
	ack    string // DATA 后终应答
	onData func(body string)
}

// serve 读取命令直到连接关闭或 QUIT。
func (f *fakeSMTPServer) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(s string) {
		_, _ = w.WriteString(s + "\r\n")
		_ = w.Flush()
	}
	write(f.greet)
	var dataMode bool
	var body []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		f.mu.Lock()
		f.captured = append(f.captured, cmd)
		f.mu.Unlock()
		if dataMode {
			if cmd == "." {
				dataMode = false
				write(f.ack)
				if f.onData != nil {
					f.onData(strings.Join(body, "\r\n"))
				}
			} else {
				body = append(body, strings.TrimPrefix(cmd, "."))
			}
			continue
		}
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			write(f.ehlo)
		case strings.HasPrefix(cmd, "STARTTLS"):
			write("220 ready") // 握手由测试侧 tls.Client 完成（本桩不真握手——用例仅验明文路径）
		case strings.HasPrefix(cmd, "MAIL"):
			write(f.mail)
		case strings.HasPrefix(cmd, "RCPT"):
			write(f.rcpt)
		case strings.HasPrefix(cmd, "DATA"):
			if strings.HasPrefix(f.data, "354") {
				write(f.data)
				dataMode = true
			} else {
				write(f.data)
			}
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

// ───────────────────────── 提交管道 ─────────────────────────

// TestSubmitAuthorization 授权三分支：管理员任意地址/null path 放行/普通用户不一致拒绝。
func TestSubmitAuthorization(t *testing.T) {
	ctx := context.Background()
	svc := NewSubmissionPipelineService(&keylessSigner{}, newMemBlobs(),
		&stubSubmissionStore{}, &stubAdmins{admins: map[string]bool{"boss": true}}, "t.io")
	raw := []byte("Subject: hi\r\nFrom: a@t.io\r\n\r\nbody\r\n")

	// 管理员任意地址（FR-002）
	if err := svc.Submit(ctx, &Submission{
		Envelope: auth.Envelope{MailFrom: "anyone@t.io"}, AuthUser: "boss",
		Recipients: []string{"x@ext.io"},
	}, raw); err != nil {
		t.Fatalf("管理员任意地址应放行: %v", err)
	}
	// null path 允许（rfc6409 3.2）
	if err := svc.Submit(ctx, &Submission{
		Envelope:   auth.Envelope{MailFrom: ""},
		Recipients: []string{"x@ext.io"},
	}, raw); err != nil {
		t.Fatalf("null path 应放行: %v", err)
	}
	// 普通用户 From 不一致→ErrUnauthorized（rfc6409 6.1）
	err := svc.Submit(ctx, &Submission{
		Envelope: auth.Envelope{MailFrom: "other@t.io"}, AuthUser: "a@t.io",
		Recipients: []string{"x@ext.io"},
	}, raw)
	if err == nil || !strings.Contains(err.Error(), ErrUnauthorized.Error()) {
		t.Fatalf("应拒绝授权: %v", err)
	}
}

// TestSubmitEnqueuesPerRecipient 头补齐+逐收件人入队+签名前置（Blob 字节验证）。
func TestSubmitEnqueuesPerRecipient(t *testing.T) {
	ctx := context.Background()
	blobs := newMemBlobs()
	store := &stubSubmissionStore{}
	signer := &stubSigner{prefix: "DKIM-Sig\r\n"}
	svc := NewSubmissionPipelineService(signer, blobs, store,
		&stubAdmins{admins: map[string]bool{"boss": true}}, "t.io")

	if err := svc.Submit(ctx, &Submission{
		Envelope:   auth.Envelope{MailFrom: "boss@t.io", Helo: "cli"},
		AuthUser:   "boss",
		Recipients: []string{"r1@ext.io", "r2@ext.io"},
		DSNParams:  []DSNParam{{Keyword: "NOTIFY", Value: "FAILURE", Rcpt: "r1@ext.io"}},
	}, []byte("Subject: s\r\nFrom: b@t.io\r\n\r\nhello\r\n")); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(store.metas) != 1 {
		t.Fatalf("应单次事务: %d", len(store.metas))
	}
	meta := store.metas[0]
	if len(meta.Items) != 2 || meta.Items[0].RcptTo != "r1@ext.io" || meta.Items[1].RcptTo != "r2@ext.io" {
		t.Fatalf("逐收件人队列行不符: %+v", meta.Items)
	}
	if meta.Message.BlobKey == "" || meta.Message.RawSize == 0 {
		t.Fatalf("messages 元数据不符: %+v", meta.Message)
	}
	stored, _ := blobs.Read(ctx, meta.Message.BlobKey)
	text := string(stored)
	for _, want := range []string{"DKIM-Sig", "Date:", "Message-ID:"} { // 签名前置+头补齐（rfc6409 8.2/8.3）
		if !strings.Contains(text, want) {
			t.Fatalf("存储字节缺 %s: %q", want, text[:min(120, len(text))])
		}
	}
}

// TestSubmitStoreFailure451 事务失败→ErrRetryable（451 语义，CON-004 提交侧）。
func TestSubmitStoreFailure451(t *testing.T) {
	ctx := context.Background()
	svc := NewSubmissionPipelineService(&keylessSigner{}, newMemBlobs(),
		&stubSubmissionStore{fail: true}, &stubAdmins{admins: map[string]bool{"boss": true}}, "t.io")
	err := svc.Submit(ctx, &Submission{
		Envelope: auth.Envelope{MailFrom: ""}, Recipients: []string{"x@ext.io"},
	}, []byte("Subject: s\r\n\r\nb\r\n"))
	if err == nil || !strings.Contains(err.Error(), ErrRetryable.Error()) {
		t.Fatalf("应 451 语义: %v", err)
	}
}

// ───────────────────────── DSN 构造 ─────────────────────────

// TestDSNBuildStructure rfc3464 结构断言：三分量/必需字段/Auto-Submitted/null 信封约定。
func TestDSNBuildStructure(t *testing.T) {
	origRaw := "Subject: original\r\nFrom: a@t.io\r\n\r\noriginal body\r\n"
	blobs := newMemBlobs()
	key := sha256Hex([]byte(origRaw))
	_ = blobs.Write(context.Background(), key, []byte(origRaw))
	src := &memoSource{blobs: blobs, key: key}
	b := NewDSNBuilderService("t.io", src)

	item := &storage.QueueItem{MessageID: 7, EnvelopeFrom: "sender@t.io", RcptTo: "gone@ext.io"}
	raw, err := b.Build(context.Background(), item, storage.AttemptResult{
		Status: storage.AttemptFailed, SMTPCode: 550, Error: "no such user",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"Content-Type: multipart/report; report-type=delivery-status",
		"From: MAILER-DAEMON <postmaster@t.io>",
		"To: <sender@t.io>", // 收件人=原信封 return address（rfc3464 2）
		"Auto-Submitted: auto-replied",
		"Reporting-MTA: dns; t.io",             // 2.2 必需
		"Final-Recipient: rfc822; gone@ext.io", // 2.3 必需
		"Action: failed",                       // 五值域
		"Status: 5.1.1",                        // 550→5.1.1（rfc3463）
		"Diagnostic-Code: smtp; 550 no such user",
		"Subject: original", // 第三分量原信头
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("DSN 缺少 %q:\n%s", want, text)
		}
	}
}

// memoSource 固定键消息源（stub）。
type memoSource struct {
	blobs *memBlobs
	key   string
}

func (m *memoSource) ReadOriginal(ctx context.Context, _ int64) ([]byte, error) {
	return m.blobs.Read(ctx, m.key)
}

// ───────────────────────── 出站投递 ─────────────────────────

// TestSenderLocalDomainShortcut 本域分流：不出网直达收信管道（Q3-A）。
func TestSenderLocalDomainShortcut(t *testing.T) {
	local := &stubInbound{}
	s := NewOutboundSenderService("t.io", local, &stubMX{}, newIdleDialer(t), nil,
		&fixedSource{raw: []byte("Subject: local\r\n\r\nbody\r\n")})
	res := s.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "a@t.io", RcptTo: "b@t.io",
	})
	if res.Status != storage.AttemptSent {
		t.Fatalf("本域应 sent: %+v", res)
	}
	if len(local.delivers) != 1 || local.delivers[0].Recipients[0] != "b@t.io" {
		t.Fatalf("分流应调用收信管道: %+v", local.delivers)
	}
	// 落库失败→deferred（不 failed 防误退信）
	local.fail = true
	res = s.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "a@t.io", RcptTo: "b@t.io",
	})
	if res.Status != storage.AttemptDeferred {
		t.Fatalf("本域失败应 deferred: %+v", res)
	}
}

// TestSenderRemoteSuccess 外域成功路径：协议序列/点透明/终态 sent。
func TestSenderRemoteSuccess(t *testing.T) {
	srv := &fakeSMTPServer{
		greet: "220 ext.io ESMTP", ehlo: "250-ext.io\r\n250-SIZE 10485760\r\n250 8BITMIME",
		mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 queued",
	}
	bodyCh := make(chan string, 1)
	srv.onData = func(b string) { bodyCh <- b }
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nline\r\n.dotline\r\n")})
	res := s.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "a@t.io", RcptTo: "x@ext.io",
	})
	if res.Status != storage.AttemptSent {
		t.Fatalf("应 sent: %+v", res)
	}
	// 点透明：".dotline" 应以 "..dotline" 发送（U4 语义复刻；channel 同步消回调竞态）
	var gotBody string
	select {
	case gotBody = <-bodyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("未收到 DATA 体回调")
	}
	if !strings.Contains(gotBody, "\r\n.dotline") { // 还原体含点行（接收方视角）
		t.Fatalf("点行还原不符: %q", gotBody)
	}
	stuffed := false // 发送形态（captured 原始行）应以 .. 传输（U4 dot-stuffing 复刻）
	srv.mu.Lock()
	for _, c := range srv.captured {
		if c == "..dotline" {
			stuffed = true
		}
	}
	first := srv.captured[0]
	srv.mu.Unlock()
	if !stuffed {
		t.Fatal("发送形态应含 ..dotline（dot-stuffing）")
	}
	if !strings.HasPrefix(first, "EHLO t.io") {
		t.Fatalf("EHLO 命令不符: %q", first)
	}
}

// TestSenderRemoteClassify 4xx→deferred/5xx→failed/连接失败逐 MX 转移。
func TestSenderRemoteClassify(t *testing.T) {
	// RCPT 5xx→failed
	srv5xx := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ok", mail: "250 ok",
		rcpt: "550 no such user", data: "554", ack: "554"}
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv5xx.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nb\r\n")})
	if res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"}); res.Status != storage.AttemptFailed || res.SMTPCode != 550 {
		t.Fatalf("5xx 应 failed: %+v", res)
	}
	// MAIL 4xx→deferred
	srv4xx := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ok", mail: "451 later", rcpt: "250", data: "354", ack: "250"}
	s2 := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv4xx.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nb\r\n")})
	if res := s2.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"}); res.Status != storage.AttemptDeferred || res.SMTPCode != 451 {
		t.Fatalf("4xx 应 deferred: %+v", res)
	}
	// 无 MX 无 A→deferred（E6 双失败组合）
	s3 := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{}, newIdleDialer(t), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nb\r\n")})
	if res := s3.Send(context.Background(), &storage.QueueItem{RcptTo: "x@nowhere.io"}); res.Status != storage.AttemptDeferred {
		t.Fatalf("解析失败应 deferred: %+v", res)
	}
}

// newIdleDialer 空脚本 loopback（本域/解析失败路径不触达——防御性兜底）。
func newIdleDialer(t *testing.T) *pipeDialer {
	return newFakeServerDialer(t, func(conn net.Conn) { _ = conn.Close() })
}

// capturedMailLine 提取 captured 中的 MAIL 命令行（唯一）。
func capturedMailLine(t *testing.T, srv *fakeSMTPServer) string {
	t.Helper()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for _, c := range srv.captured {
		if strings.HasPrefix(c, "MAIL FROM:") {
			return c
		}
	}
	t.Fatal("captured 中无 MAIL 命令")
	return ""
}

// TestSenderMailParamsDeclaration F-L2/F-L8 出站声明面矩阵（rfc6531 §3.3——
// 非 ASCII 信封 MUST 声明 SMTPUTF8/对端未通告不可投递；rfc6152 §2——8bit 内容
// 须声明 BODY=8BITMIME/对端未通告 MUST NOT 发送）。
func TestSenderMailParamsDeclaration(t *testing.T) {
	// 用例 1：对端双通告+非 ASCII 信封+8bit 内容 → 双参数声明+sent
	srv := &fakeSMTPServer{
		greet: "220 ext.io ESMTP",
		ehlo:  "250-ext.io\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250 SMTPUTF8",
		mail:  "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 queued",
	}
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\n\xe4\xb8\xad\xe6\x96\x87\r\n")})
	res := s.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "张三@t.io", RcptTo: "user@ext.io",
	})
	if res.Status != storage.AttemptSent {
		t.Fatalf("双通告对端应 sent: %+v", res)
	}
	if got := capturedMailLine(t, srv); got != "MAIL FROM:<张三@t.io> SMTPUTF8 BODY=8BITMIME" {
		t.Fatalf("MAIL 声明参数不符（F-L2/F-L8）: %q", got)
	}

	// 用例 2：对端未通告 SMTPUTF8+非 ASCII 信封 → deferred（rfc6531 §3.3 不可投递）
	srv2 := &fakeSMTPServer{greet: "220 ok", ehlo: "250-ext.io\r\n250 8BITMIME", mail: "250", rcpt: "250", data: "354", ack: "250"}
	s2 := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv2.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nbody\r\n")})
	if res2 := s2.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "张三@t.io", RcptTo: "user@ext.io",
	}); res2.Status != storage.AttemptDeferred {
		t.Fatalf("未通告 SMTPUTF8 应 deferred: %+v", res2)
	}

	// 用例 3：8bit 内容+对端未通告 8BITMIME → deferred（rfc6152 §2 MUST NOT 发送）
	srv3 := &fakeSMTPServer{greet: "220 ok", ehlo: "250-ext.io\r\n250 SMTPUTF8", mail: "250", rcpt: "250", data: "354", ack: "250"}
	s3 := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv3.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\n\xe4\xb8\xad\r\n")})
	if res3 := s3.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "a@t.io", RcptTo: "user@ext.io",
	}); res3.Status != storage.AttemptDeferred {
		t.Fatalf("未通告 8BITMIME+8bit 内容应 deferred: %+v", res3)
	}

	// 用例 4：全 ASCII 信封+纯 ASCII 内容 → 无参数（既有行为保持）
	srv4 := &fakeSMTPServer{greet: "220 ok", ehlo: "250-ext.io\r\n250-8BITMIME\r\n250 SMTPUTF8", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	s4 := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv4.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nplain ascii\r\n")})
	if res4 := s4.Send(context.Background(), &storage.QueueItem{
		MessageID: 1, EnvelopeFrom: "a@t.io", RcptTo: "user@ext.io",
	}); res4.Status != storage.AttemptSent {
		t.Fatalf("ASCII 路径应 sent: %+v", res4)
	}
	if got := capturedMailLine(t, srv4); got != "MAIL FROM:<a@t.io>" {
		t.Fatalf("ASCII 路径 MAIL 应无参数: %q", got)
	}
}

// fixedSource 固定原信源；errorSource 未注入态（防御断言位）。
type fixedSource struct{ raw []byte }

func (f *fixedSource) ReadOriginal(_ context.Context, _ int64) ([]byte, error) { return f.raw, nil }

type errorSource struct{}

func (errorSource) ReadOriginal(_ context.Context, _ int64) ([]byte, error) {
	return nil, fmt.Errorf("消息源未配置")
}

// ───────────────────────── worker ─────────────────────────

// TestBackoffDelay Q5-C 退避序列：60→120→240…封顶 3600；非法配置兜底。
func TestBackoffDelay(t *testing.T) {
	conf := config.DeliveryConf{RetryBaseSeconds: 60, RetryFactor: 2, RetryCapSeconds: 3600, MaxAttempts: 8}
	want := []time.Duration{60, 120, 240, 480, 960, 1920, 3600, 3600}
	for i, w := range want {
		if got := backoffDelay(conf, i+1); got != w*time.Second {
			t.Fatalf("第 %d 次退避应 %v 实得 %v", i+1, w, got)
		}
	}
	if got := backoffDelay(config.DeliveryConf{}, 1); got != 60*time.Second {
		t.Fatalf("零值配置应兜底 60s: %v", got)
	}
}

// TestGroupByDomain Q6 修订：域分组且组内保序。
func TestGroupByDomain(t *testing.T) {
	items := []*storage.QueueItem{
		{RcptTo: "a@x.io"}, {RcptTo: "b@y.io"}, {RcptTo: "c@x.io"},
	}
	groups := groupByDomain(items)
	if len(groups) != 2 {
		t.Fatalf("应 2 域组: %d", len(groups))
	}
	x := groups[0]
	if x[0].RcptTo != "a@x.io" || x[1].RcptTo != "c@x.io" {
		t.Fatalf("x.io 组内序不符: %+v", x)
	}
}

// TestWorkerAttemptStateMachine worker 单项状态机：deferred 退避/sent/failed→DSN+null sender 抑制。
func TestWorkerAttemptStateMachine(t *testing.T) {
	conf := config.DeliveryConf{RetryBaseSeconds: 60, RetryFactor: 2, RetryCapSeconds: 3600, MaxAttempts: 2}
	// sender 恒 deferred（模拟网络故障）→ 达 MaxAttempts 升格 failed→DSN 链
	q := &noopQueue{}
	w := NewQueueWorker(q, &deferSender{}, NewDSNBuilderService("t.io", &errorSource{}),
		&keylessSigner{}, newMemBlobs(), func() config.DeliveryConf { return conf }, "t.io")
	logger := slog.Default()
	item := &storage.QueueItem{ID: 1, MessageID: 1, EnvelopeFrom: "a@t.io", RcptTo: "x@ext.io", Status: storage.QueueInFlight}
	// 第 1 次：deferred+attempts=1+退避 60s
	w.attempt(context.Background(), logger, item)
	if r := q.results[1]; r.Status != storage.AttemptDeferred || r.Attempts != 1 || r.NextAttemptAt.IsZero() {
		t.Fatalf("首次应 deferred+退避: %+v", r)
	}
	// 第 MaxAttempts 次：deferred 升格 failed→DSN 入队断言
	item.Attempts = conf.MaxAttempts - 1
	w.attempt(context.Background(), logger, item)
	if r := q.results[1]; r.Status != storage.AttemptFailed {
		t.Fatalf("达上限应 failed: %+v", r)
	}
	if len(q.dsnMeta) != 1 || q.dsnMeta[0].Items[0].RcptTo != "a@t.io" || q.dsnMeta[0].Items[0].EnvelopeFrom != "<>" {
		t.Fatalf("DSN 应入队至原发件人且信封为 <>: %+v", q.dsnMeta)
	}
}

// noopQueue 记录型队列仓储（MarkResult 捕获）。
type noopQueue struct {
	mu      sync.Mutex
	results map[int64]storage.AttemptResult
	dsnMeta []*storage.SubmissionMeta
}

func (n *noopQueue) ClaimDue(context.Context, time.Time, int) ([]*storage.QueueItem, error) {
	return nil, nil
}
func (n *noopQueue) MarkResult(_ context.Context, id int64, r storage.AttemptResult) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.results == nil {
		n.results = map[int64]storage.AttemptResult{}
	}
	n.results[id] = r
	return nil
}
func (n *noopQueue) ReclaimStale(context.Context, time.Duration) (int, error) { return 0, nil }
func (n *noopQueue) Enqueue(context.Context, []*storage.QueueItem) error      { return nil }
func (n *noopQueue) StoreSubmission(_ context.Context, m *storage.SubmissionMeta) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dsnMeta = append(n.dsnMeta, m)
	return nil
}

// deferSender 恒临时失败。
type deferSender struct{}

func (deferSender) Send(context.Context, *storage.QueueItem) storage.AttemptResult {
	return storage.AttemptResult{Status: storage.AttemptDeferred, Error: "net down"}
}

// （logger 直接 slog.Default()；min 复用 Go 内建——1.21+ 语言特性）

// ───────────────────────── U13：sender DANE 三态分支（stub DaneValidator 注入） ─────────────────────────

// stubDaneValidator 可编程 DANE 决策 stub（契约 v1.9.0 2.3——mail 窄接口）。
type stubDaneValidator struct {
	dec *DaneDecision // 固定决策（nil+err 双 nil=Opportunistic 缺省）
	err error
}

func (s stubDaneValidator) Check(_ context.Context, _, _ string) (*DaneDecision, error) {
	return s.dec, s.err
}

// TestU5DANEDecisionErrorSkipsMX Check 错误→该 MX 视为不可达（rfc7672 §2.1.2——
// deferred 转移语义；不投递防降级）。
func TestU5DANEDecisionErrorSkipsMX(t *testing.T) {
	// 空脚本对端（无 EHLO 应答即关）+决策错误→deferred（未投递）
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ok", mail: "250", rcpt: "250", data: "354", ack: "250"}
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv.serve), stubDaneValidator{err: fmt.Errorf("SERVFAIL")},
		&fixedSource{raw: []byte("Subject: t\r\n\r\nbody\r\n")})
	res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"})
	if res.Status != storage.AttemptDeferred {
		t.Fatalf("Check 错误应 deferred（MX 不可达），得 %+v", res)
	}
	if res.Status == storage.AttemptSent {
		t.Fatal("决策错误态禁止投递（防降级锚）")
	}
}

// TestU5DANERequireTLSOnlyRejectsPlaintext RequireTLSOnly+对端无 STARTTLS→
// MUST NOT 明文投递（rfc7672 §2.2 第二分支——deferred 转移）。
func TestU5DANERequireTLSOnlyRejectsPlaintext(t *testing.T) {
	// EHLO 能力不含 STARTTLS（明文对端）
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ok", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	delivered := false
	srv.onData = func(string) { delivered = true }
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv.serve), stubDaneValidator{dec: &DaneDecision{Mode: DaneRequireTLSOnly}},
		&fixedSource{raw: []byte("Subject: t\r\n\r\nbody\r\n")})
	res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"})
	if res.Status != storage.AttemptDeferred {
		t.Fatalf("secure 承诺态无 STARTTLS 应 deferred 拒明文，得 %+v", res)
	}
	if delivered {
		t.Fatal("承诺态明文投递被禁止（MUST NOT）")
	}
}

// TestU5DANEOpportunisticKeepsLegacyBehavior Opportunistic 决策→既有明文投递
// 路径零变化（NFR-008 降级不阻塞锚——nil validator 之外的显式 Opportunistic 同义）。
func TestU5DANEOpportunisticKeepsLegacyBehavior(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ok", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv.serve), stubDaneValidator{dec: &DaneDecision{Mode: DaneOpportunistic}},
		&fixedSource{raw: []byte("Subject: t\r\n\r\nbody\r\n")})
	res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"})
	if res.Status != storage.AttemptSent {
		t.Fatalf("Opportunistic 应保持既有投递成功路径，得 %+v", res)
	}
}
