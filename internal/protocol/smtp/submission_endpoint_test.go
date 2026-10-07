// 提交端点对齐批测试（评审修复批次 2/8——架构级评审 A-11/A-12/B-S10①②③/B-F8/B-F9/B-F10 收口）。
// 覆盖：F1 DATA 大小终判 552（rfc1870 §6.1）/F2 空消息与点透明终止（rfc5321bis
// §4.1.1.4——indexDataTerminator 复用）/F3① AUTH 限流 421+失败计数+成功清零/
// F3② SASLprep 拒绝 535（rfc4954 §4 L261-268）/F3③ AUTH 行超限 500 5.5.6 与
// 命令行超长 500（L255-259+rfc5321bis §4.5.3.1.4）/F4 STARTTLS 带参 501（rfc3207
// §4 L108）+EHLO 空域 501/F5 NOTIFY/ORCPT 重复与值域 501（rfc3461 §4.1/§4.2/
// §4.5 L533-536）/F6 ctx 传递（LogID 链）。
// SRS 条目：FR-005/TC-005、NFR-004/016、NFR-007 伴随；G2 批准 2026-10-06 19:43:56。
// 修改历史：
//
//	2026-10-06 20:00:00 | 新增 | 提交端点对齐批（计划书 v1.0.0 步骤 1-8 验收用例）
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
)

// ── 测试桩 ──

// stubSubmitPipeline 提交管道桩（记录调用与入参——F6 ctx 断言载体）。
type stubSubmitPipeline struct {
	called bool
	gotCtx context.Context
	gotSub *mail.Submission
	gotRaw []byte
	err    error
}

func (s *stubSubmitPipeline) Submit(ctx context.Context, in *mail.Submission, raw []byte) error {
	s.called, s.gotCtx, s.gotSub, s.gotRaw = true, ctx, in, raw
	return s.err
}

// stubVerifier 凭据校验桩（记录 ctx/user——F3②/F6 断言载体）。
type stubVerifier struct {
	called  bool
	gotCtx  context.Context
	gotUser string
	fail    bool
}

func (v *stubVerifier) VerifyCredentials(ctx context.Context, addr, password string) error {
	v.called, v.gotCtx, v.gotUser = true, ctx, addr
	if v.fail {
		return errors.New("invalid")
	}
	return nil
}

// stubAttempts 失败计数桩（F3① 断言载体——实现 AttemptRecorder 窄接口）。
type stubAttempts struct {
	fails    int64
	recorded int
	cleared  int
}

func (a *stubAttempts) RecordAttempt(context.Context, string, string, bool, time.Time) error {
	a.recorded++
	return nil
}

func (a *stubAttempts) CountRecentFails(context.Context, string, time.Time) (int64, error) {
	return a.fails, nil
}

func (a *stubAttempts) ClearSubject(context.Context, string) error {
	a.cleared++
	return nil
}

// nopConn 无操作连接桩（data() 的 SetReadDeadline 面零依赖内存测试）。
type nopConn struct{}

func (nopConn) Read(p []byte) (int, error)       { return 0, net.ErrClosed }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nil }
func (nopConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// newSessionFor 内存态会话构造（输入预置+输出捕获；MaxMessageSize/MaxMessageSize
// 空时兜底 35MiB——沿 NewSubmissionServer 构造兜底形态，测试直构不重复该逻辑）。
func newSessionFor(input string, cfg SubmissionConfig, pipeline mail.SubmissionPipeline, verifier CredentialVerifier) (*submitSession, *bytes.Buffer) {
	if cfg.MaxMessageSize == nil {
		cfg.MaxMessageSize = func() int64 { return 36700160 }
	}
	out := &bytes.Buffer{}
	sess := &submitSession{
		srv:  &SubmissionServer{cfg: cfg, pipeline: pipeline, verifier: verifier},
		conn: nopConn{},
		rw:   bufio.NewReadWriter(bufio.NewReader(strings.NewReader(input)), bufio.NewWriter(out)),
		ctx:  context.WithValue(context.Background(), ctxTestKey{}, "logid-anchor"),
	}
	return sess, out
}

type ctxTestKey struct{}

// ── F2：终止检测复用（空消息/点透明/裸 LF） ──

// TestSubmissionDataEmptyMessage 空消息首包 ".\r\n" 立即终止并提交（A-12 修正锚：
// 原 bytesHasTerminator len<5 恒假致挂死——rfc5321bis §4.1.1.4 L2206-2207 前缀特判）。
func TestSubmissionDataEmptyMessage(t *testing.T) {
	stub := &stubSubmitPipeline{}
	sess, out := newSessionFor(".\r\n", SubmissionConfig{}, stub, nil)
	sess.inTx, sess.authUser, sess.rcpts = true, "a@ex.com", []string{"b@ex.com"}
	sess.data()
	if !stub.called {
		t.Fatal("空消息应立即触发 Submit（原实现挂死）")
	}
	if len(stub.gotRaw) != 0 {
		t.Fatalf("空消息 body 应为空，got %q", stub.gotRaw)
	}
	if !strings.Contains(out.String(), "250") {
		t.Fatalf("应答应含 250，got %q", out.String())
	}
}

// TestSubmissionDataNormalAndDotUnstuffing 正常提交+行首点透明还原（rfc5321bis §4.5.2）。
func TestSubmissionDataNormalAndDotUnstuffing(t *testing.T) {
	stub := &stubSubmitPipeline{}
	sess, out := newSessionFor("line1\r\n..dotted\r\n.\r\n", SubmissionConfig{}, stub, nil)
	sess.inTx, sess.authUser, sess.rcpts = true, "a@ex.com", []string{"b@ex.com"}
	sess.data()
	if !stub.called {
		t.Fatal("应触发 Submit")
	}
	if want := "line1\r\n.dotted\r\n"; string(stub.gotRaw) != want {
		t.Fatalf("点透明还原+末行 CRLF 收尾不符：want %q got %q", want, stub.gotRaw)
	}
	if !strings.Contains(out.String(), "250") {
		t.Fatalf("应答应含 250，got %q", out.String())
	}
}

// TestSubmissionDataBareLFNotTerminator 裸 LF 不作为终止（rfc5321bis §4.1.1.4 L2218-2224
// MUST NOT——<LF>.<LF> 段作为数据字节保留，终止仅由 <CRLF>.<CRLF> 触发）。
func TestSubmissionDataBareLFNotTerminator(t *testing.T) {
	stub := &stubSubmitPipeline{}
	sess, _ := newSessionFor("x\n.\nbody\r\n.\r\n", SubmissionConfig{}, stub, nil)
	sess.inTx, sess.authUser, sess.rcpts = true, "a@ex.com", []string{"b@ex.com"}
	sess.data()
	if !stub.called {
		t.Fatal("真实 <CRLF>.<CRLF> 终止应触发 Submit")
	}
	// "x\n.\n" 为数据字节（unstuffDots 仅 CRLF 行界后剥点——裸 LF 行界的点保留）
	if want := "x\n.\nbody\r\n"; string(stub.gotRaw) != want {
		t.Fatalf("裸 LF 段应作为数据保留：want %q got %q", want, stub.gotRaw)
	}
}

// ── F1：DATA 大小终判 ──

// TestSubmissionDataTooBig552 超实际长度终判 552 且不提交（A-11——rfc1870 §6.1 L231-233；
// MAIL 预检已有声明路径，本用例覆盖 DATA 面事实路径）。
func TestSubmissionDataTooBig552(t *testing.T) {
	stub := &stubSubmitPipeline{}
	sess, out := newSessionFor("0123456789ABCDEF\r\n.\r\n",
		SubmissionConfig{MaxMessageSize: func() int64 { return 10 }}, stub, nil)
	sess.inTx, sess.authUser, sess.rcpts = true, "a@ex.com", []string{"b@ex.com"}
	sess.data()
	if stub.called {
		t.Fatal("超限消息不得进入 Submit")
	}
	if !strings.Contains(out.String(), "552") {
		t.Fatalf("应答应含 552，got %q", out.String())
	}
}

// TestSubmissionDataSlightlyOverDeclaredAccepted 实际大于声明但未超上限仍接受
// （rfc1870 §6.1 L235-238「permitted, but not required」宽容保持——SIZE 只预检声明值）。
func TestSubmissionDataSlightlyOverDeclaredAccepted(t *testing.T) {
	stub := &stubSubmitPipeline{}
	sess, out := newSessionFor("0123456789\r\n.\r\n",
		SubmissionConfig{MaxMessageSize: func() int64 { return 100 }}, stub, nil)
	sess.inTx, sess.authUser, sess.rcpts = true, "a@ex.com", []string{"b@ex.com"}
	sess.data()
	if !stub.called || !strings.Contains(out.String(), "250") {
		t.Fatalf("实际长度在上限内应接受：called=%v out=%q", stub.called, out.String())
	}
}

// TestSubmissionDataContextPropagation F6/B-F10：Submit 收到 ss.ctx（LogID 链闭环）。
func TestSubmissionDataContextPropagation(t *testing.T) {
	stub := &stubSubmitPipeline{}
	sess, _ := newSessionFor("hi\r\n.\r\n", SubmissionConfig{}, stub, nil)
	sess.inTx, sess.authUser, sess.rcpts = true, "a@ex.com", []string{"b@ex.com"}
	sess.data()
	if stub.gotCtx != sess.ctx {
		t.Fatal("Submit 应收到 ss.ctx（原 context.Background() 断链修正）")
	}
}

// ── F4：STARTTLS 带参 501 / EHLO 空域 501 ──

// TestStartTLSWithParamRejected rfc3207 §4 L108「501 Syntax error (no parameters allowed)」。
func TestStartTLSWithParamRejected(t *testing.T) {
	sess, out := newSessionFor("", SubmissionConfig{}, nil, nil)
	sess.startTLS(nopConn{}, "EXTRA")
	if !strings.Contains(out.String(), "501") {
		t.Fatalf("STARTTLS 带参应 501，got %q", out.String())
	}
}

// TestHeloEmptyDomainRejected EHLO 空域 501（rfc5321bis §4.1.1.1/§4.1.4）。
func TestHeloEmptyDomainRejected(t *testing.T) {
	sess, out := newSessionFor("", SubmissionConfig{}, nil, nil)
	sess.helo("")
	if !strings.Contains(out.String(), "501") {
		t.Fatalf("EHLO 空域应 501，got %q", out.String())
	}
}

// ── F3③：行超限 ──

// TestReadAuthLineTooLong AUTH 交换行超 12288→500+5.5.6+哨兵（rfc4954 §4 L255-259）。
func TestReadAuthLineTooLong(t *testing.T) {
	long := strings.Repeat("A", authLineLimit+10) + "\r\n"
	sess, out := newSessionFor(long, SubmissionConfig{}, nil, nil)
	_, err := sess.readAuthLine()
	if !errors.Is(err, errAuthLineTooLong) {
		t.Fatalf("应返回超限哨兵，got %v", err)
	}
	if !strings.Contains(out.String(), "500") || !strings.Contains(out.String(), "5.5.6") {
		t.Fatalf("应答应为 500 5.5.6，got %q", out.String())
	}
}

// TestReadAuthLineWithinLimit 命令行上限内（4096<12288）的 AUTH 行正常读取。
func TestReadAuthLineWithinLimit(t *testing.T) {
	ok := strings.Repeat("A", 5000) + "\r\n" // 超 cmdLineLimit 但在 authLineLimit 内
	sess, _ := newSessionFor(ok, SubmissionConfig{}, nil, nil)
	line, err := sess.readAuthLine()
	if err != nil || len(line) != 5000 {
		t.Fatalf("AUTH 行在 12288 内应正常读取：err=%v len=%d", err, len(line))
	}
}

// TestReadLineTooLongSentinel 命令行超 4096→errLineTooLong 哨兵（rfc5321bis §4.5.3.1.4/.9）。
func TestReadLineTooLongSentinel(t *testing.T) {
	long := strings.Repeat("A", cmdLineLimit+1) + "\r\n"
	sess, _ := newSessionFor(long, SubmissionConfig{}, nil, nil)
	_, err := sess.readLine()
	if !errors.Is(err, errLineTooLong) {
		t.Fatalf("应返回 errLineTooLong，got %v", err)
	}
}

// ── F3①②：AUTH 限流与 SASLprep ──

// TestAuthLockedRejected 计数超阈值→421 且凭据不校验（F3①）。
func TestAuthLockedRejected(t *testing.T) {
	ver := &stubVerifier{}
	at := &stubAttempts{fails: 5}
	sess, out := newSessionFor("", SubmissionConfig{Attempts: at}, nil, ver)
	sess.inTLS = true
	enc := base64.StdEncoding.EncodeToString([]byte("\x00user@ex.com\x00pw"))
	sess.auth("PLAIN " + enc)
	if ver.called {
		t.Fatal("锁定态不得调用凭据校验")
	}
	if !strings.Contains(out.String(), "421") {
		t.Fatalf("锁定应答 421，got %q", out.String())
	}
}

// TestAuthFailRecordedSuccessCleared 失败计数/成功清零联动（F3①）。
func TestAuthFailRecordedSuccessCleared(t *testing.T) {
	at := &stubAttempts{}
	// 失败路径
	verFail := &stubVerifier{fail: true}
	sess, _ := newSessionFor("", SubmissionConfig{Attempts: at}, nil, verFail)
	sess.inTLS = true
	enc := base64.StdEncoding.EncodeToString([]byte("\x00user@ex.com\x00pw"))
	sess.auth("PLAIN " + enc)
	if at.recorded != 1 {
		t.Fatalf("失败应记录一次，got %d", at.recorded)
	}
	// 成功路径（新会话）
	verOK := &stubVerifier{}
	sess2, _ := newSessionFor("", SubmissionConfig{Attempts: at}, nil, verOK)
	sess2.inTLS = true
	sess2.auth("PLAIN " + enc)
	if at.cleared != 1 {
		t.Fatalf("成功应清零一次，got %d", at.cleared)
	}
	if verOK.gotUser != "user@ex.com" {
		t.Fatalf("SASLprep 后地址应小写化传入校验，got %q", verOK.gotUser)
	}
}

// TestAuthSASLprepProhibited SASLprep 禁止字符命中→535（F3②——rfc4954 §4 L261-268
// MUST fail the authentication；RFC4013 §2.3 C.2.1 控制符）。
func TestAuthSASLprepProhibited(t *testing.T) {
	ver := &stubVerifier{}
	sess, out := newSessionFor("", SubmissionConfig{}, nil, ver)
	sess.inTLS = true
	enc := base64.StdEncoding.EncodeToString([]byte("\x00\x01bad@ex.com\x00pw"))
	sess.auth("PLAIN " + enc)
	if ver.called {
		t.Fatal("SASLprep 失败不得进入凭据校验")
	}
	if !strings.Contains(out.String(), "535") {
		t.Fatalf("SASLprep 失败应 535（MUST fail 承载），got %q", out.String())
	}
}

// TestAuthVerifierReceivesSessionContext F6/B-F10：VerifyCredentials 收到 ss.ctx。
func TestAuthVerifierReceivesSessionContext(t *testing.T) {
	ver := &stubVerifier{}
	sess, _ := newSessionFor("", SubmissionConfig{}, nil, ver)
	sess.inTLS = true
	enc := base64.StdEncoding.EncodeToString([]byte("\x00user@ex.com\x00pw"))
	sess.auth("PLAIN " + enc)
	if ver.gotCtx != sess.ctx {
		t.Fatal("VerifyCredentials 应收到 ss.ctx（LogID 链）")
	}
}

// ── F5：NOTIFY/ORCPT 校验 ──

func newRcptSession(t *testing.T) (*submitSession, *bytes.Buffer) {
	t.Helper()
	sess, out := newSessionFor("", SubmissionConfig{}, nil, nil)
	sess.inTx = true
	return sess, out
}

// TestRcptDuplicateNotifyRejected 重复 NOTIFY→501（rfc3461 §4.5 L533-536）。
func TestRcptDuplicateNotifyRejected(t *testing.T) {
	sess, out := newRcptSession(t)
	sess.rcpt("TO:<b@ex.com> NOTIFY=SUCCESS")
	sess.rcpt("TO:<b@ex.com> NOTIFY=FAILURE")
	if !strings.Contains(out.String(), "501") {
		t.Fatalf("同 RCPT 重复 NOTIFY 应 501，got %q", out.String())
	}
}

// TestRcptInvalidNotifyValues 非法值域→501（NEVER 混用/未知元素/空值）。
func TestRcptInvalidNotifyValues(t *testing.T) {
	for _, v := range []string{"NEVER,SUCCESS", "BOGUS", "SUCCESS,", ""} {
		sess, out := newRcptSession(t)
		sess.rcpt("TO:<b@ex.com> NOTIFY=" + v)
		if !strings.Contains(out.String(), "501") {
			t.Fatalf("NOTIFY=%q 应 501，got %q", v, out.String())
		}
	}
}

// TestRcptValidNotifyAccepted 合法四值（大小写任意+列表）透传。
func TestRcptValidNotifyAccepted(t *testing.T) {
	for _, v := range []string{"NEVER", "SUCCESS,FAILURE", "success,delay", "FAILURE"} {
		sess, out := newRcptSession(t)
		sess.rcpt("TO:<b@ex.com> NOTIFY=" + v)
		if strings.Contains(out.String(), "501") {
			t.Fatalf("合法 NOTIFY=%q 不应 501，got %q", v, out.String())
		}
		if len(sess.dsnParams) != 1 {
			t.Fatalf("NOTIFY=%q 应透传一条，got %d", v, len(sess.dsnParams))
		}
	}
}

// TestRcptOrcptValidation ORCPT 值域（addr-type;xtext ≤500——rfc3461 §4.2 L412-422）。
func TestRcptOrcptValidation(t *testing.T) {
	// 合法
	sess, _ := newRcptSession(t)
	sess.rcpt("TO:<b@ex.com> ORCPT=rfc822;b@ex.com")
	if len(sess.dsnParams) != 1 || sess.dsnParams[0].Keyword != "ORCPT" {
		t.Fatal("合法 ORCPT 应透传")
	}
	// 非法：缺分号/空段/超 500/双分号
	for _, v := range []string{"rfc822", ";x", "a;;x", strings.Repeat("x", 501)} {
		sess, out := newRcptSession(t)
		sess.rcpt("TO:<b@ex.com> ORCPT=" + v)
		if !strings.Contains(out.String(), "501") {
			t.Fatalf("非法 ORCPT=%q（len=%d）应 501，got %q", v[:min(10, len(v))], len(v), out.String())
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── 纯函数校验表（validNotifyValue/validOrcptValue 直测） ──

func TestValidNotifyValueTable(t *testing.T) {
	valid := []string{"NEVER", "never", "SUCCESS", "SUCCESS,FAILURE", "success,delay,FAILURE"}
	invalid := []string{"", "NEVER,SUCCESS", "BOGUS", "SUCCESS,", ",SUCCESS", "SUCCESS,,FAILURE"}
	for _, v := range valid {
		if !validNotifyValue(v) {
			t.Errorf("validNotifyValue(%q) 应为 true", v)
		}
	}
	for _, v := range invalid {
		if validNotifyValue(v) {
			t.Errorf("validNotifyValue(%q) 应为 false", v)
		}
	}
}

// TestAuthSASLprepAvailable auth.SASLprep 集成面（包级函数可达性——沿 saslprep_test 形态轻量锚）。
func TestAuthSASLprepAvailable(t *testing.T) {
	if _, err := auth.SASLprep("user@ex.com"); err != nil {
		t.Fatalf("合法身份不应 SASLprep 失败：%v", err)
	}
}
