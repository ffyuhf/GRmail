// mail 域传输安全与日志增强批次定向测试（L-A 发送侧 MTA-STS 投递判定+L-B TLS-RPT
// 采集点——复用 u5_test 既有 stub 设施〔fakeSMTPServer/stubMX/fixedSource〕；
// rfc8461 §5 enforce 三判定与 rfc8460 §4 采集锚定）。
// 依据：传输安全与日志增强计划书 v1.0.0 步骤 2 检查点（G2 批准 2026-10-01 22:54:41；
// 构造签名零变更——SetSTSValidator/SetTLSReporter 可选注入先例）。
// 修改历史：
//
//	2026-10-01 23:38:00 | 新建 | 传输安全与日志增强批次（计划书步骤 2 定向锚）
//	2026-10-07 15:35:00 | 适配 | 传输安全合规批 F7：stubTLSRecorder.Record 增
//	policy 快照参数（签名扩展形态适配——断言面零变化）
package mail

import (
	"context"
	"strings"
	"sync"
	"testing"

	"GRmail/internal/storage"
)

// stubSTSValidator MTA-STS 判定 stub（按域返回固定决策）。
type stubSTSValidator struct {
	mu    sync.Mutex
	calls int
	mode  string // 目标域决策 Mode
	match bool   // MXMatched
}

func (s *stubSTSValidator) Check(_ context.Context, _, _ string) (*STSDecision, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return &STSDecision{Mode: s.mode, MXMatched: s.match}, nil
}

// stubTLSRecorder TLS-RPT 采集 stub（记录全部调用）。
type stubTLSRecorder struct {
	mu    sync.Mutex
	calls []string // "domain|mx|result" 形态
}

func (s *stubTLSRecorder) Record(domain, mxHost, resultType string, _ *TLSPolicySnapshot) {
	s.mu.Lock()
	s.calls = append(s.calls, domain+"|"+mxHost+"|"+resultType)
	s.mu.Unlock()
}

func (s *stubTLSRecorder) has(prefix string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if c == prefix {
			return true
		}
	}
	return false
}

// newSTSTestSender 装配带 STS/Recorder 注入的 sender（六参构造+双 setter——批次先例）。
func newSTSTestSender(t *testing.T, srv *fakeSMTPServer, mode string, match bool, rec *stubTLSRecorder) *OutboundSenderService {
	t.Helper()
	s := NewOutboundSenderService("t.io", &stubInbound{}, &stubMX{
		mx: map[string][]string{"ext.io": {"mx1.ext.io"}},
	}, newFakeServerDialer(t, srv.serve), nil,
		&fixedSource{raw: []byte("Subject: hi\r\n\r\nbody\r\n")})
	s.SetSTSValidator(&stubSTSValidator{mode: mode, match: match})
	s.SetTLSReporter(rec)
	return s
}

// TestSenderSTSEnforceMismatchReject enforce 且 MX 不匹配：deferred 拒投该主机
// （rfc8461 §5 enforce「MUST NOT deliver」+§5.1 转移下一候选——单 MX 无下一台=deferred
// 终态）+采集 sts-policy-invalid（§4.3.2.2）。
func TestSenderSTSEnforceMismatchReject(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ok", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	rec := &stubTLSRecorder{}
	s := newSTSTestSender(t, srv, "enforce", false, rec)
	res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"})
	if res.Status != storage.AttemptDeferred {
		t.Fatalf("enforce 不匹配应 deferred 拒投: %+v", res)
	}
	srv.mu.Lock()
	captured := len(srv.captured)
	srv.mu.Unlock()
	if captured != 0 {
		t.Fatalf("enforce 不匹配不应发生 SMTP 对话: %d", captured)
	}
	if !rec.has("ext.io|mx1.ext.io|sts-policy-invalid") {
		t.Fatalf("应采集 sts-policy-invalid: %v", rec.calls)
	}
}

// （enforce+MX 匹配+STARTTLS 握手成功的完整 sent 路径受 fakeSMTPServer 桩限制不可离线
// 模拟〔桩不真 TLS 握手〕——真 TLS 互操作归 D7 部署域实录；enforce 匹配态的明文/握手
// 失败两拒绝分支由下方 NoStartTLS 与 StartTLSFail 用例承载，成功路径与 testing 态
// 行为等价〔仅判定分支差异〕由 TestingMismatch 用例侧面锚定。）

// TestSenderSTSTestingMismatchDeliver testing 不匹配：照常投递（§5 testing「messages
// may be delivered as though there were no MTA-STS validation failure」——明文对端）。
func TestSenderSTSTestingMismatchDeliver(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ext.io", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	s := newSTSTestSender(t, srv, "testing", false, &stubTLSRecorder{})
	if res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"}); res.Status != storage.AttemptSent {
		t.Fatalf("testing 不匹配应照常投递: %+v", res)
	}
}

// TestSenderSTSEnforceNoStartTLS enforce（MX 匹配）对端无 STARTTLS：拒明文 deferred
// （rfc8461 §5「MUST NOT deliver ... that do not support STARTTLS」）+采集
// starttls-not-supported（§4.3.1）。
func TestSenderSTSEnforceNoStartTLS(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ext.io", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"} // 无 STARTTLS 能力
	rec := &stubTLSRecorder{}
	s := newSTSTestSender(t, srv, "enforce", true, rec)
	res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"})
	if res.Status != storage.AttemptDeferred {
		t.Fatalf("enforce 无 STARTTLS 应拒明文 deferred: %+v", res)
	}
	if !strings.Contains(res.Error, "STARTTLS") {
		t.Fatalf("错误语义应载明 STARTTLS 拒绝: %s", res.Error)
	}
	if !rec.has("ext.io|mx1.ext.io|starttls-not-supported") {
		t.Fatalf("应采集 starttls-not-supported: %v", rec.calls)
	}
}

// TestSenderSTSNoPolicyNoStartTLS 无策略（Mode 空串）对端无 STARTTLS：明文照投
// （Opportunistic 既有语义——批次前末态等价锚）。
func TestSenderSTSNoPolicyNoStartTLS(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ext.io", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	s := newSTSTestSender(t, srv, "", true, &stubTLSRecorder{})
	if res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"}); res.Status != storage.AttemptSent {
		t.Fatalf("无策略应明文照投（末态等价）: %+v", res)
	}
}

// TestSenderSTSStartTLSFail TLS 握手失败：deferred 不降级+采集
// certificate-not-trusted（§4.3.1 笼统类）。既有 fakeSMTPServer 桩 STARTTLS 后
// 固定回 220 不真握手——tls.Client 握手收不到 ServerHello 必失败，天然构造升级失败路径。
func TestSenderSTSStartTLSFail(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250-ext.io\r\n250 STARTTLS",
		mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	rec := &stubTLSRecorder{}
	s := newSTSTestSender(t, srv, "testing", true, rec) // testing 态同样走升级路径
	res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io"})
	if res.Status != storage.AttemptDeferred {
		t.Fatalf("STARTTLS 失败应 deferred 不降级: %+v", res)
	}
	if !rec.has("ext.io|mx1.ext.io|certificate-not-trusted") {
		t.Fatalf("应采集 certificate-not-trusted: %v", rec.calls)
	}
}
