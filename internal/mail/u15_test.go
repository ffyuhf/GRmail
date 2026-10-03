// mail 域 U15 插件钩子链测试（NFR-015 全离线——stub 钩子注入驱动）。
// 覆盖：nil 注入零回归（U14b 末态等价锚）/REJECT 短路（PluginRejectError——
// 计划偏离裁决 A 对端可见语义）/RPC 失败降级放行（CON-004）/拒绝码值域校验
// （越界按放行——宿主防线）。
// 依据：U15 计划书 v1.0.0 1.5②④⑦（G2 批准 2026-09-24 10:46:55）；FR-005 插件链位。
// 修改历史：
//
//	2026-09-24 11:11:00 | 新建 | U15 插件系统（计划书步骤 6——mail 侧三态）
package mail

import (
	"context"
	"errors"
	"testing"

	"GRmail/internal/auth"
)

// ───────────────────────── 钩子 stub ─────────────────────────

// stubHook 可配置钩子（决策/错误注入——三态矩阵驱动）。
type stubHook struct {
	name string
	dec  *HookDecision
	err  error
}

func (s *stubHook) HookName() string { return s.name }

func (s *stubHook) OnInbound(_ context.Context, _ *HookInput) (*HookDecision, error) {
	return s.dec, s.err
}

func (s *stubHook) OnSubmit(_ context.Context, _ *HookInput) (*HookDecision, error) {
	return s.dec, s.err
}

// 提交侧 stub 复用：stubSubmissionStore/stubAdmins/passthroughSigner 沿用
// u5_test.go 既有类型（零重复定义——U15 仅新增组装入口）。

// newTestSubmit 组装提交管道（stub 全离线——u5_test 既有 stubSigner/stubSubmissionStore/
// stubAdmins 复用；指针接收者取址传递）。
func newTestSubmit() *SubmissionPipelineService {
	return NewSubmissionPipelineService(&stubSigner{}, newMemBlobs(),
		&stubSubmissionStore{}, &stubAdmins{admins: map[string]bool{"admin": true}}, "test.example")
}

// ───────────────────────── 收信钩子三态 ─────────────────────────

// TestU15InboundNilHooksZeroRegression nil 钩子链=U14b 末态等价（Deliver 正常完成）。
func TestU15InboundNilHooksZeroRegression(t *testing.T) {
	p, _, _, store := newTestPipeline()
	if err := p.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw()); err != nil {
		t.Fatalf("nil 钩子链不应影响投递: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("应落库 1 次，得到 %d", len(store.saved))
	}
}

// TestU15InboundRejectShortCircuits REJECT 短路：Deliver 返回 PluginRejectError
// （Code/Message/Plugin 三字段透传——对端可见语义）且不落库。
func TestU15InboundRejectShortCircuits(t *testing.T) {
	p, _, _, store := newTestPipeline()
	p.SetPluginHooks([]InboundHook{&stubHook{
		name: "rejector",
		dec:  &HookDecision{Allow: false, SMTPCode: 550, Message: "5.7.1 blocked by policy"},
	}})
	err := p.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw())
	var rej *PluginRejectError
	if !errors.As(err, &rej) {
		t.Fatalf("期望 PluginRejectError，得到: %v", err)
	}
	if rej.Code != 550 || rej.Message != "5.7.1 blocked by policy" || rej.Plugin != "rejector" {
		t.Fatalf("拒绝三字段不符: %+v", rej)
	}
	if len(store.saved) != 0 {
		t.Fatal("REJECT 后不得落库（先拒先停——Sieve 与事务均未到达）")
	}
}

// TestU15InboundRPCFailureDegrades RPC 失败降级放行（CON-004——插件异常不阻断投递）。
func TestU15InboundRPCFailureDegrades(t *testing.T) {
	p, _, _, store := newTestPipeline()
	p.SetPluginHooks([]InboundHook{&stubHook{name: "broken", err: errors.New("rpc deadline")}})
	if err := p.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw()); err != nil {
		t.Fatalf("插件失败应降级放行: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatal("降级放行后应正常落库")
	}
}

// TestU15InboundRejectCodeOutOfRange 越界拒绝码（999）按放行（宿主值域校验防线）。
func TestU15InboundRejectCodeOutOfRange(t *testing.T) {
	p, _, _, store := newTestPipeline()
	p.SetPluginHooks([]InboundHook{&stubHook{
		name: "malformed",
		dec:  &HookDecision{Allow: false, SMTPCode: 999, Message: "bad code"},
	}})
	if err := p.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw()); err != nil {
		t.Fatalf("越界码应按放行: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatal("越界码放行后应正常落库")
	}
}

// ───────────────────────── 发信钩子三态 ─────────────────────────

func testSubmission(rcpt string) *Submission {
	return &Submission{
		Envelope:   auth.Envelope{Helo: "submission", MailFrom: "bob@test.example"},
		AuthUser:   "admin",
		Recipients: []string{rcpt},
	}
}

// TestU15SubmitNilHooksZeroRegression nil 发信钩子链=U14b 末态等价。
func TestU15SubmitNilHooksZeroRegression(t *testing.T) {
	sp := newTestSubmit()
	if err := sp.Submit(context.Background(), testSubmission("x@other.io"), sampleRaw()); err != nil {
		t.Fatalf("nil 钩子链不应影响提交: %v", err)
	}
}

// TestU15SubmitRejectShortCircuits 发信 REJECT：Submit 返回 PluginRejectError
// （错误返回=未入队——入队为编排末步，短路先返）。
func TestU15SubmitRejectShortCircuits(t *testing.T) {
	sp := newTestSubmit()
	sp.SetSubmitHooks([]SubmitHook{&stubHook{
		name: "rejector",
		dec:  &HookDecision{Allow: false, SMTPCode: 552, Message: "5.7.1 message too large per policy"},
	}})
	err := sp.Submit(context.Background(), testSubmission("x@other.io"), sampleRaw())
	var rej *PluginRejectError
	if !errors.As(err, &rej) || rej.Code != 552 || rej.Plugin != "rejector" {
		t.Fatalf("期望 552 PluginRejectError（rejector），得到: %v", err)
	}
}

// TestU15SubmitRPCFailureDegrades 发信插件失败降级放行。
func TestU15SubmitRPCFailureDegrades(t *testing.T) {
	sp := newTestSubmit()
	sp.SetSubmitHooks([]SubmitHook{&stubHook{name: "broken", err: errors.New("rpc down")}})
	if err := sp.Submit(context.Background(), testSubmission("x@other.io"), sampleRaw()); err != nil {
		t.Fatalf("插件失败应降级放行: %v", err)
	}
}

// ───────────────────────── 决策转换单元断言 ─────────────────────────

// TestU15HookRejectOfMatrix 决策→拒绝转换矩阵（nil/放行/越界/空文本兜底/有效拒绝）。
func TestU15HookRejectOfMatrix(t *testing.T) {
	cases := []struct {
		name string
		dec  *HookDecision
		want bool
	}{
		{"nil 决策放行", nil, false},
		{"allow 放行", &HookDecision{Allow: true}, false},
		{"399 越界放行", &HookDecision{Allow: false, SMTPCode: 399}, false},
		{"600 越界放行", &HookDecision{Allow: false, SMTPCode: 600}, false},
		{"550 有效拒绝", &HookDecision{Allow: false, SMTPCode: 550, Message: "x"}, true},
		{"451 有效临时拒绝", &HookDecision{Allow: false, SMTPCode: 451}, true},
	}
	for _, c := range cases {
		if got := hookRejectOf("m", c.dec); (got != nil) != c.want {
			t.Fatalf("%s: 期望拒绝=%v，得到 %v", c.name, c.want, got)
		}
	}
	// 空文本兜底（SMTP 应答文本非空惯例）
	if got := hookRejectOf("m", &HookDecision{Allow: false, SMTPCode: 550}); got == nil || got.Message == "" {
		t.Fatal("空文本拒绝应兜底默认消息")
	}
}
