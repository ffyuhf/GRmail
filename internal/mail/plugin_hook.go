// mail 域插件钩子挂接层：InboundHook/SubmitHook 窄接口（契约 v1.11.0 2.5 承载
// 形态）、SetPluginHooks/SetSubmitHooks 可选注入（沿 v1.8.0 SetSieveRunner 先例——
// 构造签名零变更，nil/空=U14b 末态等价）、钩子链编排（降级放行+拒绝短路）。
// 依据：SRS FR-005 管道语义「认证验证→插件链→Sieve→落库」（插件链位于四项验证后、
// Sieve/落库前——Deliver 编排 1.5 步）；DFD P1/P2「E6→收信钩子/发信钩子」；
// FR-016 插件系统（钩子为宿主契约面的管道消费侧）；CON-004（插件 RPC 失败/超时
// 降级放行——不阻断投递，沿 Sieve implicit keep 兜底同语义）。
// U15 计划偏离裁决 A（2026-09-24 10:53:12）：PluginRejectError 为对端可见拒绝
// （4xx/5xx 由插件给定）——smtp session/submission 各增识别 case 承载。
// 修改历史：
//
//	2026-09-24 10:56:00 | 新建 | U15 插件系统（计划书步骤 3，G2 批准 2026-09-24 10:46:55）
package mail

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"GRmail/internal/auth"
)

// ───────────────────────── 契约类型（v1.11.0 2.5） ─────────────────────────

// HookInput 钩子输入（收信/发信统一载体——字段按场景取用：收信含 Verification，
// 发信含 AuthUser 与 Recipients）。
type HookInput struct {
	Envelope     auth.Envelope   // SMTP 会话信封（Helo/RemoteIP/MailFrom）
	Recipients   []string        // 收件人集（发信形态全量；收信形态同 in.Recipients）
	AuthUser     string          // 认证身份（发信形态；FR-002 授权判定输入）
	Verification *VerifySnapshot // 四项验证结论（收信形态——Verify 产物）
	Raw          []byte          // 原始邮件字节（保真：收信=DATA 完成态；发信=DKIM 签名后）
}

// VerifySnapshot 四项验证结论快照（钩子输入侧——auth.VerifyResults 的 mail 域视图）。
type VerifySnapshot struct {
	SPF, DKIM, DMARC, ARC string // none|pass|fail|softfail|temperror|permerror...
}

// HookDecision 钩子决策（插件侧返回；REJECT 携带对端可见 4xx/5xx）。
type HookDecision struct {
	Allow    bool   // true=放行；false=拒绝
	SMTPCode int    // 拒绝应答码（400-599；越界按放行+告警——宿主值域校验）
	Message  string // 拒绝原因（对端应答文本）/说明
}

// InboundHook 收信钩子窄接口（plugin 包实现注入——mail 不 import plugin，
// 依赖方向 plugin→mail 与架构 1.2 图 PLUGIN→MAIL 一致）。
type InboundHook interface {
	// HookName 插件名（日志与监管呈现）。
	HookName() string
	// OnInbound 收信钩子（Deliver 编排 1.5 步——四项验证后、Sieve/落库前）。
	// 返回：决策（nil 视为放行）；错误由调用方按降级放行处理（CON-004）。
	OnInbound(ctx context.Context, in *HookInput) (*HookDecision, error)
}

// SubmitHook 发信钩子窄接口（plugin 包实现注入）。
type SubmitHook interface {
	// HookName 插件名（日志与监管呈现）。
	HookName() string
	// OnSubmit 发信钩子（Submit 编排 3.5 步——授权与 DKIM 后、Blob/入队前）。
	// 返回：决策（nil 视为放行）；错误由调用方按降级放行处理（CON-004）。
	OnSubmit(ctx context.Context, in *HookInput) (*HookDecision, error)
}

// PluginRejectError 插件拒绝（对端可见——smtp 会话层识别后按码应答；
// 偏离裁决 A 接线：session.go/submission.go 各一个识别 case）。
type PluginRejectError struct {
	Code    int    // 拒绝应答码（400-599）
	Message string // 对端应答文本
	Plugin  string // 拒绝来源插件名（日志定位）
}

// Error 实现 error（语义：永久/临时拒绝由 Code 4xx/5xx 区分——对端重试策略自判）。
func (e *PluginRejectError) Error() string {
	return fmt.Sprintf("mail: 插件 %s 拒绝（%d %s）", e.Plugin, e.Code, e.Message)
}

// ───────────────────────── 工程常量（U15 计划书 1.5②，G2 批复生效） ─────────────────────────

// PluginHookTimeout 单插件钩子调用超时（RPC 失败/超时→该插件降级放行+Warn——
// CON-004 插件链不阻断投递；插件慢不拖垮收信路径 NFR-001）。
const PluginHookTimeout = 5 * time.Second

// ───────────────────────── 可选注入（沿 SetSieveRunner/SetObserver 先例） ─────────────────────────

// SetPluginHooks 可选注入收信钩子链（契约 v1.11.0——构造签名零变更；
// nil/空=禁用：管道行为与 U14b 末态完全一致，测试与渐进部署兼容）。
// 参数：hooks 收信钩子链（按序执行，先拒先停）。
func (s *InboundPipelineService) SetPluginHooks(hooks []InboundHook) {
	s.pluginHooks = hooks
}

// SetSubmitHooks 可选注入发信钩子链（契约 v1.11.0——构造签名零变更；
// nil/空=禁用：提交行为与 U14b 末态完全一致）。
// 参数：hooks 发信钩子链（按序执行，先拒先停）。
func (s *SubmissionPipelineService) SetSubmitHooks(hooks []SubmitHook) {
	s.submitHooks = hooks
}

// ───────────────────────── 钩子链编排（Deliver 1.5/Submit 3.5 步） ─────────────────────────

// applyInboundHooks 执行收信插件链（Deliver 编排 1.5 步——四项验证后、Sieve/落库前）。
// 语义（计划书 1.5②）：逐插件按序调用；RPC 错误/超时→该插件降级放行+Warn（CON-004
// 不阻断投递）；REJECT 值域校验（400-599，越界按放行+Warn）→短路返回
// *PluginRejectError（对端可见——偏离裁决 A）；先拒先停（后续插件不再调用）。
// 参数：ctx 上下文；in 投递输入；raw 原始字节；res 验证产物（快照输入）。
// 返回：nil=全放行；*PluginRejectError=拒绝短路；不返回其他错误形态。
func (s *InboundPipelineService) applyInboundHooks(ctx context.Context, in *Delivery,
	raw []byte, res *auth.VerifyResults) *PluginRejectError {
	for _, h := range s.pluginHooks {
		hctx, cancel := context.WithTimeout(ctx, PluginHookTimeout)
		dec, err := h.OnInbound(hctx, &HookInput{
			Envelope:   in.Envelope,
			Recipients: in.Recipients,
			Verification: &VerifySnapshot{
				SPF: res.SPF, DKIM: res.DKIM, DMARC: res.DMARC, ARC: res.ARC,
			},
			Raw: raw,
		})
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "插件收信钩子失败，该插件降级放行（CON-004）",
				"plugin", h.HookName(), "error", err)
			continue
		}
		if rej := hookRejectOf(h.HookName(), dec); rej != nil {
			return rej
		}
	}
	return nil
}

// applySubmitHooks 执行发信插件链（Submit 编排 3.5 步——授权与 DKIM 后、入队前）。
// 语义同 applyInboundHooks（降级放行/值域校验/先拒先停）。
// 参数：ctx 上下文；in 提交输入；staged DKIM 签名后字节。
// 返回：nil=全放行；*PluginRejectError=拒绝短路。
func (s *SubmissionPipelineService) applySubmitHooks(ctx context.Context, in *Submission,
	staged []byte) *PluginRejectError {
	for _, h := range s.submitHooks {
		hctx, cancel := context.WithTimeout(ctx, PluginHookTimeout)
		dec, err := h.OnSubmit(hctx, &HookInput{
			Envelope:   in.Envelope,
			Recipients: in.Recipients,
			AuthUser:   in.AuthUser,
			Raw:        staged,
		})
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "插件发信钩子失败，该插件降级放行（CON-004）",
				"plugin", h.HookName(), "error", err)
			continue
		}
		if rej := hookRejectOf(h.HookName(), dec); rej != nil {
			return rej
		}
	}
	return nil
}

// hookRejectOf 决策→拒绝错误转换（值域校验：Code 400-599 且 Allow=false 方为有效
// 拒绝；越界/nil 决策按放行+Warn——宿主防线，防止插件畸形决策污染应答）。
// 参数：name 插件名；dec 钩子决策（nil=放行）。返回：拒绝错误或 nil。
func hookRejectOf(name string, dec *HookDecision) *PluginRejectError {
	if dec == nil || dec.Allow {
		return nil
	}
	if dec.SMTPCode < 400 || dec.SMTPCode > 599 {
		slog.Warn("插件拒绝码越界，按放行处理（宿主值域校验）",
			"plugin", name, "code", dec.SMTPCode)
		return nil
	}
	msg := dec.Message
	if msg == "" {
		msg = "rejected by plugin" // 空文本兜底（SMTP 应答文本非空惯例）
	}
	return &PluginRejectError{Code: dec.SMTPCode, Message: msg, Plugin: name}
}
