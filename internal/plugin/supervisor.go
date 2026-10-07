// Package plugin 承载 go-plugin 宿主（FR-016；SRS 3.10.1；IR-006）：plugins/ 目录
// 扫描→子进程拉起→崩溃监管→契约调用；实现 mail 域 InboundHook/SubmitHook 窄接口
// （依赖方向 plugin→mail 与架构 1.2 图 PLUGIN→MAIL 一致）。
// 依据：U15 计划书 v1.0.0（G2 批准 2026-09-24 10:46:55）；Q3-A 裁决（崩溃处置=
// 检测+Kill+告警+链路摘除，不自动重拉——重启主程序恢复）；Q2-A 裁决（最小完备
// 钩子集）；REQ-023（HashiCorp go-plugin+gRPC 强类型契约）；NFR-009（崩溃隔离）；
// NFR-014（proto/ 独立承载契约，主程序仅经生成代码消费——Q1-A 口径）。
// 传输层跨平台（Unix Socket/named pipe）由 go-plugin 框架自动适配（建模 7.3 要点 6）。
// 修改历史：
//
//	2026-09-24 11:01:00 | 新建 | U15 插件系统（计划书步骤 2）
package plugin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	pb "GRmail/proto/grmailplugin"
)

// ───────────────────────── 契约握手（宿主与插件共享约定） ─────────────────────────

// Handshake go-plugin 握手约定（协议版本 1+魔数对——宿主与插件二进制共同编译期锚定；
// 魔数值任意但必须非空且两侧一致——go-plugin 安全机制：防误拉起任意二进制）。
var Handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "GRMAIL_PLUGIN",
	MagicCookieValue: "grmail-plugin-cookie-4f1c9a2e",
}

// PluginName go-plugin 插件注册键（Plugins map 键——宿主与插件侧一致）。
const PluginName = "grmail"

// GRmailPluginGRPC go-plugin gRPC 桥接（宿主客户端与插件服务端共用形态——
// example-plugin 复用本类型注册服务端；NFR-014：两侧均仅经 proto 生成代码耦合）。
type GRmailPluginGRPC struct {
	goplugin.Plugin
	Impl pb.GRmailPluginServer // 插件侧实现注入（宿主侧为零值——仅用 GRPCClient）
}

// GRPCServer 插件进程侧：注册 gRPC 服务实现（plugin.Serve 调用）。
// 参数：broker 双向流代理；s gRPC 服务端。返回：注册错误。
func (p *GRmailPluginGRPC) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pb.RegisterGRmailPluginServer(s, p.Impl)
	return nil
}

// GRPCClient 宿主侧：返回 gRPC 客户端 stub（Dispense 产物——Supervisor 再包装为钩子）。
// 参数：ctx 上下文；broker 双向流代理；c 已建连的 gRPC 连接。返回：客户端 stub。
func (p *GRmailPluginGRPC) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker,
	c *grpc.ClientConn) (interface{}, error) {
	return pb.NewGRmailPluginClient(c), nil
}

// ───────────────────────── 钩子客户端（mail 窄接口实现） ─────────────────────────

// hookClient 单插件的宿主侧钩子包装（实现 mail.InboundHook+mail.SubmitHook）。
// 崩溃自检：每次调用前检查 client.Exited()——已退出则返回错误，由管道按 CON-004
// 降级放行（监管 goroutine 摘除与调用侧自检双保险——竞态窗口内自检兜底）。
type hookClient struct {
	name   string
	client *goplugin.Client
	raw    pb.GRmailPluginClient
	caps   []string // GetInfo 能力声明（日志呈现）
}

// HookName 插件名（日志与监管呈现——GetInfo 产物）。
func (h *hookClient) HookName() string { return h.name }

// OnInbound 收信钩子（gRPC 转发——mail.HookInput→pb.InboundContext）。
// 参数：ctx 上下文（管道已加 5s 超时——mail.PluginHookTimeout）；in 钩子输入。
// 返回：决策（mail 域形态）；错误=插件死亡/RPC 失败（调用方降级放行 CON-004）。
func (h *hookClient) OnInbound(ctx context.Context, in *mail.HookInput) (*mail.HookDecision, error) {
	if h.client.Exited() {
		return nil, fmt.Errorf("plugin: 插件 %s 已退出（崩溃摘除态）", h.name)
	}
	req := &pb.InboundContext{
		Envelope:   pbEnvelopeOf(in.Envelope),
		RawMessage: in.Raw,
	}
	if in.Verification != nil {
		req.Verification = &pb.VerifyResults{
			Spf: in.Verification.SPF, Dkim: in.Verification.DKIM,
			Dmarc: in.Verification.DMARC, Arc: in.Verification.ARC,
		}
	}
	dec, err := h.raw.OnInbound(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("plugin: OnInbound RPC: %w", err)
	}
	return mailDecisionOf(dec), nil
}

// OnSubmit 发信钩子（gRPC 转发——mail.HookInput→pb.SubmitContext）。
// 参数：ctx 上下文；in 钩子输入。返回：决策；错误同 OnInbound。
func (h *hookClient) OnSubmit(ctx context.Context, in *mail.HookInput) (*mail.HookDecision, error) {
	if h.client.Exited() {
		return nil, fmt.Errorf("plugin: 插件 %s 已退出（崩溃摘除态）", h.name)
	}
	dec, err := h.raw.OnSubmit(ctx, &pb.SubmitContext{
		Envelope:   pbEnvelopeOf(in.Envelope),
		AuthUser:   in.AuthUser,
		Recipients: in.Recipients,
		RawMessage: in.Raw,
	})
	if err != nil {
		return nil, fmt.Errorf("plugin: OnSubmit RPC: %w", err)
	}
	return mailDecisionOf(dec), nil
}

// ───────────────────────── 类型转换（mail ↔ proto 生成类型） ─────────────────────────

// pbEnvelopeOf mail 侧信封→proto 信封（RemoteIP net.IP→字符串；nil 归空串）。
func pbEnvelopeOf(e auth.Envelope) *pb.Envelope {
	ip := ""
	if e.RemoteIP != nil {
		ip = e.RemoteIP.String()
	}
	return &pb.Envelope{Helo: e.Helo, RemoteIp: ip, MailFrom: e.MailFrom}
}

// mailDecisionOf proto 决策→mail 决策（值域校验归管道 hookRejectOf——宿主双层防线）。
func mailDecisionOf(d *pb.HookDecision) *mail.HookDecision {
	if d == nil {
		return nil // nil 决策=放行（管道 nil 分支承载）
	}
	return &mail.HookDecision{Allow: d.Allow, SMTPCode: int(d.SmtpCode), Message: d.Message}
}

// ───────────────────────── 宿主 Supervisor（扫描/拉起/监管/Shutdown） ─────────────────────────

// watchPeriod 崩溃检测轮询周期（工程常量——go-plugin Client.Exited() 轻量查询）。
const watchPeriod = 3 * time.Second

// pluginHandshakeTimeout 插件握手单次预算（配置并发批 F6①/B-C5——GetInfo/
// RegisterProtocol 启动期调用 10s 超时：单个插件挂起不再阻塞主程序启动，
// NFR-003 启动可用性防线）。
const pluginHandshakeTimeout = 10 * time.Second

// 插件能力标识（配置并发批 F6④——钩子链按能力过滤；值域契约 2.5 既有：
// inbound_hook | submit_hook | protocol）。
const (
	capInboundHook = "inbound_hook"
	capSubmitHook  = "submit_hook"
)

// managedPlugin 单插件托管态。
type managedPlugin struct {
	name    string // GetInfo 产物（拉起期获取；获取失败以文件名兜底）
	version string // GetInfo 版本声明（G6 状态页呈现）
	client  *goplugin.Client
	hook    *hookClient
	alive   bool // 崩溃摘除标记（监管 goroutine 置 false+告警）
}

// Supervisor 插件宿主（FR-016 supervisor/worker 模型的 supervisor 侧）。
type Supervisor struct {
	dir    string
	logger *slog.Logger
	ctx    context.Context // F6③：生命周期 ctx（协议注册流 Recv 联动——取消即 stream 错误返回）

	mu      sync.Mutex
	plugins []*managedPlugin
}

// NewSupervisor 构造宿主并完成扫描+拉起+监管启动（main 装配调用）。
// 语义：目录不存在→Warn 零插件态（首次部署兼容）；单个插件拉起失败→Warn 跳过
// （NFR-009 精神：插件异常不影响主程序启动）；能力含 protocol→开登记流（不路由）。
// 参数：ctx 生命周期（监管 goroutine 退出联动——rootCtx 派生）；dir 插件目录
// （SRS 第 6 章部署形态 plugins/）；logger 结构化日志器。
// 返回：宿主实例（始终非 nil——零插件态亦正常承载，钩子链为空）。
func NewSupervisor(ctx context.Context, dir string, logger *slog.Logger) *Supervisor {
	s := &Supervisor{dir: dir, logger: logger, ctx: ctx}
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Warn("插件目录不可读，零插件态运行（放置插件二进制后重启生效）", "dir", dir, "error", err)
		return s
	}
	for _, e := range entries {
		if e.IsDir() {
			continue // 仅顶层二进制（SRS：插件二进制置于 plugins/）
		}
		bin := filepath.Join(dir, e.Name())
		if mp := s.launch(bin); mp != nil {
			s.plugins = append(s.plugins, mp)
		}
	}
	go s.watch(ctx)
	logger.Info("插件宿主已启动", "dir", dir, "count", len(s.plugins))
	return s
}

// launch 拉起单个插件二进制（go-plugin 标准形态：NewClient→Client 建连→Dispense→
// GetInfo 元信息；能力含 protocol→登记流）。
// 参数：bin 插件二进制路径。返回：托管态（失败返回 nil+Warn）。
func (s *Supervisor) launch(bin string) *managedPlugin {
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          map[string]goplugin.Plugin{PluginName: &GRmailPluginGRPC{}},
		Cmd:              exec.Command(bin),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		// 框架内部日志丢弃（宿主生命周期事件经 slog 承载——计划书 1.5⑨；
		// 插件 stderr 由 go-plugin 接管转发，hclog 噪声不混入主日志流）
		Logger: hclog.New(&hclog.LoggerOptions{Output: io.Discard}),
	})
	rpcClient, err := client.Client()
	if err != nil {
		s.logger.Warn("插件握手失败（跳过）", "bin", bin, "error", err)
		client.Kill()
		return nil
	}
	raw, err := rpcClient.Dispense(PluginName)
	if err != nil {
		s.logger.Warn("插件 Dispense 失败（跳过）", "bin", bin, "error", err)
		client.Kill()
		return nil
	}
	stub, ok := raw.(pb.GRmailPluginClient)
	if !ok {
		s.logger.Warn("插件 Dispense 产物类型不符（跳过）", "bin", bin, "got", fmt.Sprintf("%T", raw))
		client.Kill()
		return nil
	}
	// F6①：握手单次预算（超时跳过该插件——单个插件挂起不阻塞主程序启动）
	hctx, hcancel := context.WithTimeout(context.Background(), pluginHandshakeTimeout)
	defer hcancel()
	info, err := stub.GetInfo(hctx, &pb.GetInfoRequest{})
	if err != nil || info.GetName() == "" {
		s.logger.Warn("插件 GetInfo 失败（跳过）", "bin", bin, "error", err)
		client.Kill()
		return nil
	}
	mp := &managedPlugin{
		name:    info.GetName(),
		version: info.GetVersion(),
		client:  client,
		hook:    &hookClient{name: info.GetName(), client: client, raw: stub, caps: info.GetCapabilities()},
		alive:   true,
	}
	s.logger.Info("插件已拉起", "name", info.GetName(), "version", info.GetVersion(),
		"capabilities", info.GetCapabilities())
	// 协议注册声明流（FR-016 能力呈现——登记+日志，不路由到监听器；
	// FR-017 愿望清单边界：协议路由不实现）
	for _, c := range info.GetCapabilities() {
		if c == "protocol" {
			s.drainProtocolRegistrations(mp)
			break
		}
	}
	return mp
}

// drainProtocolRegistrations 开启协议注册双向流并收声明（插件侧 Send 声明→
// 宿主登记日志→回 ack；流结束即返回——goroutine 形态不阻塞拉起）。
// 参数：mp 插件托管态。
// F6③：流绑定生命周期 ctx（原 context.Background() 无联动——插件退出依赖流
// 关闭，泄漏窗口；gRPC stream 绑定 ctx 后取消即 Recv 错误返回自然退出）。
func (s *Supervisor) drainProtocolRegistrations(mp *managedPlugin) {
	stream, err := mp.hook.raw.RegisterProtocol(s.ctx)
	if err != nil {
		s.logger.Warn("插件协议注册流开启失败", "plugin", mp.name, "error", err)
		return
	}
	go func() {
		for {
			reg, err := stream.Recv()
			if err != nil {
				return // 流关闭（插件退出/声明完毕）
			}
			s.logger.Info("插件协议注册声明（登记不路由——本期形态）",
				"plugin", mp.name, "protocol", reg.GetProtocolName(), "endpoint", reg.GetEndpoint())
			if err = stream.Send(&pb.ProtocolAck{Accepted: true, Note: "registered (not routed in this phase)"}); err != nil {
				return
			}
		}
	}()
}

// watch 崩溃监管循环（Q3-A：Exited 检测→Kill+告警+摘除；不自动重拉——
// 重启主程序后扫描恢复）。
// 参数：ctx 生命周期（rootCtx 派生——退出联动）。
func (s *Supervisor) watch(ctx context.Context) {
	ticker := time.NewTicker(watchPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// F6②：锁内仅标记摘除（快照即时对钩子链生效）——Kill（阻塞至子进程
			// 退出）移至锁外，全局锁不再被清理动作占用（StatusSnapshot 并发不死锁）。
			var victims []*managedPlugin
			s.mu.Lock()
			for _, p := range s.plugins {
				if p.alive && p.client.Exited() {
					p.alive = false
					victims = append(victims, p)
					s.logger.Warn("插件进程崩溃，已从钩子链摘除（不自动重拉——重启主程序恢复）",
						"plugin", p.name)
				}
			}
			s.mu.Unlock()
			for _, p := range victims {
				p.client.Kill() // 清理子进程资源（僵尸态收尾——锁外执行）
			}
		}
	}
}

// InboundHooks 收信钩子链快照（main 装配注入 pipeline；仅含存活插件——
// 崩溃摘除后调用自检兜底）。
// F6④（B-C5 能力过滤）：仅 caps 含 inbound_hook 的插件入链——protocol-only
// 插件不再被挂收发信钩子（能力声明契约 2.5 值域承载）。
// 返回：钩子链（可能为空切片——零插件态）。
func (s *Supervisor) InboundHooks() []mail.InboundHook {
	s.mu.Lock()
	defer s.mu.Unlock()
	hooks := make([]mail.InboundHook, 0, len(s.plugins))
	for _, p := range s.plugins {
		if p.alive && hasCapability(p.hook.caps, capInboundHook) {
			hooks = append(hooks, p.hook)
		}
	}
	return hooks
}

// SubmitHooks 发信钩子链快照（main 装配注入 submissionPipeline；F6④ 能力过滤同 InboundHooks）。
// 返回：钩子链（可能为空切片）。
func (s *Supervisor) SubmitHooks() []mail.SubmitHook {
	s.mu.Lock()
	defer s.mu.Unlock()
	hooks := make([]mail.SubmitHook, 0, len(s.plugins))
	for _, p := range s.plugins {
		if p.alive && hasCapability(p.hook.caps, capSubmitHook) {
			hooks = append(hooks, p.hook)
		}
	}
	return hooks
}

// hasCapability 能力声明包含判定（精确匹配契约 2.5 值域原子）。
func hasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// StatusRow 插件运行状态快照行（Webmail管理职能批次 G6——/admin/plugins 只读呈现；
// 纯数据无依赖，main 装配桥接转换为 web 中性接口——沿 STSPolicy 供给先例零 web import）。
type StatusRow struct {
	Name    string
	Version string
	Caps    []string
	Alive   bool
}

// StatusSnapshot 全部托管插件状态快照（mutex 保护拷贝——含崩溃摘除态呈现；
// 拉起失败跳过的插件不在内——启动日志承载；零插件=空切片）。
func (s *Supervisor) StatusSnapshot() []StatusRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]StatusRow, 0, len(s.plugins))
	for _, p := range s.plugins {
		rows = append(rows, StatusRow{Name: p.name, Version: p.version, Caps: p.hook.caps, Alive: p.alive})
	}
	return rows
}

// Shutdown 停止全部插件子进程（优雅退出序——协议端点链之后调用）。
// F6②：锁内标记摘除+锁外 Kill（Kill 阻塞不占全局锁——与 watch 同款两段式）。
func (s *Supervisor) Shutdown() {
	var victims []*managedPlugin
	s.mu.Lock()
	for _, p := range s.plugins {
		if p.alive {
			p.alive = false
			victims = append(victims, p)
		}
	}
	s.mu.Unlock()
	for _, p := range victims {
		p.client.Kill()
		s.logger.Info("插件已停止", "plugin", p.name)
	}
}
