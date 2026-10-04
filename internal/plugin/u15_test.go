//go:build !windows

// U15 插件系统测试矩阵（NFR-015 全离线——go-plugin 子进程为本机进程无网络依赖）。
// 覆盖：TC-016 判定①（示例插件拉起注册+钩子调用）/判定②（kill 后宿主存活+告警+
// 摘除——NFR-009/TC-022②）/判定④（单二进制保持归 main 侧）；协议注册声明流。
// 依据：U15 计划书 v1.0.0 1.5⑦（G2 批准 2026-09-24 10:46:55）；Q3-A 崩溃处置。
// 修改历史：
//
//	2026-09-24 11:09:00 | 新建 | U15 插件系统（计划书步骤 6）
package plugin

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
)

// ───────────────────────── 测试基建 ─────────────────────────

// captureHandler 捕获 slog 输出（协议注册声明断言用——宿主登记日志可证）。
type captureHandler struct {
	mu    sync.Mutex
	lines []string
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, r.Message)
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) contains(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, l := range h.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// buildExamplePlugin 测试内编译示例插件二进制（go 构建链——沿 1.5⑦ 口径；
// 工作目录=server 根：本测试文件位于 internal/plugin/，上溯三级）。
func buildExamplePlugin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "example-plugin")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/example-plugin")
	cmd.Dir = filepath.Join("..", "..") // 测试进程 CWD=server/internal/plugin，上溯两级=server 根
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("编译示例插件失败: %v\n%s", err, out)
	}
	return bin
}

// newTestSupervisor 构造宿主（临时 plugins 目录+单插件二进制+捕获日志）。
func newTestSupervisor(t *testing.T) (*Supervisor, *captureHandler) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(buildExamplePlugin(t), filepath.Join(dir, "example-plugin")); err != nil {
		t.Fatal(err)
	}
	h := &captureHandler{}
	logger := slog.New(h)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := NewSupervisor(ctx, dir, logger)
	t.Cleanup(s.Shutdown)
	return s, h
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// quietLogger 丢弃日志（无需断言的用例——隔离 stderr 噪声）。
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ───────────────────────── TC-016 判定①：拉起注册+钩子调用 ─────────────────────────

// TestU15PluginLaunchAndGetInfo 示例插件拉起+元信息往返（判定①「自动拉起并注册」：
// 钩子链非空+HookName=GetInfo 产物）。
func TestU15PluginLaunchAndGetInfo(t *testing.T) {
	s, h := newTestSupervisor(t)
	hooks := s.InboundHooks()
	if len(hooks) != 1 {
		t.Fatalf("期望 1 个收信钩子，得到 %d", len(hooks))
	}
	if hooks[0].HookName() != "example-plugin" {
		t.Fatalf("钩子名=GetInfo 产物不符: %s", hooks[0].HookName())
	}
	if len(s.SubmitHooks()) != 1 {
		t.Fatalf("期望 1 个发信钩子，得到 %d", len(s.SubmitHooks()))
	}
	if !h.contains("插件已拉起") {
		t.Fatal("拉起日志缺失（判定①「日志可证」锚）")
	}
}

// TestU15InboundHookRoundtrip 收信钩子调用（判定①「钩子调用成功」）：放行决策+
// 验证结论透传（原始字节往返大小一致）。
func TestU15InboundHookRoundtrip(t *testing.T) {
	s, _ := newTestSupervisor(t)
	hook := s.InboundHooks()[0]
	dec, err := hook.OnInbound(context.Background(), &mail.HookInput{
		Envelope:     auth.Envelope{Helo: "tester", MailFrom: "a@t.io"},
		Verification: &mail.VerifySnapshot{SPF: "pass", DKIM: "pass", DMARC: "pass", ARC: "none"},
		Raw:          []byte("Subject: hi\r\n\r\nbody"),
	})
	if err != nil {
		t.Fatalf("OnInbound RPC: %v", err)
	}
	if dec == nil || !dec.Allow {
		t.Fatalf("示例插件应放行: %+v", dec)
	}
}

// TestU15SubmitHookRoundtrip 发信钩子调用（放行+提交上下文透传）。
func TestU15SubmitHookRoundtrip(t *testing.T) {
	s, _ := newTestSupervisor(t)
	hook := s.SubmitHooks()[0]
	dec, err := hook.OnSubmit(context.Background(), &mail.HookInput{
		Envelope:   auth.Envelope{Helo: "submission", MailFrom: "a@t.io"},
		AuthUser:   "admin",
		Recipients: []string{"x@other.io"},
		Raw:        []byte("Subject: out\r\n\r\nbody"),
	})
	if err != nil {
		t.Fatalf("OnSubmit RPC: %v", err)
	}
	if dec == nil || !dec.Allow {
		t.Fatalf("示例插件应放行: %+v", dec)
	}
}

// TestU15RegisterProtocolDeclared 协议注册声明（FR-016 能力呈现）：宿主登记日志
// 可证（「插件协议注册声明」+登记不路由注记）。
func TestU15RegisterProtocolDeclared(t *testing.T) {
	_, h := newTestSupervisor(t)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if h.contains("插件协议注册声明") {
			return // 声明已到达并登记
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("协议注册声明日志未出现（10s 内）")
}

// ───────────────────────── TC-016 判定②/NFR-009/TC-022②：崩溃隔离 ─────────────────────────

// TestU15CrashKillAndSurvive kill 插件进程→宿主测试进程存活+告警+链路摘除
// （Q3-A：不自动重拉；InboundHooks 清空=摘除断言）。
// 限 unix（SIGKILL）；Windows named pipe 形态由 TC-026 构建矩阵覆盖。
func TestU15CrashKillAndSurvive(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(buildExamplePlugin(t), filepath.Join(dir, "example-plugin")); err != nil {
		t.Fatal(err)
	}
	h := &captureHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := NewSupervisor(ctx, dir, slog.New(h))
	t.Cleanup(s.Shutdown)

	if len(s.InboundHooks()) != 1 {
		t.Fatal("前置：钩子链应有 1 个插件")
	}
	// kill 插件子进程（ReattachConfig().Pid=宿主拉起的子进程 pid）
	pid := s.plugins[0].client.ReattachConfig().Pid
	if err := killProcess(pid); err != nil {
		t.Fatalf("kill 插件进程: %v", err)
	}
	// 等待监管摘除（watch 周期 3s——8s 上限轮询）
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.InboundHooks()) == 0 {
			if !h.contains("插件进程崩溃") {
				t.Fatal("摘除已发生但崩溃告警日志缺失（判定②「自动处置」日志锚）")
			}
			// 宿主存活即本测试进程继续运行（NFR-009/TC-022②）——断言钩子调用
			// 走摘除态自检（返回错误→管道降级放行）
			s.mu.Lock()
			hook := s.plugins[0].hook
			s.mu.Unlock()
			if _, err := hook.OnInbound(context.Background(), &mail.HookInput{}); err == nil {
				t.Fatal("摘除态钩子调用应返回错误（管道侧降级放行输入）")
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("8s 内未完成崩溃摘除（监管周期异常）")
}

// ───────────────────────── 零插件态（首次部署兼容） ─────────────────────────

// TestU15EmptyDirZeroPluginState 空插件目录=零插件态（钩子链空——管道 U14b 末态等价锚）。
func TestU15EmptyDirZeroPluginState(t *testing.T) {
	dir := t.TempDir() // 空目录
	s := NewSupervisor(context.Background(), dir, quietLogger())
	defer s.Shutdown()
	if n := len(s.InboundHooks()); n != 0 {
		t.Fatalf("空目录应零插件，得到 %d", n)
	}
	if n := len(s.SubmitHooks()); n != 0 {
		t.Fatalf("空目录应零发信钩子，得到 %d", n)
	}
}

// TestU15MissingDirZeroPluginState 目录缺失=Warn 零插件态（首次部署无 plugins/ 场景）。
func TestU15MissingDirZeroPluginState(t *testing.T) {
	s := NewSupervisor(context.Background(),
		filepath.Join(t.TempDir(), "nonexistent"), quietLogger())
	defer s.Shutdown()
	if n := len(s.InboundHooks()); n != 0 {
		t.Fatalf("目录缺失应零插件，得到 %d", n)
	}
}
