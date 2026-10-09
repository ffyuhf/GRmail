// B-S安全域批 F4 新用例（计划书 v2.0.0 步骤 7 检查点承载）——AUTHENTICATE 命令行
// 凭据掩码纯函数锚（ManageSieve 侧）+脚本名防御校验（F3）+认证限流判定白盒（F3）。
// 依据：NFR-016 日志安全承载；rfc5804 §1.6 name 文法；B-S批 F3 限流（沿提交端点先例）。
// 修改历史：
//
//	2026-10-09 21:38:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package managesieve

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestBSF4RedactAuthLine AUTHENTICATE 命令行 initial-response 掩码（宽容引号形态同掩）；
// 非认证命令原样；无 initial-response 原样。
func TestBSF4RedactAuthLine(t *testing.T) {
	if got := redactAuthLine(`AUTHENTICATE "PLAIN" AGFsaWNlAHMzY3JldA==` + "\r\n"); got != `AUTHENTICATE "PLAIN" [REDACTED]`+"\r\n" {
		t.Fatalf("AUTHENTICATE initial-response 应掩码: %q", got)
	}
	if got := redactAuthLine("AUTHENTICATE \"PLAIN\"\r\n"); got != "AUTHENTICATE \"PLAIN\"\r\n" {
		t.Fatalf("无 initial-response 应原样: %q", got)
	}
	if got := redactAuthLine("LISTSCRIPTS\r\n"); got != "LISTSCRIPTS\r\n" {
		t.Fatalf("非认证命令应原样: %q", got)
	}
}

// TestBSF3ValidScriptName 脚本名防御校验（B-S批 F3）：非空+≤128+无控制字符。
func TestBSF3ValidScriptName(t *testing.T) {
	if err := validScriptName(""); err == nil {
		t.Fatal("空名应拒绝")
	}
	if err := validScriptName(strings.Repeat("a", 129)); err == nil {
		t.Fatal("超长名（>128）应拒绝")
	}
	if err := validScriptName("bad\x01name"); err == nil {
		t.Fatal("控制字符应拒绝")
	}
	for _, ok := range []string{"a", "我的脚本", strings.Repeat("n", 128)} {
		if err := validScriptName(ok); err != nil {
			t.Fatalf("合法名 %q 不应拒绝: %v", ok, err)
		}
	}
}

// stubAttempts F3 限流白盒桩（CountRecentFails 可注入计数值）。
type bsStubAttempts struct {
	fails int64
}

func (s *bsStubAttempts) RecordAttempt(ctx context.Context, subjectKey, ip string, success bool, at time.Time) error {
	return nil
}
func (s *bsStubAttempts) CountRecentFails(ctx context.Context, subjectKey string, since time.Time) (int64, error) {
	return s.fails, nil
}
func (s *bsStubAttempts) ClearSubject(ctx context.Context, subjectKey string) error { return nil }

// TestBSF3AuthLocked 认证失败限流判定白盒（B-S批 F3）：计数达阈值锁定；nil 注入关闭；
// 计数不足放行。
func TestBSF3AuthLocked(t *testing.T) {
	locked := &session{ctx: context.Background(), cfg: ServerConfig{
		Attempts: &bsStubAttempts{fails: 5}, AttemptLimit: func() (time.Duration, int64) { return 15 * time.Minute, 5 },
	}}
	if !locked.authLocked("managesieve:x") {
		t.Fatal("计数达阈值（5/5）应锁定")
	}
	open := &session{ctx: context.Background(), cfg: ServerConfig{
		Attempts: &bsStubAttempts{fails: 2}, AttemptLimit: func() (time.Duration, int64) { return 15 * time.Minute, 5 },
	}}
	if open.authLocked("managesieve:x") {
		t.Fatal("计数不足（2/5）应放行")
	}
	nilCfg := &session{ctx: context.Background(), cfg: ServerConfig{}}
	if nilCfg.authLocked("managesieve:x") {
		t.Fatal("nil 注入（渐进态）应恒放行")
	}
}
