// U21 SMTP 协议 debug 测试（计划书 1.5⑥——debugFrame 开启输出/关闭与 nil 注入零输出锚；
// NFR-015 全离线：同包私有字段直构，log_id 经 ctx 注入断言）。
// 修改历史：
//
//	2026-09-27 06:24:00 | 新建 | U21 可观测性增强（计划书步骤 4，G2 批准 2026-09-27 06:13:36）
package smtp

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"GRmail/internal/observability"
)

// TestU21SMTPDebugFrame smtp 协议 debug 条件输出（H5 等价锚——25 端点命令应答面）。
func TestU21SMTPDebugFrame(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := observability.LoggerIntoContext(context.Background(), logger.With(slog.String("log_id", "u21-smtp-logid")))

	on := &Server{cfg: ServerConfig{ProtocolDebug: func() bool { return true }}}
	sessOn := &session{srv: on, ctx: ctx}
	sessOn.debugFrame("C", "EHLO client.example\r\n")
	out := buf.String()
	if !strings.Contains(out, "smtp_debug") || !strings.Contains(out, "EHLO client.example") || !strings.Contains(out, "u21-smtp-logid") {
		t.Fatalf("开启态输出缺失（事件/帧/log_id 三锚），实际: %s", out)
	}

	buf.Reset()
	off := &Server{cfg: ServerConfig{}} // ProtocolDebug nil=禁用
	sessOff := &session{srv: off, ctx: ctx}
	sessOff.debugFrame("S", "250 ok\r\n")
	if buf.Len() != 0 {
		t.Fatalf("nil 注入禁用态应零输出，实际: %s", buf.String())
	}
}
