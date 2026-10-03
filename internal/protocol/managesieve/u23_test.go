// U23 ManageSieve 协议 debug 测试（计划书 1.5⑧④——debugFrame 开启输出/关闭与 nil 注入
// 零输出锚；NFR-015 全离线：同包私有字段直构，沿 u21_test 先例）。
// 修改历史：
//
//	2026-09-27 13:54:00 | 新建 | U23 可观测性扩展（计划书步骤 5，G2 批准 2026-09-27 13:20:53）
package managesieve

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"GRmail/internal/observability"
)

// TestU23ManageSieveDebugFrame managesieve 协议 debug 条件输出（H5 等价锚——U21 登记项②收口）。
func TestU23ManageSieveDebugFrame(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := observability.LoggerIntoContext(context.Background(), logger.With(slog.String("logid", "u23-ms-logid")))

	on := &session{ctx: ctx, cfg: ServerConfig{ProtocolDebug: func() bool { return true }}}
	on.debugFrame("C", "CAPABILITY\r\n")
	on.debugFrame("S", "OK \"ready\"\r\n")
	out := buf.String()
	// slog TextHandler 对含引号值转义：OK "ready" 实际渲染为 OK \"ready\"——锚按转义后形态断言。
	for _, anchor := range []string{"managesieve_debug", "CAPABILITY", `OK \"ready\"`, "u23-ms-logid"} {
		if !strings.Contains(out, anchor) {
			t.Fatalf("开启态输出缺失锚 %q，实际: %s", anchor, out)
		}
	}

	buf.Reset()
	off := &session{ctx: ctx, cfg: ServerConfig{}} // ProtocolDebug nil=禁用（缺省装配防御锚）
	off.debugFrame("S", "BYE \"bye\"\r\n")
	if buf.Len() != 0 {
		t.Fatalf("nil 注入禁用态应零输出，实际: %s", buf.String())
	}

	// ctx 缺失防御锚（直构遗漏场景——零输出零 panic）
	noCtx := &session{cfg: ServerConfig{ProtocolDebug: func() bool { return true }}}
	noCtx.debugFrame("C", "NOOP\r\n")
	if buf.Len() != 0 {
		t.Fatalf("nil ctx 防御态应零输出，实际: %s", buf.String())
	}
}
