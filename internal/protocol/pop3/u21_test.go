// U21 POP3 协议 debug 测试（计划书 1.5⑥——debugFrame 开启输出含 logid/关闭零输出锚；
// NFR-015 全离线：同包私有字段直构，slog.Default 捕获+defer 恢复——包内测试串行零竞争）。
// 修改历史：
//
//	2026-09-27 06:24:00 | 新建 | U21 可观测性增强（计划书步骤 4，G2 批准 2026-09-27 06:13:36）
package pop3

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestU21POP3DebugFrame pop3 协议 debug 条件输出（H5 等价锚——命令响应面+logid 关联）。
func TestU21POP3DebugFrame(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	on := &Server{cfg: ServerConfig{ProtocolDebug: func() bool { return true }}}
	ss := &session{server: on, logID: "u21-pop3-logid"}
	ss.debugFrame("C", "CAPA\r\n")
	out := buf.String()
	if !strings.Contains(out, "pop3_debug") || !strings.Contains(out, "CAPA") || !strings.Contains(out, "u21-pop3-logid") {
		t.Fatalf("开启态输出缺失（事件/帧/logid 三锚），实际: %s", out)
	}

	buf.Reset()
	off := &Server{} // ProtocolDebug nil=禁用
	ss2 := &session{server: off, logID: "u21-pop3-logid-2"}
	ss2.debugFrame("S", "+OK ready\r\n")
	if buf.Len() != 0 {
		t.Fatalf("nil 注入禁用态应零输出，实际: %s", buf.String())
	}
}
