// U21 IMAP 协议 debug 测试（计划书 1.5⑥——debugWriter 条件输出/静默丢弃/nil 禁用锚；
// 双源核对结论承载：go-imap v2 imapserver.Options 原生 DebugWriter io.Writer 字段挂接）。
// 修改历史：
//
//	2026-09-27 06:24:00 | 新建 | U21 可观测性增强（计划书步骤 4，G2 批准 2026-09-27 06:13:36）
package imap

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestU21IMAPDebugWriter IMAP 条件 Writer 三态（H5 等价锚——开启输出/false 静默/nil 禁用；
// 消费语义恒返回 len(p)——go-imap v2 Write 契约不因丢弃而报错）。
func TestU21IMAPDebugWriter(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	// 开启态：raw 帧输出（行尾 CRLF 剥除断言）
	w := &debugWriter{enabled: func() bool { return true }}
	n, err := w.Write([]byte("a1 LOGIN user@example {8}\r\n"))
	if err != nil || n != len("a1 LOGIN user@example {8}\r\n") {
		t.Fatalf("Write 消费语义破坏: n=%d err=%v", n, err)
	}
	out := buf.String()
	if !strings.Contains(out, "imap_debug") || !strings.Contains(out, "a1 LOGIN") {
		t.Fatalf("开启态输出缺失，实际: %s", out)
	}
	if strings.Contains(out, "\r\n") {
		t.Fatalf("行尾 CRLF 应剥除，实际: %q", out)
	}

	// false 快照：静默丢弃（消费语义保持）
	buf.Reset()
	w2 := &debugWriter{enabled: func() bool { return false }}
	if n, err := w2.Write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("false 态 Write 消费语义破坏: n=%d err=%v", n, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("false 态应零输出，实际: %s", buf.String())
	}

	// nil 快照注入：禁用（缺省装配形态）
	w3 := &debugWriter{}
	if _, err := w3.Write([]byte("y")); err != nil {
		t.Fatalf("nil 态 Write 报错: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("nil 注入态应零输出，实际: %s", buf.String())
	}
}
