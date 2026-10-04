// U23 提交端点协议 debug 测试（计划书 1.5⑧③——debugFrame 开启输出/关闭与 nil 注入零输出锚；
// NFR-015 全离线：同包私有字段直构，logid 经 ctx 注入断言——沿 u21_test 先例）。
// 修改历史：
//
//	2026-09-27 13:50:00 | 新建 | U23 可观测性扩展（计划书步骤 4，G2 批准 2026-09-27 13:20:53）
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"GRmail/internal/observability"
)

// TestU23SubmissionDebugFrame 提交端点协议 debug 条件输出（H5 等价锚——U21 登记项①收口）。
func TestU23SubmissionDebugFrame(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := observability.LoggerIntoContext(context.Background(), logger.With(slog.String("logid", "u23-submission-logid")))

	on := &SubmissionServer{cfg: SubmissionConfig{ProtocolDebug: func() bool { return true }}}
	sessOn := &submitSession{srv: on, ctx: ctx}
	sessOn.debugFrame("C", "AUTH PLAIN dGVzdA==\r\n")
	sessOn.debugFrame("S", "235 authenticated")
	out := buf.String()
	for _, anchor := range []string{"submission_debug", "AUTH PLAIN", "235 authenticated", "u23-submission-logid"} {
		if !strings.Contains(out, anchor) {
			t.Fatalf("开启态输出缺失锚 %q，实际: %s", anchor, out)
		}
	}

	buf.Reset()
	off := &SubmissionServer{cfg: SubmissionConfig{}} // ProtocolDebug nil=禁用
	sessOff := &submitSession{srv: off, ctx: ctx}
	sessOff.debugFrame("S", "250 ok\r\n")
	if buf.Len() != 0 {
		t.Fatalf("nil 注入禁用态应零输出，实际: %s", buf.String())
	}
}

// TestU23SubmissionReadWriteFrame 提交会话读写辅助埋点贯通锚（readLine 命令面/replyRaw 应答面）。
// net.Pipe 为同步无缓冲——写命令与 drain 应答须并发（否则应答写阻塞死锁）。
func TestU23SubmissionReadWriteFrame(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := observability.LoggerIntoContext(context.Background(), logger.With(slog.String("logid", "u23-rw-logid")))
	sess := &submitSession{
		srv: &SubmissionServer{cfg: SubmissionConfig{ProtocolDebug: func() bool { return true }}},
		rw:  bufio.NewReadWriter(bufio.NewReader(c2), bufio.NewWriter(c2)),
		ctx: ctx,
	}
	go func() {
		_, _ = c1.Write([]byte("EHLO client\r\n"))
		drain := make([]byte, 64)
		for {
			if _, err := c1.Read(drain); err != nil {
				return // 持续 drain 应答帧（防 replyRaw 写阻塞）
			}
		}
	}()
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := sess.readLine()
	if err != nil || line != "EHLO client" {
		t.Fatalf("readLine 应读取命令行，实际 line=%q err=%v", line, err)
	}
	sess.reply(250, "ok")
	out := buf.String()
	for _, anchor := range []string{"EHLO client", "250 ok"} {
		if !strings.Contains(out, anchor) {
			t.Fatalf("读写埋点输出缺失锚 %q，实际: %s", anchor, out)
		}
	}
}
