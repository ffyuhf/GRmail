// smtp 25 端点超长行防护单测（访问协议资源限制批 u30——F5/B-S8）：
// 原 bufio.ReadLine 默认 4096 缓冲下 `len(raw) > cmdLineLimit(4096)` 恒假、
// errLineTooLong 从未触发（超长命令被静默吞并剩余段、末段按整行处理）；
// ReadSlice 循环计数重构后 500 "5.5.2 行超长" 实际生效且会话继续。
// 规范锚：rfc5321bis §4.5.3.1.4（命令行 512 下限——扩展放宽 4096）+
// §4.5.3.1.9（超限 500 会话可继续）。
// 修改历史：
//
//	2026-10-07 14:12:00 | 新建 | 访问协议资源限制批（计划书 v1.0.0 步骤 5，
//	G2 批准 2026-10-07 14:00:02）
package smtp

import (
	"strings"
	"testing"

	"GRmail/internal/storage"
)

// TestCommandLineTooLongRejected F5 主锚：超长命令行 → 500 实际收到（原缺陷：
// 静默截断当有效）+ 会话继续（后续合法命令正常应答）。
func TestCommandLineTooLongRejected(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"rcpt@t.io": storage.MailboxStatusActive}, true, 1<<20)
	h.send("EHLO t.io") // MAIL 前置（rfc5321bis 4.1.4）
	h.expect("250")

	// 超长行：合法前缀 + 5000 字节填充（总长 > cmdLineLimit=4096）
	h.sendRaw("MAIL FROM:<a@t.io> " + strings.Repeat("X", 5000) + "\r\n")
	resp := h.expect("500")
	if !strings.Contains(resp, "行超长") {
		t.Fatalf("应答应含行超长语义: %q", resp)
	}
	// 会话继续：正常命令照常应答（超长行剩余已被消费，流同步）
	h.send("NOOP")
	h.expect("250")
	// 常规 MAIL 流程回归（防护不误伤）
	h.send("MAIL FROM:<a@t.io>")
	h.expect("250")
}

// TestCommandLineWithinLimit F5 回归：恰限内长行（<4096）正常解析。
func TestCommandLineWithinLimit(t *testing.T) {
	h := newHarness(t, map[string]storage.MailboxStatus{"rcpt@t.io": storage.MailboxStatusActive}, true, 1<<20)
	h.send("EHLO t.io") // MAIL 前置（rfc5321bis 4.1.4）
	h.expect("250")

	// 3000 字节地址行（< cmdLineLimit）——正常走 MAIL 语义（250 发件人确认；
	// 地址长度无独立上限——MAIL path 解析宽容承载）
	long := "MAIL FROM:<a" + strings.Repeat("Y", 3000) + "@t.io>"
	h.sendRaw(long + "\r\n")
	h.expect("250")
}
