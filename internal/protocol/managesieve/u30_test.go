// managesieve 资源限制单测（访问协议资源限制批 u30——F3/F6）：
// F3（A-13③）字面量声明计数前置校验（32 位语法上界/配额上限/合法通过三态）+
// readLiteralBytes 分配防御（超配额零分配拒绝）；F6（M4）readLine 超长哨兵
// （ReadSlice 循环计数——ReadString 无界累积防御）。
// 规范锚：rfc5804 语法章 L1855-1858（number=32-bit unsigned 0 ≤ n < 4,294,967,296）
// /§1.5 配额语义（QUOTA/MAXSIZE）。
// 修改历史：
//
//	2026-10-07 14:12:00 | 新建 | 访问协议资源限制批（计划书 v1.0.0 步骤 3·6，
//	G2 批准 2026-10-07 14:00:02）
package managesieve

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// TestCheckLiteralCount F3 主锚：前置校验三态（配额缺省 64KB——QuotaConfig.Defaults）。
func TestCheckLiteralCount(t *testing.T) {
	s := &session{cfg: ServerConfig{}} // Quota nil → 缺省档 MaxBytes=64KB

	if msg, ok := s.checkLiteralCount(4294967296); ok || !strings.Contains(msg, "32 位") {
		t.Fatalf("超 32 位上界应拒绝: ok=%v msg=%q", ok, msg)
	}
	if msg, ok := s.checkLiteralCount(70000); ok || !strings.Contains(msg, "QUOTA/MAXSIZE") {
		t.Fatalf("超配额（64KB）应拒绝: ok=%v msg=%q", ok, msg)
	}
	if msg, ok := s.checkLiteralCount(65536); !ok || msg != "" {
		t.Fatalf("恰配额上限应通过: ok=%v msg=%q", ok, msg)
	}
	if msg, ok := s.checkLiteralCount(0); !ok || msg != "" {
		t.Fatalf("零长度应通过: ok=%v msg=%q", ok, msg)
	}
}

// TestReadLiteralBytesAllocationGuard F3：readLiteralBytes 分配防御——超配额
// 计数在 make 前拒绝（原 make([]byte,n) 先分配后校验的 OOM 面根治）。
func TestReadLiteralBytesAllocationGuard(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	s := newSession(nil, server, ServerConfig{})

	// 超配额（64KB）——零读取零分配即拒绝
	start := time.Now()
	if _, err := s.readLiteralBytes(10 * 1024 * 1024); err == nil ||
		!strings.Contains(err.Error(), "QUOTA/MAXSIZE") {
		t.Fatalf("超配额应前置拒绝: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("前置拒绝应瞬时（未读取 10MB），耗时 %v", elapsed)
	}
	// 超 32 位语法上界
	if _, err := s.readLiteralBytes(4294967296); err == nil || !strings.Contains(err.Error(), "32 位") {
		t.Fatalf("超语法上界应拒绝: %v", err)
	}
}

// TestReadLineTooLong F3+F6：超长行（>readLineMax=512）返回哨兵错误——
// ReadSlice 循环计数形态（不无界累积）。
func TestReadLineTooLong(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	s := newSession(nil, server, ServerConfig{})

	go func() {
		// 超长行（600 字节无换行）+ 换行终止；随后再发一行验证流同步状态
		_, _ = client.Write([]byte(strings.Repeat("A", 600) + "\r\n"))
		time.Sleep(50 * time.Millisecond)
		_, _ = client.Write([]byte("CAPABILITY\r\n"))
	}()

	if _, err := s.readLine(); !errors.Is(err, errLineTooLong) {
		t.Fatalf("超长行应返回哨兵: %v", err)
	}
	// 流同步：超长消费至行尾后，下一行可正常读取
	line, err := s.readLine()
	if err != nil {
		t.Fatalf("后续行读取: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "CAPABILITY") {
		t.Fatalf("流同步破坏（应读到 CAPABILITY）: %q", line)
	}
}

// TestReadLineWithinLimit F6：正常行（≤512）通过——行为回归。
func TestReadLineWithinLimit(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	s := newSession(nil, server, ServerConfig{})

	go func() {
		_, _ = client.Write([]byte("NOOP\r\n"))
	}()
	line, err := s.readLine()
	if err != nil {
		t.Fatalf("正常行读取: %v", err)
	}
	if strings.TrimSpace(line) != "NOOP" {
		t.Fatalf("行内容不符: %q", line)
	}
}
