// cmd/mail-server 后台清理任务单测（U14b——NFR-015：临时 SQLite 库+短周期注入，零网络端点）
// 与版本查询参数单测（发布准备批次——parseVersionFlag 四断言）、HTTP 端口参数单测
// （HTTP端口参数化批次——parseHTTPPortFlag 五断言）。
// 覆盖锚点：runTokenPurgeLoop 四断言（首轮清过期行/未过期与永久行保留/周期 tick 续清
// 新过期行/ctx 取消即返回）；U14b 计划书 1.5⑤；数据模型 v1.2.0 3.11 过期语义
// （expires_at NULL=永久——零值行不可被清理）；发布准备计划书 1.2-VB 组（--version
// 早退路径——NFR-013 构建产物元数据运维查询锚）；HTTP端口参数化计划书 1.2-CLI 组
// （-p 解析/值域/错误归属——FR-015 受限端口环境可达性锚）。
// 修改历史：
//
//	2026-09-24 03:20:00 | 新建 | U14b Token 清理（计划书步骤 2，G2 批准 2026-09-24 03:12:52）
//	2026-10-03 17:11:00 | 扩展 | 发布准备批次：TestParseVersionFlag 四断言（--version
//	命中打印三元组/-version 等价/无参数不命中零输出/未知 flag 静默不命中；G2 批准
//	2026-10-03 17:09:00——计划书阶段 1 检查点）
//	2026-10-04 11:35:00 | 扩展 | HTTP端口参数化批次：TestParseHTTPPortFlag 五断言
//	（-p=8080 等价形态/越界 0 与 65536 报错/缺省 nil 零值不覆盖/-p abc 报错归属/
//	未知 flag 静默零值；G2 批准 2026-10-04 11:32:10——计划书阶段 1 检查点）
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// newPurgeTokenRepo 临时库迁移后构造 Token 仓储（沿 storage/token_repo_test.go 构造形态
// ——main 包侧同源复制：Open+MigrateUp+NewSQLiteTokenRepo）。
func newPurgeTokenRepo(t *testing.T) storage.TokenRepo {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u14btest.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移测试库: %v", err)
	}
	return storage.NewSQLiteTokenRepo(db)
}

// waitListSize 轮询等待主体行数达到期望（至多 2s——清理 goroutine 异步完成判定）。
func waitListSize(t *testing.T, r storage.TokenRepo, userID int64, want int) []*storage.ApiToken {
	t.Helper()
	ctx := context.Background()
	deadline := time.After(2 * time.Second)
	for {
		list, err := r.ListByUser(ctx, userID)
		if err != nil {
			t.Fatalf("列表查询: %v", err)
		}
		if len(list) == want {
			return list
		}
		select {
		case <-deadline:
			t.Fatalf("等待行数 %d 超时（当前 %d）", want, len(list))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestU14bRunTokenPurgeLoop 清理循环四断言：首轮清过期/保留未过期与永久/tick 续清/取消返回。
func TestU14bRunTokenPurgeLoop(t *testing.T) {
	r := newPurgeTokenRepo(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// 预置三态行：过期（1 小时前）/未过期（1 小时后）/永久（ExpiresAt 零值→DB NULL）
	preload := []*storage.ApiToken{
		{UserID: 1, TokenHash: hash64ForMain("a"), ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour)},
		{UserID: 1, TokenHash: hash64ForMain("b"), ExpiresAt: now.Add(time.Hour), CreatedAt: now},
		{UserID: 1, TokenHash: hash64ForMain("c"), CreatedAt: now}, // 永久（零值）
	}
	for _, tok := range preload {
		if err := r.Create(ctx, tok); err != nil {
			t.Fatalf("预置 Token: %v", err)
		}
	}

	// 短周期 10ms 驱动（生产 24h——计划书 1.5⑤ 测试注入形态）
	loopCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runTokenPurgeLoop(loopCtx, r, 10*time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()

	// 断言①：首轮立即清理存量过期行（3→2）
	list := waitListSize(t, r, 1, 2)

	// 断言②：未过期与永久行保留（哈希集合核验）
	got := map[string]bool{}
	for i := range list {
		got[list[i].TokenHash] = true
	}
	if !got[hash64ForMain("b")] || !got[hash64ForMain("c")] {
		t.Fatalf("未过期/永久行被误删: %v", got)
	}

	// 断言③：周期 tick 续清——插入新过期行 d，等待下一轮 tick 清理（3→2：b/c/d 清 d）
	if err := r.Create(ctx, &storage.ApiToken{
		UserID: 1, TokenHash: hash64ForMain("d"), ExpiresAt: now.Add(-time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatalf("插入第二枚过期行: %v", err)
	}
	list = waitListSize(t, r, 1, 2)
	remain := map[string]bool{}
	for i := range list {
		remain[list[i].TokenHash] = true
	}
	if !remain[hash64ForMain("b")] || !remain[hash64ForMain("c")] || remain[hash64ForMain("d")] {
		t.Fatalf("续清后剩余行异常（期望 b/c，d 已清）: %v", remain)
	}

	// 断言④：ctx 取消即返回（goroutine 退出）
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后清理循环未返回")
	}
}

// hash64ForMain 测试用 64 字符哈希（char 重复 64 次——CHAR(64) 形态；沿 storage 包
// token_repo_test.go hash64 同源形态，main 包侧独立命名避免跨包测试符号）。
func hash64ForMain(char string) string { return strings.Repeat(char, 64) }

// captureStdout 重定向标准输出执行 fn 并捕获其写入内容（os.Pipe 形态——
// parseVersionFlag 的 fmt.Printf 输出断言载体；fn 返回值经返回值透出）。
func captureStdout(t *testing.T, fn func() bool) (string, bool) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建输出管道: %v", err)
	}
	os.Stdout = w
	hit := fn()
	_ = w.Close()
	os.Stdout = old
	var buf strings.Builder
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), hit
}

// TestParseVersionFlag 版本查询参数四断言（发布准备批次——NFR-013 产物元数据锚）：
// ①--version 命中且输出含版本三元组结构 ②-version 单横线等价 ③无参数不命中零输出
// ④未知 flag 静默不命中（ContinueOnError 吞错误——服务既有启动行为零变化）。
func TestParseVersionFlag(t *testing.T) {
	// 断言①：--version 命中，输出含 GRmail 前缀与三元组结构（commit=/built=）
	out, hit := captureStdout(t, func() bool { return parseVersionFlag([]string{"--version"}) })
	if !hit {
		t.Fatal("--version 未命中（期望命中早退）")
	}
	if !strings.Contains(out, "GRmail") || !strings.Contains(out, "commit=") || !strings.Contains(out, "built=") {
		t.Fatalf("版本输出形态缺失三元组结构: %q", out)
	}

	// 断言②：-version 单横线等价命中（flag 包标准语义）
	if _, hit := captureStdout(t, func() bool { return parseVersionFlag([]string{"-version"}) }); !hit {
		t.Fatal("-version 单横线未命中（期望与 --version 等价）")
	}

	// 断言③：无参数不命中且零输出
	out, hit = captureStdout(t, func() bool { return parseVersionFlag(nil) })
	if hit || out != "" {
		t.Fatalf("无参数路径异常（hit=%v output=%q——期望不命中零输出）", hit, out)
	}

	// 断言④：未知 flag 静默不命中（解析错误吞掉返回 false，不 panic 不输出）
	out, hit = captureStdout(t, func() bool { return parseVersionFlag([]string{"--unknown-flag"}) })
	if hit || out != "" {
		t.Fatalf("未知 flag 路径异常（hit=%v output=%q——期望静默不命中）", hit, out)
	}
}

// TestParseHTTPPortFlag HTTP 明文端口参数五断言（HTTP端口参数化批次——FR-015 受限
// 端口环境可达性锚）：①-p=8080 赋值形态与 -p 8080 空格形态等价 ②越界值（0 与 65536）
// 返回错误（值域 1~65535——main 据此退出 2）③无参数返回 0,nil（不覆盖——缺省 80
// 兜底归 main 接线）④-p abc 非数字返回错误（错误归属：调用方明确使用 -p）
// ⑤未知 flag（非 -p 引发）静默返回 0,nil（沿 parseVersionFlag 先例——交由既有启动流程）。
func TestParseHTTPPortFlag(t *testing.T) {
	// 断言①：-p=8080 与 -p 8080 两形态等价解析为 8080
	port, err := parseHTTPPortFlag([]string{"-p=8080"})
	if err != nil || port != 8080 {
		t.Fatalf("-p=8080 解析异常（port=%d err=%v——期望 8080,nil）", port, err)
	}
	port, err = parseHTTPPortFlag([]string{"-p", "18080"})
	if err != nil || port != 18080 {
		t.Fatalf("-p 18080 解析异常（port=%d err=%v——期望 18080,nil）", port, err)
	}

	// 断言②：越界值 0 与 65536 报错（值域 1~65535；合法边界 1 与 65535 通过）
	for _, bad := range []string{"-p=0", "-p=65536"} {
		if _, err := parseHTTPPortFlag([]string{bad}); err == nil {
			t.Fatalf("%s 越界值未报错（期望值域错误）", bad)
		}
	}
	for _, ok := range []string{"-p=1", "-p=65535"} {
		if _, err := parseHTTPPortFlag([]string{ok}); err != nil {
			t.Fatalf("%s 合法边界值报错: %v", ok, err)
		}
	}

	// 断言③：无参数返回 0,nil（未指定不覆盖——缺省 80 兜底由 main 0.6 段承载）
	port, err = parseHTTPPortFlag(nil)
	if err != nil || port != 0 {
		t.Fatalf("无参数路径异常（port=%d err=%v——期望 0,nil）", port, err)
	}

	// 断言④：-p abc 非数字报错（错误归属判定——调用方明确使用 -p，值解析失败上报）
	if _, err := parseHTTPPortFlag([]string{"-p", "abc"}); err == nil {
		t.Fatal("-p abc 非数字值未报错（期望错误上报供 main 退出 2）")
	}

	// 断言⑤：未知 flag 静默返回 0,nil（非 -p 引发的解析失败——沿 parseVersionFlag 先例）
	port, err = parseHTTPPortFlag([]string{"--unknown-flag"})
	if err != nil || port != 0 {
		t.Fatalf("未知 flag 路径异常（port=%d err=%v——期望静默 0,nil）", port, err)
	}
}
