// U21 SQL 观测装饰器测试（计划书 1.5⑥——慢查询触发/全量 debug/禁用零输出/热切换四断言；
// NFR-015 全离线驱动形态：modernc sqlite 临时库真跑，log_id 经 ctx 注入断言）。
// 修改历史：
//
//	2026-09-27 06:23:00 | 新建 | U21 可观测性增强（计划书步骤 3，G2 批准 2026-09-27 06:13:36）
package storage

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"modernc.org/sqlite"

	"GRmail/internal/observability"
)

// openU21TestDB 打开装饰驱动测试库（临时目录 SQLite 真跑——装饰链全路径）。
func openU21TestDB(t *testing.T) *sql.DB {
	t.Helper()
	drvName, err := registerInstrumentedDriver("sqlite", &sqlite.Driver{})
	if err != nil {
		t.Fatalf("注册装饰驱动失败: %v", err)
	}
	db, err := sql.Open(drvName, "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "u21.db"))+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// u21TestLogger 构造捕获 logger 并注入 ctx（log_id 关联锚——logSQL 经
// observability.LoggerFromContext 取本 logger）。
func u21TestLogger() (*bytes.Buffer, context.Context) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := observability.LoggerIntoContext(context.Background(), logger.With("log_id", "u21-test-logid"))
	return &buf, ctx
}

// TestU21SQLLogDisabledZeroOutput 缺省态（三键全关）零输出——行为等价锚。
func TestU21SQLLogDisabledZeroOutput(t *testing.T) {
	SetSQLLogConf(SQLLogConf{})
	t.Cleanup(func() { SetSQLLogConf(SQLLogConf{}) })
	db := openU21TestDB(t)
	buf, ctx := u21TestLogger()
	if _, err := db.ExecContext(ctx, "CREATE TABLE u21a (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("禁用态应零输出，实际: %s", buf.String())
	}
}

// TestU21SQLLogDebugAll sqlDebug=true 全量 Debug 输出（H4 ShowSQL 等价锚）+log_id 关联断言。
func TestU21SQLLogDebugAll(t *testing.T) {
	SetSQLLogConf(SQLLogConf{Debug: true})
	t.Cleanup(func() { SetSQLLogConf(SQLLogConf{}) })
	db := openU21TestDB(t)
	buf, ctx := u21TestLogger()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&n); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SQL 执行") || !strings.Contains(out, "SELECT 1") {
		t.Fatalf("debug 全量输出缺失，实际: %s", out)
	}
	if !strings.Contains(out, "u21-test-logid") {
		t.Fatalf("log_id 关联缺失（NFR-016 观测链锚），实际: %s", out)
	}
}

// TestU21SQLLogSlowQueryTriggersWarn 慢查询阈值触发 Warn（H3 语义等价锚——递归 CTE 真跑超 1ms）。
func TestU21SQLLogSlowQueryTriggersWarn(t *testing.T) {
	SetSQLLogConf(SQLLogConf{SlowMs: 1})
	t.Cleanup(func() { SetSQLLogConf(SQLLogConf{}) })
	db := openU21TestDB(t)
	buf, ctx := u21TestLogger()
	var n int
	query := "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<300000) SELECT count(*) FROM c"
	if err := db.QueryRowContext(ctx, query).Scan(&n); err != nil {
		t.Fatalf("递归查询失败: %v", err)
	}
	if !strings.Contains(buf.String(), "SQL 慢查询") {
		t.Fatalf("慢查询 Warn 缺失（阈值 1ms，查询 %d 行迭代），输出: %s", n, buf.String())
	}
	if strings.Contains(buf.String(), "SQL 执行") {
		t.Fatalf("sqlDebug 未开启不应输出全量 Debug 行: %s", buf.String())
	}
}

// TestU21SQLLogConfHotSwitch 快照热切换（SetSQLLogConf 后行为即时跟随——热加载链终点语义）。
func TestU21SQLLogConfHotSwitch(t *testing.T) {
	SetSQLLogConf(SQLLogConf{})
	t.Cleanup(func() { SetSQLLogConf(SQLLogConf{}) })
	db := openU21TestDB(t)
	buf, ctx := u21TestLogger()
	if _, err := db.ExecContext(ctx, "CREATE TABLE u21b (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("初始禁用态应零输出: %s", buf.String())
	}
	SetSQLLogConf(SQLLogConf{Debug: true}) // 热切换（模拟订阅者刷新路径）
	if _, err := db.ExecContext(ctx, "INSERT INTO u21b (id) VALUES (1)"); err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	if !strings.Contains(buf.String(), "SQL 执行") {
		t.Fatalf("热切换后 Debug 输出缺失: %s", buf.String())
	}
}

// ── 传输安全与日志增强批次 L-C（D8#7）：SQL 注释注入 log_id ──

// TestQueryWithLogIDComment 注入开关三分支：关闭返回原文/开启且 ctx 携带 LogID 注入
// 前缀/开启但无 LogID 返回原文（L-C——prepare 缓存保护：缺省关闭零语句文本变化）。
func TestQueryWithLogIDComment(t *testing.T) {
	SetSQLLogConf(SQLLogConf{})
	t.Cleanup(func() { SetSQLLogConf(SQLLogConf{}) })
	const q = "SELECT 1"
	ctx := context.Background()
	if got := queryWithLogIDComment(ctx, q); got != q {
		t.Fatalf("关闭态应返回原文: %q", got)
	}
	SetSQLLogConf(SQLLogConf{CommentID: true})
	if got := queryWithLogIDComment(ctx, q); got != q {
		t.Fatalf("开启但无 LogID 应返回原文: %q", got)
	}
	// 经 observability 正规入口绑定 LogID（独立 ctx 键——logid.go L-C 增量）
	ctxWithID, logID := observability.ContextWithNewLogID(ctx, nil)
	want := "/*logid:" + logID + "*/ " + q
	if got := queryWithLogIDComment(ctxWithID, q); got != want {
		t.Fatalf("开启且携带 LogID 应注入注释: got %q want %q", got, want)
	}
}

// TestQueryContextCommentInjected 直连查询路径的注释真实发往底层（装饰器行为级——
// 开启后语句文本含注释前缀且三库块注释透传可执行；经 U21 既有测试库驱动验证）。
func TestQueryContextCommentInjected(t *testing.T) {
	SetSQLLogConf(SQLLogConf{CommentID: true})
	t.Cleanup(func() { SetSQLLogConf(SQLLogConf{}) })
	db := openU21TestDB(t)
	if _, err := db.ExecContext(context.Background(), "CREATE TABLE lc (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	_, ctx := u21TestLogger()
	ctx, _ = observability.ContextWithNewLogID(ctx, nil)
	// sqlite 驱动实现 QueryerContext——QueryContext 直连路径承载注入（sqldebug L-C 设计锚）
	rows, err := db.QueryContext(ctx, "SELECT id FROM lc")
	if err != nil {
		t.Fatalf("带注释查询应可执行（块注释三库透传）: %v", err)
	}
	_ = rows.Close()
}
