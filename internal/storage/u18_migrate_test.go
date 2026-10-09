// U18 迁移 00005 Down 往返测试（U16 登记项⑤收口，Q2-A 裁决——三库自动测试）：
// Up→列存在→Down（回退一版）→列不存在→再 Up→列恢复；既有表数据行无损
// （body_cache 为缓存维度——Down 丢弃无损语义，数据模型 v1.3.0 1.3 第 6 条）。
// MySQL/PostgreSQL 沿 U11 集成测试环境标签形态（netDialProbe 探活+Skip——
// compose 环境就绪时执行）；SQLite 引擎 DROP COLUMN 需 ≥3.35（modernc 驱动
// 版本核对注记归修改文档——1.5⑥ 口径）。
// SRS 条目：FR-014（3.9）迁移一致性关联；TC-014 迁移链证据。
// 修改历史：
//
//	2026-09-26 16:15:00 | 新建 | U18 登记项收尾（计划书步骤 5/1.5⑥，G2 批准 2026-09-26 15:25:47）
//	2026-10-07 09:05:00 | 适配 | 迁移 00012 队列防丢信收口批（末版本演进 00011→00012
//	——Down 步数三→四对齐断言面；断言面保持不变；G2 批准 2026-10-07 01:03:52）
package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"

	"GRmail/internal/config"
	"GRmail/migrations"
)

// u18MigrateDownOne 回退一版迁移（goose DownContext 单步——00005→00004）。
// 参数：ctx 上下文；db 连接；driver 驱动名（fsys/dialect 分派沿 MigrateUp）。
// 返回：回退失败原因。
func u18MigrateDownOne(ctx context.Context, db *sql.DB, driver string) error {
	var (
		fsys    = migrations.SQLite
		dir     = "sqlite"
		dialect = "sqlite3"
	)
	switch driver {
	case "mysql":
		fsys, dir, dialect = migrations.MySQL, "mysql", "mysql"
	case "postgres":
		fsys, dir, dialect = migrations.Postgres, "postgres", "postgres"
	}
	goose.SetBaseFS(fsys)
	if err := goose.SetDialect(dialect); err != nil {
		return err
	}
	return goose.DownContext(ctx, db, dir) // 单步回退（一版本）
}

// u18ColumnExists 列存在性判定（sqlite=PRAGMA；MySQL/PG=information_schema）。
func u18ColumnExists(ctx context.Context, db *sql.DB, driver, table, column string) (bool, error) {
	var query string
	var args []any
	switch driver {
	case "mysql":
		query = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?"
		args = []any{table, column}
	case "postgres":
		query = "SELECT COUNT(*) FROM information_schema.columns WHERE table_name=$1 AND column_name=$2"
		args = []any{table, column}
	default:
		query = "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?"
		args = []any{table, column}
	}
	var n int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// u18RoundTrip 三库同构往返断言集（Up→列在→Down→列不在+数据无损→再 Up→列恢复）。
func u18RoundTrip(t *testing.T, driver, dsn string) {
	t.Helper()
	ctx := context.Background()
	conf := config.DatabaseConf{Driver: driver, DSN: dsn}
	db, err := Open(ctx, conf)
	if err != nil {
		t.Fatalf("[%s] 连接: %v", driver, err)
	}
	defer func() { _ = db.Close() }()
	if err = MigrateUp(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Up: %v", driver, err)
	}

	// 1. Up 态：body_cache 与 is_answered/is_draft 列存在+预置既有表数据行
	//（RF-J/F-I16：末迁移演进为 00006——Up 态含两标志列）
	has, err := u18ColumnExists(ctx, db, driver, "messages", "body_cache")
	if err != nil || !has {
		t.Fatalf("[%s] Up 后 body_cache 列应存在: has=%v err=%v", driver, has, err)
	}
	hasFlags, err := u18ColumnExists(ctx, db, driver, "mailbox_messages", "is_answered")
	if err != nil || !hasFlags {
		t.Fatalf("[%s] Up 后 is_answered 列应存在（F-I16）: has=%v err=%v", driver, hasFlags, err)
	}
	// 预置 users 行（按方言：PG 驱动不翻译 ? 占位符——$n 形态；is_admin PG 为
	// BOOLEAN 不接受整型字面量——TRUE 形态；预置前清理残留行保证幂等——容器数据卷
	// 跨轮持久场景；本批真库首跑暴露的既有测试方言/幂等缺陷，最小定点修正，归
	// CHANGE5 缺陷修正记录）
	_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE username='u18'")
	u18Place, u18Admin := "?, ?", "1"
	if driver == "postgres" {
		u18Place, u18Admin = "$1, $2", "TRUE"
	}
	if _, err = db.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, is_admin, created_at, updated_at) VALUES ('u18', 'x', "+u18Admin+", "+u18Place+")",
		u18Now(driver), u18Now(driver)); err != nil {
		t.Fatalf("[%s] 预置 users 行: %v", driver, err)
	}

	// 2. Down 六步（00014→00013→00012→00011→00010→00009→00008）：mailboxes 2FA 四列消失+
	// mailbox_keywords/internal_date/ret_full 保持+users 行无损（迁移演进后末版本=00014
	// 〔SCRAM认证批 mailboxes SCRAM 四列〕——六步回退至 v8 对齐断言面；
	// 数据行无损语义不变；沿 00006~00013 加入时的同一适配先例：既有断言面保持，本批仅
	// 增一步回退）
	if err = u18MigrateDownOne(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Down 00014: %v", driver, err)
	}
	if err = u18MigrateDownOne(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Down 00013: %v", driver, err)
	}
	if err = u18MigrateDownOne(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Down 00012: %v", driver, err)
	}
	if err = u18MigrateDownOne(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Down 00011: %v", driver, err)
	}
	if err = u18MigrateDownOne(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Down 00010: %v", driver, err)
	}
	if err = u18MigrateDownOne(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 迁移 Down 00009: %v", driver, err)
	}
	for _, col := range []string{"totp_secret", "recovery_codes", "two_factor_required", "totp_last_step"} {
		has, err = u18ColumnExists(ctx, db, driver, "mailboxes", col)
		if err != nil || has {
			t.Fatalf("[%s] Down 后 mailboxes.%s 应不存在（U24）: has=%v err=%v", driver, col, has, err)
		}
	}
	has, err = u18ColumnExists(ctx, db, driver, "mailbox_keywords", "keyword")
	if err != nil || !has {
		t.Fatalf("[%s] Down 单步后 mailbox_keywords 表应保持（v8 态——非末迁移不回退）: has=%v err=%v", driver, has, err)
	}
	has, err = u18ColumnExists(ctx, db, driver, "mailbox_messages", "internal_date")
	if err != nil || !has {
		t.Fatalf("[%s] Down 单步后 internal_date 列应保持（v7 态）: has=%v err=%v", driver, has, err)
	}
	has, err = u18ColumnExists(ctx, db, driver, "delivery_queue", "ret_full")
	if err != nil || !has {
		t.Fatalf("[%s] Down 单步后 ret_full 列应保持（v7 态）: has=%v err=%v", driver, has, err)
	}
	var userCount int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username='u18'").Scan(&userCount); err != nil || userCount != 1 {
		t.Fatalf("[%s] Down 后既有数据行应无损: count=%d err=%v", driver, userCount, err)
	}

	// 3. 再 Up：末迁移列组恢复（升级路径可重放）
	if err = MigrateUp(ctx, db, driver); err != nil {
		t.Fatalf("[%s] 再 Up: %v", driver, err)
	}
	for _, col := range []string{"totp_secret", "two_factor_required", "totp_last_step"} {
		has, err = u18ColumnExists(ctx, db, driver, "mailboxes", col)
		if err != nil || !has {
			t.Fatalf("[%s] 再 Up 后 mailboxes.%s 应恢复（U24）: has=%v err=%v", driver, col, has, err)
		}
	}
	has, err = u18ColumnExists(ctx, db, driver, "mailbox_keywords", "keyword")
	if err != nil || !has {
		t.Fatalf("[%s] 再 Up 后 mailbox_keywords 表应保持: has=%v err=%v", driver, has, err)
	}
}

// u18Now 各库时间字面量（SQLite RFC3339 文本；MySQL/PG 原生函数——列型差异收敛）。
func u18Now(driver string) string {
	switch driver {
	case "mysql":
		return "NOW(6)"
	case "postgres":
		return "NOW()"
	default:
		return "2026-09-26T16:15:00Z"
	}
}

// TestU18SqliteMigrationRoundTrip SQLite 往返（真跑——TC-014 迁移链证据）。
// DSN 为纯路径形态（2026-10-03 测试库落位缺陷修复批次——去自带 "file:" 前缀，
// 前缀与参数构造统一归 sqliteDSN 承载；G2 批准 2026-10-03 21:29:59）。
func TestU18SqliteMigrationRoundTrip(t *testing.T) {
	u18RoundTrip(t, "sqlite", filepath.Join(t.TempDir(), "u18rt.db"))
}

// TestU18MySQLMigrationRoundTrip MySQL 往返（compose 环境就绪时执行；否则跳过）。
func TestU18MySQLMigrationRoundTrip(t *testing.T) {
	if _, err := netDialProbe("127.0.0.1:13306"); err != nil {
		t.Skip("MySQL 容器未就绪——跳过（沿 U11 环境标签形态；实测实录归修改文档）")
	}
	u18RoundTrip(t, "mysql", u11MySQLDSN)
}

// TestU18PostgresMigrationRoundTrip PostgreSQL 往返（compose 环境就绪时执行；否则跳过）。
func TestU18PostgresMigrationRoundTrip(t *testing.T) {
	if _, err := netDialProbe("127.0.0.1:15432"); err != nil {
		t.Skip("PostgreSQL 容器未就绪——跳过（沿 U11 环境标签形态）")
	}
	u18RoundTrip(t, "postgres", u11PGDSN)
}
