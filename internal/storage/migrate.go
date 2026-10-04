// 内嵌数据库迁移执行：goose 版本化（Q5 裁决）。
// 语义：程序启动时自动 Up 至最新（FR-015 全新环境零手工）；三库分目录迁移脚本经
// GRmail/migrations 包内嵌（embed 基准目录约束：声明必须位于脚本同包）。
// 修改历史：
//
//	2026-09-16 04:37:00 | 新建 | U1 工程骨架
//	2026-09-16 04:40:00 | 修正 | embed 声明迁至 migrations 包（基准目录问题）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/pressly/goose/v3"

	"GRmail/migrations"
)

// MigrateUp 执行内嵌迁移至最新版本。
// 参数：ctx 上下文（日志）；db 已建立的连接；driver 数据库驱动名。
// 返回：迁移失败原因（启动即失败，禁止带旧 schema 运行）。
func MigrateUp(ctx context.Context, db *sql.DB, driver string) error {
	logger := slog.Default()
	var (
		fsys    fs.FS
		dir     string
		dialect string
	)
	switch driver {
	case "sqlite", "":
		fsys, dir, dialect = migrations.SQLite, "sqlite", "sqlite3"
	case "mysql":
		fsys, dir, dialect = migrations.MySQL, "mysql", "mysql"
	case "postgres":
		fsys, dir, dialect = migrations.Postgres, "postgres", "postgres"
	default:
		return fmt.Errorf("未知数据库驱动: %q", driver)
	}
	goose.SetBaseFS(fsys)
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("设置迁移方言: %w", err)
	}
	if err := goose.UpContext(ctx, db, dir); err != nil {
		return fmt.Errorf("执行迁移（dir=%s）: %w", dir, err)
	}
	logger.Info("数据库迁移完成", "driver", driver, "dir", dir)
	return nil
}
