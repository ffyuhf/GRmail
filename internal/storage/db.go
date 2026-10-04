// Package storage 实现三库连接、内嵌迁移与 CAS 字节存储。
// 依据：FR-014（SQLite 内置默认 / MySQL / PostgreSQL）、Q5（sqlc/goose/Bob）、
// Q13（BlobStore CAS）、数据库表结构 v1.0.0 第五章（三库适配口径）。
// 修改历史：
//
//	2026-09-16 04:36:00 | 新建 | U1 工程骨架
//	2026-09-27 06:17:00 | 扩展 | U21 可观测性增强：三驱动经 registerInstrumentedDriver
//	装饰注册（sqldebug.go——SQL 慢查询/全量 debug 输出；Q2-A repo 层零侵入）
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 3；阶段三"可以有"档）
//	2026-10-03 21:33:00 | 修正 | 测试库落位缺陷修复批次：sqliteDSN 输入 "file:" 前缀
//	剥离——带前缀输入经 filepath.Abs 被视作相对路径名拼上工作目录，产出含 "file:"
//	路径段的 DSN 致包目录再生垃圾库（发布准备_删除登记#1 复现实证；驱动四形态
//	落位矩阵实测后最小修复——输出形态保持；G2 批准 2026-10-03 21:29:59）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql" // MySQL 驱动（U21 具名——装饰器 base 实例；注册副作用保留）
	"github.com/jackc/pgx/v5/stdlib"       // PostgreSQL 驱动（U21 具名——同上）
	"modernc.org/sqlite"                   // SQLite 驱动（纯 Go，Q14 裁决；U21 具名——同上）

	"GRmail/internal/config"
)

// Open 建立数据库连接（三库方言差异收敛点：DSN 组装与连接池参数）。
// 参数：ctx 根上下文（日志）；conf 数据库配置（driver + dsn）。
// 返回：标准库连接池；driver 非法或连接失败时返回 error。
func Open(ctx context.Context, conf config.DatabaseConf) (*sql.DB, error) {
	logger := slog.Default()
	var (
		db  *sql.DB
		err error
	)
	switch conf.Driver {
	case "sqlite", "": // 空值回退内置默认（SQLite 文件态）
		dsn := sqliteDSN(conf.DSN)
		// 首启目录保障：数据库文件父目录不存在将导致 open 失败（冒烟实测缺陷修正）
		if dir := filepath.Dir(conf.DSN); dir != "" && dir != "." {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				return nil, fmt.Errorf("创建数据库目录: %w", mkErr)
			}
		}
		// U21：观测装饰驱动接线（Q2-A——repo 层零侵入，全部 SQL 经装饰层拦截）
		drvName, regErr := registerInstrumentedDriver("sqlite", &sqlite.Driver{})
		if regErr != nil {
			return nil, fmt.Errorf("注册 SQLite 观测驱动: %w", regErr)
		}
		db, err = sql.Open(drvName, dsn)
		if err != nil {
			return nil, fmt.Errorf("打开 SQLite: %w", err)
		}
		// SQLite 单写者模型：收敛连接数避免写锁竞争；WAL 提升并发读
		db.SetMaxOpenConns(8)
		db.SetMaxIdleConns(8)
	case "mysql":
		// U21：观测装饰驱动接线（同 sqlite case）
		drvName, regErr := registerInstrumentedDriver("mysql", &mysql.MySQLDriver{})
		if regErr != nil {
			return nil, fmt.Errorf("注册 MySQL 观测驱动: %w", regErr)
		}
		db, err = sql.Open(drvName, conf.DSN)
		if err != nil {
			return nil, fmt.Errorf("打开 MySQL: %w", err)
		}
		db.SetMaxOpenConns(16)
		db.SetMaxIdleConns(8)
	case "postgres":
		// U21：观测装饰驱动接线（同 sqlite case）
		drvName, regErr := registerInstrumentedDriver("pgx", &stdlib.Driver{})
		if regErr != nil {
			return nil, fmt.Errorf("注册 PostgreSQL 观测驱动: %w", regErr)
		}
		db, err = sql.Open(drvName, conf.DSN)
		if err != nil {
			return nil, fmt.Errorf("打开 PostgreSQL: %w", err)
		}
		db.SetMaxOpenConns(16)
		db.SetMaxIdleConns(8)
	default:
		return nil, fmt.Errorf("未知数据库驱动: %q（可选 sqlite/mysql/postgres）", conf.Driver)
	}
	db.SetConnMaxIdleTime(5 * time.Minute)

	// 连通性探活：失败即启动失败（fail-fast，避免带病运行）
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("数据库连通性校验失败（driver=%s）: %w", conf.Driver, err)
	}
	logger.Info("数据库连接就绪", "driver", conf.Driver)
	return db, nil
}

// sqliteDSN 组装 SQLite DSN：启用 WAL、busy_timeout、外键（数据模型文档第五章约定）。
// 输入容忍已携带 "file:" URI 前缀的路径（集成测试形态）——先行剥离：否则
// filepath.Abs 会把 "file:/tmp/..." 整串当作相对路径名拼上进程工作目录，产出
// 含 "file:" 路径段的 DSN，驱动按字面路径在包目录下创建库文件（落位缺陷根因）。
func sqliteDSN(path string) string {
	if path == "" {
		path = "data/grmail.db"
	}
	path = strings.TrimPrefix(path, "file:")
	// 目标目录确保存在（嵌入部署首启场景）
	abs, err := filepath.Abs(path)
	if err == nil {
		path = filepath.ToSlash(abs) // Windows 兼容：URI 形式 DSN 使用正斜杠
	}
	return "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
}
