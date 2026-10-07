// Package storage 三库方言基础层：驱动标识、约束冲突判定器与 repo 工厂。
// 依据：SRS v1.0.1 FR-014（三库适配）；数据库表结构 v1.1.0 第五章（三库适配口径）；
// U11 计划书 1.5⑥/⑪（错误判定按 driver 绑定分派；沿 NewSQLiteXxxRepo 先例扩展工厂单入口）。
// 覆盖条目：FR-014（TC-014 存储层锚点）。
// 错误码事实来源（编码前 go doc/源码实测，U11 计划书 1.5⑮）：
//   - MySQL：github.com/go-sql-driver/mysql MySQLError.Number（uint16）——1062 唯一/1452 外键
//   - PostgreSQL：github.com/jackc/pgx/v5/pgconn PgError.Code（string）——23505 唯一/23503 外键
//   - SQLite：modernc.org/sqlite *sqlite.Error.Code()——2067/787（U2 修改文档缺陷记录②先例）
//
// 修改历史：
//
//	2026-09-20 05:26:00 | 新增 | U11 三库验收（计划书步骤 4，G2 批准 2026-09-20 05:07:20）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	pmysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"GRmail/internal/config"
)

// 三库驱动标识（config.DatabaseConf.Driver 值域；空值回退 SQLite——storage.Open 同口径）。
const (
	DriverSQLite   = "sqlite"
	DriverMySQL    = "mysql"
	DriverPostgres = "postgres"
)

// ───────────────────────── 约束冲突判定器（1.5⑥） ─────────────────────────

// constraintChecker 方言约束冲突判定器：按 repo 构造期 driver 绑定，
// uniqueViolation/fkViolation 语义三库一致（唯一索引冲突/外键引用冲突）。
type constraintChecker interface {
	uniqueViolation(err error) bool
	fkViolation(err error) bool
}

// newConstraintChecker 按 driver 构造判定器；未知 driver 回退 SQLite（与 Open 兜底同口径）。
func newConstraintChecker(driver string) constraintChecker {
	switch driver {
	case DriverMySQL:
		return mysqlChecker{}
	case DriverPostgres:
		return pgChecker{}
	default:
		return sqliteChecker{}
	}
}

// sqliteChecker SQLite 判定（modernc 错误码 2067/787——沿 U2 既有 isUniqueConstraint 实现）。
type sqliteChecker struct{}

func (sqliteChecker) uniqueViolation(err error) bool { return isUniqueConstraint(err) }
func (sqliteChecker) fkViolation(err error) bool     { return isForeignKeyConstraint(err) }

// mysqlChecker MySQL 判定（MySQLError.Number：1062 ER_DUP_ENTRY/1452 ER_NO_REFERENCED_ROW_2）。
type mysqlChecker struct{}

func (mysqlChecker) uniqueViolation(err error) bool {
	var me *pmysql.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}

func (mysqlChecker) fkViolation(err error) bool {
	var me *pmysql.MySQLError
	return errors.As(err, &me) && me.Number == 1452
}

// pgChecker PostgreSQL 判定（PgError.Code SQLSTATE：23505 unique_violation/23503 foreign_key_violation）。
type pgChecker struct{}

func (pgChecker) uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (pgChecker) fkViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503"
}

// ───────────────────────── repo 工厂单入口（1.5⑪） ─────────────────────────

// RepoSet 一次装配的三库 repo 集合（cmd 装配层消费；全部为契约 2.1 接口——按 driver 返回对应实现）。
type RepoSet struct {
	Mailboxes     MailboxRepo
	Folders       FolderRepo
	Messages      MessageRepo
	Queue         QueueRepo
	Sessions      SessionRepo
	Users         UserRepo
	LoginAttempts LoginAttemptRepo
	SieveScripts  SieveScriptRepo // v1.8.0（U12）：FR-011 邮箱级 Sieve 脚本
}

// NewRepoSet 按 config.DatabaseConf.Driver 装配全套 repo（空值/未知回退 SQLite——Open 同口径）。
// 参数：conf 数据库配置（driver 判定来源；连接已由调用方经 Open 建立）。返回：repo 集合。
func NewRepoSet(conf config.DatabaseConf, db *sql.DB) (*RepoSet, error) {
	switch conf.Driver {
	case DriverMySQL:
		return newMySQLRepoSet(db)
	case DriverPostgres:
		return newPostgresRepoSet(db)
	case DriverSQLite, "":
		return &RepoSet{
			Mailboxes:     NewSQLiteMailboxRepo(db),
			Folders:       NewSQLiteFolderRepo(db),
			Messages:      NewSQLiteMessageRepo(db),
			Queue:         NewSQLiteQueueRepo(db),
			Sessions:      NewSQLiteSessionRepo(db),
			Users:         NewSQLiteUserRepo(db),
			LoginAttempts: NewSQLiteLoginAttemptRepo(db),
			SieveScripts:  NewSQLiteSieveScriptRepo(db),
		}, nil
	default:
		return nil, fmt.Errorf("未知数据库驱动: %q（可选 sqlite/mysql/postgres）", conf.Driver)
	}
}

// 域工厂（main 装配层与单测按需单取；语义同 NewRepoSet 的分派）。

// NewMailboxRepoFor 按驱动构造邮箱仓储。
func NewMailboxRepoFor(driver string, db *sql.DB) MailboxRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLMailboxRepo(db)
	case DriverPostgres:
		return NewPostgresMailboxRepo(db)
	default:
		return NewSQLiteMailboxRepo(db)
	}
}

// NewFolderRepoFor 按驱动构造文件夹仓储。
func NewFolderRepoFor(driver string, db *sql.DB) FolderRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLFolderRepo(db)
	case DriverPostgres:
		return NewPostgresFolderRepo(db)
	default:
		return NewSQLiteFolderRepo(db)
	}
}

// NewMessageRepoFor 按驱动构造邮件仓储。
func NewMessageRepoFor(driver string, db *sql.DB) MessageRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLMessageRepo(db)
	case DriverPostgres:
		return NewPostgresMessageRepo(db)
	default:
		return NewSQLiteMessageRepo(db)
	}
}

// QueueStore QueueRepo 四契约方法 + StoreSubmission 提交入队事务（mail 域窄接口
// submissionStore/queueClaimStore 的超集；SQLite 具体类型既有形态的接口化——U11 装配分派；
// 队列防丢信收口批 F4/F5 增补 QueueClaimOps 三方法——装配层经本超集分派至 worker）。
type QueueStore interface {
	QueueRepo
	QueueClaimOps
	StoreSubmission(ctx context.Context, txmeta *SubmissionMeta) error
}

// NewQueueRepoFor 按驱动构造投递队列仓储。
func NewQueueRepoFor(driver string, db *sql.DB) QueueRepo {
	return NewQueueStoreFor(driver, db)
}

// NewQueueStoreFor 按驱动构造队列仓储超集（含 StoreSubmission——main 装配消费）。
func NewQueueStoreFor(driver string, db *sql.DB) QueueStore {
	switch driver {
	case DriverMySQL:
		return NewMySQLQueueRepo(db)
	case DriverPostgres:
		return NewPostgresQueueRepo(db)
	default:
		return NewSQLiteQueueRepo(db)
	}
}

// NewSessionRepoFor 按驱动构造会话仓储。
func NewSessionRepoFor(driver string, db *sql.DB) SessionRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLSessionRepo(db)
	case DriverPostgres:
		return NewPostgresSessionRepo(db)
	default:
		return NewSQLiteSessionRepo(db)
	}
}

// NewUserRepoFor 按驱动构造管理员仓储。
func NewUserRepoFor(driver string, db *sql.DB) UserRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLUserRepo(db)
	case DriverPostgres:
		return NewPostgresUserRepo(db)
	default:
		return NewSQLiteUserRepo(db)
	}
}

// NewLoginAttemptRepoFor 按驱动构造登录尝试仓储。
func NewLoginAttemptRepoFor(driver string, db *sql.DB) LoginAttemptRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLLoginAttemptRepo(db)
	case DriverPostgres:
		return NewPostgresLoginAttemptRepo(db)
	default:
		return NewSQLiteLoginAttemptRepo(db)
	}
}

// NewSieveScriptRepoFor 按驱动构造 Sieve 脚本仓储（v1.8.0 增量，U12——FR-011）。
func NewSieveScriptRepoFor(driver string, db *sql.DB) SieveScriptRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLSieveScriptRepo(db)
	case DriverPostgres:
		return NewPostgresSieveScriptRepo(db)
	default:
		return NewSQLiteSieveScriptRepo(db)
	}
}

// NewTokenRepoFor 按 driver 构造 Token 仓储（U14——契约 v1.10.0 2.1；空值/未知回退 SQLite）。
func NewTokenRepoFor(driver string, db *sql.DB) TokenRepo {
	switch driver {
	case DriverMySQL:
		return NewMySQLTokenRepo(db)
	case DriverPostgres:
		return NewPostgresTokenRepo(db)
	default:
		return NewSQLiteTokenRepo(db)
	}
}

// newMySQLRepoSet MySQL 全套装配。
func newMySQLRepoSet(db *sql.DB) (*RepoSet, error) {
	return &RepoSet{
		Mailboxes:     NewMySQLMailboxRepo(db),
		Folders:       NewMySQLFolderRepo(db),
		Messages:      NewMySQLMessageRepo(db),
		Queue:         NewMySQLQueueRepo(db),
		Sessions:      NewMySQLSessionRepo(db),
		Users:         NewMySQLUserRepo(db),
		LoginAttempts: NewMySQLLoginAttemptRepo(db),
		SieveScripts:  NewMySQLSieveScriptRepo(db),
	}, nil
}

// newPostgresRepoSet PostgreSQL 全套装配。
func newPostgresRepoSet(db *sql.DB) (*RepoSet, error) {
	return &RepoSet{
		Mailboxes:     NewPostgresMailboxRepo(db),
		Folders:       NewPostgresFolderRepo(db),
		Messages:      NewPostgresMessageRepo(db),
		Queue:         NewPostgresQueueRepo(db),
		Sessions:      NewPostgresSessionRepo(db),
		Users:         NewPostgresUserRepo(db),
		LoginAttempts: NewPostgresLoginAttemptRepo(db),
		SieveScripts:  NewPostgresSieveScriptRepo(db),
	}, nil
}

// withTxCompat 通用事务包装（数据模型第五章「storage 层统一 WithTx(ctx, fn) 封装」的
// 简约承载：MySQL/PG repo 事务路径共用；SQLite 沿既有 BeginTx 直用形态零改动）。
// 参数：ctx 上下文；db 连接；fn 事务体（传入事务）。返回：事务失败原因（含回滚语义）。
func withTxCompat(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 提交后回滚为无害空操作
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交事务: %w", err)
	}
	return nil
}
