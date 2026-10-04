// Package storage 追加 U12 Sieve 脚本仓储：SieveScriptRepo 接口族与 SQLite 实现。
// 依据：模块接口契约 v1.8.0 2.1 节（v1.8.0 增量——Q1-R1 裁决 2026-09-21 00:30:59：
// R1-A 全自研）；数据库表结构 v1.1.0 第二章 ER 实体 sieve_scripts（迁移 00003 落盘
// 载体——结构零演进；SETACTIVE 互斥单激活由本仓储事务保证：先清后置）。
// 覆盖条目：FR-011（3.6，TC-011 判定②③存储层）；SRS v1.0.1 基线来源 S5-REV-20260918-001。
// 修改历史：
//
//	2026-09-21 00:43:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 3，G2 批准 2026-09-21 00:36:18）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 域类型（数据模型 v1.1.0 第二章 ER 实体） ─────────────────────────

// SieveScript Sieve 脚本域模型（表 sieve_scripts；rfc5804 多脚本+单激活）。
// IsActive 互斥语义由 SetActive 事务承载（先清后置）；PutScript upsert 不改变激活态
// （rfc5804 §2 PUTSCRIPT 语义——激活独立管理）。
type SieveScript struct {
	ID        int64
	MailboxID int64 // 归属邮箱（仅 active 邮箱可登录编辑——FR-011 邮箱用户语义）
	Name      string
	Content   string // rfc5228 脚本源（保存时编译期校验先行——调用方责任）
	IsActive  bool
}

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrSieveScriptNotFound 脚本不存在（GetScript/ListSieve 无行映射）
	ErrSieveScriptNotFound = errors.New("sieve: 脚本不存在")
	// ErrNoActiveScript 无激活脚本（管道逐收件人查询——nil runner 等价的正常态）
	ErrNoActiveScript = errors.New("sieve: 无激活脚本")
)

// ───────────────────────── 接口族（契约 v1.8.0 2.1 逐字） ─────────────────────────

// SieveScriptRepo Sieve 脚本仓储（FR-011；表 sieve_scripts 迁移 00003 落盘——
// 数据模型 v1.1.0 第二章 ER 实体，结构零演进；SETACTIVE 事务内互斥单激活——rfc5804 §2）
type SieveScriptRepo interface {
	// ListScripts 列出邮箱全部脚本（含 is_active 标记，按名排序）。
	ListScripts(ctx context.Context, mailboxID int64) ([]*SieveScript, error)
	// GetScript 按名取单脚本；无行返回 ErrSieveScriptNotFound。
	GetScript(ctx context.Context, mailboxID int64, name string) (*SieveScript, error)
	// PutScript upsert 脚本内容（语法校验由调用方先行——PUTSCRIPT/CHECKSCRIPT/Web 保存；
	// 不改变激活态——rfc5804 §2 PUTSCRIPT 语义）。
	PutScript(ctx context.Context, s *SieveScript) error
	// DeleteScript 删除脚本（激活脚本删除连带清激活——is_active 随行消失）。
	DeleteScript(ctx context.Context, mailboxID int64, name string) error
	// SetActive 事务内互斥单激活（先清旧后置新——rfc5804 §2 SETACTIVE 语义）。
	SetActive(ctx context.Context, mailboxID int64, name string) error
	// GetActiveScript 取激活脚本（管道逐收件人执行位查询）；无激活返回 ErrNoActiveScript。
	GetActiveScript(ctx context.Context, mailboxID int64) (*SieveScript, error)
}

// ───────────────────────── SQLite 实现 ─────────────────────────

// SQLiteSieveScriptRepo SQLite Sieve 脚本仓储（U12；沿 SQLiteXxxRepo 先例）。
type SQLiteSieveScriptRepo struct {
	db *sql.DB
	q  *dbgen.Queries
}

// NewSQLiteSieveScriptRepo 构造 SQLite Sieve 脚本仓储。
// 参数：db 已打开连接（MigrateUp 后）。返回：仓储实例。
func NewSQLiteSieveScriptRepo(db *sql.DB) *SQLiteSieveScriptRepo {
	return &SQLiteSieveScriptRepo{db: db, q: dbgen.New(db)}
}

// 编译期断言：契约 v1.8.0 2.1 接口实现锁定。
var _ SieveScriptRepo = (*SQLiteSieveScriptRepo)(nil)

// ListScripts 列出邮箱全部脚本（契约 v1.8.0；ORDER BY name）。
func (r *SQLiteSieveScriptRepo) ListScripts(ctx context.Context, mailboxID int64) ([]*SieveScript, error) {
	rows, err := r.q.ListSieveScripts(ctx, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("sieve 脚本列举: %w", err)
	}
	out := make([]*SieveScript, 0, len(rows))
	for i := range rows {
		out = append(out, sieveScriptFromRow(rows[i].ID, rows[i].MailboxID, rows[i].Name, rows[i].Content, rows[i].IsActive))
	}
	return out, nil
}

// GetScript 按名取单脚本（契约 v1.8.0）；无行返回 ErrSieveScriptNotFound。
func (r *SQLiteSieveScriptRepo) GetScript(ctx context.Context, mailboxID int64, name string) (*SieveScript, error) {
	row, err := r.q.GetSieveScript(ctx, dbgen.GetSieveScriptParams{MailboxID: mailboxID, Name: name})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSieveScriptNotFound
		}
		return nil, fmt.Errorf("sieve 脚本查询: %w", err)
	}
	return sieveScriptFromRow(row.ID, row.MailboxID, row.Name, row.Content, row.IsActive), nil
}

// PutScript upsert 脚本（契约 v1.8.0；ON CONFLICT(mailbox_id,name) 更新 content，
// 激活态保持——rfc5804 §2 PUTSCRIPT 不触碰激活）。
func (r *SQLiteSieveScriptRepo) PutScript(ctx context.Context, s *SieveScript) error {
	if err := r.q.UpsertSieveScript(ctx, dbgen.UpsertSieveScriptParams{
		MailboxID: s.MailboxID, Name: s.Name, Content: s.Content,
	}); err != nil {
		return fmt.Errorf("sieve 脚本保存: %w", err)
	}
	return nil
}

// DeleteScript 删除脚本（契约 v1.8.0；激活脚本删除连带清激活——行删除即语义达成）。
func (r *SQLiteSieveScriptRepo) DeleteScript(ctx context.Context, mailboxID int64, name string) error {
	if err := r.q.DeleteSieveScript(ctx, dbgen.DeleteSieveScriptParams{MailboxID: mailboxID, Name: name}); err != nil {
		return fmt.Errorf("sieve 脚本删除: %w", err)
	}
	return nil
}

// SetActive 互斥单激活（契约 v1.8.0；事务内先清后置——崩溃安全：全清或全置，
// 不出现双激活悬挂态；目标名不存在时置零行=激活落空，返回 ErrSieveScriptNotFound）。
func (r *SQLiteSieveScriptRepo) SetActive(ctx context.Context, mailboxID int64, name string) error {
	// 取消激活哨兵（managesieve SETACTIVE "" 经哨兵名承载「清空且不置新」语义；
	// 原实现清空后置新 0 行→NotFound→事务回滚连清空一并丢失——取消从未持久化，
	// RFC规范修正 RF-D 测试扩展首次单独暴露，缺陷修正 2026-09-29 02:52）
	if name == "\x00none" {
		return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
			if err := r.q.WithTx(tx).ClearSieveActive(ctx, mailboxID); err != nil {
				return fmt.Errorf("清空激活: %w", err)
			}
			return nil
		})
	}
	return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
		q := r.q.WithTx(tx)
		if err := q.ClearSieveActive(ctx, mailboxID); err != nil {
			return fmt.Errorf("清旧激活: %w", err)
		}
		res, err := q.ActivateSieveScript(ctx, dbgen.ActivateSieveScriptParams{MailboxID: mailboxID, Name: name})
		if err != nil {
			return fmt.Errorf("置新激活: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrSieveScriptNotFound
		}
		return nil
	})
}

// GetActiveScript 取激活脚本（契约 v1.8.0）；无激活返回 ErrNoActiveScript
// （管道调用方按无脚本直达 INBOX 处理——计划书 1.5①）。
func (r *SQLiteSieveScriptRepo) GetActiveScript(ctx context.Context, mailboxID int64) (*SieveScript, error) {
	row, err := r.q.GetActiveSieveScript(ctx, mailboxID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoActiveScript
		}
		return nil, fmt.Errorf("sieve 激活脚本查询: %w", err)
	}
	return sieveScriptFromRow(row.ID, row.MailboxID, row.Name, row.Content, row.IsActive), nil
}

// sieveScriptFromRow SQLite 行→域模型（is_active INTEGER 0/1→bool）。
func sieveScriptFromRow(id, mailboxID int64, name, content string, isActive int64) *SieveScript {
	return &SieveScript{ID: id, MailboxID: mailboxID, Name: name, Content: content, IsActive: isActive != 0}
}
