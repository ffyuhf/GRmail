// Package storage 追加 U12 Sieve 脚本仓储 MySQL 实现（沿 U11 MySQLXxxRepo 先例；
// 本表无时间列——零时间适配负担，IsActive TINYINT(1) sqlc 直映射 bool）。
// 依据：契约 v1.8.0 2.1；U12 计划书 1.5⑧（三库落盘）与 2.3（For 工厂分派）。
// 修改历史：
//
//	2026-09-21 00:44:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 3）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	dbgen "GRmail/internal/storage/dbgen/mysql"
)

// MySQLSieveScriptRepo MySQL Sieve 脚本仓储。
type MySQLSieveScriptRepo struct {
	db *sql.DB
	q  *dbgen.Queries
}

// NewMySQLSieveScriptRepo 构造 MySQL Sieve 脚本仓储。
func NewMySQLSieveScriptRepo(db *sql.DB) *MySQLSieveScriptRepo {
	return &MySQLSieveScriptRepo{db: db, q: dbgen.New(db)}
}

var _ SieveScriptRepo = (*MySQLSieveScriptRepo)(nil)

// ListScripts 列出邮箱全部脚本（契约 v1.8.0）。
func (r *MySQLSieveScriptRepo) ListScripts(ctx context.Context, mailboxID int64) ([]*SieveScript, error) {
	rows, err := r.q.ListSieveScripts(ctx, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("sieve 脚本列举: %w", err)
	}
	out := make([]*SieveScript, 0, len(rows))
	for i := range rows {
		out = append(out, &SieveScript{
			ID: rows[i].ID, MailboxID: rows[i].MailboxID, Name: rows[i].Name,
			Content: rows[i].Content, IsActive: rows[i].IsActive,
		})
	}
	return out, nil
}

// GetScript 按名取单脚本；无行返回 ErrSieveScriptNotFound。
func (r *MySQLSieveScriptRepo) GetScript(ctx context.Context, mailboxID int64, name string) (*SieveScript, error) {
	row, err := r.q.GetSieveScript(ctx, dbgen.GetSieveScriptParams{MailboxID: mailboxID, Name: name})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSieveScriptNotFound
		}
		return nil, fmt.Errorf("sieve 脚本查询: %w", err)
	}
	return &SieveScript{ID: row.ID, MailboxID: row.MailboxID, Name: row.Name, Content: row.Content, IsActive: row.IsActive}, nil
}

// PutScript upsert 脚本（ON DUPLICATE KEY UPDATE content——激活态保持）。
func (r *MySQLSieveScriptRepo) PutScript(ctx context.Context, s *SieveScript) error {
	if err := r.q.UpsertSieveScript(ctx, dbgen.UpsertSieveScriptParams{
		MailboxID: s.MailboxID, Name: s.Name, Content: s.Content,
	}); err != nil {
		return fmt.Errorf("sieve 脚本保存: %w", err)
	}
	return nil
}

// DeleteScript 删除脚本（激活脚本删除连带清激活）。
func (r *MySQLSieveScriptRepo) DeleteScript(ctx context.Context, mailboxID int64, name string) error {
	if err := r.q.DeleteSieveScript(ctx, dbgen.DeleteSieveScriptParams{MailboxID: mailboxID, Name: name}); err != nil {
		return fmt.Errorf("sieve 脚本删除: %w", err)
	}
	return nil
}

// SetActive 互斥单激活（事务内先清后置）。
func (r *MySQLSieveScriptRepo) SetActive(ctx context.Context, mailboxID int64, name string) error {
	// 取消激活哨兵（同 sqlite 版缺陷修正——清空且不置新；2026-09-29 02:52）
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

// GetActiveScript 取激活脚本；无激活返回 ErrNoActiveScript。
func (r *MySQLSieveScriptRepo) GetActiveScript(ctx context.Context, mailboxID int64) (*SieveScript, error) {
	row, err := r.q.GetActiveSieveScript(ctx, mailboxID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoActiveScript
		}
		return nil, fmt.Errorf("sieve 激活脚本查询: %w", err)
	}
	return &SieveScript{ID: row.ID, MailboxID: row.MailboxID, Name: row.Name, Content: row.Content, IsActive: row.IsActive}, nil
}
