// Package storage token 域 PostgreSQL 实现（U14；契约 v1.10.0 2.1 签名逐字）。
// 依据：数据库表结构 v1.2.0 第五章；U14 计划书 1.5②（唯一冲突经 constraintChecker——23505）。
// 覆盖条目：FR-014（TC-014 token 域 PostgreSQL 格）；FR-013（3.8 Token 管理子项）。
// 修改历史：
//
//	2026-09-24 02:44:00 | 新增 | U14 API Token 管理（计划书步骤 3）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/postgres"
)

// 编译期断言：契约 v1.10.0 2.1 接口实现锁定（PostgreSQL 形态）。
var _ TokenRepo = (*PostgresTokenRepo)(nil)

// PostgresTokenRepo TokenRepo 的 PostgreSQL 实现。
type PostgresTokenRepo struct {
	q  *dbgen.Queries
	ck constraintChecker
}

// NewPostgresTokenRepo 构造 Token 仓储（PostgreSQL）。
func NewPostgresTokenRepo(db *sql.DB) *PostgresTokenRepo {
	return &PostgresTokenRepo{q: dbgen.New(db), ck: newConstraintChecker(DriverPostgres)}
}

// Create 创建 Token 行（token_hash 唯一冲突→ErrTokenExists）。
func (r *PostgresTokenRepo) Create(ctx context.Context, t *ApiToken) error {
	err := r.q.CreateApiToken(ctx, dbgen.CreateApiTokenParams{
		UserID:    t.UserID,
		TokenHash: t.TokenHash,
		ExpiresAt: nullZeroTime(t.ExpiresAt),
		ClientIp:  nullString(t.ClientIP),
		CreatedAt: t.CreatedAt,
	})
	if r.ck.uniqueViolation(err) {
		return ErrTokenExists
	}
	return fmt.Errorf("插入 Token: %w", err) //nolint:wrapcheck // err 为 nil 时返回 nil
}

// FindValidByHash 按哈希查有效 Token（过期判定在 SQL——NULL=永久语义）。
func (r *PostgresTokenRepo) FindValidByHash(ctx context.Context, hash string, now time.Time) (*ApiToken, error) {
	row, err := r.q.FindValidApiTokenByHash(ctx, dbgen.FindValidApiTokenByHashParams{
		TokenHash: hash,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询 Token: %w", err)
	}
	return apiTokenFromRowTime(row.ID, row.UserID, row.TokenHash, row.ExpiresAt, row.ClientIp, row.LastUsedAt, row.CreatedAt), nil
}

// ListByUser 按持有主体列 Token（created_at DESC）。
func (r *PostgresTokenRepo) ListByUser(ctx context.Context, userID int64) ([]*ApiToken, error) {
	rows, err := r.q.ListApiTokensByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("列出 Token: %w", err)
	}
	out := make([]*ApiToken, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiTokenFromRowTime(row.ID, row.UserID, row.TokenHash, row.ExpiresAt, row.ClientIp, row.LastUsedAt, row.CreatedAt))
	}
	return out, nil
}

// Delete 双条件撤销。
func (r *PostgresTokenRepo) Delete(ctx context.Context, id, userID int64) error {
	if err := r.q.DeleteApiToken(ctx, dbgen.DeleteApiTokenParams{ID: id, UserID: userID}); err != nil {
		return fmt.Errorf("撤销 Token: %w", err)
	}
	return nil
}

// PurgeExpired 清理已过期行。
func (r *PostgresTokenRepo) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := r.q.PurgeExpiredApiTokens(ctx, sql.NullTime{Time: now, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("清理过期 Token: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// TouchLastUsed 刷新最后使用时刻（尽力语义归调用方）。
func (r *PostgresTokenRepo) TouchLastUsed(ctx context.Context, id int64, at time.Time) error {
	if err := r.q.TouchApiTokenLastUsed(ctx, dbgen.TouchApiTokenLastUsedParams{
		LastUsedAt: sql.NullTime{Time: at, Valid: true},
		ID:         id,
	}); err != nil {
		return fmt.Errorf("刷新 Token 使用时刻: %w", err)
	}
	return nil
}

// apiTokenFromRowTime MySQL/PG 行 → 域模型（时间原生 time.Time；可空列 NullTime/NullString）。
func apiTokenFromRowTime(id, userID int64, hash string, expiresAt sql.NullTime, clientIP sql.NullString, lastUsedAt sql.NullTime, createdAt time.Time) *ApiToken {
	t := &ApiToken{ID: id, UserID: userID, TokenHash: hash, ClientIP: clientIP.String, CreatedAt: createdAt}
	if expiresAt.Valid {
		t.ExpiresAt = expiresAt.Time
	}
	if lastUsedAt.Valid {
		t.LastUsedAt = lastUsedAt.Time
	}
	return t
}
