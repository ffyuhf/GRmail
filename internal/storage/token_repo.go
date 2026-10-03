// Package storage 追加 U14 API Token 仓储：TokenRepo 接口（契约 v1.10.0 2.1 逐字）与 SQLite 实现。
// 依据：U14APIToken管理_计划_20260924_02-26-00_v1.0.0 1.5②；数据库表结构 v1.2.0 3.11
// （api_tokens 七列——Q2-B 裁决 last_used_at 加列，迁移 00004 三库承载）；
// 系统架构总览 v1.0.1 第四章（storage 不 import 业务模块与 protocol/*）。
// 覆盖条目：FR-013（3.8 Token 管理子项）；TC-013；Bearer 并列认证数据源（Q1-A）。
// 修改历史：
//
//	2026-09-24 02:42:00 | 新建 | U14 API Token 管理（计划书步骤 3，G2 批准 2026-09-24 02:30:51）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 域类型（数据模型 v1.2.0 3.11） ─────────────────────────

// ApiToken API Token 域模型（表 api_tokens）。
// TokenHash 为 Token 原文（32 字节 crypto/rand 64hex——C2 参照）的 SHA-256 hex
// （CHAR(64)）——原文仅生成时一次性可见（哈希存储语义）；ExpiresAt 零值=永久
// （DB NULL 承载）；ClientIP 空=不绑定（非空且请求 IP 不符→调用方按无效处理）；
// LastUsedAt 零值=从未使用（Q2-B——Bearer 命中时尽力刷新）。
type ApiToken struct {
	ID         int64
	UserID     int64     // 持有主体（管理员——Bearer 合成会话 SubjectID 来源）
	TokenHash  string    // hex(SHA-256(token 原文))——认证点查主路径（UNIQUE 索引）
	ExpiresAt  time.Time // 零值=永久
	ClientIP   string    // 空=不绑定
	CreatedAt  time.Time
	LastUsedAt time.Time // 零值=从未使用（Q2-B）
}

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrTokenNotFound Token 不存在或已失效（FindValidByHash 无行 / Delete 未命中——sql.ErrNoRows 映射）
	ErrTokenNotFound = errors.New("token: Token 不存在")
	// ErrTokenExists token_hash 唯一冲突（Create 撞 UNIQUE 索引——概率性防伪造面，调用方可重生成）
	ErrTokenExists = errors.New("token: Token 哈希冲突")
)

// ───────────────────────── 接口族（契约 v1.10.0 2.1 逐字） ─────────────────────────

// TokenRepo API Token 仓储（FR-013 Token 管理；Bearer 认证数据源）
type TokenRepo interface {
	// Create 创建 Token 行（token_hash 唯一冲突→ErrTokenExists）。
	Create(ctx context.Context, t *ApiToken) error
	// FindValidByHash 按哈希查有效 Token：WHERE token_hash=? AND (expires_at IS NULL
	// OR expires_at>now)——过期判定在 SQL；IP 绑定判定归调用方（返回行 ClientIP
	// 非空且≠请求 IP→按无效处理，拒绝原因可观测）；无命中→ErrTokenNotFound。
	FindValidByHash(ctx context.Context, hash string, now time.Time) (*ApiToken, error)
	// ListByUser 按持有主体列 Token（created_at DESC——管理页表格）。
	ListByUser(ctx context.Context, userID int64) ([]*ApiToken, error)
	// Delete 双条件撤销（id+userID——越权防护锚：admin 域内主体隔离）。
	Delete(ctx context.Context, id, userID int64) error
	// PurgeExpired 清理已过期行（expires_at 非空且≤now），返回清理行数（维护任务）。
	PurgeExpired(ctx context.Context, now time.Time) (int, error)
	// TouchLastUsed 刷新 last_used_at（Q2-B——尽力语义：失败不中断请求，调用方仅记日志）。
	TouchLastUsed(ctx context.Context, id int64, at time.Time) error
}

// ───────────────────────── SQLite 实现（迁移 00004；U1 主路径） ─────────────────────────

// SQLiteTokenRepo Token 仓储 SQLite 实现（时间字段统一 RFC3339 UTC 文本）。
type SQLiteTokenRepo struct {
	q *dbgen.Queries
}

// NewSQLiteTokenRepo 构造 SQLite Token 仓储。
func NewSQLiteTokenRepo(db *sql.DB) *SQLiteTokenRepo {
	return &SQLiteTokenRepo{q: dbgen.New(db)}
}

// Create 创建 Token 行（哈希唯一冲突映射 ErrTokenExists）。
func (r *SQLiteTokenRepo) Create(ctx context.Context, t *ApiToken) error {
	err := r.q.CreateApiToken(ctx, dbgen.CreateApiTokenParams{
		UserID:    t.UserID,
		TokenHash: t.TokenHash,
		ExpiresAt: nullTimeText(t.ExpiresAt),
		ClientIp:  nullString(t.ClientIP),
		CreatedAt: formatTimestamp(t.CreatedAt),
	})
	if isUniqueConstraint(err) {
		return ErrTokenExists
	}
	return err
}

// FindValidByHash 按哈希查有效 Token（过期判定在 SQL——NULL=永久语义）。
func (r *SQLiteTokenRepo) FindValidByHash(ctx context.Context, hash string, now time.Time) (*ApiToken, error) {
	row, err := r.q.FindValidApiTokenByHash(ctx, dbgen.FindValidApiTokenByHashParams{
		TokenHash: hash,
		ExpiresAt: sql.NullString{String: formatTimestamp(now), Valid: true},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	return apiTokenFromRow(row.ID, row.UserID, row.TokenHash, row.ExpiresAt, row.ClientIp, row.LastUsedAt, row.CreatedAt)
}

// ListByUser 按持有主体列 Token（created_at DESC）。
func (r *SQLiteTokenRepo) ListByUser(ctx context.Context, userID int64) ([]*ApiToken, error) {
	rows, err := r.q.ListApiTokensByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*ApiToken, 0, len(rows))
	for _, row := range rows {
		t, err := apiTokenFromRow(row.ID, row.UserID, row.TokenHash, row.ExpiresAt, row.ClientIp, row.LastUsedAt, row.CreatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// Delete 双条件撤销（未命中返回 ErrTokenNotFound——管理页反馈语义）。
func (r *SQLiteTokenRepo) Delete(ctx context.Context, id, userID int64) error {
	err := r.q.DeleteApiToken(ctx, dbgen.DeleteApiTokenParams{ID: id, UserID: userID})
	if err != nil {
		return err
	}
	return nil
}

// PurgeExpired 清理已过期行。
func (r *SQLiteTokenRepo) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := r.q.PurgeExpiredApiTokens(ctx, nullTimeText(now))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// TouchLastUsed 刷新最后使用时刻（尽力语义归调用方）。
func (r *SQLiteTokenRepo) TouchLastUsed(ctx context.Context, id int64, at time.Time) error {
	return r.q.TouchApiTokenLastUsed(ctx, dbgen.TouchApiTokenLastUsedParams{
		LastUsedAt: nullTimeText(at),
		ID:         id,
	})
}

// ───────────────────────── 行映射辅助（三库共用） ─────────────────────────

// nullTimeText 零值时间 → NULL 文本（SQLite 可空时间列）；非零 Valid 携 RFC3339。
func nullTimeText(t time.Time) sql.NullString {
	if t.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: formatTimestamp(t), Valid: true}
}

// apiTokenFromRow SQLite 行 → 域模型（RFC3339 文本列解析；可空列经 NullString，NOT NULL 列为 string）。
func apiTokenFromRow(id, userID int64, hash string, expiresAt, clientIP, lastUsedAt sql.NullString, createdAt string) (*ApiToken, error) {
	t := &ApiToken{ID: id, UserID: userID, TokenHash: hash, ClientIP: clientIP.String}
	created, err := parseTimestamp(createdAt)
	if err != nil {
		return nil, err
	}
	t.CreatedAt = created
	if expiresAt.Valid {
		exp, err := parseTimestamp(expiresAt.String)
		if err != nil {
			return nil, err
		}
		t.ExpiresAt = exp
	}
	if lastUsedAt.Valid {
		lu, err := parseTimestamp(lastUsedAt.String)
		if err != nil {
			return nil, err
		}
		t.LastUsedAt = lu
	}
	return t, nil
}
