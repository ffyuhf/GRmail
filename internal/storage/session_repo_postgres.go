// Package storage session/user/login_attempt 域 PostgreSQL 实现（U11 Q2-A；契约 2.1 签名零变更）。
// 依据：数据库表结构 v1.1.0 第五章；U11 计划书 1.5③（EnsureAdmin ON CONFLICT DO NOTHING）。
// 覆盖条目：FR-014（TC-014 session 域 PostgreSQL 格）。
// 修改历史：
//
//	2026-09-20 05:39:00 | 新增 | U11 三库验收（计划书步骤 4）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/postgres"
)

// 编译期断言：契约 2.1 接口实现锁定（PostgreSQL 形态）。
var (
	_ SessionRepo      = (*PostgresSessionRepo)(nil)
	_ UserRepo         = (*PostgresUserRepo)(nil)
	_ LoginAttemptRepo = (*PostgresLoginAttemptRepo)(nil)
)

// PostgresSessionRepo SessionRepo 的 PostgreSQL 实现。
type PostgresSessionRepo struct {
	q *dbgen.Queries
}

// NewPostgresSessionRepo 构造会话仓储（PostgreSQL）。
func NewPostgresSessionRepo(db *sql.DB) *PostgresSessionRepo {
	return &PostgresSessionRepo{q: dbgen.New(db)}
}

// Create 创建会话。
func (r *PostgresSessionRepo) Create(ctx context.Context, s *Session) error {
	if _, err := r.q.CreateSession(ctx, dbgen.CreateSessionParams{
		ID:                s.ID,
		SubjectType:       string(s.SubjectType),
		SubjectID:         s.SubjectID,
		Ip:                nullString(s.IP),
		UserAgent:         nullString(s.UserAgent),
		CsrfToken:         nullString(s.CSRFToken),
		CreatedAt:         s.CreatedAt,
		LastSeenAt:        s.LastSeenAt,
		AbsoluteExpiresAt: s.AbsoluteExpiresAt,
	}); err != nil {
		return fmt.Errorf("插入会话: %w", err)
	}
	return nil
}

// Find 按 ID 哈希查会话。
func (r *PostgresSessionRepo) Find(ctx context.Context, idHash string) (*Session, error) {
	row, err := r.q.GetSessionByIDHash(ctx, idHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询会话: %w", err)
	}
	return &Session{
		ID:                row.ID,
		SubjectType:       SubjectType(row.SubjectType),
		SubjectID:         row.SubjectID,
		IP:                row.Ip.String,
		UserAgent:         row.UserAgent.String,
		CSRFToken:         row.CsrfToken.String,
		CreatedAt:         row.CreatedAt,
		LastSeenAt:        row.LastSeenAt,
		AbsoluteExpiresAt: row.AbsoluteExpiresAt,
	}, nil
}

// Touch 刷新会话活跃痕迹。
func (r *PostgresSessionRepo) Touch(ctx context.Context, idHash, ip, ua string, now time.Time) error {
	if err := r.q.TouchSession(ctx, dbgen.TouchSessionParams{
		LastSeenAt: now,
		Ip:         nullString(ip),
		UserAgent:  nullString(ua),
		ID:         idHash,
	}); err != nil {
		return fmt.Errorf("刷新会话: %w", err)
	}
	return nil
}

// Delete 删除会话。
func (r *PostgresSessionRepo) Delete(ctx context.Context, idHash string) error {
	if err := r.q.DeleteSession(ctx, idHash); err != nil {
		return fmt.Errorf("删除会话: %w", err)
	}
	return nil
}

// PurgeExpired 清理绝对超时会话。
func (r *PostgresSessionRepo) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	n, err := r.q.PurgeExpiredSessions(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("清理过期会话: %w", err)
	}
	return int(n), nil
}

// PostgresUserRepo UserRepo 的 PostgreSQL 实现。
type PostgresUserRepo struct {
	q  *dbgen.Queries
	db *sql.DB // 管理员主体增强批次：ConsumeRecoveryCode 事务承载
}

// NewPostgresUserRepo 构造管理员仓储（PostgreSQL）。
func NewPostgresUserRepo(db *sql.DB) *PostgresUserRepo {
	return &PostgresUserRepo{q: dbgen.New(db), db: db}
}

// EnsureAdmin 确保管理员存在（ON CONFLICT DO NOTHING 幂等——1.5③ PG 形态）。
func (r *PostgresUserRepo) EnsureAdmin(ctx context.Context, u *User) error {
	now := time.Now().UTC()
	if _, err := r.q.EnsureAdmin(ctx, dbgen.EnsureAdminParams{
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		return fmt.Errorf("确保管理员存在: %w", err)
	}
	return nil
}

// FindByName 按用户名查管理员。
func (r *PostgresUserRepo) FindByName(ctx context.Context, name string) (*User, error) {
	row, err := r.q.GetUserByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询管理员: %w", err)
	}
	return &User{
		ID:           row.ID,
		Username:     row.Username,
		PasswordHash: row.PasswordHash,
		IsAdmin:      row.IsAdmin,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

// FindByID 按 ID 查管理员；无行返回 ErrUserNotFound（B-S批 F10——Bearer 合成会话
// 前二次校验管理员身份消费位）。
func (r *PostgresUserRepo) FindByID(ctx context.Context, id int64) (*User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询管理员: %w", err)
	}
	return &User{
		ID:           row.ID,
		Username:     row.Username,
		PasswordHash: row.PasswordHash,
		IsAdmin:      row.IsAdmin,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

// UpdatePassword 更新管理员密码哈希。
func (r *PostgresUserRepo) UpdatePassword(ctx context.Context, id int64, hash string) error {
	if err := r.q.UpdateUserPassword(ctx, dbgen.UpdateUserPasswordParams{
		PasswordHash: hash,
		UpdatedAt:    time.Now().UTC(),
		ID:           id,
	}); err != nil {
		return fmt.Errorf("更新管理员密码: %w", err)
	}
	return nil
}

// PostgresLoginAttemptRepo LoginAttemptRepo 的 PostgreSQL 实现。
type PostgresLoginAttemptRepo struct {
	q *dbgen.Queries
}

// NewPostgresLoginAttemptRepo 构造登录尝试仓储（PostgreSQL）。
func NewPostgresLoginAttemptRepo(db *sql.DB) *PostgresLoginAttemptRepo {
	return &PostgresLoginAttemptRepo{q: dbgen.New(db)}
}

// RecordAttempt 记录一次登录尝试。
func (r *PostgresLoginAttemptRepo) RecordAttempt(ctx context.Context, subjectKey, ip string, success bool, at time.Time) error {
	if _, err := r.q.RecordLoginAttempt(ctx, dbgen.RecordLoginAttemptParams{
		SubjectKey:  subjectKey,
		Ip:          nullString(ip),
		Success:     success,
		AttemptedAt: at,
	}); err != nil {
		return fmt.Errorf("记录登录尝试: %w", err)
	}
	return nil
}

// CountRecentFails 统计 since 之后的失败次数。
func (r *PostgresLoginAttemptRepo) CountRecentFails(ctx context.Context, subjectKey string, since time.Time) (int64, error) {
	n, err := r.q.CountRecentFailedAttempts(ctx, dbgen.CountRecentFailedAttemptsParams{
		SubjectKey:  subjectKey,
		AttemptedAt: since,
	})
	if err != nil {
		return 0, fmt.Errorf("统计登录失败: %w", err)
	}
	return n, nil
}

// ClearSubject 清空主体尝试记录。
func (r *PostgresLoginAttemptRepo) ClearSubject(ctx context.Context, subjectKey string) error {
	if err := r.q.ClearLoginAttempts(ctx, subjectKey); err != nil {
		return fmt.Errorf("清空登录尝试: %w", err)
	}
	return nil
}

// PurgeOld 清理 olderThan 之前的记录。
func (r *PostgresLoginAttemptRepo) PurgeOld(ctx context.Context, olderThan time.Time) (int, error) {
	n, err := r.q.PurgeOldLoginAttempts(ctx, olderThan)
	if err != nil {
		return 0, fmt.Errorf("清理登录尝试: %w", err)
	}
	return int(n), nil
}
