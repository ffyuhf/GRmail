// Package storage session/user/login_attempt 域 MySQL 实现（U11 Q2-A；契约 2.1 签名零变更）。
// 依据：数据库表结构 v1.1.0 第五章；U11 计划书 1.5⑧（时间 time.Time 直传；bool 直传）。
// 覆盖条目：FR-014（TC-014 session 域 MySQL 格）。
// 修改历史：
//
//	2026-09-20 05:38:00 | 新增 | U11 三库验收（计划书步骤 4）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/mysql"
)

// 编译期断言：契约 2.1 接口实现锁定（MySQL 形态）。
var (
	_ SessionRepo      = (*MySQLSessionRepo)(nil)
	_ UserRepo         = (*MySQLUserRepo)(nil)
	_ LoginAttemptRepo = (*MySQLLoginAttemptRepo)(nil)
)

// MySQLSessionRepo SessionRepo 的 MySQL 实现。
type MySQLSessionRepo struct {
	q *dbgen.Queries
}

// NewMySQLSessionRepo 构造会话仓储（MySQL）。
func NewMySQLSessionRepo(db *sql.DB) *MySQLSessionRepo {
	return &MySQLSessionRepo{q: dbgen.New(db)}
}

// Create 创建会话（幂等键=ID 哈希主键；空 CSRFToken 映射 NULL）。
func (r *MySQLSessionRepo) Create(ctx context.Context, s *Session) error {
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

// Find 按 ID 哈希查会话（NULL 列映射空串）。
func (r *MySQLSessionRepo) Find(ctx context.Context, idHash string) (*Session, error) {
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

// Touch 刷新会话活跃痕迹（OWASP 双超时服务端强制判定源）。
func (r *MySQLSessionRepo) Touch(ctx context.Context, idHash, ip, ua string, now time.Time) error {
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
func (r *MySQLSessionRepo) Delete(ctx context.Context, idHash string) error {
	if err := r.q.DeleteSession(ctx, idHash); err != nil {
		return fmt.Errorf("删除会话: %w", err)
	}
	return nil
}

// PurgeExpired 清理绝对超时会话。
func (r *MySQLSessionRepo) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	n, err := r.q.PurgeExpiredSessions(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("清理过期会话: %w", err)
	}
	return int(n), nil
}

// MySQLUserRepo UserRepo 的 MySQL 实现。
type MySQLUserRepo struct {
	q  *dbgen.Queries
	db *sql.DB // 管理员主体增强批次：ConsumeRecoveryCode 事务承载
}

// NewMySQLUserRepo 构造管理员仓储（MySQL）。
func NewMySQLUserRepo(db *sql.DB) *MySQLUserRepo {
	return &MySQLUserRepo{q: dbgen.New(db), db: db}
}

// EnsureAdmin 确保管理员存在（INSERT IGNORE 幂等——1.5③ MySQL 形态）。
func (r *MySQLUserRepo) EnsureAdmin(ctx context.Context, u *User) error {
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

// FindByName 按用户名查管理员；无行返回 ErrUserNotFound。
func (r *MySQLUserRepo) FindByName(ctx context.Context, name string) (*User, error) {
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
func (r *MySQLUserRepo) FindByID(ctx context.Context, id int64) (*User, error) {
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

// UpdatePassword 更新管理员密码哈希（特权变化——上层同步重建会话）。
func (r *MySQLUserRepo) UpdatePassword(ctx context.Context, id int64, hash string) error {
	if err := r.q.UpdateUserPassword(ctx, dbgen.UpdateUserPasswordParams{
		PasswordHash: hash,
		UpdatedAt:    time.Now().UTC(),
		ID:           id,
	}); err != nil {
		return fmt.Errorf("更新管理员密码: %w", err)
	}
	return nil
}

// MySQLLoginAttemptRepo LoginAttemptRepo 的 MySQL 实现。
type MySQLLoginAttemptRepo struct {
	q *dbgen.Queries
}

// NewMySQLLoginAttemptRepo 构造登录尝试仓储（MySQL）。
func NewMySQLLoginAttemptRepo(db *sql.DB) *MySQLLoginAttemptRepo {
	return &MySQLLoginAttemptRepo{q: dbgen.New(db)}
}

// RecordAttempt 记录一次登录尝试（success bool 直传——TINYINT(1) 映射）。
func (r *MySQLLoginAttemptRepo) RecordAttempt(ctx context.Context, subjectKey, ip string, success bool, at time.Time) error {
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

// CountRecentFails 统计 since 之后的失败次数（滑动窗口）。
func (r *MySQLLoginAttemptRepo) CountRecentFails(ctx context.Context, subjectKey string, since time.Time) (int64, error) {
	n, err := r.q.CountRecentFailedAttempts(ctx, dbgen.CountRecentFailedAttemptsParams{
		SubjectKey:  subjectKey,
		AttemptedAt: since,
	})
	if err != nil {
		return 0, fmt.Errorf("统计登录失败: %w", err)
	}
	return n, nil
}

// ClearSubject 清空主体尝试记录（登录成功清零）。
func (r *MySQLLoginAttemptRepo) ClearSubject(ctx context.Context, subjectKey string) error {
	if err := r.q.ClearLoginAttempts(ctx, subjectKey); err != nil {
		return fmt.Errorf("清空登录尝试: %w", err)
	}
	return nil
}

// PurgeOld 清理 olderThan 之前的记录（防膨胀）。
func (r *MySQLLoginAttemptRepo) PurgeOld(ctx context.Context, olderThan time.Time) (int, error) {
	n, err := r.q.PurgeOldLoginAttempts(ctx, olderThan)
	if err != nil {
		return 0, fmt.Errorf("清理登录尝试: %w", err)
	}
	return int(n), nil
}
