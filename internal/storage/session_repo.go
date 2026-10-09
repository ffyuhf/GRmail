// Package storage 追加 U8 会话域仓储：SessionRepo/UserRepo/LoginAttemptRepo 接口族与 SQLite 实现。
// 依据：模块接口契约 v1.4.0 2.1 节（SessionRepo/UserRepo 签名沿用 v1.3.1；LoginAttemptRepo 为
// v1.4.0 增量——Q4-B 裁决 2026-09-19 04:48:48）；数据库表结构 v1.1.0 3.1/3.6/3.10 节
// （users/sessions 表 U1 迁移已建，csrf_token 列与 login_attempts 表 00002 迁移已建）；
// 系统架构总览 v1.0.1 第四章（storage 不 import 业务模块与 protocol/*）。
// 覆盖条目：FR-001（TC-001 三入口之三 Webmail 格存储层）、OWASP 会话指南
// （Session ID Properties——库存哈希 cookie 载原文；Session Expiration——双超时字段）。
// 修改历史：
//
//	2026-09-19 05:05:00 | 新建 | U8 Web 会话与登录（计划书步骤 3，G2 批准 2026-09-19 04:56:31）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 域类型（数据模型 v1.1.0 3.1/3.6/3.10） ─────────────────────────

// SubjectType 会话主体类型（sessions.subject_type CHECK 枚举：双主体登录）
type SubjectType string

// 会话主体两态（与迁移 DDL CHECK 约束一致）
const (
	SubjectTypeAdmin   SubjectType = "admin"   // 管理员（users.id 引用）
	SubjectTypeMailbox SubjectType = "mailbox" // 邮箱账号（mailboxes.id 引用）
)

// Session 自研会话域模型（表 sessions；Q7 + OWASP）。
// ID 为 session ID 原文的 SHA-256 hex（CHAR(64)）——cookie 携带原文、库存哈希
// （OWASP Session ID Properties：存储库防泄露）；CSRFToken 为会话绑定 CSRF token
// （Q5-B：登录成功生成、特权重建时刷新；空串=未绑定映射 NULL）。
type Session struct {
	ID                string      // hex(SHA-256(sessionID 原文))
	SubjectType       SubjectType // admin | mailbox
	SubjectID         int64       // users.id 或 mailboxes.id
	IP                string      // 绑定检测（OWASP 异常告警）
	UserAgent         string      // 同上
	CSRFToken         string      // 会话绑定 CSRF token（Q5-B）
	CreatedAt         time.Time
	LastSeenAt        time.Time // 空闲超时判定（服务端强制）
	AbsoluteExpiresAt time.Time // 绝对超时（OWASP 双超时）
}

// User 管理员账户域模型（表 users；单管理员模型 REQ-001，argon2id PHC 串 Q12）
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// LoginAttempt 登录尝试记录行（表 login_attempts；Q4-B DB 持久化限流数据源）
type LoginAttempt struct {
	ID          int64
	SubjectKey  string // 主体标识（管理员用户名或邮箱地址，小写规范化）
	IP          string
	Success     bool
	AttemptedAt time.Time
}

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrSessionNotFound 会话不存在或已失效（Find 无行 / sql.ErrNoRows 映射）
	ErrSessionNotFound = errors.New("session: 会话不存在")
	// ErrUserNotFound 管理员用户不存在（FindByName 无行）
	ErrUserNotFound = errors.New("user: 用户不存在")
)

// ───────────────────────── 接口族（契约 v1.4.0 2.1 逐字） ─────────────────────────

// SessionRepo 会话仓储（Q7 自研）
type SessionRepo interface {
	// Create 创建会话（s 全字段须就绪；空 CSRFToken 映射 NULL）。
	Create(ctx context.Context, s *Session) error
	// Find 按 ID 哈希查会话（idHash=hex(SHA-256(sessionID 原文))）；无行返回 ErrSessionNotFound。
	Find(ctx context.Context, idHash string) (*Session, error)
	// Touch 刷新会话活跃痕迹（last_seen/ip/ua，空闲超时判定输入）。
	Touch(ctx context.Context, idHash, ip, ua string, now time.Time) error
	// Delete 删除会话（登出/重建前置）。
	Delete(ctx context.Context, idHash string) error
	// PurgeExpired 清理绝对超时已过会话，返回清理行数（过期清理任务）。
	PurgeExpired(ctx context.Context, now time.Time) (int, error)
}

// UserRepo 管理员仓储
type UserRepo interface {
	// EnsureAdmin 确保管理员存在（用户名已存在时幂等忽略——Setup 向导 U10 调用）。
	EnsureAdmin(ctx context.Context, u *User) error
	// FindByName 按用户名查管理员；无行返回 ErrUserNotFound。
	FindByName(ctx context.Context, name string) (*User, error)
	// FindByID 按 ID 查管理员（B-S批 F10——既定裁决 2026-10-08 22:09:57「维持全域
	// +加固」：Bearer 合成会话前二次校验管理员身份的消费位；无行返回 ErrUserNotFound）。
	FindByID(ctx context.Context, id int64) (*User, error)
	// UpdatePassword 更新管理员密码哈希。
	UpdatePassword(ctx context.Context, id int64, hash string) error

	// ── 管理员主体增强批次增量（admin 2FA 通道——沿 MailboxRepo v1.20.0 先例；
	// 迁移 00011 三库；admin 无强制标记语义不设 SetTwoFactorRequired） ──

	// GetTwoFactor 读取管理员 2FA 绑定态（绑定完成判定 TwoFactorState.Bound）。
	GetTwoFactor(ctx context.Context, userID int64) (*TwoFactorState, error)
	// SetTwoFactorSecret 发起绑定：覆盖式写 pending TOTP 密钥（SQL 内联清 totp_last_step
	// ——新密钥重放基线重置；绑定确认前 Bound() 保持 false，登录判定不受影响）。
	SetTwoFactorSecret(ctx context.Context, userID int64, secret string) error
	// ConfirmTwoFactor 绑定确认：TOTP 验证通过后写恢复码哈希集（自此 Bound()=true，
	// /login 登录二步生效）。恢复码明文仅生成时一次性展示，本接口只落哈希态。
	ConfirmTwoFactor(ctx context.Context, userID int64, codeHashes []string) error
	// MarkTOTPStep 记录最近一次 TOTP 验证成功的时间步（rfc6238 §5.2 同窗重放拒绝 MUST）。
	MarkTOTPStep(ctx context.Context, userID, step int64) error
	// ConsumeRecoveryCode 消耗一枚恢复码（事务读→匹配→移除→写回；false=未命中拒绝）。
	ConsumeRecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error)
	// ClearTwoFactor 停用 2FA：清空密钥/恢复码/重放步（调用方须先完成第二因子验证）。
	ClearTwoFactor(ctx context.Context, userID int64) error
}

// LoginAttemptRepo 登录尝试仓储（v1.4.0 增量，Q4-B：DB 持久化失败计数限流）
type LoginAttemptRepo interface {
	// RecordAttempt 记录一次登录尝试（成功/失败均记录——失败计数与成功清零的数据源）。
	RecordAttempt(ctx context.Context, subjectKey, ip string, success bool, at time.Time) error
	// CountRecentFails 统计主体在 since 之后的失败次数（滑动窗口锁定判定输入）。
	CountRecentFails(ctx context.Context, subjectKey string, since time.Time) (int64, error)
	// ClearSubject 清空主体全部尝试记录（登录成功即清零）。
	ClearSubject(ctx context.Context, subjectKey string) error
	// PurgeOld 清理 olderThan 之前的记录，返回清理行数（维护任务）。
	PurgeOld(ctx context.Context, olderThan time.Time) (int, error)
}

// compile-time 接口实现校验（签名偏离契约 v1.4.0 时在此处编译失败）
var (
	_ SessionRepo      = (*SQLiteSessionRepo)(nil)
	_ UserRepo         = (*SQLiteUserRepo)(nil)
	_ LoginAttemptRepo = (*SQLiteLoginAttemptRepo)(nil)
)

// ───────────────────────── SQLite 实现 ─────────────────────────

// SQLiteSessionRepo SessionRepo 的 SQLite 实现
type SQLiteSessionRepo struct {
	q *dbgen.Queries
}

// NewSQLiteSessionRepo 构造会话仓储。
// 参数：db 已迁移就绪的数据库连接；返回：仓储实例。
func NewSQLiteSessionRepo(db *sql.DB) *SQLiteSessionRepo {
	return &SQLiteSessionRepo{q: dbgen.New(db)}
}

// Create 创建会话（幂等键=ID 哈希主键；时间字段统一 RFC3339 UTC 文本）。
func (r *SQLiteSessionRepo) Create(ctx context.Context, s *Session) error {
	if _, err := r.q.CreateSession(ctx, dbgen.CreateSessionParams{
		ID:                s.ID,
		SubjectType:       string(s.SubjectType),
		SubjectID:         s.SubjectID,
		Ip:                nullString(s.IP),
		UserAgent:         nullString(s.UserAgent),
		CsrfToken:         nullString(s.CSRFToken),
		CreatedAt:         formatTimestamp(s.CreatedAt),
		LastSeenAt:        formatTimestamp(s.LastSeenAt),
		AbsoluteExpiresAt: formatTimestamp(s.AbsoluteExpiresAt),
	}); err != nil {
		return fmt.Errorf("插入会话: %w", err)
	}
	return nil
}

// Find 按 ID 哈希查会话（NULL 列映射空串）。
func (r *SQLiteSessionRepo) Find(ctx context.Context, idHash string) (*Session, error) {
	row, err := r.q.GetSessionByIDHash(ctx, idHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询会话: %w", err)
	}
	created, err := parseTimestamp(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("解析会话 created_at: %w", err)
	}
	lastSeen, err := parseTimestamp(row.LastSeenAt)
	if err != nil {
		return nil, fmt.Errorf("解析会话 last_seen_at: %w", err)
	}
	absExpires, err := parseTimestamp(row.AbsoluteExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("解析会话 absolute_expires_at: %w", err)
	}
	return &Session{
		ID:                row.ID,
		SubjectType:       SubjectType(row.SubjectType),
		SubjectID:         row.SubjectID,
		IP:                row.Ip.String,
		UserAgent:         row.UserAgent.String,
		CSRFToken:         row.CsrfToken.String,
		CreatedAt:         created,
		LastSeenAt:        lastSeen,
		AbsoluteExpiresAt: absExpires,
	}, nil
}

// Touch 刷新活跃痕迹（OWASP：超时管理服务端强制——last_seen 为唯一判定源）。
func (r *SQLiteSessionRepo) Touch(ctx context.Context, idHash, ip, ua string, now time.Time) error {
	if err := r.q.TouchSession(ctx, dbgen.TouchSessionParams{
		LastSeenAt: formatTimestamp(now),
		Ip:         nullString(ip),
		UserAgent:  nullString(ua),
		ID:         idHash,
	}); err != nil {
		return fmt.Errorf("刷新会话: %w", err)
	}
	return nil
}

// Delete 删除会话。
func (r *SQLiteSessionRepo) Delete(ctx context.Context, idHash string) error {
	if err := r.q.DeleteSession(ctx, idHash); err != nil {
		return fmt.Errorf("删除会话: %w", err)
	}
	return nil
}

// PurgeExpired 清理绝对超时会话（数据模型 3.6：idx_sessions_expires 索引主路径）。
func (r *SQLiteSessionRepo) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	n, err := r.q.PurgeExpiredSessions(ctx, formatTimestamp(now))
	if err != nil {
		return 0, fmt.Errorf("清理过期会话: %w", err)
	}
	return int(n), nil
}

// SQLiteUserRepo UserRepo 的 SQLite 实现
type SQLiteUserRepo struct {
	q  *dbgen.Queries
	db *sql.DB // 管理员主体增强批次：ConsumeRecoveryCode 事务承载
}

// NewSQLiteUserRepo 构造管理员仓储。
// 参数：db 已迁移就绪的数据库连接；返回：仓储实例。
func NewSQLiteUserRepo(db *sql.DB) *SQLiteUserRepo {
	return &SQLiteUserRepo{q: dbgen.New(db), db: db}
}

// EnsureAdmin 确保管理员存在（INSERT OR IGNORE 幂等；u.ID/CreatedAt/UpdatedAt 回填尽力语义）。
func (r *SQLiteUserRepo) EnsureAdmin(ctx context.Context, u *User) error {
	now := time.Now().UTC()
	if _, err := r.q.EnsureAdmin(ctx, dbgen.EnsureAdminParams{
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
		CreatedAt:    formatTimestamp(now),
		UpdatedAt:    formatTimestamp(now),
	}); err != nil {
		return fmt.Errorf("确保管理员存在: %w", err)
	}
	return nil
}

// FindByName 按用户名查管理员；无行返回 ErrUserNotFound（登录防枚举语义由上层统一拒绝承载）。
func (r *SQLiteUserRepo) FindByName(ctx context.Context, name string) (*User, error) {
	row, err := r.q.GetUserByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询管理员: %w", err)
	}
	created, err := parseTimestamp(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("解析管理员 created_at: %w", err)
	}
	updated, err := parseTimestamp(row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("解析管理员 updated_at: %w", err)
	}
	return &User{
		ID:           row.ID,
		Username:     row.Username,
		PasswordHash: row.PasswordHash,
		IsAdmin:      row.IsAdmin,
		CreatedAt:    created,
		UpdatedAt:    updated,
	}, nil
}

// FindByID 按 ID 查管理员；无行返回 ErrUserNotFound（B-S批 F10——Bearer 合成会话前
// 二次校验管理员身份消费位；查询 GetUserByID 三库同构）。
func (r *SQLiteUserRepo) FindByID(ctx context.Context, id int64) (*User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询管理员: %w", err)
	}
	created, err := parseTimestamp(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("解析管理员 created_at: %w", err)
	}
	updated, err := parseTimestamp(row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("解析管理员 updated_at: %w", err)
	}
	return &User{
		ID:           row.ID,
		Username:     row.Username,
		PasswordHash: row.PasswordHash,
		IsAdmin:      row.IsAdmin,
		CreatedAt:    created,
		UpdatedAt:    updated,
	}, nil
}

// UpdatePassword 更新管理员密码哈希（特权变化事件——上层须同步重建会话，流程设计第六章第 4 条）。
func (r *SQLiteUserRepo) UpdatePassword(ctx context.Context, id int64, hash string) error {
	if err := r.q.UpdateUserPassword(ctx, dbgen.UpdateUserPasswordParams{
		PasswordHash: hash,
		UpdatedAt:    formatTimestamp(time.Now().UTC()),
		ID:           id,
	}); err != nil {
		return fmt.Errorf("更新管理员密码: %w", err)
	}
	return nil
}

// SQLiteLoginAttemptRepo LoginAttemptRepo 的 SQLite 实现（Q4-B）
type SQLiteLoginAttemptRepo struct {
	q *dbgen.Queries
}

// NewSQLiteLoginAttemptRepo 构造登录尝试仓储。
// 参数：db 已迁移就绪的数据库连接；返回：仓储实例。
func NewSQLiteLoginAttemptRepo(db *sql.DB) *SQLiteLoginAttemptRepo {
	return &SQLiteLoginAttemptRepo{q: dbgen.New(db)}
}

// RecordAttempt 记录登录尝试（成功 true / 失败 false；subjectKey 须已小写规范化）。
func (r *SQLiteLoginAttemptRepo) RecordAttempt(ctx context.Context, subjectKey, ip string, success bool, at time.Time) error {
	if _, err := r.q.RecordLoginAttempt(ctx, dbgen.RecordLoginAttemptParams{
		SubjectKey:  subjectKey,
		Ip:          nullString(ip),
		Success:     boolToInt64(success),
		AttemptedAt: formatTimestamp(at),
	}); err != nil {
		return fmt.Errorf("记录登录尝试: %w", err)
	}
	return nil
}

// CountRecentFails 统计 since 之后的失败次数（成功行不计入）。
func (r *SQLiteLoginAttemptRepo) CountRecentFails(ctx context.Context, subjectKey string, since time.Time) (int64, error) {
	n, err := r.q.CountRecentFailedAttempts(ctx, dbgen.CountRecentFailedAttemptsParams{
		SubjectKey:  subjectKey,
		AttemptedAt: formatTimestamp(since),
	})
	if err != nil {
		return 0, fmt.Errorf("统计登录失败: %w", err)
	}
	return n, nil
}

// ClearSubject 清空主体尝试记录（登录成功清零——窗口计数归位）。
func (r *SQLiteLoginAttemptRepo) ClearSubject(ctx context.Context, subjectKey string) error {
	if err := r.q.ClearLoginAttempts(ctx, subjectKey); err != nil {
		return fmt.Errorf("清空登录尝试: %w", err)
	}
	return nil
}

// PurgeOld 清理 olderThan 之前的记录（维护任务；防止表无限膨胀）。
func (r *SQLiteLoginAttemptRepo) PurgeOld(ctx context.Context, olderThan time.Time) (int, error) {
	n, err := r.q.PurgeOldLoginAttempts(ctx, formatTimestamp(olderThan))
	if err != nil {
		return 0, fmt.Errorf("清理登录尝试: %w", err)
	}
	return int(n), nil
}

// nullString 空串 → NULL（sqlc 可空列 sql.NullString 语义）；否则 Valid 携值。
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// boolToInt64 布尔 → SQLite INTEGER 0/1（数据模型第五章 BOOLEAN 口径）。
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
