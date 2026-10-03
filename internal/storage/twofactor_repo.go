// Package storage 追加 2FA 仓储：MailboxRepo 2FA 方法族 SQLite 实现+三库共享辅助（U24）。
// 依据：模块接口契约 v1.20.0 2.1（MailboxRepo 七方法增量）；数据库表结构 v1.7.0 3.2
// （mailboxes 四增列——迁移 00009）；rfc6238 §4（TOTP=HOTP(K,T)，X=30s/T0=0）/
// §5.2 L343-347（同窗重放拒绝 MUST）；SRS v1.1.0 FR-018（TC-027/TC-028 存储层锚点）。
// 覆盖条目：FR-018（应具备）。
// 实现取舍：S4-W 三裁决 A/A/A（2026-10-01 16:44:56）——pending 密钥列明文（Q3-A）、
// 恢复码 SHA-256 快哈希（Q2-A，沿 token_hash/idHashOf 先例）、重放步承载列（Q1 域外
// rfc6238 MUST 履行）。
// 修改历史：
//
//	2026-10-01 16:50:00 | 新增 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 2FA 共享辅助（三库共用） ─────────────────────────

// marshalRecoveryCodes 恢复码哈希集 → JSON 列值（空集映射 nil——列 NULL，停用态）。
// 参数：hashes 哈希集（非空时序列化为 JSON 数组字符串）。
// 返回：列值（string 或 nil——sqlite interface{} / mysql·pg 由调用方包装）；错误为序列化故障。
func marshalRecoveryCodes(hashes []string) (string, error) {
	if len(hashes) == 0 {
		return "", nil
	}
	b, err := json.Marshal(hashes)
	if err != nil {
		return "", fmt.Errorf("序列化恢复码集: %w", err)
	}
	return string(b), nil
}

// parseRecoveryCodesJSON JSON 列值 → 恢复码哈希集（空串→nil——NULL/未绑定态）。
// 参数：raw 列字符串值。返回：哈希集（nil=无恢复码）；错误为格式损坏。
func parseRecoveryCodesJSON(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return nil, fmt.Errorf("解析恢复码集: %w", err)
	}
	return hashes, nil
}

// ───────────────────────── SQLite 实现（U24） ─────────────────────────

// stringOfAny sqlite interface{} 列值 → string（nil/非 string→空串——NULL 语义）。
func stringOfAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// stepOfAny sqlite interface{} 列值 → int64（nil/非数值→0——NULL/从未验证语义）。
func stepOfAny(v any) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}

// GetTwoFactor 读取 2FA 绑定态（绑定完成判定 TwoFactorState.Bound）。
// 参数：ctx 上下文；mailboxID 邮箱 ID。返回：状态快照；ErrMailboxNotFound 无行。
func (r *SQLiteMailboxRepo) GetTwoFactor(ctx context.Context, mailboxID int64) (*TwoFactorState, error) {
	row, err := r.q.GetTwoFactorByID(ctx, mailboxID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询 2FA 状态: %w", err)
	}
	codes, err := parseRecoveryCodesJSON(stringOfAny(row.RecoveryCodes))
	if err != nil {
		return nil, err
	}
	return &TwoFactorState{
		PendingSecret: stringOfAny(row.TotpSecret),
		CodesHash:     codes,
		Required:      row.TwoFactorRequired,
		LastTOTPStep:  stepOfAny(row.TotpLastStep),
	}, nil
}

// SetTwoFactorSecret 发起绑定（覆盖式写 pending 密钥；SQL 内联清 totp_last_step——
// 新密钥重放基线重置；绑定确认前 Bound() 保持 false，登录判定不受影响）。
func (r *SQLiteMailboxRepo) SetTwoFactorSecret(ctx context.Context, mailboxID int64, secret string) error {
	if err := r.q.SetTwoFactorSecret(ctx, dbgen.SetTwoFactorSecretParams{
		TotpSecret: secret, // 非空由调用方（account 层）保证——生成器恒产非空密钥
		UpdatedAt:  formatTimestamp(time.Now().UTC()),
		ID:         mailboxID,
	}); err != nil {
		return fmt.Errorf("写入 pending TOTP 密钥: %w", err)
	}
	return nil
}

// ConfirmTwoFactor 绑定确认（写恢复码哈希集——自此 Bound()=true 二步生效）。
// 参数：codeHashes 恢复码哈希集（account 层生成明文→SHA-256 后传入，明文零落库）。
func (r *SQLiteMailboxRepo) ConfirmTwoFactor(ctx context.Context, mailboxID int64, codeHashes []string) error {
	codes, err := marshalRecoveryCodes(codeHashes)
	if err != nil {
		return err
	}
	if err := r.q.UpdateRecoveryCodes(ctx, dbgen.UpdateRecoveryCodesParams{
		RecoveryCodes: codes,
		UpdatedAt:     formatTimestamp(time.Now().UTC()),
		ID:            mailboxID,
	}); err != nil {
		return fmt.Errorf("写入恢复码集: %w", err)
	}
	return nil
}

// MarkTOTPStep 记录 TOTP 验证成功步（rfc6238 §5.2 同窗重放拒绝承载——登录二步/
// 绑定确认/停用验证三路径验证成功后统一调用）。
func (r *SQLiteMailboxRepo) MarkTOTPStep(ctx context.Context, mailboxID, step int64) error {
	if err := r.q.MarkTOTPStep(ctx, dbgen.MarkTOTPStepParams{
		TotpLastStep: step,
		UpdatedAt:    formatTimestamp(time.Now().UTC()),
		ID:           mailboxID,
	}); err != nil {
		return fmt.Errorf("记录 TOTP 验证步: %w", err)
	}
	return nil
}

// ConsumeRecoveryCode 消耗一枚恢复码（事务内读→哈希匹配→移除→写回——逐枚一次性
// 语义 TC-028 判定①；未命中返回 false 且零写入，重放即拒绝）。
// 参数：codeHash 待消耗恢复码的 SHA-256 hex。返回：是否命中消耗。
func (r *SQLiteMailboxRepo) ConsumeRecoveryCode(ctx context.Context, mailboxID int64, codeHash string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("开启事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 未命中路径不 Commit——回滚为无害空操作

	qtx := r.q.WithTx(tx)
	row, err := qtx.GetTwoFactorByID(ctx, mailboxID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrMailboxNotFound
	}
	if err != nil {
		return false, fmt.Errorf("查询恢复码集: %w", err)
	}
	hashes, err := parseRecoveryCodesJSON(stringOfAny(row.RecoveryCodes))
	if err != nil {
		return false, err
	}
	idx := -1
	for i, h := range hashes {
		if h == codeHash {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil // 未命中：重放/伪造（TC-028 判定①重放拒绝锚）
	}
	remaining := append(hashes[:idx:idx], hashes[idx+1:]...) // 三索引切片防底层数组污染
	codes, err := marshalRecoveryCodes(remaining)
	if err != nil {
		return false, err
	}
	if err := qtx.UpdateRecoveryCodes(ctx, dbgen.UpdateRecoveryCodesParams{
		RecoveryCodes: codes,
		UpdatedAt:     formatTimestamp(time.Now().UTC()),
		ID:            mailboxID,
	}); err != nil {
		return false, fmt.Errorf("消耗恢复码: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("提交恢复码消耗: %w", err)
	}
	return true, nil
}

// ClearTwoFactor 停用 2FA（三列同清：密钥/恢复码/重放步；强制标记独立保留——
// 停用不改写管理员策略，FR-018 判定④边界）。
func (r *SQLiteMailboxRepo) ClearTwoFactor(ctx context.Context, mailboxID int64) error {
	if err := r.q.ClearTwoFactor(ctx, dbgen.ClearTwoFactorParams{
		UpdatedAt: formatTimestamp(time.Now().UTC()),
		ID:        mailboxID,
	}); err != nil {
		return fmt.Errorf("停用 2FA: %w", err)
	}
	return nil
}

// SetTwoFactorRequired 管理员强制标记增删（TC-028 判定⑤落库锚）。
func (r *SQLiteMailboxRepo) SetTwoFactorRequired(ctx context.Context, mailboxID int64, required bool) error {
	if err := r.q.SetTwoFactorRequired(ctx, dbgen.SetTwoFactorRequiredParams{
		TwoFactorRequired: required,
		UpdatedAt:         formatTimestamp(time.Now().UTC()),
		ID:                mailboxID,
	}); err != nil {
		return fmt.Errorf("设置 2FA 强制标记: %w", err)
	}
	return nil
}

// FindMailboxByID 按 ID 查邮箱（U24——2FA 域地址反查：otpauth label/主体呈现名）。
func (r *SQLiteMailboxRepo) FindMailboxByID(ctx context.Context, id int64) (*Mailbox, error) {
	row, err := r.q.FindMailboxByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询邮箱: %w", err)
	}
	return mailboxFromRow(row.ID, row.LocalPart, row.Domain, row.Address, row.PasswordHash, row.Status, row.CreatedAt, row.UpdatedAt), nil
}
