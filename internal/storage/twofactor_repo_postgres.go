// Package storage 2FA 仓储 PostgreSQL 实现（U24；契约 v1.20.0 2.1 七方法——语义同
// SQLite 版，差异仅：dbgen 调用包、时间 time.Time 直传、NULL 经 sql.NullString/
// NullInt64 包装；与 MySQL 实现同构——U11 三库收敛原则）。
// 覆盖条目：FR-014（TC-014 account 域 2FA 面 PG 格）+FR-018。
// 修改历史：
//
//	2026-10-01 16:50:00 | 新增 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/postgres"
)

// GetTwoFactor 读取 2FA 绑定态（语义同 SQLite 版——绑定完成判定 Bound()）。
func (r *PostgresMailboxRepo) GetTwoFactor(ctx context.Context, mailboxID int64) (*TwoFactorState, error) {
	row, err := r.q.GetTwoFactorByID(ctx, mailboxID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询 2FA 状态: %w", err)
	}
	codes, err := parseRecoveryCodesJSON(row.RecoveryCodes.String)
	if err != nil {
		return nil, err
	}
	return &TwoFactorState{
		TotpSecret:   row.TotpSecret.String, // F4/C5 改名（原 PendingSecret）
		CodesHash:    codes,
		Required:     row.TwoFactorRequired,
		LastTOTPStep: row.TotpLastStep.Int64,
	}, nil
}

// SetTwoFactorSecret 发起绑定（覆盖式 pending 密钥；重放基线 SQL 内联重置）。
func (r *PostgresMailboxRepo) SetTwoFactorSecret(ctx context.Context, mailboxID int64, secret string) error {
	if err := r.q.SetTwoFactorSecret(ctx, dbgen.SetTwoFactorSecretParams{
		TotpSecret: nullString(secret),
		UpdatedAt:  time.Now().UTC(),
		ID:         mailboxID,
	}); err != nil {
		return fmt.Errorf("写入 pending TOTP 密钥: %w", err)
	}
	return nil
}

// ConfirmTwoFactor 绑定确认（写恢复码哈希集——Bound()=true 生效）。
func (r *PostgresMailboxRepo) ConfirmTwoFactor(ctx context.Context, mailboxID int64, codeHashes []string) error {
	codes, err := marshalRecoveryCodes(codeHashes)
	if err != nil {
		return err
	}
	if err := r.q.UpdateRecoveryCodes(ctx, dbgen.UpdateRecoveryCodesParams{
		RecoveryCodes: nullCodes(codes),
		UpdatedAt:     time.Now().UTC(),
		ID:            mailboxID,
	}); err != nil {
		return fmt.Errorf("写入恢复码集: %w", err)
	}
	return nil
}

// MarkTOTPStep 记录 TOTP 验证成功步（rfc6238 §5.2 同窗重放拒绝承载；安全原子性批
// F3 2026-10-06：SQL 条件 UPDATE 原子守卫——0 行受影响 → ErrTOTPStepConflict，
// 见 sqlite 版注记；条件参数恒 Valid 携值〔严格大于守卫〕）。
func (r *PostgresMailboxRepo) MarkTOTPStep(ctx context.Context, mailboxID, step int64) error {
	res, err := r.q.MarkTOTPStep(ctx, dbgen.MarkTOTPStepParams{
		TotpLastStep:   nullStep(step),
		UpdatedAt:      time.Now().UTC(),
		ID:             mailboxID,
		TotpLastStep_2: sql.NullInt64{Int64: step, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("记录 TOTP 验证步: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("记录 TOTP 验证步（受影响行数）: %w", err)
	}
	if n == 0 {
		return ErrTOTPStepConflict
	}
	return nil
}

// ConsumeRecoveryCode 消耗一枚恢复码（安全原子性批 F4 2026-10-06：CAS 覆写+单轮
// 重试——同码并发恰一成功〔PG READ COMMITTED 读-改-写覆写竞态收口，三库中最易
// 双消耗场景〕；见 sqlite 版注记）。
func (r *PostgresMailboxRepo) ConsumeRecoveryCode(ctx context.Context, mailboxID int64, codeHash string) (bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		consumed, retry, err := r.consumeRecoveryCodeOnce(ctx, mailboxID, codeHash)
		if err != nil {
			return false, err
		}
		if !retry {
			return consumed, nil
		}
	}
	return false, nil
}

// consumeRecoveryCodeOnce 单轮消耗尝试（独立事务；CAS 参数为 sql.NullString 形态）。
func (r *PostgresMailboxRepo) consumeRecoveryCodeOnce(ctx context.Context, mailboxID int64, codeHash string) (consumed, retry bool, err error) {
	tx, txErr := r.db.BeginTx(ctx, nil)
	if txErr != nil {
		return false, false, fmt.Errorf("开启事务: %w", txErr)
	}
	defer func() { _ = tx.Rollback() }()

	qtx := r.q.WithTx(tx)
	row, gerr := qtx.GetTwoFactorByID(ctx, mailboxID)
	if errors.Is(gerr, sql.ErrNoRows) {
		return false, false, ErrMailboxNotFound
	}
	if gerr != nil {
		return false, false, fmt.Errorf("查询恢复码集: %w", gerr)
	}
	hashes, perr := parseRecoveryCodesJSON(row.RecoveryCodes.String)
	if perr != nil {
		return false, false, perr
	}
	idx := -1
	for i, h := range hashes {
		if h == codeHash {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, false, nil // 重放/伪造拒绝（TC-028 判定①）
	}
	remaining := append(hashes[:idx:idx], hashes[idx+1:]...)
	codes, merr := marshalRecoveryCodes(remaining)
	if merr != nil {
		return false, false, merr
	}
	res, uerr := qtx.ConsumeRecoveryCodeCAS(ctx, dbgen.ConsumeRecoveryCodeCASParams{
		RecoveryCodes:   nullCodes(codes),
		UpdatedAt:       time.Now().UTC(),
		ID:              mailboxID,
		RecoveryCodes_2: row.RecoveryCodes, // CAS 条件：本事务读到的旧集原串
	})
	if uerr != nil {
		return false, false, fmt.Errorf("消耗恢复码: %w", uerr)
	}
	n, rerr := res.RowsAffected()
	if rerr != nil {
		return false, false, fmt.Errorf("消耗恢复码（受影响行数）: %w", rerr)
	}
	if n == 0 {
		return false, true, nil // CAS 冲突——由调用方重试
	}
	if cerr := tx.Commit(); cerr != nil {
		return false, false, fmt.Errorf("提交恢复码消耗: %w", cerr)
	}
	return true, false, nil
}

// ClearTwoFactor 停用 2FA（三列同清；强制标记独立保留）。
func (r *PostgresMailboxRepo) ClearTwoFactor(ctx context.Context, mailboxID int64) error {
	if err := r.q.ClearTwoFactor(ctx, dbgen.ClearTwoFactorParams{
		UpdatedAt: time.Now().UTC(),
		ID:        mailboxID,
	}); err != nil {
		return fmt.Errorf("停用 2FA: %w", err)
	}
	return nil
}

// SetTwoFactorRequired 管理员强制标记增删（TC-028 判定⑤落库锚）。
func (r *PostgresMailboxRepo) SetTwoFactorRequired(ctx context.Context, mailboxID int64, required bool) error {
	if err := r.q.SetTwoFactorRequired(ctx, dbgen.SetTwoFactorRequiredParams{
		TwoFactorRequired: required,
		UpdatedAt:         time.Now().UTC(),
		ID:                mailboxID,
	}); err != nil {
		return fmt.Errorf("设置 2FA 强制标记: %w", err)
	}
	return nil
}

// FindMailboxByID 按 ID 查邮箱（U24——2FA 域地址反查；同构 MySQL 版）。
func (r *PostgresMailboxRepo) FindMailboxByID(ctx context.Context, id int64) (*Mailbox, error) {
	row, err := r.q.FindMailboxByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询邮箱: %w", err)
	}
	return &Mailbox{
		ID:           row.ID,
		LocalPart:    row.LocalPart,
		Domain:       row.Domain,
		Address:      row.Address,
		PasswordHash: row.PasswordHash.String,
		Status:       MailboxStatus(row.Status),
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}
