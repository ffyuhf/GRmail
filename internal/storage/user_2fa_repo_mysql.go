// Package storage 追加管理员 2FA 仓储：UserRepo admin 2FA 方法族 MySQL 实现
// （管理员主体增强与Webmail职能补全批次 G2——沿 U24 twofactor_repo_mysql.go 先例）。
// 依据：契约 v1.29.0 2.1；表结构 v1.9.0 3.15（迁移 00011）；rfc6238 §4/§5.2；
// SRS v1.1.0 FR-018 admin 通道扩展（S3-W Q2-A 2026-10-05 23:20:14）。
// 修改历史：
//
//	2026-10-05 23:38:00 | 新增 | 管理员主体增强与Webmail职能补全批次（G2 批准 2026-10-05 23:31:37）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/mysql"
)

// GetTwoFactor 读取管理员 2FA 绑定态（MySQL——TEXT NULL 列 sql.NullString 映射）。
func (r *MySQLUserRepo) GetTwoFactor(ctx context.Context, userID int64) (*TwoFactorState, error) {
	row, err := r.q.GetAdmin2FAByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询管理员 2FA 状态: %w", err)
	}
	codes, err := parseRecoveryCodesJSON(row.RecoveryCodes.String)
	if err != nil {
		return nil, err
	}
	return &TwoFactorState{
		PendingSecret: row.TotpSecret.String,
		CodesHash:     codes,
		Required:      false, // admin 无强制标记语义（迁移 00011 不设 required 列）
		LastTOTPStep:  row.TotpLastStep.Int64,
	}, nil
}

// SetTwoFactorSecret 发起绑定（覆盖式写 pending 密钥+SQL 内联清重放步）。
func (r *MySQLUserRepo) SetTwoFactorSecret(ctx context.Context, userID int64, secret string) error {
	if err := r.q.SetAdmin2FASecret(ctx, dbgen.SetAdmin2FASecretParams{
		TotpSecret: nullString(secret),
		UpdatedAt:  time.Now().UTC(),
		ID:         userID,
	}); err != nil {
		return fmt.Errorf("写入管理员 pending TOTP 密钥: %w", err)
	}
	return nil
}

// ConfirmTwoFactor 绑定确认（写恢复码哈希集——Bound()=true 生效）。
func (r *MySQLUserRepo) ConfirmTwoFactor(ctx context.Context, userID int64, codeHashes []string) error {
	codes, err := marshalRecoveryCodes(codeHashes)
	if err != nil {
		return err
	}
	if err := r.q.UpdateAdminRecoveryCodes(ctx, dbgen.UpdateAdminRecoveryCodesParams{
		RecoveryCodes: nullString(codes),
		UpdatedAt:     time.Now().UTC(),
		ID:            userID,
	}); err != nil {
		return fmt.Errorf("写入管理员恢复码集: %w", err)
	}
	return nil
}

// MarkTOTPStep 记录 TOTP 验证成功步（rfc6238 §5.2 同窗重放拒绝；安全原子性批 F3
// 2026-10-06：SQL 条件 UPDATE 原子守卫——0 行受影响 → ErrTOTPStepConflict）。
func (r *MySQLUserRepo) MarkTOTPStep(ctx context.Context, userID, step int64) error {
	res, err := r.q.MarkAdminTOTPStep(ctx, dbgen.MarkAdminTOTPStepParams{
		TotpLastStep:   sql.NullInt64{Int64: step, Valid: true},
		UpdatedAt:      time.Now().UTC(),
		ID:             userID,
		TotpLastStep_2: sql.NullInt64{Int64: step, Valid: true}, // 条件守卫参数
	})
	if err != nil {
		return fmt.Errorf("记录管理员 TOTP 验证步: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("记录管理员 TOTP 验证步（受影响行数）: %w", err)
	}
	if n == 0 {
		return ErrTOTPStepConflict
	}
	return nil
}

// ConsumeRecoveryCode 消耗一枚管理员恢复码（安全原子性批 F4 2026-10-06：CAS 覆写
// +单轮重试——同码并发恰一成功；见 mailbox 侧注记）。
func (r *MySQLUserRepo) ConsumeRecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		consumed, retry, err := r.consumeRecoveryCodeOnce(ctx, userID, codeHash)
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
func (r *MySQLUserRepo) consumeRecoveryCodeOnce(ctx context.Context, userID int64, codeHash string) (consumed, retry bool, err error) {
	tx, txErr := r.db.BeginTx(ctx, nil)
	if txErr != nil {
		return false, false, fmt.Errorf("开启事务: %w", txErr)
	}
	defer func() { _ = tx.Rollback() }()

	qtx := r.q.WithTx(tx)
	row, gerr := qtx.GetAdmin2FAByID(ctx, userID)
	if errors.Is(gerr, sql.ErrNoRows) {
		return false, false, ErrUserNotFound
	}
	if gerr != nil {
		return false, false, fmt.Errorf("查询管理员恢复码集: %w", gerr)
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
		return false, false, nil // 未命中：重放/伪造拒绝
	}
	remaining := append(hashes[:idx:idx], hashes[idx+1:]...)
	codes, merr := marshalRecoveryCodes(remaining)
	if merr != nil {
		return false, false, merr
	}
	res, uerr := qtx.ConsumeAdminRecoveryCodeCAS(ctx, dbgen.ConsumeAdminRecoveryCodeCASParams{
		RecoveryCodes:   nullString(codes),
		UpdatedAt:       time.Now().UTC(),
		ID:              userID,
		RecoveryCodes_2: row.RecoveryCodes, // CAS 条件：本事务读到的旧集原串
	})
	if uerr != nil {
		return false, false, fmt.Errorf("消耗管理员恢复码: %w", uerr)
	}
	n, rerr := res.RowsAffected()
	if rerr != nil {
		return false, false, fmt.Errorf("消耗管理员恢复码（受影响行数）: %w", rerr)
	}
	if n == 0 {
		return false, true, nil // CAS 冲突——由调用方重试
	}
	if cerr := tx.Commit(); cerr != nil {
		return false, false, fmt.Errorf("提交事务: %w", cerr)
	}
	return true, false, nil
}

// ClearTwoFactor 停用 2FA（三列同清）。
func (r *MySQLUserRepo) ClearTwoFactor(ctx context.Context, userID int64) error {
	if err := r.q.ClearAdmin2FA(ctx, dbgen.ClearAdmin2FAParams{
		UpdatedAt: time.Now().UTC(),
		ID:        userID,
	}); err != nil {
		return fmt.Errorf("停用管理员 2FA: %w", err)
	}
	return nil
}
