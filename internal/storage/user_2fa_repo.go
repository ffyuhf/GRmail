// Package storage 追加管理员 2FA 仓储：UserRepo admin 2FA 方法族 SQLite 实现
// （管理员主体增强与Webmail职能补全批次 G2——D13 缺陷收口）。
// 依据：模块接口契约 v1.29.0 2.1（UserRepo 六方法增量——沿 MailboxRepo v1.20.0 先例）；
// 数据库表结构 v1.9.0 3.15（users 三增列——迁移 00011）；rfc6238 §4/§5.2 L343-347；
// SRS v1.1.0 FR-018 admin 通道扩展（S3-W Q2-A 裁决 2026-10-05 23:20:14——/login 登录
// 入口二步验证；「仅 Webmail HTTPS 登录入口」语义内，协议入口零触及）；
// 计划书 v1.1.0 1.3 G2（G2 批准 2026-10-05 23:31:37）。
// 实现取舍：沿 U24 S4-W 三裁决 A/A/A 同源口径——pending 密钥列明文、恢复码 SHA-256
// 快哈希、重放步承载列；admin 无强制标记语义（唯一最高权限主体，Required 恒 false）。
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

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// GetTwoFactor 读取管理员 2FA 绑定态（绑定完成判定 TwoFactorState.Bound——
// /login 登录二步生效条件；pending 态不生效防死锁）。
// 参数：ctx 上下文；userID 管理员 ID。返回：状态快照；ErrUserNotFound 无行。
func (r *SQLiteUserRepo) GetTwoFactor(ctx context.Context, userID int64) (*TwoFactorState, error) {
	row, err := r.q.GetAdmin2FAByID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询管理员 2FA 状态: %w", err)
	}
	codes, err := parseRecoveryCodesJSON(stringOfAny(row.RecoveryCodes))
	if err != nil {
		return nil, err
	}
	return &TwoFactorState{
		TotpSecret:   stringOfAny(row.TotpSecret), // F4/C5 改名（原 PendingSecret）
		CodesHash:    codes,
		Required:     false, // admin 无强制标记语义（迁移 00011 不设 required 列）
		LastTOTPStep: stepOfAny(row.TotpLastStep),
	}, nil
}

// SetTwoFactorSecret 发起绑定（覆盖式写 pending 密钥；SQL 内联清 totp_last_step——
// 新密钥重放基线重置；绑定确认前 Bound() 保持 false，登录判定不受影响）。
func (r *SQLiteUserRepo) SetTwoFactorSecret(ctx context.Context, userID int64, secret string) error {
	if err := r.q.SetAdmin2FASecret(ctx, dbgen.SetAdmin2FASecretParams{
		TotpSecret: secret, // 非空由调用方（account 层）保证——生成器恒产非空密钥
		UpdatedAt:  formatTimestamp(time.Now().UTC()),
		ID:         userID,
	}); err != nil {
		return fmt.Errorf("写入管理员 pending TOTP 密钥: %w", err)
	}
	return nil
}

// ConfirmTwoFactor 绑定确认（写恢复码哈希集——自此 Bound()=true 二步生效）。
// 参数：codeHashes 恢复码哈希集（account 层生成明文→SHA-256 后传入，明文零落库）。
func (r *SQLiteUserRepo) ConfirmTwoFactor(ctx context.Context, userID int64, codeHashes []string) error {
	codes, err := marshalRecoveryCodes(codeHashes)
	if err != nil {
		return err
	}
	if err := r.q.UpdateAdminRecoveryCodes(ctx, dbgen.UpdateAdminRecoveryCodesParams{
		RecoveryCodes: codes,
		UpdatedAt:     formatTimestamp(time.Now().UTC()),
		ID:            userID,
	}); err != nil {
		return fmt.Errorf("写入管理员恢复码集: %w", err)
	}
	return nil
}

// MarkTOTPStep 记录 TOTP 验证成功步（rfc6238 §5.2 同窗重放拒绝承载——登录二步/
// 绑定确认/停用验证三路径验证成功后统一调用；安全原子性批 F3 2026-10-06：SQL 条件
// UPDATE 原子守卫——0 行受影响 → ErrTOTPStepConflict，见 mailbox 侧注记）。
func (r *SQLiteUserRepo) MarkTOTPStep(ctx context.Context, userID, step int64) error {
	res, err := r.q.MarkAdminTOTPStep(ctx, dbgen.MarkAdminTOTPStepParams{
		TotpLastStep:   step,
		UpdatedAt:      formatTimestamp(time.Now().UTC()),
		ID:             userID,
		TotpLastStep_2: step, // WHERE 条件参数（严格大于守卫——与 SET 值同源）
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
// +单轮重试——同码并发恰一成功，逐枚一次性 TC-028 判定①；见 mailbox 侧注记）。
// 参数：codeHash 待消耗恢复码的 SHA-256 hex。返回：是否命中消耗。
func (r *SQLiteUserRepo) ConsumeRecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error) {
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

// consumeRecoveryCodeOnce 单轮消耗尝试（独立事务；CAS 参数为 sqlite interface{} 形态）。
func (r *SQLiteUserRepo) consumeRecoveryCodeOnce(ctx context.Context, userID int64, codeHash string) (consumed, retry bool, err error) {
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
	raw := stringOfAny(row.RecoveryCodes)
	hashes, perr := parseRecoveryCodesJSON(raw)
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
	remaining := append(hashes[:idx:idx], hashes[idx+1:]...) // 三索引切片防底层数组污染
	codes, merr := marshalRecoveryCodes(remaining)
	if merr != nil {
		return false, false, merr
	}
	res, uerr := qtx.ConsumeAdminRecoveryCodeCAS(ctx, dbgen.ConsumeAdminRecoveryCodeCASParams{
		RecoveryCodes:   codes,
		UpdatedAt:       formatTimestamp(time.Now().UTC()),
		ID:              userID,
		RecoveryCodes_2: raw, // CAS 条件：本事务读到的旧集原串
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

// ClearTwoFactor 停用 2FA（三列同清；调用方须先完成第二因子验证——TC-028 判定②语义）。
func (r *SQLiteUserRepo) ClearTwoFactor(ctx context.Context, userID int64) error {
	if err := r.q.ClearAdmin2FA(ctx, dbgen.ClearAdmin2FAParams{
		UpdatedAt: formatTimestamp(time.Now().UTC()),
		ID:        userID,
	}); err != nil {
		return fmt.Errorf("停用管理员 2FA: %w", err)
	}
	return nil
}
