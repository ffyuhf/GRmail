// account 域管理员 2FA 服务：admin 主体的 TOTP 绑定/验证、恢复码生成/消耗、停用验证
// （管理员主体增强与Webmail职能补全批次 G2——D13 缺陷收口：admin 登录入口二步验证）。
// 依据：SRS v1.1.0 3.11 FR-018 admin 通道扩展（S3-W Q2-A 裁决 2026-10-05 23:20:14——
// 「仅 Webmail HTTPS 登录入口」语义内承载：/login 即 Webmail 入口，IMAP/POP3/SMTP
// 协议入口零触及）；IR-009（otpauth URI）；rfc6238 §4/§5.2（算法与同窗重放拒绝——
// verifyTOTP 包级函数复用）；契约 v1.29.0 2.1（UserRepo 六方法族）；
// 计划书 v1.1.0 1.3 G2（G2 批准 2026-10-05 23:31:37）。
// 形态：与 mailbox 版 TwoFactorService 并列的独立服务（users 仓储注入——零相互依赖，
// 计划书 1.5 倾向单案）；admin 无强制标记语义（唯一最高权限主体，无 Required 承载）。
// 修改历史：
//
//	2026-10-05 23:40:00 | 新增 | 管理员主体增强与Webmail职能补全批次（G2 批准 2026-10-05 23:31:37）
package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"GRmail/internal/storage"
)

// AdminTwoFactorService 管理员 2FA 域服务（web 层 /login 与 /admin/2fa 端点族注入消费；
// 协议端点零触及——mailbox 版同款入口隔离语义）。
type AdminTwoFactorService struct {
	users storage.UserRepo
}

// NewAdminTwoFactorService 构造管理员 2FA 域服务。
// 参数：users 管理员仓储（2FA 方法族——契约 v1.29.0）。返回：服务实例。
func NewAdminTwoFactorService(users storage.UserRepo) *AdminTwoFactorService {
	return &AdminTwoFactorService{users: users}
}

// State 读取管理员 2FA 绑定态（呈现与 /login 登录判定共用——Bound() 为二步生效条件）。
func (s *AdminTwoFactorService) State(ctx context.Context, userID int64) (*storage.TwoFactorState, error) {
	return s.users.GetTwoFactor(ctx, userID)
}

// InitiateBinding 发起绑定（FR-018 判定①前半 admin 承载）：生成 20B CSPRNG 密钥→
// Base32→pending 落库（覆盖式——重复发起以最新密钥为准，未确认期间登录判定不生效），
// 返回二维码 URI 与明文密钥。accountLabel 为 otpauth label（管理员用户名），
// issuer 为发行方名（主域名）。
func (s *AdminTwoFactorService) InitiateBinding(ctx context.Context, userID int64, accountLabel, issuer string) (*BindingMaterial, error) {
	st, err := s.users.GetTwoFactor(ctx, userID)
	if err != nil {
		return nil, err
	}
	if st.Bound() {
		return nil, ErrTwoFactorBound // 已绑定禁止重发起（防覆盖劫持——须先停用）
	}
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("生成管理员 TOTP 密钥: %w", err)
	}
	secret := base32NoPadding.EncodeToString(raw)
	if err := s.users.SetTwoFactorSecret(ctx, userID, secret); err != nil {
		return nil, err
	}
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, accountLabel, secret, issuer, totpDigits, totpPeriodSeconds)
	return &BindingMaterial{Secret: secret, OtpauthURI: uri}, nil
}

// ConfirmBinding 绑定确认（FR-018 判定①后半 admin 承载）：校验当前 TOTP 码通过后，
// 生成 10 枚恢复码并落哈希集——自此 Bound()=true，/login 登录二步生效。返回恢复码
// 明文（仅本次返回——一次性展示语义，明文零落库）。
func (s *AdminTwoFactorService) ConfirmBinding(ctx context.Context, userID int64, code string) ([]string, error) {
	st, err := s.users.GetTwoFactor(ctx, userID)
	if err != nil {
		return nil, err
	}
	if st.PendingSecret == "" {
		return nil, ErrTwoFactorNotBound // 未发起绑定（会话态与库态不一致防护）
	}
	if st.Bound() {
		return nil, ErrTwoFactorBound // 已确认（防重复确认重复发码）
	}
	step, ok := verifyTOTP(st.PendingSecret, code, st.LastTOTPStep)
	if !ok {
		return nil, ErrTwoFactorCode // 错误码拒绝
	}
	// 绑定确认即记验证步（同密钥登录重放防护起点——rfc6238 §5.2 MUST 同窗拒绝）
	if err := s.users.MarkTOTPStep(ctx, userID, step); err != nil {
		return nil, err
	}
	codes, hashes, err := generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.users.ConfirmTwoFactor(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifyLoginFactor /login 登录二步/停用验证共用因子校验：先 TOTP（容差 ±1 窗+同窗
// 重放拒绝），未命中再恢复码（SHA-256 匹配逐枚消耗）；双失败统一 ErrTwoFactorCode。
func (s *AdminTwoFactorService) VerifyLoginFactor(ctx context.Context, userID int64, code string) error {
	st, err := s.users.GetTwoFactor(ctx, userID)
	if err != nil {
		return err
	}
	if !st.Bound() {
		return ErrTwoFactorNotBound
	}
	if step, ok := verifyTOTP(st.PendingSecret, code, st.LastTOTPStep); ok {
		return s.users.MarkTOTPStep(ctx, userID, step) // 重放基线推进
	}
	// 恢复码路径：SHA-256 hex 匹配消耗（逐枚一次性）
	sum := sha256.Sum256([]byte(code))
	hit, err := s.users.ConsumeRecoveryCode(ctx, userID, hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	if !hit {
		return ErrTwoFactorCode // 未命中：重放（已消耗枚）或伪造
	}
	return nil
}

// Disable 停用管理员 2FA（须通过一次第二因子验证方可停用——TC-028 判定②语义同款）。
func (s *AdminTwoFactorService) Disable(ctx context.Context, userID int64, code string) error {
	if err := s.VerifyLoginFactor(ctx, userID, code); err != nil {
		return err
	}
	return s.users.ClearTwoFactor(ctx, userID)
}
