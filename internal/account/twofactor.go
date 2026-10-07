// account 域 2FA 服务：TOTP 绑定/验证、恢复码生成/消耗、停用验证、管理员强制策略
// （FR-018 全量业务语义——U24 单元核心）。
// 依据：SRS v1.1.0 3.11 FR-018（判定①~⑤）/IR-009（otpauth URI）；rfc6238 全文回读
// （§4.1 X=30s/T0=0 缺省；§5.1 密钥 SHOULD 匹配 HMAC 输出长〔SHA-1=20B〕；§5.2 L300-306
// RECOMMEND 至多一步网络延迟容差；L343-347 同窗验证成功后 MUST NOT 接受第二次）；
// 建模记录 v1.1.0 7.3 第 7/8 条（入口隔离 Web 会话层/绑定与恢复机制）；
// 干系人选型指示 D10（creachadair/otp——SRS 附录 D；REQ-20261001-006）；
// S4-W 三裁决 A/A/A（2026-10-01 16:44:56——pending 密钥 Base32 列明文/恢复码 SHA-256/短时凭据归 web 层）。
// 修改历史：
//
//	2026-10-01 16:55:00 | 新增 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）
package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"GRmail/internal/storage"

	"github.com/creachadair/otp"
)

// ───────────────────────── 2FA 参数常量（rfc6238 锚定） ─────────────────────────

const (
	// totpPeriodSeconds X 时间步 30 秒（rfc6238 §4.1 缺省值；Google Authenticator 兼容）。
	totpPeriodSeconds int64 = 30
	// totpSkewWindows 验证容差 ±1 时间步（rfc6238 §5.2 L300-306「We RECOMMEND that at
	// most one time step is allowed as the network delay」——RECOMMEND 级直接采信）。
	totpSkewWindows int64 = 1
	// totpDigits 6 位验证码（authenticator 生态缺省；库 Digits 零值同）。
	totpDigits = 6
	// totpSecretBytes 密钥 20 字节（rfc6238 §5.1「Keys SHOULD be of the length of the
	// HMAC output」——SHA-1 输出 20 字节）。
	totpSecretBytes = 20
	// recoveryCodeCount 恢复码集合规模 10 枚（REQ-20261001-005「一次性生成展示的备用
	// 验证码集合」；规模为实现级，业界惯例）。
	recoveryCodeCount = 10
	// recoveryCodeBytes 单枚恢复码熵 10 字节 80bit（hex 展示 20 字符——高熵随机串，
	// SHA-256 快哈希依据 S4-W Q2-A）。
	recoveryCodeBytes = 10
)

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrTwoFactorBound 已绑定（重复发起绑定——须先停用；防绑定覆盖劫持）
	ErrTwoFactorBound = errors.New("account: 2FA 已绑定")
	// ErrTwoFactorNotBound 未绑定（确认/验证/停用无载体）
	ErrTwoFactorNotBound = errors.New("account: 2FA 未绑定")
	// ErrTwoFactorCode 第二因子验证失败（TOTP 与恢复码均未命中——统一拒绝，
	// 沿 ErrInvalidCredentials 防枚举口径）
	ErrTwoFactorCode = errors.New("account: 第二因子验证失败")
	// ErrTwoFactorFormat 验证码输入格式非法（空/超长——先于校验拒绝）
	ErrTwoFactorFormat = errors.New("account: 验证码格式非法")
)

// base32NoPadding Base32 无填充编码（otpauth secret 参数标准形态——Google key-uri-format）。
var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// BindingMaterial 绑定呈现物（FR-018 判定①：二维码与明文密钥双形态）。
type BindingMaterial struct {
	Secret     string // Base32 密钥（明文呈现——authenticator 手动输入通道）
	OtpauthURI string // otpauth:// URI（IR-009——二维码渲染内容，web 层产 PNG）
}

// TwoFactorService 2FA 域服务（web 层注入消费；协议端点零触及——建模 7.3 第 7 条入口隔离）。
type TwoFactorService struct {
	mailboxes storage.MailboxRepo
}

// NewTwoFactorService 构造 2FA 域服务。
// 参数：mailboxes 邮箱仓储（2FA 方法族——契约 v1.20.0）。返回：服务实例。
func NewTwoFactorService(mailboxes storage.MailboxRepo) *TwoFactorService {
	return &TwoFactorService{mailboxes: mailboxes}
}

// State 读取 2FA 绑定态（呈现与登录判定共用——Bound() 为二步生效条件）。
func (s *TwoFactorService) State(ctx context.Context, mailboxID int64) (*storage.TwoFactorState, error) {
	return s.mailboxes.GetTwoFactor(ctx, mailboxID)
}

// InitiateBinding 发起绑定（FR-018 判定①前半）：生成 20B CSPRNG 密钥→Base32→
// pending 落库（覆盖式——重复发起以最新密钥为准，未确认期间登录判定不生效），
// 返回二维码 URI 与明文密钥。account 为邮箱地址（otpauth label），issuer 为发行方名
// （主域名——authenticator App 内区分条目）。
func (s *TwoFactorService) InitiateBinding(ctx context.Context, mailboxID int64, accountAddr, issuer string) (*BindingMaterial, error) {
	st, err := s.mailboxes.GetTwoFactor(ctx, mailboxID)
	if err != nil {
		return nil, err
	}
	if st.Bound() {
		return nil, ErrTwoFactorBound // 已绑定禁止重发起（防覆盖劫持——须先停用）
	}
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("生成 TOTP 密钥: %w", err)
	}
	secret := base32NoPadding.EncodeToString(raw)
	if err := s.mailboxes.SetTwoFactorSecret(ctx, mailboxID, secret); err != nil {
		return nil, err
	}
	// otpauth URI（Google key-uri-format 事实标准——IR-009；参数显式化：SHA1/6 位/30s
	// 与服务端验证参数一致，authenticator 导入即对齐）
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, accountAddr, secret, issuer, totpDigits, totpPeriodSeconds)
	return &BindingMaterial{Secret: secret, OtpauthURI: uri}, nil
}

// ConfirmBinding 绑定确认（FR-018 判定①后半）：校验用户输入的当前 TOTP 码通过后，
// 生成 10 枚恢复码并落哈希集——自此 Bound()=true 二步生效。返回恢复码明文
// （仅本次返回——一次性展示语义，TC-027 判定①；明文零落库）。
func (s *TwoFactorService) ConfirmBinding(ctx context.Context, mailboxID int64, code string) ([]string, error) {
	st, err := s.mailboxes.GetTwoFactor(ctx, mailboxID)
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
		return nil, ErrTwoFactorCode // TC-027 判定③关联：错误码拒绝
	}
	// 绑定确认即记验证步（同密钥登录重放防护起点——rfc6238 §5.2 MUST 同窗拒绝）
	if err := s.mailboxes.MarkTOTPStep(ctx, mailboxID, step); err != nil {
		return nil, err
	}
	codes, hashes, err := generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.mailboxes.ConfirmTwoFactor(ctx, mailboxID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifyLoginFactor 登录二步/停用验证共用因子校验（FR-018 判定②与停用语段）：
// 先 TOTP（容差 ±1 窗+同窗重放拒绝），未命中再恢复码（SHA-256 匹配逐枚消耗）；
// 双失败统一 ErrTwoFactorCode（TC-027 判定③/TC-028 判定①②锚）。
func (s *TwoFactorService) VerifyLoginFactor(ctx context.Context, mailboxID int64, code string) error {
	st, err := s.mailboxes.GetTwoFactor(ctx, mailboxID)
	if err != nil {
		return err
	}
	if !st.Bound() {
		return ErrTwoFactorNotBound
	}
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 64 {
		return ErrTwoFactorFormat
	}
	if step, ok := verifyTOTP(st.PendingSecret, code, st.LastTOTPStep); ok {
		// 安全原子性批 F3（2026-10-06）：SQL 条件守卫的并发冲突（另一请求已推进
		// 重放基线）按验证失败统一呈现——对调用方等同重放拒绝（rfc6238 §5.2）。
		if err := s.mailboxes.MarkTOTPStep(ctx, mailboxID, step); err != nil {
			if errors.Is(err, storage.ErrTOTPStepConflict) {
				return ErrTwoFactorCode
			}
			return err
		}
		return nil // 重放基线推进成功
	}
	// 恢复码路径：SHA-256 hex 匹配消耗（高熵随机串快哈希——S4-W Q2-A；逐枚一次性）
	sum := sha256.Sum256([]byte(code))
	hit, err := s.mailboxes.ConsumeRecoveryCode(ctx, mailboxID, hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	if !hit {
		return ErrTwoFactorCode // 未命中：重放（已消耗枚）或伪造
	}
	return nil
}

// Disable 停用 2FA（FR-018 停用语段：须通过一次第二因子验证方可停用——
// TC-028 判定②锚；强制标记 Required 独立保留不随停用清除）。
func (s *TwoFactorService) Disable(ctx context.Context, mailboxID int64, code string) error {
	if err := s.VerifyLoginFactor(ctx, mailboxID, code); err != nil {
		return err
	}
	return s.mailboxes.ClearTwoFactor(ctx, mailboxID)
}

// SetRequired 管理员强制标记增删（FR-018 判定④；ERD 设计语义第 5 条——
// 标记主体为管理员，本服务仅承载存储透传，主体判定归 web admin 门卫）。
func (s *TwoFactorService) SetRequired(ctx context.Context, mailboxID int64, required bool) error {
	return s.mailboxes.SetTwoFactorRequired(ctx, mailboxID, required)
}

// ───────────────────────── 纯函数（NFR-015 可独立测试） ─────────────────────────

// verifyTOTP TOTP 验证：Base32 密钥解析→容差窗 [t-skew, t+skew] 逐窗 HOTP 比对→
// 命中步必须严格大于 lastStep（rfc6238 §5.2 L343-347 同窗重放拒绝 MUST——
// 「the verifier MUST NOT accept the second attempt of the OTP after the
// successful validation has been issued for the first OTP」）。
// 参数：secretBase32 列存密钥；code 用户输入；lastStep 重放基线（0=无验证史）。
// 返回：命中时间步与是否通过。
func verifyTOTP(secretBase32, code string, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return 0, false
	}
	cfg, err := (otp.Config{Digits: totpDigits}).WithKey(secretBase32)
	if err != nil {
		return 0, false // 密钥损坏按验证失败（防探测差异化）
	}
	t := time.Now().Unix() / totpPeriodSeconds
	for step := t + totpSkewWindows; step >= t-totpSkewWindows; step-- {
		if step <= lastStep {
			break // 窗口已落入重放基线之下——同窗/回退码全部拒绝（MUST）
		}
		if cfg.HOTP(uint64(step)) == code {
			return step, true
		}
	}
	return 0, false
}

// generateRecoveryCodes 生成恢复码集合（CSPRNG 10 字节/枚→hex 20 字符）。
// 返回：明文集（一次性展示）与 SHA-256 哈希集（落库形态——明文零持久化）。
func generateRecoveryCodes() (codes []string, hashes []string, err error) {
	codes = make([]string, 0, recoveryCodeCount)
	hashes = make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		buf := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("生成恢复码: %w", err)
		}
		code := hex.EncodeToString(buf)
		sum := sha256.Sum256([]byte(code))
		codes = append(codes, code)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	return codes, hashes, nil
}
