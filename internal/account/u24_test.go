// U24 双因素认证 account 域全离线测试（NFR-015：临时 SQLite 库独立驱动）。
// 覆盖：FR-018 判定①（绑定：密钥生成/otpauth URI/确认/恢复码 10 枚一次性）/
// 判定②③（验证：正确码通过/错误码拒绝/同窗重放拒绝〔rfc6238 §5.2 MUST〕）/
// 恢复码逐枚消耗与重放拒绝（TC-028 判定①）/停用须因子（TC-028 判定②）/
// 强制标记落库读取（TC-028 判定⑤存储面）。
// 修改历史：
//
//	2026-10-01 17:15:00 | 新增 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）
package account

import (
	"context"
	"strings"
	"testing"
	"time"

	"GRmail/internal/storage"

	"github.com/creachadair/otp"
)

// u24NewService 建立临时库+2FA 服务与测试邮箱。
// 返回：服务实例/邮箱/上下文取消无关的 ctx。
func u24NewService(t *testing.T) (*TwoFactorService, *storage.Mailbox) {
	t.Helper()
	svc, db := newTestService(t)
	ctx := context.Background()
	m, err := svc.CreateMailbox(ctx, "u24@test.local", "passw0rd!")
	if err != nil {
		t.Fatalf("创建邮箱: %v", err)
	}
	_ = db // 仅保持 newTestService 签名消费（历史邮件构造本测试不需要）
	return NewTwoFactorService(storage.NewSQLiteMailboxRepo(db)), m
}

// u24CurrentCode 以服务端同参数计算当前 TOTP 码（测试 oracle——与实现同源独立调用库）。
func u24CurrentCode(t *testing.T, secretBase32 string) string {
	t.Helper()
	cfg, err := (otp.Config{Digits: totpDigits}).WithKey(secretBase32)
	if err != nil {
		t.Fatalf("解析密钥: %v", err)
	}
	return cfg.HOTP(uint64(time.Now().Unix() / totpPeriodSeconds))
}

// TestU24BindingFlow 绑定全流程（FR-018 判定①）：
// 发起→pending 态（Bound=false——登录判定不生效防死锁）→otpauth URI 形态→
// 确认码通过→恢复码 10 枚一次性返回+Bound=true→重复确认/重复发起拒绝。
func TestU24BindingFlow(t *testing.T) {
	svc, m := u24NewService(t)
	ctx := context.Background()

	mat, err := svc.InitiateBinding(ctx, m.ID, m.Address, "test.local")
	if err != nil {
		t.Fatalf("发起绑定: %v", err)
	}
	if mat.Secret == "" || !strings.HasPrefix(mat.OtpauthURI, "otpauth://totp/test.local:") {
		t.Fatalf("绑定材料形态异常: secret=%q uri=%q", mat.Secret, mat.OtpauthURI)
	}
	if !strings.Contains(mat.OtpauthURI, "secret="+mat.Secret) {
		t.Fatal("otpauth URI 未携带密钥参数（IR-009）")
	}
	st, _ := svc.State(ctx, m.ID)
	if st.Bound() {
		t.Fatal("pending 态不应 Bound（绑定中途中断防死锁锚）")
	}

	codes, err := svc.ConfirmBinding(ctx, m.ID, u24CurrentCode(t, mat.Secret))
	if err != nil {
		t.Fatalf("确认绑定: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("恢复码数量: got %d want %d", len(codes), recoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != recoveryCodeBytes*2 {
			t.Fatalf("恢复码长度: %q", c)
		}
		seen[c] = true
	}
	if len(seen) != recoveryCodeCount {
		t.Fatal("恢复码存在重复")
	}
	if st, _ = svc.State(ctx, m.ID); !st.Bound() {
		t.Fatal("确认后应 Bound")
	}
	if _, err = svc.ConfirmBinding(ctx, m.ID, u24CurrentCode(t, mat.Secret)); err != ErrTwoFactorBound {
		t.Fatalf("重复确认应拒绝: %v", err)
	}
	if _, err = svc.InitiateBinding(ctx, m.ID, m.Address, "test.local"); err != ErrTwoFactorBound {
		t.Fatalf("已绑定重复发起应拒绝: %v", err)
	}
}

// TestU24VerifyAndReplay 验证与同窗重放拒绝（FR-018 判定②③+rfc6238 §5.2 L343-347 MUST）。
// 语义锚：绑定确认即消耗确认时刻的 TOTP 码（MarkTOTPStep 推进重放基线——同一验证
// 系统内该码已成功验证一次）；同窗内该码再用于登录必须拒绝（MUST 字面忠实）。
// 独立验证路径用恢复码承载（跨窗不受影响）。
func TestU24VerifyAndReplay(t *testing.T) {
	svc, m := u24NewService(t)
	ctx := context.Background()
	mat, _ := svc.InitiateBinding(ctx, m.ID, m.Address, "test.local")
	confirmCode := u24CurrentCode(t, mat.Secret)
	codes, err := svc.ConfirmBinding(ctx, m.ID, confirmCode)
	if err != nil {
		t.Fatalf("绑定: %v", err)
	}

	// 同窗重放：绑定确认消耗的码再验必须拒绝（rfc6238 §5.2 MUST）
	if err := svc.VerifyLoginFactor(ctx, m.ID, confirmCode); err == nil {
		t.Fatal("绑定确认消耗的码同窗重放必须拒绝（rfc6238 §5.2 MUST）")
	}
	// 恢复码独立路径：未用枚通过→同枚重放拒绝
	if err := svc.VerifyLoginFactor(ctx, m.ID, codes[0]); err != nil {
		t.Fatalf("未用恢复码应通过: %v", err)
	}
	if err := svc.VerifyLoginFactor(ctx, m.ID, codes[0]); err == nil {
		t.Fatal("已消耗恢复码重放必须拒绝")
	}
	// 错误码统一拒绝（TC-027 判定③关联）
	if err := svc.VerifyLoginFactor(ctx, m.ID, "000000"); err != ErrTwoFactorCode {
		t.Fatalf("错误码应 ErrTwoFactorCode: %v", err)
	}
}

// TestU24RecoveryCodes 恢复码逐枚消耗与重放拒绝（TC-028 判定①）+停用须因子（判定②）。
func TestU24RecoveryCodes(t *testing.T) {
	svc, m := u24NewService(t)
	ctx := context.Background()
	mat, _ := svc.InitiateBinding(ctx, m.ID, m.Address, "test.local")
	codes, err := svc.ConfirmBinding(ctx, m.ID, u24CurrentCode(t, mat.Secret))
	if err != nil {
		t.Fatalf("绑定: %v", err)
	}

	// 未用枚通过→同枚重放拒绝（一次性消耗语义）
	if err := svc.VerifyLoginFactor(ctx, m.ID, codes[0]); err != nil {
		t.Fatalf("未用恢复码应通过: %v", err)
	}
	if err := svc.VerifyLoginFactor(ctx, m.ID, codes[0]); err == nil {
		t.Fatal("已消耗恢复码重放必须拒绝")
	}
	// 伪造码拒绝
	if err := svc.VerifyLoginFactor(ctx, m.ID, "deadbeefdeadbeefdead"); err != ErrTwoFactorCode {
		t.Fatalf("伪造码应 ErrTwoFactorCode: %v", err)
	}

	// 停用：错误因子拒绝→正确恢复码通过→Bound=false（TC-028 判定②/⑤联动）
	if err := svc.Disable(ctx, m.ID, "bad-code"); err == nil {
		t.Fatal("停用须第二因子验证（错误因子拒绝）")
	}
	if err := svc.Disable(ctx, m.ID, codes[1]); err != nil {
		t.Fatalf("正确恢复码停用: %v", err)
	}
	if st, _ := svc.State(ctx, m.ID); st.Bound() {
		t.Fatal("停用后不应 Bound")
	}
}

// TestU24RequiredFlag 强制标记落库与读取（FR-018 判定④存储面——TC-028 判定⑤锚）。
func TestU24RequiredFlag(t *testing.T) {
	svc, m := u24NewService(t)
	ctx := context.Background()
	if err := svc.SetRequired(ctx, m.ID, true); err != nil {
		t.Fatalf("设置强制标记: %v", err)
	}
	st, err := svc.State(ctx, m.ID)
	if err != nil || !st.Required {
		t.Fatalf("强制标记读取: st=%+v err=%v", st, err)
	}
	if err := svc.SetRequired(ctx, m.ID, false); err != nil {
		t.Fatalf("取消强制标记: %v", err)
	}
	if st, _ = svc.State(ctx, m.ID); st.Required {
		t.Fatal("取消后标记应为 false")
	}
}

// TestU24VerifyNotBound 未绑定时验证/停用拒绝（哨兵语义）。
func TestU24VerifyNotBound(t *testing.T) {
	svc, m := u24NewService(t)
	ctx := context.Background()
	if err := svc.VerifyLoginFactor(ctx, m.ID, "123456"); err != ErrTwoFactorNotBound {
		t.Fatalf("未绑定验证应 ErrTwoFactorNotBound: %v", err)
	}
	if err := svc.Disable(ctx, m.ID, "123456"); err != ErrTwoFactorNotBound {
		t.Fatalf("未绑定停用应 ErrTwoFactorNotBound: %v", err)
	}
}
