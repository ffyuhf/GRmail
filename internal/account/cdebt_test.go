// C级债务收尾批 account 域测试（F1/F2/F3/F5——2026-10-10，G2 批准 15:45:40）。
// 覆盖：admin 版 2FA 输入防御补齐（mock UserRepo 独立驱动——NFR-015）、otpauth
// URI 百分号编码、verifyTOTP 时钟注入纯函数化、EnsurePostmasterMailbox 并发幂等。
// 修改历史：
//
//	2026-10-10 16:15:00 | 新建 | C级债务收尾批（计划书步骤 2/3/5）
package account

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/creachadair/otp"

	"GRmail/internal/storage"
)

// TestCDebtVerifyTOTPInjectedClock F3/C4：nowSec 注入——固定时刻生成码命中、
// 同窗重放拒绝、旧时刻码不命中（时间可测性——纯函数化直接验证）。
func TestCDebtVerifyTOTPInjectedClock(t *testing.T) {
	secret := base32NoPadding.EncodeToString(make([]byte, totpSecretBytes))
	cfg, err := (otp.Config{Digits: totpDigits}).WithKey(secret)
	if err != nil {
		t.Fatalf("密钥构造: %v", err)
	}
	nowSec := int64(1700000000)
	step := nowSec / totpPeriodSeconds
	code := cfg.HOTP(uint64(step))

	if _, ok := verifyTOTP(secret, code, 0, nowSec); !ok {
		t.Fatal("注入时刻命中步应通过")
	}
	if _, ok := verifyTOTP(secret, code, step, nowSec); ok {
		t.Fatal("lastStep=同窗步应拒绝（rfc6238 §5.2 同窗重放）")
	}
	if _, ok := verifyTOTP(secret, cfg.HOTP(uint64(step-1)), step, nowSec); ok {
		t.Fatal("重放基线之下的旧码应拒绝")
	}
}

// TestCDebtOtpauthURIEncoding F2/C3：issuer 含空格时 label 与 query 参数编码；
// 纯常规字符 issuer 编码后语义等价（label 解码==issuer:account）。
func TestCDebtOtpauthURIEncoding(t *testing.T) {
	svc, db := newTestService(t)
	ctx := context.Background()
	m, err := svc.CreateMailbox(ctx, "user@d.c", "pw-123456")
	if err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	tfSvc := NewTwoFactorService(storage.NewSQLiteMailboxRepo(db))
	bm, err := tfSvc.InitiateBinding(ctx, m.ID, "user@d.c", "My Issuer")
	if err != nil {
		t.Fatalf("发起绑定: %v", err)
	}
	if !strings.Contains(bm.OtpauthURI, "/My%20Issuer:") {
		t.Fatalf("label 空格应被 PathEscape 编码: %s", bm.OtpauthURI)
	}
	if !strings.Contains(bm.OtpauthURI, "issuer=My+Issuer") {
		t.Fatalf("query issuer 空格应被 QueryEscape 编码: %s", bm.OtpauthURI)
	}
	// 兼容锚：@ 与 . 属 path 合法字符（RFC 3986）保持原样——常规地址 label 输出
	// 与旧版逐字节一致（Google Authenticator 兼容形态）。
	if !strings.Contains(bm.OtpauthURI, ":user@d.c?") {
		t.Fatalf("path 合法字符 @ 应保持原样（兼容锚）: %s", bm.OtpauthURI)
	}
}

// TestCDebtAdminVerifyFactorFormatDefense F1/C2：admin 版 VerifyLoginFactor 补齐
// mailbox 版同款防御——空白/超长码先格式拒绝（mock UserRepo 独立驱动 Bound 态）。
func TestCDebtAdminVerifyFactorFormatDefense(t *testing.T) {
	secret := base32NoPadding.EncodeToString(make([]byte, totpSecretBytes))
	admin := NewAdminTwoFactorService(&fakeBoundUserRepo{secret: secret})
	if err := admin.VerifyLoginFactor(context.Background(), 1, strings.Repeat("1", 65)); err != ErrTwoFactorFormat {
		t.Fatalf("超长码应 ErrTwoFactorFormat: %v", err)
	}
	if err := admin.VerifyLoginFactor(context.Background(), 1, "   "); err != ErrTwoFactorFormat {
		t.Fatalf("空白码应 ErrTwoFactorFormat: %v", err)
	}
}

// fakeBoundUserRepo Bound 态 mock（F1 测试专用——GetTwoFactor 返回绑定态快照，
// 其余方法 stub；真实链路由 u24/u28 既有测试承载）。
type fakeBoundUserRepo struct{ secret string }

func (f *fakeBoundUserRepo) EnsureAdmin(context.Context, *storage.User) error { return nil }
func (f *fakeBoundUserRepo) FindByName(context.Context, string) (*storage.User, error) {
	return nil, storage.ErrUserNotFound
}
func (f *fakeBoundUserRepo) UpdatePassword(context.Context, int64, string) error { return nil }
func (f *fakeBoundUserRepo) FindByID(context.Context, int64) (*storage.User, error) {
	return nil, storage.ErrUserNotFound
}
func (f *fakeBoundUserRepo) GetTwoFactor(_ context.Context, _ int64) (*storage.TwoFactorState, error) {
	return &storage.TwoFactorState{TotpSecret: f.secret, CodesHash: []string{"h1"}}, nil
}
func (f *fakeBoundUserRepo) SetTwoFactorSecret(context.Context, int64, string) error { return nil }
func (f *fakeBoundUserRepo) ConfirmTwoFactor(context.Context, int64, []string) error {
	return nil
}
func (f *fakeBoundUserRepo) MarkTOTPStep(context.Context, int64, int64) error { return nil }
func (f *fakeBoundUserRepo) ConsumeRecoveryCode(context.Context, int64, string) (bool, error) {
	return false, nil
}
func (f *fakeBoundUserRepo) ClearTwoFactor(context.Context, int64) error { return nil }

// TestCDebtEnsurePostmasterConcurrent F5/C6：并发 EnsurePostmasterMailbox——
// 全部成功且返回同一邮箱（UNIQUE 冲突回读幂等收口）。
func TestCDebtEnsurePostmasterConcurrent(t *testing.T) {
	svc, _ := newTestService(t)
	const n = 8
	ids := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, err := svc.EnsurePostmasterMailbox(context.Background(), "d.c")
			errs[i] = err
			if m != nil {
				ids[i] = m.ID
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("并发[%d]应幂等成功: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("并发[%d]应同 ID: %d vs %d", i, ids[i], ids[0])
		}
	}
}
