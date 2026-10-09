// B-S安全域批 F7 新用例（计划书 v2.0.0 步骤 3 检查点承载）——登录时序均匀化行为
// 等价锚（时序断言易 flaky——按计划书口径以行为等价承载：不存在/影子/禁用路径
// 统一 ErrInvalidCredentials 语义零变化；dummy 校验为内部时延消费不改变判定）。
// 依据：FR-001 三入口认证/安全行伴随（用户名枚举侧信道收口）。
// 修改历史：
//
//	2026-10-09 21:35:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package account

import (
	"context"
	"testing"
)

// TestBSF7VerifyCredentialsUniformRejection 三类失败路径统一拒绝语义（B-S批 F7：
// dummy 校验仅拉平时序——判定与错误形态零变化）。
func TestBSF7VerifyCredentialsUniformRejection(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// 夾具：active 邮箱（密码 right-pw-1）+影子邮箱（无凭据）
	if _, err := svc.CreateMailbox(ctx, "active@example.com", "right-pw-1"); err != nil {
		t.Fatalf("active 夾具建立失败: %v", err)
	}
	if _, err := svc.CreateShadowMailbox(ctx, "shadow@example.com"); err != nil {
		t.Fatalf("shadow 夾具建立失败: %v", err)
	}

	// 不存在地址：统一 ErrInvalidCredentials
	if _, err := svc.VerifyCredentials(ctx, "nobody@example.com", "pw"); err != ErrInvalidCredentials {
		t.Fatalf("不存在地址应统一 ErrInvalidCredentials（实际 %v）", err)
	}
	// 影子地址（无凭据）：统一 ErrInvalidCredentials
	if _, err := svc.VerifyCredentials(ctx, "shadow@example.com", "pw"); err != ErrInvalidCredentials {
		t.Fatalf("影子地址应统一 ErrInvalidCredentials（实际 %v）", err)
	}
	// active 错误密码：统一 ErrInvalidCredentials
	if _, err := svc.VerifyCredentials(ctx, "active@example.com", "wrong"); err != ErrInvalidCredentials {
		t.Fatalf("active 错误密码应统一 ErrInvalidCredentials（实际 %v）", err)
	}
	// active 正确密码：成功（时序拉平不劣化成功路径——失败判定第 8 条守卫）
	m, err := svc.VerifyCredentials(ctx, "active@example.com", "right-pw-1")
	if err != nil || m == nil {
		t.Fatalf("active 正确密码应成功: %v", err)
	}
}
