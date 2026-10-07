// 提交端点对齐批 web 层测试（评审修复批次 2/8——B-S10④：改密/2FA 二步失败锁定）。
// 覆盖：二步因子连续失败达阈值后——正确因子亦 423 拒绝（会话不建立）——recordFail
// 既有计数的消费闭环（F3④ 沿 login 限流母版 s.locked 前置判定）。
// 改密双通道与 admin 二步端点与 login2FAPost 同款判定代码（password.go×2/
// admin_2fa_web.go 同构 locked 前置块），正常路径回归由 u24/u28 既有用例承载。
// SRS 条目：FR-013 安全性行伴随/NFR-005（LoginLimitConf 阈值）；G2 批准 2026-10-06 19:43:56。
// 修改历史：
//
//	2026-10-06 20:05:00 | 新增 | 提交端点对齐批（计划书 v1.0.0 步骤 7 验收用例）
package web

import (
	"net/http"
	"net/url"
	"testing"
)

// TestU29TwoStepLockedAfterFails 二步失败锁定端到端：绑定账号连续 5 次错误因子
// （阈值=limitConf 兜底档 15min/5 次）→第 6 次携带正确恢复码仍 423（锁定判定先于
// 因子验证）→会话 cookie 不签发（TC-027 判定②语义在锁定态的延伸锚）。
func TestU29TwoStepLockedAfterFails(t *testing.T) {
	e := newU24Env(t)
	codes := e.u24Bind(t)

	// 密码步：绑定账号→二步页+一次性凭据
	resp := e.u24PostLogin(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("密码步应渲染二步页: %d", resp.StatusCode)
	}
	tok := u24ExtractToken(t, readBody(t, resp))

	// 连续 5 次错误因子：每次 200 重签重试（recordFail 计数累积）
	for i := 0; i < 5; i++ {
		r := postFormCookie(t, e.ts, "/webmail/login/2fa", url.Values{"t": {tok}, "code": {"000000"}})
		if r.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次错误因子应 200 重渲染可重试: %d", i+1, r.StatusCode)
		}
		tok = u24ExtractToken(t, readBody(t, r))
		if tok == "" {
			t.Fatalf("第 %d 次重试应重签凭据", i+1)
		}
	}

	// 第 6 次：正确恢复码→423（locked 前置判定先于 VerifyLoginFactor）+无会话
	resp = postFormCookie(t, e.ts, "/webmail/login/2fa", url.Values{"t": {tok}, "code": {codes[0]}})
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("锁定态正确因子亦应 423: got %d", resp.StatusCode)
	}
	if sessionCookieOf(resp) != nil {
		t.Fatal("锁定态不得签发会话 cookie")
	}
}
