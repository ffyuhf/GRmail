// acme 请求级超时常量锁（访问协议资源限制批 u30——F7/M4-2）：
// lego v4 Obtain 族 API 不接收 ctx，超时经 lego.Config.HTTPClient.Timeout 承载
// （obtain 内注入——形态锚见 acme.go obtain 注释）；本用例锁定常量防误改。
// 修改历史：
//
//	2026-10-07 14:12:00 | 新建 | 访问协议资源限制批（计划书 v1.0.0 步骤 7，
//	G2 批准 2026-10-07 14:00:02）
package transport

import (
	"testing"
	"time"
)

// TestACMERequestTimeoutConstant F7：请求级超时预算常量锁（2min——DNS-01
// 传播等待窗口内单请求充分；整链上界≈请求数×本预算，每日 tick 重试兜底）。
func TestACMERequestTimeoutConstant(t *testing.T) {
	if acmeRequestTimeout != 2*time.Minute {
		t.Fatalf("acmeRequestTimeout 应为 2min，得 %v", acmeRequestTimeout)
	}
}
