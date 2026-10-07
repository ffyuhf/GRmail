// web 域安全原子性批 F10 纯函数单测：probeHostOf 提取与 setupProbeAllow 限速窗口。
// 依据：安全原子性批计划书 v1.0.1 F10（G2 批准 2026-10-06 18:12:59）；SRS FR-015。
// 修改历史：
//
//	2026-10-06 18:45:00 | 新建 | 安全原子性批（评审修复批次 1/8）
package web

import (
	"testing"
	"time"
)

// TestProbeHostOf F10：mysql tcp() 形态/PG URL 形态/解析失败空串三态。
func TestProbeHostOf(t *testing.T) {
	if got := probeHostOf("mysql", "user:pass@tcp(192.168.1.5:3306)/db"); got != "192.168.1.5" {
		t.Fatalf("mysql host 提取: %q", got)
	}
	if got := probeHostOf("mysql", "user:pass@tcp([2001:db8::1]:3306)/db"); got != "2001:db8::1" {
		t.Fatalf("mysql IPv6 提取: %q", got)
	}
	if got := probeHostOf("postgres", "postgres://u:p@10.0.0.2:5432/db"); got != "10.0.0.2" {
		t.Fatalf("pg host 提取: %q", got)
	}
	if got := probeHostOf("mysql", "no-tcp-form"); got != "" {
		t.Fatalf("解析失败应空串: %q", got)
	}
	if got := probeHostOf("sqlite", "any"); got != "" {
		t.Fatalf("sqlite 不拦截: %q", got)
	}
}

// TestSetupProbeAllow F10：窗口内限 10 次、第 11 次拒绝；窗口滑动后恢复。
func TestSetupProbeAllow(t *testing.T) {
	base := time.Now()
	for i := 0; i < 10; i++ {
		if !setupProbeAllow("1.2.3.4", base.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("第 %d 次应放行", i+1)
		}
	}
	if setupProbeAllow("1.2.3.4", base.Add(20*time.Second)) {
		t.Fatalf("窗口内第 11 次应拒绝")
	}
	if !setupProbeAllow("1.2.3.4", base.Add(6*time.Minute)) {
		t.Fatalf("窗口滑出后应恢复放行")
	}
	if !setupProbeAllow("5.6.7.8", base) {
		t.Fatalf("独立 IP 不受他人窗口影响")
	}
}
