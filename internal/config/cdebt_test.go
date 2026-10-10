// C级债务收尾批 config 域测试（F6——2026-10-10，G2 批准 15:45:40）。
// 覆盖：Close 后迟到的去抖 AfterFunc 回调零重载零广播（Reload closed 前置守卫）。
// 修改历史：
//
//	2026-10-10 16:15:00 | 新建 | C级债务收尾批（计划书步骤 1）
package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// reloadRecorder 广播计数订阅者。
type reloadRecorder struct{ calls atomic.Int32 }

func (r *reloadRecorder) OnConfigChange(*Config) { r.calls.Add(1) }

// TestCDebtReloadAfterCloseZeroBroadcast F6/C13：scheduleReload 排队去抖回调后
// Close——已排队触发的回调经 Reload closed 守卫静默退出（订阅者零回调）。
func TestCDebtReloadAfterCloseZeroBroadcast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cdebt-config.json")
	if err := Save(path, Default()); err != nil {
		t.Fatalf("写入配置: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("读取配置: %v", err)
	}
	w, err := Watch(context.Background(), path, cfg)
	if err != nil {
		t.Fatalf("启动监听: %v", err)
	}
	rec := &reloadRecorder{}
	w.Subscribe(rec)

	// 触发去抖（300ms 后回调）并在其触发前 Close——守卫路径生效。
	w.scheduleReload(slog.Default())
	if err := w.Close(); err != nil {
		t.Fatalf("关闭: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // 等待已排队回调越过触发点

	if got := rec.calls.Load(); got != 0 {
		t.Fatalf("Close 后迟到回调应零广播: %d", got)
	}
	if err := w.Reload(); err != nil {
		t.Fatalf("Close 后 Reload 应幂等 nil: %v", err)
	}
	if got := rec.calls.Load(); got != 0 {
		t.Fatalf("Close 后显式 Reload 应零广播: %d", got)
	}
}
