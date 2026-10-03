// LogID 生成器单测（NFR-015/NFR-016）。
// 修改历史：
//
//	2026-09-16 04:45:00 | 新建 | U1 工程骨架
package observability

import (
	"context"
	"log/slog"
	"testing"
)

// TestNewLogIDFormat 形态校验：32 字符 hex（128bit 熵）
func TestNewLogIDFormat(t *testing.T) {
	id := NewLogID()
	if len(id) != 32 {
		t.Fatalf("长度不符: %d", len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Fatalf("非 hex 字符: %q", c)
		}
	}
}

// TestNewLogIDUniqueness 大样本唯一性（碰撞检测）
func TestNewLogIDUniqueness(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewLogID()
		if _, dup := seen[id]; dup {
			t.Fatalf("碰撞: %s", id)
		}
		seen[id] = struct{}{}
	}
}

// TestContextWithNewLogID ctx 绑定与提取（全链路传播机制）
func TestContextWithNewLogID(t *testing.T) {
	ctx, id := ContextWithNewLogID(context.Background(), nil)
	if len(id) != 32 {
		t.Fatalf("LogID 形态错误: %s", id)
	}
	logger := LoggerFromContext(ctx)
	if logger == nil {
		t.Fatal("ctx 未携带 logger")
	}
	// 回退路径：无绑定时返回 Default
	if LoggerFromContext(context.Background()) != slog.Default() {
		t.Fatal("未绑定 ctx 应回退 slog.Default()")
	}
}
