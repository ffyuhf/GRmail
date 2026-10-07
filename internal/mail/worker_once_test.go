// mail 域 M7 单测：worker stopped 通道并发退出恰一次 close（复核报告遗漏项——
// 双 goroutine 同收 ctx.Done 并发退出时 select-default 竞态致 double close panic；
// sync.Once 收敛根治）。go test -race 下 panic 必现——本用例为其回归锚。
// SRS 条目：NFR-003（4.5——worker panic=服务崩溃，可用率维度伴随）；TC-019 关联锚。
// 修改历史：
//
//	2026-10-07 09:07:00 | 新建 | 队列防丢信收口批（计划书 2.3 新增测试③；
//	G2 批准 2026-10-07 01:03:52）
package mail

import (
	"context"
	"testing"
	"time"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// onceSender 恒 sent 的投递 stub（worker 循环最小驱动）。
type onceSender struct{}

func (onceSender) Send(_ context.Context, _ *storage.QueueItem) storage.AttemptResult {
	return storage.AttemptResult{Status: storage.AttemptSent}
}

// suppressDSN 恒抑制的 DSN stub（避免 emitDSN 落库路径——本用例仅锚退出语义）。
type suppressDSN struct{}

func (suppressDSN) Build(_ context.Context, _ *storage.QueueItem, _ storage.AttemptResult) ([]byte, error) {
	return nil, ErrDSNSuppressed
}

// TestWorkerConcurrentStopClosesOnce M7：多轮启动-立即取消——双 worker 同收
// ctx.Done 并发退出窗口下 stopped 恰关闭一次（不 panic、不阻塞）；20 轮放大
// 竞态触发面（-race 检测下 double close panic 必现）。
func TestWorkerConcurrentStopClosesOnce(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		w := NewQueueWorker(&noopQueue{}, onceSender{}, suppressDSN{}, keylessSigner{}, newMemBlobs(),
			func() config.DeliveryConf { return config.DeliveryConf{} }, "t.io")
		stopped := w.Start(ctx)
		cancel() // 双 goroutine 同收 ctx.Done——并发退出窗口
		select {
		case <-stopped:
			// 恰一次关闭（第二次 close 将 panic——由 -race/运行时捕获）
		case <-time.After(2 * time.Second):
			t.Fatalf("第 %d 轮 stopped 通道未关闭", i)
		}
		// stopped 已关：再次等待应立即通过（通道关闭态幂等读）。
		select {
		case <-stopped:
		default:
			t.Fatalf("第 %d 轮 stopped 关闭态异常", i)
		}
	}
}
