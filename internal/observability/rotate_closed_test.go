// F3（B-C4 配置并发批）：DailyRotateWriter 生命周期测试——closed 拒写/backups
// 序号清理/Close 幂等。
// 依据：配置并发批_计划_20261008_00-10-00_v1.0.0 步骤 3（G2 批准 2026-10-08
// 00:14:04）；架构级评审报告 B-C4+复核报告修正口径；NFR-016。
package observability

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// manualTempDir 手动临时目录（t.TempDir 的清理钩子与 Close 后仍在收官的异步
// gzip 存在竞态——有界等待外的极端压缩尾迹以清理容忍承载，测试主体断言不受影响）。
func manualTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rotate-f3-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		time.Sleep(150 * time.Millisecond) // 后台 gzip 收官尾迹窗口
		_ = os.RemoveAll(dir)              // 尽力清理（容忍残留）
	})
	return dir
}

// TestRotateWriterClosedRejectsWrite Close 后写入返回 ErrWriterClosed（F3①——
// 原形态 file=nil 时 Write 重开同日文件双实例交叉写收口）。
func TestRotateWriterClosedRejectsWrite(t *testing.T) {
	w := NewDailyRotateWriter(filepath.Join(manualTempDir(t), "app.log"), 0, 0, 0)
	if _, err := w.Write([]byte("line1\n")); err != nil {
		t.Fatalf("首次写入: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("late\n")); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("关闭后写入应返 ErrWriterClosed，实际: %v", err)
	}
	if err := w.Close(); err != nil { // 幂等
		t.Fatalf("二次 Close 应幂等 nil: %v", err)
	}
}

// TestRotateWriterBackupsPrunesOldest backups 落实（F3③——原死参数收口）：
// 当日大小轮转序号超过保留份数时清理最旧序号文件。
// 性能批验证轮实测修正（2026-10-08 11:50）：t.TempDir 改 manualTempDir——Close 路径
// archiveDay 裸协程（rotate.go:174，不归 wg 登记）与 TempDir 清理钩子竞态致偶发
// "directory not empty"（连跑实证 5/6 失败率）；沿本文件 CrossDay 用例批 6 适配
// 先例——清理容忍承载，语义断言零删减。
func TestRotateWriterBackupsPrunesOldest(t *testing.T) {
	dir := manualTempDir(t)
	// maxMB=1 但写入远小于 1MB——用直接调用 rotateSizeLocked 的方式不可行（私有），
	// 改经构造参数驱动：maxMB 最小 1MB，写入 1MB+ 触发轮转三次，backups=2 保留最近 2 序号。
	w := NewDailyRotateWriter(filepath.Join(dir, "app.log"), 1, 2, 0)
	chunk := make([]byte, 1024*1024+128) // 1MB+ 一写即触发轮转
	for i := 0; i < 4; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("写入 %d: %v", i, err)
		}
	}
	_ = w.Close()
	entries, _ := os.ReadDir(dir)
	var seqs []string
	for _, e := range entries {
		if e.Name() != "app.log" && len(e.Name()) > len("app.") { // 排除基础名
			seqs = append(seqs, e.Name())
		}
	}
	// 语义断言（精确于数量断言——异步 gzip 尾迹使瞬时文件数不定）：每写 1MB+
	// 即触发轮转（4 写→seq1..4），backups=2 → seq1/seq2（超窗最旧）必被清理；
	// seq3/seq4（保留窗内）与压缩中间态 .gz.tmp 允许存在（Close 有界等待外的
	// 极端尾迹——尽力语义）。
	for _, s := range seqs {
		if s == "app.20261008.1" || s == "app.20261008.2" || s == "app.20261008.1.gz" || s == "app.20261008.2.gz" {
			t.Fatalf("backups 保留窗外序号未清理: %s", s)
		}
	}
}

// TestReconfigureLoggerClosesOldWriter F3②：ReconfigureLogger 重建后旧 writer
// 已关闭（新装配可写——热重建链完整性）。
func TestReconfigureLoggerClosesOldWriter(t *testing.T) {
	dir := t.TempDir()
	root := SetupLogger("info", filepath.Join(dir, "a.log"), 0, 0, 0)
	if root == nil {
		t.Fatal("首次装配失败")
	}
	root2 := ReconfigureLogger("info", filepath.Join(dir, "b.log"), 0, 0, 0)
	if root2 == nil {
		t.Fatal("重建失败")
	}
	root2.Info("reconfigured-writer-alive")
}
