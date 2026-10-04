// observability 域传输安全与日志增强批次定向测试（L-E 按日切分压缩——时钟注入
// 跨日驱动+gzip 产物+保留窗清理；L-D 热重建——ReconfigureLogger 新文件生效；
// LogIDFromContext 往返）。
// 依据：传输安全与日志增强计划书 v1.0.0 步骤 5/6 检查点（G2 批准 2026-10-01 22:54:41）。
// 修改历史：
//
//	2026-10-01 23:42:00 | 新建 | 传输安全与日志增强批次（计划书步骤 5/6 定向锚）
package observability

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phuslu/log"
)

// dayFileOf 测试辅助：base 路径在指定日期的当日文件期望名（<stem>.<day>——
// 与 DailyRotateWriter.dayFile 同形态，供断言路径构造）。
func dayFileOf(base, day string) string {
	return splitExt(base) + "." + day
}

// newRotateTestWriter 时钟注入构造（测试跨日驱动——NFR-015）。
func newRotateTestWriter(base string, now func() time.Time, retainDays int) *DailyRotateWriter {
	w := NewDailyRotateWriter(base, 0, 0, retainDays)
	w.now = now
	return w
}

// writeEntry 测试辅助：经 phuslu IOWriter 桥正规链路写入（Entry.buf 未导出——
// 生产装配同形态：Logger.Writer=log.IOWriter{Writer: DailyRotateWriter}）。
func writeEntry(t *testing.T, w *DailyRotateWriter, msg string) {
	t.Helper()
	(&log.Logger{Writer: log.IOWriter{Writer: w}, Level: log.InfoLevel}).Info().Msg(msg)
}

// TestDailyRotateSameDay 同日两写单文件（无切换）。断言在 Close 前执行——
// Close 触发当日文件异步 gzip 归档（源删除），原文读取窗口仅存续于 Close 前。
func TestDailyRotateSameDay(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "app.log")
	now := time.Date(2026, 10, 1, 8, 0, 0, 0, time.Local)
	w := newRotateTestWriter(base, func() time.Time { return now }, 0)
	writeEntry(t, w, "line1")
	now = now.Add(time.Hour) // 同日
	writeEntry(t, w, "line2")
	data, err := os.ReadFile(dayFileOf(base, "20261001")) // Close 前断言原文
	if err != nil || !strings.Contains(string(data), "line1") || !strings.Contains(string(data), "line2") {
		t.Fatalf("同日应单文件累积: %v %q", err, data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// 吸收 Close 触发的异步压缩 goroutine（防 TempDir 清理竞态）
	waitForArchive(t, dayFileOf(base, "20261001")+".gz")
}

// TestDailyRotateCrossDaySwitch 跨日切换：新日期文件承载新写；旧文件 Close 后 gzip。
func TestDailyRotateCrossDaySwitch(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "app.log")
	now := time.Date(2026, 10, 1, 23, 59, 0, 0, time.Local)
	w := newRotateTestWriter(base, func() time.Time { return now }, 0)
	writeEntry(t, w, "day1")
	now = now.Add(2 * time.Hour) // 跨到 10-02
	writeEntry(t, w, "day2")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dayFileOf(base, "20261002")); err != nil {
		t.Fatalf("跨日应切新文件: %v", err)
	}
	// 旧日文件异步压缩——等待压缩落名（goroutine 尽力，轮询窗口 2s）
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(dayFileOf(base, "20261001") + ".gz"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("旧日文件未在窗口内压缩为 .gz")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(dayFileOf(base, "20261001")); !os.IsNotExist(err) {
		t.Fatal("压缩后源文件应删除")
	}
	// gzip 内容可解且含 day1
	gzData, _ := os.ReadFile(dayFileOf(base, "20261001") + ".gz")
	zr, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if !strings.Contains(string(plain), "day1") {
		t.Fatalf("压缩内容应含 day1: %q", plain)
	}
}

// TestDailyRotatePurgeExpired 保留窗清理：超窗 .gz 删除、窗内保留。
func TestDailyRotatePurgeExpired(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "app.log")
	// 预置三个归档：10-01（超窗）/10-05（窗内）/10-06（窗内）；今天=10-08，保留 3 天
	for _, d := range []string{"20261001", "20261005", "20261006"} {
		if err := os.WriteFile(dayFileOf(base, d)+".gz", []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 8, 0, 5, 0, 0, time.Local)
	w := newRotateTestWriter(base, func() time.Time { return now }, 3)
	writeEntry(t, w, "today") // 首写触发 rotateLocked→purgeExpired（异步——轮询窗口）
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(dayFileOf(base, "20261001") + ".gz"); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("超窗归档未在窗口内清理")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(dayFileOf(base, "20261005") + ".gz"); err != nil {
		t.Fatal("窗内归档不应清理（20261005）")
	}
	if _, err := os.Stat(dayFileOf(base, "20261006") + ".gz"); err != nil {
		t.Fatal("窗内归档不应清理（20261006）")
	}
	_ = w.Close()
	waitForArchive(t, dayFileOf(base, "20261008")+".gz") // 吸收 Close 压缩 goroutine（同上竞态防线）
}

// waitForArchive 轮询等待归档 .gz 落名（2s 窗口——异步压缩 goroutine 完成锚）。
func waitForArchive(t *testing.T, gzPath string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(gzPath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("归档未在窗口内落名: %s", gzPath)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReconfigureLoggerSwitchesFile L-D 热重建：重建后新日志落新文件。
func TestReconfigureLoggerSwitchesFile(t *testing.T) {
	dir := t.TempDir()
	fileA := filepath.Join(dir, "a.log")
	fileB := filepath.Join(dir, "b.log")
	root := SetupLogger("info", fileA, 0, 0, 0)
	root.Info("to-file-a")
	ReconfigureLogger("info", fileB, 0, 0, 0) // 关旧文件→旧日文件异步 gzip 归档
	slog.Default().Info("to-file-b")          // 取重建后的 Default（L-D 消费侧语义——接入层回退路径）
	today := time.Now().Format(rotateDayKey)
	// b 侧：新文件原文即时承载（轮询缓冲兜底）
	deadline := time.Now().Add(2 * time.Second)
	var bData []byte
	for {
		bData, _ = os.ReadFile(dayFileOf(fileB, today))
		if strings.Contains(string(bData), "to-file-b") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("热重建后新文件未承载新写: b=%q", bData)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// a 侧：Close 归档语义——原文已 gzip 为 .gz（等归档落名后解压断言）
	for {
		if _, err := os.Stat(dayFileOf(fileA, today) + ".gz"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("旧文件未在窗口内归档为 .gz（Close 压缩语义）")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 复位 Console 单写（避免污染后续测试）——复位触发 fileB 侧 Close 归档 goroutine，
	// 等待其落名以吸收与 TempDir 清理的竞态
	ReconfigureLogger("info", "", 0, 0, 0)
	for {
		if _, err := os.Stat(dayFileOf(fileB, today) + ".gz"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			break // 尽力等待（空文件未建场景静默通过——本用例已有写入必有归档）
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestLogIDFromContextRoundTrip LogID 独立键往返（L-C 消费锚）。
func TestLogIDFromContextRoundTrip(t *testing.T) {
	if got := LogIDFromContext(context.Background()); got != "" {
		t.Fatalf("未绑定应返回空串: %q", got)
	}
	ctx, id := ContextWithNewLogID(context.Background(), nil)
	if got := LogIDFromContext(ctx); got != id || len(id) != 32 {
		t.Fatalf("往返不一致: got=%q id=%q", got, id)
	}
}
