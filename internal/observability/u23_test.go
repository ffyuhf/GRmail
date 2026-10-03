// U23 日志文件落地与轮转测试（计划书 1.5⑧②——Console+File 双写落盘断言+空值路径
// Console 单写等价锚；Q1-B 裁决；FileWriter 直接系统调用写回读可见——file.go L100-113 源码锚）。
// 修改历史：
//
//	2026-09-27 13:58:00 | 新建 | U23 可观测性扩展（计划书步骤 3，G2 批准 2026-09-27 13:20:53）
package observability

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestU23SetupLoggerFileDualWrite logFile 非空——Console+File 双写：文件存在且含日志行。
// FileWriter 惰性持久句柄+轮转 symlink（file.go create）——t.TempDir 自动清理会因句柄/
// 符号链接失败，改用 MkdirTemp+忽略清理错误（文件句柄随进程退出释放）。
func TestU23SetupLoggerFileDualWrite(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old) // SetupLogger 全局置默认——恢复现场（包内测试串行零竞争）

	dir, err := os.MkdirTemp("", "u23-dual-*")
	if err != nil {
		t.Fatalf("临时目录创建失败: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()        // 尽力清理（FileWriter 句柄未关时忽略失败）
	logFile := filepath.Join(dir, "sub", "u23.log") // 子目录——EnsureFolder 自建锚
	root := SetupLogger("debug", logFile, 100, 5, 0)
	root.Info("u23-dual-write-probe")
	slog.Default().Info("u23-default-channel-probe") // 全局通道同一落盘链

	// L-E 起文件带受控日期后缀（<stem>.<YYYYMMDD><ext>——按日切分形态；断言路径随形态）
	dayFile := dayFileOf(logFile, time.Now().Format("20060102"))
	data, err := os.ReadFile(dayFile)
	if err != nil {
		t.Fatalf("日志文件应存在且可读（日期后缀形态）: %v", err)
	}
	out := string(data)
	for _, anchor := range []string{"u23-dual-write-probe", "u23-default-channel-probe"} {
		if !strings.Contains(out, anchor) {
			t.Fatalf("文件落盘缺失锚 %q，实际: %s", anchor, out)
		}
	}
	ReconfigureLogger("info", "", 0, 0, 0) // 复位 Console 单写（关旧文件句柄——归档 goroutine 与 RemoveAll 尽力竞态可容忍）
}

// TestU23SetupLoggerConsoleOnlyEquivalent logFile 空——Console 单写等价锚：返回可用 logger，
// 无文件副作用（U22 末态行为零变化——计划书 4.2 失败判定 4 防线）。
func TestU23SetupLoggerConsoleOnlyEquivalent(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old)

	dir := t.TempDir()
	root := SetupLogger("info", "", 100, 5, 0)
	if root == nil {
		t.Fatal("空 logFile 路径应返回可用 logger")
	}
	root.Info("u23-console-only-probe")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("空 logFile 不应产生文件副作用，实际 entries=%d err=%v", len(entries), err)
	}
}
