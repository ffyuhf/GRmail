// F1（A-10+D3+C14 配置并发批）：config 快照竞态根治与 Save 崩溃安全测试。
// 依据：配置并发批_计划_20261008_00-10-00_v1.0.0 步骤 1（G2 批准 2026-10-08
// 00:14:04）；架构级评审报告 A-10+复核报告 A− 修正口径；NFR-016/NFR-005。
package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestCurrentReturnsIndependentCopy Current 返回深拷贝副本——调用方修改副本
// 不影响内部实例（F1 快照隔离锚）。
func TestCurrentReturnsIndependentCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Default()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	w, err := Watch(context.Background(), path, Default())
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer func() { _ = w.Close() }()
	before := w.Current().Server.Domain
	cp := w.Current()
	cp.Server.Domain = "mutated.example"
	if w.Current().Server.Domain != before {
		t.Fatalf("副本修改泄漏到内部实例: before=%q after=%q", before, w.Current().Server.Domain)
	}
}

// TestCurrentConcurrentReadsWithReloadSave（-race 锚）：并发 Current 读+并发
// Reload 写零数据竞争（修复前 Current 返回内部指针——saveConfig 就地 modify 与
// 无锁读构成 data race，-race 必报）。
func TestCurrentConcurrentReadsWithReloadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := Save(path, Default()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	w, err := Watch(context.Background(), path, Default())
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	defer func() { _ = w.Close() }()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ { // 并发读者：持续快照读取（F1 修复后读副本零共享）
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = w.Current().Server.Domain
					_ = w.Current().Mail.MaxMessageSizeBytes
				}
			}
		}()
	}
	for i := 0; i < 8; i++ { // 并发写者：saveConfig 拷贝改写链（Reload 重建内部实例）
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			d := "writer" + string(rune('a'+n))
			if err := Save(path, func() *Config { c := Default(); c.Server.Domain = d; return c }()); err != nil {
				t.Errorf("Save: %v", err)
			}
			if err := w.Reload(); err != nil {
				t.Errorf("Reload: %v", err)
			}
		}(i)
	}
	// 写者完成后停止读者
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(stop)
	}()
	wg.Wait()
}

// TestSaveCrashSafeForm Save 崩溃安全形态（F1/C14）：唯一临时名（并发 Save 互不
// 覆写——写入后无残留 .tmp-* 中间态）+内容完整可回读。
func TestSaveCrashSafeForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c1, c2 := Default(), Default()
	c1.Server.Domain = "one.example"
	c2.Server.Domain = "two.example"
	var wg sync.WaitGroup
	for _, c := range []*Config{c1, c2} { // 并发 Save——临时名唯一互不覆写
		wg.Add(1)
		go func(cc *Config) {
			defer wg.Done()
			if err := Save(path, cc); err != nil {
				t.Errorf("Save: %v", err)
			}
		}(c)
	}
	wg.Wait()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	var got Config
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if got.Server.Domain != "one.example" && got.Server.Domain != "two.example" {
		t.Fatalf("并发 Save 内容损坏: %q", got.Server.Domain)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if hasTmpSegment(e.Name()) { // 唯一临时名应已被 rename 消费——零残留
			t.Fatalf("残留临时文件: %s", e.Name())
		}
	}
}

// hasTmpSegment 文件名含 ".tmp-" 段判定（CreateTemp 临时名标记）。
func hasTmpSegment(name string) bool {
	for i := 0; i+5 <= len(name); i++ {
		if name[i:i+5] == ".tmp-" {
			return true
		}
	}
	return false
}
