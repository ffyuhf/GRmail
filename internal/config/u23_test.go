// U23 LogConf 日志文件三键测试（计划书 1.5⑧①——Default 缺省档断言+旧 JSON 无键零值
// 兼容断言；沿 U21 零值兼容先例）。
// 修改历史：
//
//	2026-09-27 14:00:00 | 新建 | U23 可观测性扩展（计划书步骤 2，G2 批准 2026-09-27 13:20:53）
package config

import (
	"encoding/json"
	"testing"
)

// TestU23LogConfDefaults Default 缺省档：LogFile 空+MaxMB 100+Backups 5。
func TestU23LogConfDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Log.LogFile != "" {
		t.Fatalf("LogFile 缺省应空串（仅 Console），实际 %q", cfg.Log.LogFile)
	}
	if cfg.Log.LogFileMaxMB != 100 {
		t.Fatalf("LogFileMaxMB 缺省应 100，实际 %d", cfg.Log.LogFileMaxMB)
	}
	if cfg.Log.LogFileBackups != 5 {
		t.Fatalf("LogFileBackups 缺省应 5，实际 %d", cfg.Log.LogFileBackups)
	}
}

// TestU23LogConfLegacyJSONCompat 旧 JSON 无三键——零值解析兼容（缺省态语义=仅 Console）。
func TestU23LogConfLegacyJSONCompat(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"log":{"level":"info","sqlSlowMs":500}}`), &c); err != nil {
		t.Fatalf("旧 JSON 解析失败: %v", err)
	}
	if c.Log.LogFile != "" || c.Log.LogFileMaxMB != 0 || c.Log.LogFileBackups != 0 {
		t.Fatalf("旧 JSON 无键应零值，实际 %+v", c.Log)
	}
	var c2 Config
	if err := json.Unmarshal([]byte(`{"log":{"logFile":"/var/log/grmail.log","logFileMaxMB":20,"logFileBackups":3}}`), &c2); err != nil {
		t.Fatalf("新键 JSON 解析失败: %v", err)
	}
	if c2.Log.LogFile != "/var/log/grmail.log" || c2.Log.LogFileMaxMB != 20 || c2.Log.LogFileBackups != 3 {
		t.Fatalf("新键解析值不符，实际 %+v", c2.Log)
	}
}
