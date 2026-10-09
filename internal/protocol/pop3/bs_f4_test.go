// B-S安全域批 F4 新用例（计划书 v2.0.0 步骤 7 检查点承载）——AUTH 命令行凭据掩码
// 纯函数锚（POP3 侧；challenge 轮整行掩码由 authRedact 状态承载——会话级行为）。
// 依据：NFR-016 日志安全承载（ProtocolDebug 开启时明文口令不落 30 天日志文件）。
// 修改历史：
//
//	2026-10-09 21:38:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package pop3

import "testing"

// TestBSF4RedactAuthLine AUTH 命令行 initial-response 参数整段掩码（保留机制名）；
// 非认证命令原样；无参数形态原样（凭据走 challenge 轮）。
func TestBSF4RedactAuthLine(t *testing.T) {
	if got := redactAuthLine("AUTH PLAIN AGFsaWNlAHMzY3JldA==\r\n"); got != "AUTH PLAIN [REDACTED]\r\n" {
		t.Fatalf("AUTH initial-response 应掩码: %q", got)
	}
	if got := redactAuthLine("CAPA\r\n"); got != "CAPA\r\n" {
		t.Fatalf("非认证命令应原样: %q", got)
	}
	if got := redactAuthLine("AUTH PLAIN\r\n"); got != "AUTH PLAIN\r\n" {
		t.Fatalf("无参数形态应原样（凭据走 challenge 轮）: %q", got)
	}
}
