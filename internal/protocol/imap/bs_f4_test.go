// B-S安全域批 F4 新用例（计划书 v2.0.0 步骤 7 检查点承载）——IMAP debugWriter
// 行缓冲掩码状态机纯函数锚（AUTHENTICATE 命令行 initial-response 掩码+continuation
// 轮应答整行掩码——"+" 前缀 challenge 后下一行状态承载）。
// 依据：NFR-016 日志安全承载；rfc9051 §7.5 continuation 数据形态。
// 修改历史：
//
//	2026-10-09 21:38:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package imap

import "testing"

// TestBSF4MaskLine IMAP 认证帧掩码状态机：tag AUTHENTICATE 机制 ir 形态掩 ir；
// challenge（"+" 前缀）标记下一行；challenge 后行整行掩码；普通行原样。
func TestBSF4MaskLine(t *testing.T) {
	w := &debugWriter{}

	// ①AUTHENTICATE 命令行（tag+命令+机制+initial-response）——ir 掩码
	out, masked := w.maskLine("a001 AUTHENTICATE PLAIN AGFsaWNlAHMzY3JldA==\r\n")
	if out != "a001 AUTHENTICATE PLAIN [REDACTED]\r\n" || masked {
		t.Fatalf("AUTHENTICATE ir 应掩码: %q masked=%v", out, masked)
	}
	// ②普通命令行原样
	out, masked = w.maskLine("a002 SELECT INBOX\r\n")
	if out != "a002 SELECT INBOX\r\n" || masked {
		t.Fatalf("普通行应原样: %q masked=%v", out, masked)
	}
	// ③服务端 continuation challenge（"+" 前缀）——本行原样+标记下一行掩码
	out, masked = w.maskLine("+ \r\n")
	if out != "+ \r\n" || !masked {
		t.Fatalf("challenge 行应原样且标记下轮: %q masked=%v", out, masked)
	}
	// 状态置位模拟：Write 循环内 `w.afterChallenge = masked`（③ 返回 true——纯函数
	// 不自改状态，状态机归 Write；本测试模拟其置位后续断言④⑤）
	w.afterChallenge = true
	// ④challenge 后的客户端行（base64 凭据）——整行掩码
	out, masked = w.maskLine("AGFsaWNlAHMzY3JldA==\r\n")
	if out != "[REDACTED]\r\n" || masked {
		t.Fatalf("challenge 应答应整行掩码: %q masked=%v", out, masked)
	}
	// ⑤掩码后状态复位（后续普通行原样）——Write 循环以④返回 masked=false 复位
	w.afterChallenge = false
	out, masked = w.maskLine("a003 NOOP\r\n")
	if out != "a003 NOOP\r\n" || masked {
		t.Fatalf("掩码后状态应复位: %q masked=%v", out, masked)
	}
}
