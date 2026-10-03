// auth 包 RFCSHOULD修正批次定向测试锚（F-P7——SASLprep 身份准备）。
// SRS 条目：FR-007/NFR-004；TC-006；RFC4013 §2 逐条。
// 修改历史：
//
//	2026-09-30 19:35:00 | 新建 | RFCSHOULD修正批次 RF-C（G2 批准 2026-09-30 18:28:20）
package auth

import "testing"

// TestRFCSHOULDSASLprep F-P7：RFC4013 映射/规范化/禁止/双向四步。
func TestRFCSHOULDSASLprep(t *testing.T) {
	// 普通 ASCII 身份：原样（本本项目邮箱地址主流形态）
	if got, err := SASLprep("user@test.example"); err != nil || got != "user@test.example" {
		t.Fatalf("ASCII 身份应原样: got=%q err=%v", got, err)
	}
	// 映射：非 ASCII 空白（U+3000）→ SP
	if got, err := SASLprep("a\xE3\x80\x80b"); err != nil || got != "a b" {
		t.Fatalf("U+3000 应映射为 SP: got=%q err=%v", got, err)
	}
	// NFKC：全角→半角（＠U+FF20→@）
	if got, err := SASLprep("user＠test.example"); err != nil || got != "user@test.example" {
		t.Fatalf("NFKC 全角＠应规范化: got=%q err=%v", got, err)
	}
	// 禁止：ASCII 控制字符（RFC3454 C.2.1）
	if _, err := SASLprep("bad\x01identity"); err != ErrSaslprepProhibited {
		t.Fatalf("控制字符应禁止: err=%v", err)
	}
	// 禁止：私用区
	if _, err := SASLprep("badprivate"); err != ErrSaslprepProhibited {
		t.Fatalf("私用区应禁止: err=%v", err)
	}
}
