// mail 域 F6 单测：DSN 防循环检查（B-R3——原信 Auto-Submitted≠no 抑制生成）。
// 规范锚点：rfc3834 §2 L219-221「automatic responses SHOULD NOT be issued in
// response to any message which contains an Auto-Submitted header field, where
// that field has any value other than "no"」+§5 L738-739 值域 ABNF（no/
// auto-generated/auto-replied/extension）；与 worker null sender 跳过构成双防线。
// SRS 条目：FR-005（3.2 判定③伴随）；TC-005 关联锚。
// 修改历史：
//
//	2026-10-07 09:07:00 | 新建 | 队列防丢信收口批（计划书 2.3 新增测试②；
//	G2 批准 2026-10-07 01:03:52）
package mail

import (
	"context"
	"errors"
	"strings"
	"testing"

	"GRmail/internal/storage"
)

// dsnSourceWith 原信字节固定的消息源（memoSource 复用装配）。
func dsnSourceWith(raw string) *memoSource {
	blobs := newMemBlobs()
	key := sha256Hex([]byte(raw))
	_ = blobs.Write(context.Background(), key, []byte(raw))
	return &memoSource{blobs: blobs, key: key}
}

// dsnBuildItem 抑制用例的队列行（固定形态）。
func dsnBuildItem() *storage.QueueItem {
	return &storage.QueueItem{MessageID: 7, EnvelopeFrom: "sender@t.io", RcptTo: "gone@ext.io"}
}

// TestDSNAutoSubmittedSuppressed F6：原信含 Auto-Submitted: auto-replied →
// Build 返回 ErrDSNSuppressed（抑制生成——调用方置位终态防重扫死循环）。
func TestDSNAutoSubmittedSuppressed(t *testing.T) {
	orig := "Subject: original\r\nAuto-Submitted: auto-replied\r\nFrom: a@t.io\r\n\r\nbody\r\n"
	b := NewDSNBuilderService("t.io", dsnSourceWith(orig))
	_, err := b.Build(context.Background(), dsnBuildItem(), storage.AttemptResult{
		Status: storage.AttemptFailed, SMTPCode: 550, Error: "no such user",
	})
	if !errors.Is(err, ErrDSNSuppressed) {
		t.Fatalf("自动消息原信应抑制: %v", err)
	}
}

// TestDSNAutoSubmittedNoPasses F6 回归：Auto-Submitted: no 为人工投递——正常生成
// （防误拒合法 DSN——计划书 4.2 失败判定⑤防线）。
func TestDSNAutoSubmittedNoPasses(t *testing.T) {
	orig := "Subject: original\r\nAuto-Submitted: no\r\nFrom: a@t.io\r\n\r\nbody\r\n"
	b := NewDSNBuilderService("t.io", dsnSourceWith(orig))
	raw, err := b.Build(context.Background(), dsnBuildItem(), storage.AttemptResult{
		Status: storage.AttemptFailed, SMTPCode: 550, Error: "no such user",
	})
	if err != nil {
		t.Fatalf("Auto-Submitted: no 不应抑制: %v", err)
	}
	if !strings.Contains(string(raw), "multipart/report") {
		t.Fatalf("应正常生成 DSN 结构")
	}
}

// TestDSNAutoSubmittedAbsentPasses F6 回归：原信无该头（常规人工邮件）——正常生成。
func TestDSNAutoSubmittedAbsentPasses(t *testing.T) {
	orig := "Subject: original\r\nFrom: a@t.io\r\n\r\nbody\r\n"
	b := NewDSNBuilderService("t.io", dsnSourceWith(orig))
	if _, err := b.Build(context.Background(), dsnBuildItem(), storage.AttemptResult{
		Status: storage.AttemptFailed, SMTPCode: 550, Error: "no such user",
	}); err != nil {
		t.Fatalf("无 Auto-Submitted 头不应抑制: %v", err)
	}
}

// TestSuppressedByAutoSubmittedTable F6 纯函数表：字段名大小写不敏感；值域取首
// token（可选参数形如 "auto-replied; type=..."）；任何非 no 值（auto-generated/
// extension）均抑制；no（含大写 NO——值归一比较）不抑制；空头区不抑制（原信不可读
// 降级口径——退信可达性优先）。
func TestSuppressedByAutoSubmittedTable(t *testing.T) {
	cases := []struct {
		header string
		want   bool
	}{
		{"Auto-Submitted: no", false},
		{"Auto-Submitted: NO", false}, // 值归一比较（大小写不敏感）
		{"Auto-Submitted: auto-generated", true},
		{"Auto-Submitted: auto-replied", true},
		{"Auto-Submitted: AUTO-REPLIED", true}, // 字段名与值均大小写不敏感
		{"auto-submitted: auto-replied", true},
		{"Auto-Submitted: auto-replied; type=ar", true}, // 首 token 语义
		{"Auto-Submitted: some-extension", true},        // extension 值域
		{"Subject: x", false},                           // 其他头不触发
		{"", false},                                     // 空头区（降级不抑制）
	}
	for _, c := range cases {
		if got := suppressedByAutoSubmitted(c.header); got != c.want {
			t.Fatalf("suppressedByAutoSubmitted(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}
