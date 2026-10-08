// 性能批 F1（B-P2，评审修复批次 7）验收测试：HTML-only 邮件派生兜底。
// 依据：性能批_计划_20261008_10-08-00_v1.0.0 步骤 1（G2 批准 2026-10-08 10:13:49）；
// SRS FR-013 正文检索子项覆盖面收口；rfc2046 §5.1.4 递增序（plain 为最朴素呈现）。
package mail

import (
	"strings"
	"testing"
)

// TestBodyCacheOfHTMLOnlyDerived 纯 HTML 正文输入派生非空缓存——原恒空（BodyText
// 空串映射 NULL）致此类邮件正文搜索永不命中的缺陷收口断言。
func TestBodyCacheOfHTMLOnlyDerived(t *testing.T) {
	raw := []byte("From: a@b.c\r\nSubject: s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<html><body><p>促销活动进行中</p><div>全场五折</div></body></html>\r\n")
	got := BodyCacheOf(raw)
	if !strings.Contains(got, "促销活动进行中") || !strings.Contains(got, "全场五折") {
		t.Fatalf("HTML-only 派生缓存应含正文文本, got %q", got)
	}
}

// TestBodyCacheOfPlainPreferred alternative 双形态 plain part 优先既有语义保持
// （F1 仅在 BodyText 为空时兜底——已有路径零触碰）。
func TestBodyCacheOfPlainPreferred(t *testing.T) {
	raw := []byte("From: a@b.c\r\nContent-Type: multipart/alternative; boundary=XX\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\n纯文本正文\r\n" +
		"--XX\r\nContent-Type: text/html\r\n\r\n<p>富文本</p>\r\n--XX--\r\n")
	if got := BodyCacheOf(raw); got != "纯文本正文" {
		t.Fatalf("plain part 优先既有语义应保持, got %q", got)
	}
}

// TestBodyCacheOfTruncationKept 截断上限保持（bodyCacheMaxBytes 既有工程常量）。
func TestBodyCacheOfTruncationKept(t *testing.T) {
	body := strings.Repeat("x", bodyCacheMaxBytes+100)
	raw := []byte("From: a@b.c\r\nContent-Type: text/plain\r\n\r\n" + body)
	if got := BodyCacheOf(raw); len(got) != bodyCacheMaxBytes {
		t.Fatalf("截断上限应保持 %d, got %d", bodyCacheMaxBytes, len(got))
	}
}

// TestBodyCacheOfHTMLDerivedTruncated HTML 派生路径同样受截断上限约束。
func TestBodyCacheOfHTMLDerivedTruncated(t *testing.T) {
	html := "<p>" + strings.Repeat("y", bodyCacheMaxBytes+50) + "</p>"
	raw := []byte("From: a@b.c\r\nContent-Type: text/html\r\n\r\n" + html)
	if got := BodyCacheOf(raw); len(got) > bodyCacheMaxBytes {
		t.Fatalf("派生缓存应受截断上限约束, got %d", len(got))
	}
}
