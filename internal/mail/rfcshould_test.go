// mail 包 RFCSHOULD修正批次定向测试锚（计划书步骤 2/5 检查点——先红后绿形态：
// 修正前行为与下列断言相反，修正后全绿）。
// 覆盖：F-S22/F-S23（parseHeaderMap 匹配语义）、F-9（buildSubmissionReceived trace
// 构造）、F-L3（dsnRetFull 检测）。
// SRS 条目：FR-005/FR-011；TC-005/TC-011；契约 v1.17.0。
// 修改历史：
//
//	2026-09-30 19:35:00 | 新建 | RFCSHOULD修正批次（G2 批准 2026-09-30 18:28:20）
package mail

import (
	"strings"
	"testing"

	"GRmail/internal/auth"
)

// TestRFCSHOULDHeaderMapSemantics F-S22/F-S23：头值收集 TrimSpace+折叠续行展开。
func TestRFCSHOULDHeaderMapSemantics(t *testing.T) {
	raw := "Subject:  hello world  \r\nX-Fold: first line\r\n second line\r\nX-Tail: value with trailing\t\r\n\r\nbody"
	m := parseHeaderMap([]byte(raw))
	// F-S22：值首尾空白同忽略（rfc5228 §5.7 L1580-1582）
	if v := m["subject"]; len(v) != 1 || v[0] != "hello world" {
		t.Fatalf("F-S22 Subject 首尾空白应去除: %q", v)
	}
	if v := m["x-tail"]; len(v) != 1 || v[0] != "value with trailing" {
		t.Fatalf("F-S22 尾部空白/tab 应去除: %q", v)
	}
	// F-S23：折叠续行展开拼接（rfc5228 §2.7.1 L495-496——原 continue 丢弃缺陷修正）
	if v := m["x-fold"]; len(v) != 1 || v[0] != "first line second line" {
		t.Fatalf("F-S23 折叠续行应展开拼接: %q", v)
	}
}

// TestRFCSHOULDSubmissionReceived F-9：MSA 接收 trace 头构造（with ESMTPSA+tls 子句+单收件人 for）。
func TestRFCSHOULDSubmissionReceived(t *testing.T) {
	in := &Submission{
		Envelope:   auth.Envelope{MailFrom: "a@test.example", Helo: "client.example", RemoteIP: nil},
		Recipients: []string{"bob@remote.example"},
		TLSCipher:  "TLS_AES_128_GCM_SHA256",
	}
	h := buildSubmissionReceived("test.example", in)
	for _, want := range []string{"from client.example", "by test.example", "with ESMTPSA", "tls TLS_AES_128_GCM_SHA256", "for <bob@remote.example>"} {
		if !strings.Contains(h, want) {
			t.Fatalf("F-9 Received 缺 %q:\n%s", want, h)
		}
	}
	// 非 TLS 兜底：无 tls 子句
	in.TLSCipher = ""
	if strings.Contains(buildSubmissionReceived("test.example", in), " tls ") {
		t.Fatalf("F-9 非 TLS 会话不应含 tls 子句")
	}
	// 多收件人：省略 for 子句（沿收信路径先例）
	in.Recipients = []string{"a@x.example", "b@x.example"}
	if strings.Contains(buildSubmissionReceived("test.example", in), " for <") {
		t.Fatalf("F-9 多收件人应省略 for 子句")
	}
}

// TestRFCSHOULDDsnRetFull F-L3：MAIL 级 RET=FULL 检测。
func TestRFCSHOULDDsnRetFull(t *testing.T) {
	cases := []struct {
		params []DSNParam
		want   bool
	}{
		{nil, false},
		{[]DSNParam{{Keyword: "RET", Value: "HDRS"}}, false},
		{[]DSNParam{{Keyword: "RET", Value: "FULL"}}, true},
		{[]DSNParam{{Keyword: "RET", Value: "full"}}, true}, // 大小写防御
		{[]DSNParam{{Keyword: "NOTIFY", Value: "NEVER"}}, false},
	}
	for i, c := range cases {
		if got := dsnRetFull(c.params); got != c.want {
			t.Fatalf("F-L3 用例 %d: got=%v want=%v", i, got, c.want)
		}
	}
}
