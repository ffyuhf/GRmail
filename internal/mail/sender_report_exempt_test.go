// mail 域传输安全合规批定向测试（F1/A-9：TLS-RPT 报告行投递豁免——rfc8460 §5.3.1
// L1050-1051「when sending failure reports via SMTP, Sending MTAs MUST NOT honor
// MTA-STS or DANE TLSA failures」；复用 sender_sts_test 既有 stub 设施）。
// 依据：传输安全合规批_计划_20261007_15-10-00_v1.0.0 步骤 2 检查点（G2 批准
// 2026-10-07 15:13:06；enforce 域 MX 不匹配+SkipTLSPolicy 行投递通过）。
// 修改历史：
//
//	2026-10-07 15:45:00 | 新建 | 传输安全合规批 F1（计划书步骤 2 定向锚）
package mail

import (
	"context"
	"testing"

	"GRmail/internal/storage"
)

// TestSenderReportExemptSkipsSTSEnforce F1/A-9：SkipTLSPolicy=true 行对 enforce 域
// （MX 不匹配策略）照常投递——豁免判定跳过 MTA-STS 策略（MUST NOT honor 全语义；
// 对照组：同条件非豁免行 deferred 拒投=既有 TestSenderSTSEnforceMismatchReject）。
func TestSenderReportExemptSkipsSTSEnforce(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ext.io", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"}
	s := newSTSTestSender(t, srv, "enforce", false, &stubTLSRecorder{})
	if res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io", SkipTLSPolicy: true}); res.Status != storage.AttemptSent {
		t.Fatalf("豁免行（报告）应照常投递（MUST NOT honor）: %+v", res)
	}
}

// TestSenderReportExemptSkipsNoStartTLSEnforce F1 补充：豁免行对 enforce 域无
// STARTTLS 对端不触发拒明文分支（TLS 承诺态拒投对报告行豁免——两豁免位合成）。
func TestSenderReportExemptSkipsNoStartTLSEnforce(t *testing.T) {
	srv := &fakeSMTPServer{greet: "220 ok", ehlo: "250 ext.io", mail: "250 ok", rcpt: "250 ok", data: "354 go", ack: "250 ok"} // 无 STARTTLS 能力
	s := newSTSTestSender(t, srv, "enforce", true, &stubTLSRecorder{})
	if res := s.Send(context.Background(), &storage.QueueItem{RcptTo: "x@ext.io", SkipTLSPolicy: true}); res.Status != storage.AttemptSent {
		t.Fatalf("豁免行无 STARTTLS 对端应照常明文投递: %+v", res)
	}
}
