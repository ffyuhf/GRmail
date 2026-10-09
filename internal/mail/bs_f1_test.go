// B-S安全域批 F1 新用例（计划书 v2.0.0 步骤 1 检查点承载）——redirect 调度修复
// 白盒锚：NextAttemptAt 取投递入队时刻（未来 Date 头邮件的 redirect 不再被推迟）。
// 依据：FR-005 投递及时性伴随/NFR-007 伴随；rfc5228 §4.2 redirect 五义务（调度非义务面
// ——队列语义「尽快投递」，SentAt 保留为元数据）。
// 修改历史：
//
//	2026-10-09 21:38:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package mail

import (
	"context"
	"net"
	"testing"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// stubRedirectStore redirectStore 捕获桩（F1 断言面——捕获 StoreSubmission 入参）。
type stubRedirectStore struct {
	captured *storage.SubmissionMeta
}

func (s *stubRedirectStore) StoreSubmission(ctx context.Context, meta *storage.SubmissionMeta) error {
	s.captured = meta
	return nil
}

// TestBSF1RedirectSchedulesAtEnqueueTime 未来 Date 头邮件的 redirect 入队调度取当前
// 时刻（B-S批 F1——原取 meta.Message.SentAt 致未来 Date 推迟投递）。
func TestBSF1RedirectSchedulesAtEnqueueTime(t *testing.T) {
	stub := &stubRedirectStore{}
	svc := &InboundPipelineService{redirects: stub} // 白盒：仅装配 redirect 通道

	future := time.Now().UTC().Add(24 * time.Hour) // 恶意/误配的未来 Date 头
	meta := &storage.InboundMeta{Message: storage.MessageMeta{SentAt: future}}
	in := &Delivery{
		Envelope:   auth.Envelope{Helo: "h.x", RemoteIP: net.ParseIP("127.0.0.1"), MailFrom: "from@x.com"},
		Recipients: []string{"rcpt@x.com"},
	}

	before := time.Now().UTC()
	if err := svc.enqueueRedirect(context.Background(), meta, in, "rcpt@x.com"); err != nil {
		t.Fatalf("enqueueRedirect 失败: %v", err)
	}
	if stub.captured == nil || len(stub.captured.Items) != 1 {
		t.Fatalf("StoreSubmission 未被捕获: %+v", stub.captured)
	}
	got := stub.captured.Items[0].NextAttemptAt
	// 断言：调度时刻在入队时刻附近（before~now+缓冲），绝非未来 Date 时刻
	if got.After(before.Add(5*time.Second)) || got.Equal(future) {
		t.Fatalf("redirect 调度应取投递入队时刻（B-S批 F1）: got=%v future=%v", got, future)
	}
	if got.Before(before.Add(-5 * time.Second)) {
		t.Fatalf("redirect 调度时刻异常（早于入队前）: %v", got)
	}
}
