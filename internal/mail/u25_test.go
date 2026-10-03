// mail 域 U25 影子邮箱聚合可达单测（stub 全离线——NFR-015）。
// 覆盖锚点：SRS FR-003（聚合副本 target）/S3-W Q1-B（管道层）/Q3（聚合跳过 Sieve）；
// 契约 v1.22.0 2.3 Deliver 步 5.5。
// 修改历史：
//
//	2026-10-03 06:42:00 | 新建 | U25影子邮箱聚合可达批次（G2 批准 2026-10-02 19:41:00）
package mail

import (
	"context"
	"strings"
	"testing"

	"GRmail/internal/storage"
)

// TestU25ShadowDeliverAppendsAggregateTarget 影子投递（新建+既有 postmaster）→聚合
// target 追加（FolderName=Unregistered+Aggregate 置位+postmaster 邮箱承载）；通知保留。
func TestU25ShadowDeliverAppendsAggregateTarget(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["postmaster@test.example"] = &storage.Mailbox{ID: 50, Address: "postmaster@test.example", Status: storage.MailboxStatusShadow}

	if err := svc.Deliver(context.Background(), testDelivery("newguy@test.example"), sampleRaw()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	meta := store.saved[len(store.saved)-1]
	var agg *storage.RecipientTarget
	for i := range meta.Recipients {
		if meta.Recipients[i].Aggregate {
			agg = &meta.Recipients[i]
		}
	}
	if agg == nil {
		t.Fatal("聚合 target 缺失（Aggregate 置位行）")
	}
	if agg.FolderName != "Unregistered" || agg.Address != "postmaster@test.example" || agg.MailboxID != 50 {
		t.Fatalf("聚合 target 形态错: %+v", agg)
	}
	if meta.Notice == nil || !strings.Contains(meta.Notice.Message.Subject, "newguy@test.example") {
		t.Fatalf("影子通知应保留（Q5 裁决）: %+v", meta.Notice)
	}
}

// TestU25ExistingShadowNewMailAlsoAggregates 既有影子的新来信同样聚合（FR-003
// catch-all 全量语义——shadowPresent 双分支）；既有影子无新建→无通知。
func TestU25ExistingShadowNewMailAlsoAggregates(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["ghost@test.example"] = &storage.Mailbox{ID: 60, Address: "ghost@test.example", Status: storage.MailboxStatusShadow}

	if err := svc.Deliver(context.Background(), testDelivery("ghost@test.example"), sampleRaw()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	meta := store.saved[len(store.saved)-1]
	var hasAgg, hasShadow bool
	for _, r := range meta.Recipients {
		if r.Aggregate {
			hasAgg = true
		}
		if r.Address == "ghost@test.example" && !r.Aggregate {
			hasShadow = true
		}
	}
	if !hasAgg || !hasShadow {
		t.Fatalf("既有影子新信应同时含影子原行+聚合副本: %+v", meta.Recipients)
	}
	if len(accounts.Created) != 1 || accounts.Created[0] != "postmaster@test.example" {
		t.Fatalf("应仅新建 postmaster 影子: %v", accounts.Created)
	}
	if meta.Notice != nil {
		t.Fatal("既有影子无新建——不应有通知邮件（Q4-A 语义保持）")
	}
}

// TestU25ActiveOnlyNoAggregate 纯 active 投递零聚合 target（非影子路径零变化）。
func TestU25ActiveOnlyNoAggregate(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["a@test.example"] = &storage.Mailbox{ID: 70, Address: "a@test.example", Status: storage.MailboxStatusActive}

	if err := svc.Deliver(context.Background(), testDelivery("a@test.example"), sampleRaw()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	meta := store.saved[len(store.saved)-1]
	if len(meta.Recipients) != 1 || meta.Recipients[0].Aggregate {
		t.Fatalf("纯 active 投递应仅 1 目标且零聚合: %+v", meta.Recipients)
	}
}

// TestU25AggregateTargetSkipsSieve 聚合 target 跳过 Sieve（S3-W Q3 裁决）：runner
// 记录调用邮箱集——postmaster 聚合目标不出现，影子原行正常求值。
func TestU25AggregateTargetSkipsSieve(t *testing.T) {
	svc, _, _, store := newTestPipeline()
	recorder := &u25SieveRecorder{}
	svc.SetSieveRunner(recorder, nil)

	if err := svc.Deliver(context.Background(), testDelivery("newbie@test.example"), sampleRaw()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	meta := store.saved[len(store.saved)-1]
	var aggMailboxID int64 = -1
	for _, r := range meta.Recipients {
		if r.Aggregate {
			aggMailboxID = r.MailboxID
		}
	}
	if aggMailboxID == -1 {
		t.Fatal("聚合 target 缺失（前置条件）")
	}
	for _, called := range recorder.mailboxes {
		if called == aggMailboxID {
			t.Fatalf("聚合目标（mailbox=%d）不应进 Sieve 求值: %v", aggMailboxID, recorder.mailboxes)
		}
	}
	if len(recorder.mailboxes) == 0 {
		t.Fatal("影子原行应正常求值（Sieve 保持——仅聚合跳过）")
	}
}

// u25SieveRecorder Sieve 调用记录桩（nil 投递=无动作 keep）。
type u25SieveRecorder struct {
	mailboxes []int64
}

func (r *u25SieveRecorder) RunForMailbox(_ context.Context, mailboxID int64, _ *EvalContext) (*SieveDelivery, error) {
	r.mailboxes = append(r.mailboxes, mailboxID)
	return nil, nil
}
