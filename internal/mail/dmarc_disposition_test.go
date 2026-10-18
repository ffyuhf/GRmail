// DMARC处置实施批测试（SRS v1.3.0 FR-008 判定③ DMARC p 值处置三终态/TC-033 矩阵——
// G2 批准 2026-10-17 22:46「全A批准：E-1 A / E-2 A / E-3 A / E-4 A / E-5 A」；
// S5-REV-20261017-002）。
// 覆盖锚点：TC-033 DMARC p 值处置矩阵（p=reject 拒收格 5xx+零落库零 Blob/p=quarantine
// 隔离格 Junk 落位/p=none·无记录·结论 none·temperror·permerror·开关关闭照收格/
// 空路径恒豁免/照收格 A-R 头与 SPF·DKIM 档位行为零变化锚/开关热生效时序格）。
// 实现形态：disposition 由验证器预计算（E-1-A）——本文件消费侧矩阵以
// res.DMARCDisposition 取值模拟验证器各结论产出（verify 侧预计算单元锚归
// verify_test.go 域；拒收/隔离/照收三终态的管道消费全链在此锚定）。
// 修改历史：
//
//	2026-10-17 23:04:00 | 新建 | DMARC处置实施批（计划书步骤 4）
//	2026-10-18 00-40-00 | 扩展 | DMARC收尾批（计划书步骤 4）：新增
//	  TestDMARCQuarantineEmptyPathExempt——空路径×p=quarantine 恒豁免格（DMARC 批
//	  G3 漏检格堵口；SRS v1.3.0 FR-008 判定③/REQ-20261017-006）
package mail

import (
	"context"
	"errors"
	"testing"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// ───────────────────────── TC-033 拒收格（纯函数逐格） ─────────────────────────

// TestDMARCRejectPolicyMatrix p=reject 拒收矩阵（TC-033 拒收格——5xx+零落库；
// disposition 取值模拟验证器预计算产出：仅「结论 fail 且 p=reject」时为 "reject"）。
func TestDMARCRejectPolicyMatrix(t *testing.T) {
	svc, _, _, _ := newTestPipeline()

	cases := []struct {
		name          string
		disposition   string // 验证器预计算分派结论（""=不分派）
		mailFrom      string
		wantReject    bool
		wantReasonSub string
	}{
		// p=reject 且 fail → 拒收（REQ-20261017-005）
		{name: "p=reject且fail-拒收", disposition: "reject", mailFrom: "a@b.io", wantReject: true, wantReasonSub: "DMARC p=reject 且 fail 拒收"},
		// 空路径恒豁免（REQ-20261017-006——退信防丢，优先于一切处置）
		{name: "空路径-p=reject-照收（恒豁免）", disposition: "reject", mailFrom: "", wantReject: false},
		// p=quarantine → 非拒收路径（隔离经 Deliver 步 5.7——拒收判定恒放行）
		{name: "p=quarantine且fail-拒收判定放行（隔离归步5.7）", disposition: "quarantine", mailFrom: "a@b.io", wantReject: false},
		// p=none/无记录/结论 none·temperror·permerror/开关关闭 → 验证器 disposition=""
		// （E-1-A 预计算口径——REQ-20261017-006 恒照收仅 A-R 标注）
		{name: "p=none-照收", disposition: "", mailFrom: "a@b.io", wantReject: false},
		{name: "无记录-照收", disposition: "", mailFrom: "a@b.io", wantReject: false},
		{name: "结论temperror-照收", disposition: "", mailFrom: "a@b.io", wantReject: false},
		{name: "结论permerror-照收", disposition: "", mailFrom: "a@b.io", wantReject: false},
		{name: "开关关闭-照收（disposition恒空）", disposition: "", mailFrom: "a@b.io", wantReject: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &auth.VerifyResults{SPF: "pass", DKIM: "pass", DMARC: "fail", ARC: "none", DMARCDisposition: tc.disposition}
			in := testDelivery("x@test.example")
			in.Envelope.MailFrom = tc.mailFrom
			err := svc.checkRejectionPolicy(context.Background(), in, res, sampleRaw())
			if tc.wantReject {
				if err == nil {
					t.Fatalf("应拒收: %+v", tc)
				}
				rej, ok := err.(*RejectPolicyError)
				if !ok {
					t.Fatalf("应返回 RejectPolicyError: %T %v", err, err)
				}
				if rej.Code != 550 {
					t.Fatalf("应答码应 550: %d", rej.Code)
				}
				if !contains(rej.Reason, tc.wantReasonSub) {
					t.Fatalf("原因子串不符: got %q want %q", rej.Reason, tc.wantReasonSub)
				}
				// From 域可观测锚（手册 4.12 运维定位链——Reason 含 From 域）
				if !contains(rej.Reason, "example.com") {
					t.Fatalf("Reason 应含 From 域（sampleRaw 发件域 example.com）: %q", rej.Reason)
				}
			} else if err != nil {
				t.Fatalf("应照收: %v", err)
			}
		})
	}
}

// TestDMARCRejectDeliverShortCircuits p=reject 拒收短路全链（TC-033 拒收格判定：
// 「DATA 结束后 5xx 且零落库」——Deliver 层：拒收即零 Blob 零落库事务）。
func TestDMARCRejectDeliverShortCircuits(t *testing.T) {
	svc, blobs, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	deliver := newDeliverWithDisposition(t, svc, "reject")
	err := svc.Deliver(context.Background(), deliver, sampleRaw())
	if err == nil {
		t.Fatal("p=reject 且 fail 应拒收（Deliver 短路）")
	}
	var rej *RejectPolicyError
	if !errors.As(err, &rej) || rej.Code != 550 {
		t.Fatalf("应 RejectPolicyError 550: %T %v", err, err)
	}
	if len(store.saved) != 0 {
		t.Fatalf("拒收格零落库（messages 事务）: %d", len(store.saved))
	}
	if len(blobs.data) != 0 {
		t.Fatalf("拒收格零 Blob: %d", len(blobs.data))
	}
}

// ───────────────────────── TC-033 隔离格（Deliver 全链） ─────────────────────────

// TestDMARCQuarantineDeliversToJunk p=quarantine 隔离投递（TC-033 隔离格判定：
// 「250 且邮件落入收件人 Junk 文件夹〔非收件箱〕」——FolderName="Junk" 落点锚，
// E-3-A archiveToInbox GetFolderByName 既有解析链承载）。
func TestDMARCQuarantineDeliversToJunk(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	deliver := newDeliverWithDisposition(t, svc, "quarantine")
	deliver.Recipients = []string{"bob@test.example"}
	if err := svc.Deliver(context.Background(), deliver, sampleRaw()); err != nil {
		t.Fatalf("隔离投递应成功（250 语义）: %v", err)
	}
	meta := store.saved[0]
	if len(meta.Recipients) != 1 {
		t.Fatalf("应恰 1 收件目标: %+v", meta.Recipients)
	}
	if meta.Recipients[0].FolderName != "Junk" {
		t.Fatalf("隔离格应落 Junk（E-3-A）: %+v", meta.Recipients[0])
	}
}

// TestDMARCQuarantineSkipsSieve 隔离邮件跳过 Sieve（E-4-A——落点固定 Junk 不被
// 收件人脚本重排；TC-033 隔离格判定全场景稳定锚）。
func TestDMARCQuarantineSkipsSieve(t *testing.T) {
	svc, _, _, _ := newTestPipeline()
	recorder := &u25SieveRecorder{}
	svc.SetSieveRunner(recorder, nil)

	deliver := newDeliverWithDisposition(t, svc, "quarantine")
	if err := svc.Deliver(context.Background(), deliver, sampleRaw()); err != nil {
		t.Fatalf("隔离投递应成功: %v", err)
	}
	if len(recorder.mailboxes) != 0 {
		t.Fatalf("隔离邮件不应进 Sieve 求值（E-4-A）: %v", recorder.mailboxes)
	}
}

// TestDMARCQuarantineAggregateUntouched 隔离改写不触及聚合 target（影子来信隔离场景：
// 收件目标落 Junk；U25 聚合 target 自带 Unregistered 落点保持——管理员聚合视图不受
// DMARC 隔离改写；步 5.7 先于步 5.5 追加的定序锚）。
func TestDMARCQuarantineAggregateUntouched(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["ghost@test.example"] = &storage.Mailbox{ID: 60, Address: "ghost@test.example", Status: storage.MailboxStatusShadow}

	deliver := newDeliverWithDisposition(t, svc, "quarantine")
	deliver.Recipients = []string{"ghost@test.example"} // 预置影子收件人（缺省 bob 错位修正）
	if err := svc.Deliver(context.Background(), deliver, sampleRaw()); err != nil {
		t.Fatalf("隔离投递应成功: %v", err)
	}
	meta := store.saved[len(store.saved)-1]
	var ghost, agg bool
	for _, r := range meta.Recipients {
		switch {
		case r.Aggregate:
			if r.FolderName != "Unregistered" {
				t.Fatalf("聚合 target 落点应保持 Unregistered: %+v", r)
			}
			agg = true
		case r.Address == "ghost@test.example":
			if r.FolderName != "Junk" {
				t.Fatalf("影子收件目标应隔离落 Junk: %+v", r)
			}
			ghost = true
		}
	}
	if !ghost || !agg {
		t.Fatalf("应含影子目标（Junk）+聚合目标（Unregistered）: %+v", meta.Recipients)
	}
}

// ───────────────────────── TC-033 照收格（零变化锚） ─────────────────────────

// TestDMARCPassThroughUnchanged 照收格零变化锚（TC-033 判定原文：「照收格的 A-R 头
// 与 SPF/DKIM 档位行为和 v1.2.0 基线逐格一致」——disposition="" 时 FolderName 空
// 〔收件箱默认〕+A-R 头与验证结论缓存列原样传递+档位判定不参与）。
func TestDMARCPassThroughUnchanged(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	deliver := newDeliverWithDisposition(t, svc, "")
	deliver.Recipients = []string{"bob@test.example"}
	if err := svc.Deliver(context.Background(), deliver, sampleRaw()); err != nil {
		t.Fatalf("照收格应正常投递: %v", err)
	}
	meta := store.saved[0]
	if len(meta.Recipients) != 1 || meta.Recipients[0].FolderName != "" {
		t.Fatalf("照收格应收件箱默认（FolderName 空）: %+v", meta.Recipients)
	}
	// A-R 头与四元组结论原样（零变化锚——stub 产物逐字节传递）
	if meta.Message.AuthResultsHeader != "Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com" {
		t.Fatalf("A-R 头应原样传递（零变化锚）: %q", meta.Message.AuthResultsHeader)
	}
	if meta.Message.SPFResult != "pass" || meta.Message.DKIMResult != "pass" || meta.Message.DMARCResult != "fail" {
		t.Fatalf("验证结论缓存列应原样: %+v", meta.Message)
	}
}

// ───────────────────────── TC-033 开关热生效时序格 ─────────────────────────

// TestDMARCDispositionHotToggle 开关热生效时序（TC-033 判定：「开关关闭格经
// 『关闭→投递→照收』时序核对」——disposition 随 dmarcEnabled 开关由验证器实时产出：
// 隔离态投递落 Junk；关闭（disposition 空）后下一封照收落收件箱——快照语义热生效锚）。
func TestDMARCDispositionHotToggle(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	// 开启态：隔离落 Junk
	if err := svc.Deliver(context.Background(), newDeliverWithDisposition(t, svc, "quarantine"), sampleRaw()); err != nil {
		t.Fatalf("开启态隔离投递应成功: %v", err)
	}
	if f := store.saved[0].Recipients[0].FolderName; f != "Junk" {
		t.Fatalf("开启态应落 Junk: %q", f)
	}
	// 关闭态（dmarcEnabled=false→验证器 disposition 恒空——E-1-A 预计算口径）：
	// 下一封照收落收件箱，全程无重启
	if err := svc.Deliver(context.Background(), newDeliverWithDisposition(t, svc, ""), sampleRaw()); err != nil {
		t.Fatalf("关闭态照收应成功: %v", err)
	}
	if f := store.saved[1].Recipients[0].FolderName; f != "" {
		t.Fatalf("关闭态应恢复收件箱默认（热生效）: %q", f)
	}
}

// TestDMARCQuarantineEmptyPathExempt 空路径 × p=quarantine 恒豁免（DMARC收尾批——
// SRS v1.3.0 FR-008 判定③/REQ-20261017-006：空路径（<>）来信既不拒收也不隔离，
// 恒照常投递收件箱；DMARC 批 G3 漏检格堵口——步 1.7 修正前该场景被误改写落 Junk）。
func TestDMARCQuarantineEmptyPathExempt(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	deliver := newDeliverWithDisposition(t, svc, "quarantine")
	deliver.Envelope.MailFrom = "" // 空路径（<>）——退信场景（REQ-20261017-006 恒豁免）
	if err := svc.Deliver(context.Background(), deliver, sampleRaw()); err != nil {
		t.Fatalf("空路径来信应照常投递: %v", err)
	}
	meta := store.saved[0]
	if len(meta.Recipients) != 1 || meta.Recipients[0].FolderName != "" {
		t.Fatalf("空路径豁免隔离——应收件箱默认（FolderName 空）非 Junk: %+v", meta.Recipients)
	}
}

// ───────────────────────── 测试辅助 ─────────────────────────

// newDeliverWithDisposition 构造携带指定 DMARC 分派结论的投递（替换 svc 验证器
// stub——disposition 模拟验证器预计算产出；收件人缺省单目标 bob@test.example）。
func newDeliverWithDisposition(t *testing.T, svc *InboundPipelineService, disposition string) *Delivery {
	t.Helper()
	svc.verifier = stubVerifier{results: &auth.VerifyResults{
		SPF: "pass", DKIM: "pass", DMARC: "fail", ARC: "none",
		AuthResultsHeader: "Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com",
		DMARCDisposition:  disposition,
	}}
	in := testDelivery("bob@test.example")
	in.Envelope.MailFrom = "alice@example.com"
	return in
}

// TestMultiFromViolationRejected E-3② Deliver 级（V批核查修复批——G2 批准
// 2026-10-18 05:47「Sender 头 没有了，直接拒收」）：多地址 From 无 Sender 头
// （FromHeaderViolation 置位）→ 拒收短路＋零落库＋零 Blob（rfc5322bis §3.6.2
// MUST 违规＋rfc9989 §11.5 L2498-2499 授权否定处置）。
func TestMultiFromViolationRejected(t *testing.T) {
	svc, blobs, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	svc.verifier = stubVerifier{results: &auth.VerifyResults{
		SPF: "pass", DKIM: "pass", DMARC: "permerror", ARC: "none",
		AuthResultsHeader:   "Authentication-Results: mx.test; dmarc=permerror header.from=example.com",
		FromHeaderViolation: true,
	}}
	in := testDelivery("bob@test.example")
	in.Envelope.MailFrom = "alice@example.com"
	err := svc.Deliver(context.Background(), in, sampleRaw())
	if err == nil {
		t.Fatal("violation 应拒收")
	}
	var rej *RejectPolicyError
	if !errors.As(err, &rej) || rej.Code != 550 {
		t.Fatalf("应 RejectPolicyError 550: %T %v", err, err)
	}
	if !contains(rej.Reason, "Sender") {
		t.Fatalf("Reason 应含 Sender 违规语义: %q", rej.Reason)
	}
	if len(store.saved) != 0 {
		t.Fatalf("拒收零落库: %d", len(store.saved))
	}
	if len(blobs.data) != 0 {
		t.Fatalf("拒收零 Blob: %d", len(blobs.data))
	}
}
