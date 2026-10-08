// mail 域单测：MIME 缓存列解析与收信管道编排（NFR-015：stub 全离线驱动）。
// 覆盖锚点：TC-004 判定①（影子建立+postmaster 通知）、TC-008 判定②存储侧
// （trace/A-R 头注入）、TC-021 判定①离线半场（Blob/事务失败→ErrRetryable→451 语义）。
// 修改历史：
//
//	2026-09-17 04:15:00 | 新建 | U4 SMTP 收信（计划书步骤 11）
package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// ───────────────────────── 测试 stub（NFR-015：零网络端点） ─────────────────────────

// stubVerifier 固定四元组+A-R 头的验证器 stub。
type stubVerifier struct{ results *auth.VerifyResults }

func (s stubVerifier) Verify(_ context.Context, _ *auth.IncomingMail) (*auth.VerifyResults, error) {
	return s.results, nil
}

// memBlobs 内存 BlobStore（Write 幂等语义与 FS 实现对齐）。
type memBlobs struct {
	data map[string][]byte
	fail bool
}

func newMemBlobs() *memBlobs { return &memBlobs{data: map[string][]byte{}} }

func (m *memBlobs) Write(_ context.Context, key string, data []byte) error {
	if m.fail {
		return errors.New("stub: blob 写入失败")
	}
	m.data[key] = data
	return nil
}
func (m *memBlobs) Read(_ context.Context, key string) ([]byte, error) { return m.data[key], nil }
func (m *memBlobs) Delete(_ context.Context, key string) error         { delete(m.data, key); return nil }

// memSeekCloser 内存流式句柄（性能批 F7 stub 适配——bytes.Reader 的 Close 空实现
// 包装，满足 io.ReadSeekCloser）。
type memSeekCloser struct{ *bytes.Reader }

func (memSeekCloser) Close() error { return nil }

// Open 性能批 F7 扩展（接口 v1.36.0 增量适配——内存 bytes.Reader 包装形态对齐
// io.ReadSeekCloser 契约；数据缺失返回 os.ErrNotExist 与 FS 实现语义一致）。
func (m *memBlobs) Open(_ context.Context, key string) (io.ReadSeekCloser, error) {
	data, ok := m.data[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return memSeekCloser{bytes.NewReader(data)}, nil
}

// List F7 扩展（接口 v1.32.0 增量适配——测试 stub 形态对齐 FS 实现）。
func (m *memBlobs) List(_ context.Context) ([]string, error) {
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}
func (m *memBlobs) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

// stubAccounts 内存账号服务（影子建立记录）。
type stubAccounts struct {
	mailboxes map[string]*storage.Mailbox
	nextID    int64
	Created   []string // CreateShadowMailbox 调用记录
}

func newStubAccounts(pre map[string]storage.MailboxStatus) *stubAccounts {
	a := &stubAccounts{mailboxes: map[string]*storage.Mailbox{}, nextID: 100}
	for addr, st := range pre {
		a.nextID++
		a.mailboxes[addr] = &storage.Mailbox{ID: a.nextID, Address: addr, Status: st}
	}
	return a
}

func (a *stubAccounts) GetMailbox(_ context.Context, addr string) (*storage.Mailbox, error) {
	if m, ok := a.mailboxes[strings.ToLower(addr)]; ok {
		return m, nil
	}
	return nil, storage.ErrMailboxNotFound
}

func (a *stubAccounts) CreateShadowMailbox(_ context.Context, addr string) (*storage.Mailbox, error) {
	a.nextID++
	m := &storage.Mailbox{ID: a.nextID, Address: strings.ToLower(addr), Status: storage.MailboxStatusShadow}
	a.mailboxes[m.Address] = m
	a.Created = append(a.Created, m.Address)
	return m, nil
}

// EnsureAggregateFolder 内存 stub（U25——聚合文件夹确保位，零副作用记录）。
func (a *stubAccounts) EnsureAggregateFolder(_ context.Context, _ int64) error {
	return nil
}

// stubStore 记录型仓储（或按注入错误失败）。
type stubStore struct {
	saved []*storage.InboundMeta
	fail  bool
}

func (s *stubStore) StoreInbound(_ context.Context, txmeta *storage.InboundMeta) error {
	if s.fail {
		return errors.New("stub: 事务失败")
	}
	s.saved = append(s.saved, txmeta)
	return nil
}

// compile-time stub 接口锁定。
var (
	_ storage.BlobStore = (*memBlobs)(nil)
	_ shadowAccounts    = (*stubAccounts)(nil)
	_ inboundStore      = (*stubStore)(nil)
	_ auth.Verifier     = stubVerifier{}
)

// newTestPipeline 组装测试管道与各 stub。
func newTestPipeline() (*InboundPipelineService, *memBlobs, *stubAccounts, *stubStore) {
	blobs, accounts, store := newMemBlobs(), newStubAccounts(nil), &stubStore{}
	verifier := stubVerifier{results: &auth.VerifyResults{
		SPF: "pass", DKIM: "pass", DMARC: "pass", ARC: "none",
		AuthResultsHeader: "Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com",
	}}
	return NewInboundPipelineService(verifier, accounts, blobs, store, "test.example"), blobs, accounts, store
}

// sampleRaw 测试消息字节（CRLF 行尾）。
func sampleRaw() []byte {
	return []byte("Message-ID: <orig@example.com>\r\n" +
		"From: Alice <alice@example.com>\r\n" +
		"To: bob@test.example\r\n" +
		"Cc: carol@example.com\r\n" +
		"Subject: =?utf-8?B?5L2g5aW9?=\r\n" +
		"Date: Mon, 07 Sep 2026 10:00:00 +0800\r\n" +
		"\r\nhello world\r\n")
}

func testDelivery(rcpts ...string) *Delivery {
	return &Delivery{
		Envelope:   auth.Envelope{Helo: "mail.example.com", RemoteIP: net.ParseIP("192.0.2.1"), MailFrom: "alice@example.com"},
		Recipients: rcpts,
	}
}

// ───────────────────────── MIME 解析 ─────────────────────────

// TestParseCachedHeaders 正常头提取（rfc2047 主题解码/多地址 JSON/Date/Message-ID）。
func TestParseCachedHeaders(t *testing.T) {
	p := ParseCachedHeaders(sampleRaw())
	// go-message v0.18.2 实测：MessageID() 返回剥除尖括号的裸 ID（2026-09-17 实测定档）
	if p.MessageID != "orig@example.com" || p.FromAddr != "alice@example.com" {
		t.Fatalf("MessageID/From 提取错: %+v", p)
	}
	if p.Subject != "你好" { // rfc2047 B 编码解码（Q8：go-message 承载）
		t.Fatalf("rfc2047 主题解码错: %q", p.Subject)
	}
	if p.ToAddrs != `["bob@test.example"]` || p.CcAddrs != `["carol@example.com"]` {
		t.Fatalf("地址 JSON 缓存错: to=%s cc=%s", p.ToAddrs, p.CcAddrs)
	}
	if p.SentAt.IsZero() || p.SentAt.Year() != 2026 {
		t.Fatalf("Date 解析错: %v", p.SentAt)
	}
}

// TestParseCachedHeadersMalformedTolerated 畸形头容忍（缺头置空不报错，数据模型 3.4 容错口径）。
func TestParseCachedHeadersMalformedTolerated(t *testing.T) {
	p := ParseCachedHeaders([]byte("垃圾字节无头结构"))
	if p.Subject != "" || p.FromAddr != "" || !p.SentAt.IsZero() {
		t.Fatalf("畸形输入应全零值: %+v", p)
	}
}

// ───────────────────────── 管道编排 ─────────────────────────

// TestDeliverInjectsTraceHeaders trace 头注入与头序（rfc5321bis 4.4.5/4.4.1/4.4.2+TC-008 判定②存储侧）：
// 存储字节=Return-path→Received→A-R→原消息。
func TestDeliverInjectsTraceHeaders(t *testing.T) {
	svc, blobs, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}

	if err := svc.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("应恰一次事务: %d", len(store.saved))
	}
	meta := store.saved[0]
	raw := blobs.data[meta.Message.BlobKey]
	head := string(raw[:strings.Index(string(raw), "Message-ID:")])
	if !strings.HasPrefix(head, "Return-path: <alice@example.com>\r\n") {
		t.Fatalf("Return-path 未在最前（4.4.2）:\n%s", head)
	}
	if !strings.Contains(head, "Received: from mail.example.com ([192.0.2.1]) by test.example (GRmail) with ESMTP for <bob@test.example>; ") {
		t.Fatalf("Received trace 头不符（4.4.1 from/by/单收件人 FOR 子句）:\n%s", head)
	}
	if !strings.Contains(head, "Authentication-Results: mx.test;") {
		t.Fatalf("A-R 头缺失（FR-008）:\n%s", head)
	}
	if meta.Message.SPFResult != "pass" || meta.Message.AuthResultsHeader == "" {
		t.Fatalf("验证结论缓存列缺失: %+v", meta.Message)
	}
}

// TestDeliverShadowNotice 影子建立+postmaster 通知同事务（FR-004 判定①/TC-004/Q4-A）。
func TestDeliverShadowNotice(t *testing.T) {
	svc, blobs, accounts, store := newTestPipeline()

	if err := svc.Deliver(context.Background(), testDelivery("newguy@test.example"), sampleRaw()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	// 影子邮箱建立（不存在→建）
	if len(accounts.Created) != 2 || accounts.Created[0] != "newguy@test.example" || accounts.Created[1] != "postmaster@test.example" {
		t.Fatalf("影子建立序列错（newguy+postmaster）: %v", accounts.Created)
	}
	// 通知邮件与来信同事务
	meta := store.saved[0]
	if meta.Notice == nil {
		t.Fatal("影子通知邮件缺失（Q4-A）")
	}
	if !strings.Contains(meta.Notice.Message.Subject, "newguy@test.example") {
		t.Fatalf("通知主题缺影子地址: %s", meta.Notice.Message.Subject)
	}
	if _, ok := blobs.data[meta.Notice.Message.BlobKey]; !ok {
		t.Fatal("通知邮件 blob 未写入（数据模型 1.3 顺序对全部邮件一致）")
	}
	if meta.Notice.MailboxID != accounts.mailboxes["postmaster@test.example"].ID {
		t.Fatalf("通知目标邮箱错: %d", meta.Notice.MailboxID)
	}
}

// TestDeliverMultiRecipientSingleTransaction 多收件人单事务（Q1-A/流程设计第一章要点 4；
// U25 适配：含 shadow 收件人→追加聚合副本目标——三目标形态=active+影子原行+聚合）。
func TestDeliverMultiRecipientSingleTransaction(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["a@test.example"] = &storage.Mailbox{ID: 1, Address: "a@test.example", Status: storage.MailboxStatusActive}
	accounts.mailboxes["b@test.example"] = &storage.Mailbox{ID: 2, Address: "b@test.example", Status: storage.MailboxStatusShadow}

	if err := svc.Deliver(context.Background(), testDelivery("a@test.example", "b@test.example"), sampleRaw()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	meta := store.saved[0]
	// U25：双收件人（含影子）+聚合副本=3 目标；postmaster 影子随聚合 ensure 新建（唯一 Created）
	if len(meta.Recipients) != 3 {
		t.Fatalf("双收件人+聚合副本应 3 目标: %+v", meta.Recipients)
	}
	var aggCount int
	for _, r := range meta.Recipients {
		if r.Aggregate {
			aggCount++
		}
	}
	if aggCount != 1 {
		t.Fatalf("聚合副本目标应恰 1: %+v", meta.Recipients)
	}
	if len(accounts.Created) != 1 || accounts.Created[0] != "postmaster@test.example" {
		t.Fatalf("应仅新建 postmaster 聚合承载影子: %v", accounts.Created)
	}
	if meta.Notice != nil {
		t.Fatal("无新建影子不应有通知邮件")
	}
}

// TestDeliverRetryableOnBlobFailure Blob 失败→ErrRetryable（TC-021 判定①：451 语义锚点）。
func TestDeliverRetryableOnBlobFailure(t *testing.T) {
	svc, blobs, accounts, _ := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}
	blobs.fail = true

	err := svc.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw())
	if !errors.Is(err, ErrRetryable) {
		t.Fatalf("Blob 失败应为 ErrRetryable: %v", err)
	}
}

// TestDeliverRetryableOnStoreFailure 事务失败→ErrRetryable（TC-021：451 促重试禁虚假 250）。
func TestDeliverRetryableOnStoreFailure(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()
	accounts.mailboxes["bob@test.example"] = &storage.Mailbox{ID: 1, Address: "bob@test.example", Status: storage.MailboxStatusActive}
	store.fail = true

	err := svc.Deliver(context.Background(), testDelivery("bob@test.example"), sampleRaw())
	if !errors.Is(err, ErrRetryable) {
		t.Fatalf("事务失败应为 ErrRetryable: %v", err)
	}
}

// TestDeliverDisabledRecipientSkipped disabled 到达管道层的防御性跳过（1.5⑥：RCPT 已 550）。
func TestDeliverDisabledRecipientSkipped(t *testing.T) {
	svc, _, _, store := newTestPipeline()
	// stub 中塞入 disabled 邮箱（正常路径不可达，防御态验证）
	// —— 经独立 stub 实例而非全局构造
	accounts := newStubAccounts(nil)
	accounts.nextID++
	accounts.mailboxes["off@test.example"] = &storage.Mailbox{ID: accounts.nextID, Address: "off@test.example", Status: storage.MailboxStatusDisabled}
	svc.accounts = accounts

	err := svc.Deliver(context.Background(), testDelivery("off@test.example"), sampleRaw())
	if err == nil || !strings.Contains(err.Error(), "无有效收件人") {
		t.Fatalf("全 disabled 应报无有效收件人: %v", err)
	}
	if len(store.saved) != 0 {
		t.Fatal("不应有落库事务")
	}
}

// TestGenerateMessageIDUniqueness 通知 Message-ID 唯一性（域内生成格式）。
func TestGenerateMessageIDUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := generateMessageID("test.example")
		if !strings.HasPrefix(id, "<grmail-") || !strings.HasSuffix(id, "@test.example>") {
			t.Fatalf("Message-ID 格式错: %s", id)
		}
		if seen[id] {
			t.Fatalf("Message-ID 重复: %s", id)
		}
		seen[id] = true
	}
	_ = fmt.Sprint()
}
