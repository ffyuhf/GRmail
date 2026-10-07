// imap 资源限制单测（访问协议资源限制批 u30——F1/F2/F8）：
// F2（A-13②）resolveNumSet/translateCriteria 大区间解析受控断言（`1:4294967295`
// 原逐 UID 枚举 ≈42.9 亿次循环根治——交集化/截断后瞬时）；F1（A-13①）APPEND
// 声明大小前置拒绝+恰限通过；F8 connLimitListener 超限连接即关+计数回收。
// 规范锚：rfc9051 §2.3.1.2（UID 引用忽略不存在者——交集语义依据）/§6.3.12
// L3444-3446（失败恢复原状）/§4.3 L813-852（字面量）。
// 修改历史：
//
//	2026-10-07 14:12:00 | 新建 | 访问协议资源限制批（计划书 v1.0.0 步骤 1·2·8，
//	G2 批准 2026-10-07 14:00:02）
package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// ───────────────────────── F2：序号/UID 集解析受控 ─────────────────────────

// TestResolveNumSetHugeRange F2 主锚：`1:4294967295` 双分支瞬时完成（修复前
// UIDSet 分支逐 UID 枚举 ≈42.9 亿次循环、SeqSet 分支循环枚举至 Stop——CPU 放大）。
func TestResolveNumSetHugeRange(t *testing.T) {
	s := &Session{uids: []int64{1, 5, 100}}

	var uidSet imap.UIDSet
	uidSet.AddRange(1, 4294967295)
	var seqSet imap.SeqSet
	seqSet.AddRange(1, 4294967295)

	start := time.Now()
	uids, byUID := s.resolveNumSet(uidSet)
	if !byUID || len(uids) != 3 || uids[0] != 1 || uids[1] != 5 || uids[2] != 100 {
		t.Fatalf("UIDSet 巨区间交集化结果不符: %v byUID=%v", uids, byUID)
	}
	seqs, _ := s.resolveNumSet(seqSet)
	if len(seqs) != 3 || seqs[0] != 1 || seqs[1] != 5 || seqs[2] != 100 {
		t.Fatalf("SeqSet 巨区间截断结果不符: %v", seqs)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("巨区间解析耗时 %v（修复后应瞬时）", elapsed)
	}
}

// TestResolveNumSetSemanticsUnchanged F2 语义回归：小区间输出与原逐 UID 枚举
// 过滤语义一致（含部分越界与间隙区间）。
func TestResolveNumSetSemanticsUnchanged(t *testing.T) {
	s := &Session{uids: []int64{2, 4, 6, 8}}

	var uidSet imap.UIDSet
	uidSet.AddRange(3, 7) // 命中 4、6
	got, _ := s.resolveNumSet(uidSet)
	if len(got) != 2 || got[0] != 4 || got[1] != 6 {
		t.Fatalf("UID 区间 3:7 应命中 [4 6]，得 %v", got)
	}

	var seqSet imap.SeqSet
	seqSet.AddRange(2, 3) // 序号 2、3 → UID 4、6
	got2, _ := s.resolveNumSet(seqSet)
	if len(got2) != 2 || got2[0] != 4 || got2[1] != 6 {
		t.Fatalf("序号区间 2:3 应映射 [4 6]，得 %v", got2)
	}
}

// TestTranslateCriteriaUIDIntersect F2：SEARCH UID 集交集化（原无界展开根治）。
func TestTranslateCriteriaUIDIntersect(t *testing.T) {
	var us imap.UIDSet
	us.AddRange(1, 4294967295)
	criteria := &imap.SearchCriteria{UID: []imap.UIDSet{us}}
	start := time.Now()
	f, err := translateCriteria(criteria, []int64{3, 9})
	if err != nil {
		t.Fatalf("翻译: %v", err)
	}
	if len(f.UIDs) != 2 || f.UIDs[0] != 3 || f.UIDs[1] != 9 {
		t.Fatalf("UID 交集结果不符: %v", f.UIDs)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("UID 巨区间翻译耗时 %v（应瞬时）", elapsed)
	}
}

// ───────────────────────── F1：APPEND 大小前置 ─────────────────────────

// u30Literal 测试字面量（imap.LiteralReader：Reader+Size）。
type u30Literal struct {
	data []byte
	size int64
}

func (l *u30Literal) Read(p []byte) (int, error) {
	if len(p) == 0 || len(l.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, l.data)
	l.data = l.data[n:]
	return n, nil
}

func (l *u30Literal) Size() int64 { return l.size }

// TestAppendSizePreflight F1 主锚：声明计数（Size）超限零读取拒绝；恰限通过全链。
func TestAppendSizePreflight(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u30.db")})
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	mailboxRepo := storage.NewMailboxRepoFor("sqlite", db)
	folderRepo := storage.NewFolderRepoFor("sqlite", db)
	accounts := account.NewService(mailboxRepo, folderRepo)
	mb, err := accounts.CreateMailbox(ctx, "u30@t.io", "pw123456")
	if err != nil {
		t.Fatalf("建邮箱: %v", err)
	}
	blobs := storage.NewFileSystemBlobStore(t.TempDir())
	srv := &Server{
		cfg:      ServerConfig{MaxAppendSize: func() int64 { return 16 }},
		accounts: accounts, messages: storage.NewSQLiteMessageRepo(db), blobs: blobs,
	}
	s := &Session{server: srv, mbox: mb}

	// 声明超限（Size=100 > 16）——前置拒绝，零字面量读取
	_, err = s.Append("INBOX", &u30Literal{size: 100, data: bytes.Repeat([]byte("x"), 100)}, &imap.AppendOptions{})
	if err == nil || err.Error() != "message too big" {
		t.Fatalf("超限应拒绝 message too big，得 %v", err)
	}
	// 恰限通过（10 字节 ≤ 16——全链落库；options 恒传非 nil——库层生产形态）
	_, err = s.Append("INBOX", &u30Literal{size: 10, data: []byte("0123456789")}, &imap.AppendOptions{})
	if err != nil {
		t.Fatalf("恰限 APPEND 应通过: %v", err)
	}
	// 实际大于声明（Size=8 但 data=100）——LimitReader 兜底路径：读上界 8+1=9
	// 字节仍 < 16 通过？否——上界=limit+1=17，读得 17 字节 > 16 → 兜底拒绝
	//（声明与实际偏差的截获——读取上界受控主旨的直接断言）
	_, err = s.Append("INBOX", &u30Literal{size: 8, data: bytes.Repeat([]byte("y"), 100)}, &imap.AppendOptions{})
	if err == nil || err.Error() != "message too big" {
		t.Fatalf("偏差兜底应拒绝 message too big，得 %v", err)
	}
}

// ───────────────────────── F8：connLimitListener ─────────────────────────

// TestConnLimitListenerOverLimit F8 主锚：计数满时 Accept 仍成功返回（不终止
// 库层 Serve——返回 *tls.Conn 库层 TLS 断言成立），超限连接已关（握手/读取
// 即错），计数经 once 即时回收。
func TestConnLimitListenerOverLimit(t *testing.T) {
	var count atomic.Int64
	count.Add(imapMaxConns) // 预置满档
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cl := &connLimitListener{Listener: ln, count: &count, tlsCfg: selfSignedTLSConfig(t)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			t.Error(derr)
			return
		}
		_, _ = c.Write([]byte("x")) // 触发服务端握手尝试（连接已关即失败）
		_ = c.Close()
	}()
	conn, err := cl.Accept()
	if err != nil {
		t.Fatalf("超限 Accept 不应返回错误（错误形态会终止库层 Serve）: %v", err)
	}
	if _, isTLS := conn.(*tls.Conn); !isTLS {
		t.Fatal("Accept 应返回 *tls.Conn（库层 TLS 断言承载）")
	}
	// 超限连接内层已关——TLS 握手/读取即失败（等待窗口内任一错误形态）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1)
		if _, rerr := conn.Read(buf); rerr != nil {
			break // 已关连接——握手/读失败即预期
		}
	}
	if got := count.Load(); got != imapMaxConns {
		t.Fatalf("计数应回收至 %d，得 %d", imapMaxConns, got)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("客户端 goroutine 未退出")
	}
}
