//go:build perf

// 性能基准验证批次 P-C：TC-018 全协议服务承载十万封级库运行典型操作的内存峰值
// 采样（NFR-002——确认测试计划 v1.1.0 TC-018 判定标准「进程内存峰值 ≤ 512MB」）。
// 承载形态（计划书 2.3-3，实现级取舍落 CHANGE5 第三章）：
//   - 操作循环＝mail.InboundPipeline 真收信管道（Deliver 全链：A-R 边界删除→trace
//     注入→Blob CAS→收件人三态→Sieve nil 直通→元数据事务）+仓储全路径（分页/
//     搜索/详情/blob 回读/标志写入）——SMTP 收信业务主干与 Webmail 读路径全覆盖；
//     协议端点编解码层（会话 goroutine/监听器）非内存主体（u12b loopback 已验证
//     功能面），判定口径以管道+仓储承载，形态差异如实落档
//   - 投递限速：每 50 轮投 1 封（30 分钟增量数千封——十万封级基数保持）
//   - 内存轮询：5s 间隔 runtime.ReadMemStats，峰值取 Sys（进程向 OS 申请内存总量
//     ——保守上界口径）+HeapAlloc 双落档；断言 Sys ≤ 512MB
//   - 时长：环境变量 PERF_TC018_DURATION 可缩（逻辑验证轮）；正式判定轮缺省 30m
//
// 修改历史：
//
//	2026-10-03 12:05:00 | 新建 | 性能基准验证批次 P-C（G2 批准 2026-10-03 11:51:26）
package storage_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// perfMemBudget NFR-002 目标值（512MB）。
const perfMemBudget = 512 << 20

// perfTC018Duration 采样时长（缺省 30 分钟判定口径；env 可缩——逻辑验证用）。
func perfTC018Duration(t *testing.T) time.Duration {
	t.Helper()
	if v := os.Getenv("PERF_TC018_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second {
			t.Fatalf("PERF_TC018_DURATION 非法: %q", v)
		}
		t.Logf("TC-018 采样时长缩至 %v（逻辑验证轮——正式判定须 30m）", d)
		return d
	}
	return 30 * time.Minute
}

// perfAccounts 管道账号依赖适配器：真实 MailboxRepo/FolderRepo 包装为
// mail.shadowAccounts 三方法（GetMailbox/CreateShadowMailbox/EnsureAggregateFolder）。
type perfAccounts struct {
	mailboxes storage.MailboxRepo
	folders   storage.FolderRepo
}

func (p *perfAccounts) GetMailbox(ctx context.Context, addr string) (*storage.Mailbox, error) {
	return p.mailboxes.FindByAddress(ctx, addr)
}

func (p *perfAccounts) CreateShadowMailbox(ctx context.Context, addr string) (*storage.Mailbox, error) {
	local, domain, _ := func() (string, string, bool) { // addr 拆分（shadow 建立——ReuseMailbox 形态）
		for i := 0; i < len(addr); i++ {
			if addr[i] == '@' {
				return addr[:i], addr[i+1:], true
			}
		}
		return addr, "", false
	}()
	mb := &storage.Mailbox{LocalPart: local, Domain: domain, Address: addr, Status: storage.MailboxStatusShadow}
	if err := p.mailboxes.Create(ctx, mb); err != nil {
		return nil, err
	}
	return mb, nil
}

func (p *perfAccounts) EnsureAggregateFolder(ctx context.Context, mailboxID int64) error {
	return p.folders.EnsureAggregateFolder(ctx, mailboxID)
}

// perfVerifier 验证器 stub（零 DNS 依赖——固定四项结论；真实验证链内存非主体，
// raven 验证路径经 u3/u4 测试覆盖）。
type perfVerifier struct{}

func (perfVerifier) Verify(_ context.Context, _ *auth.IncomingMail) (*auth.VerifyResults, error) {
	return &auth.VerifyResults{
		SPF: "pass", DKIM: "pass", DMARC: "pass", ARC: "none",
		AuthResultsHeader: "Authentication-Results: mx.test; spf=pass",
	}, nil
}

// perfDeliverRaw 构造第 n 封真投递原始字节（RFC 5322 形态，1~4KB 变体）。
func perfDeliverRaw(n int) []byte {
	return []byte(fmt.Sprintf("From: sender%d@source.example\r\nTo: perf@bench.test\r\n"+
		"Subject: TC-018 投递样本 %d\r\nMessage-ID: <perf-%d@bench.test>\r\n"+
		"Date: Sat, 03 Oct 2026 04:00:00 +0000\r\n\r\n", n%97, n, n) +
		fmt.Sprintf("典型操作循环投递正文第%d封。", n))
}

// TestPerfTC018MemoryFootprint TC-018 三库全量采样（SQLite 必跑；MySQL/PG compose
// 就绪时跑——S3-W Q2-B 裁决；未就绪 Skip 沿 u11 环境口径）。
func TestPerfTC018MemoryFootprint(t *testing.T) {
	for _, c := range []struct{ driver, dsn string }{
		{"sqlite", ""},
		{"mysql", perfMySQLDSN},
		{"postgres", perfPGDSN},
	} {
		t.Run(c.driver, func(t *testing.T) {
			t.Parallel() // 三库独立连接——库级并行
			if c.driver != "sqlite" && !perfDBReady(t, c.driver) {
				t.Skipf("%s 容器未就绪——跳过（降级登记口径见 CHANGE5 第四章）", c.driver)
			}
			env := perfOpenEnv(t, c.driver, c.dsn)
			env.perfBuildDataset(context.Background())
			env.perfRunTC018(t)
		})
	}
}

// perfRunTC018 单库采样执行：管道装配→内存轮询→操作循环→峰值断言。
func (e *perfEnv) perfRunTC018(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	inbox, ok := e.folders["inbox"]
	if !ok {
		t.Fatalf("[%s] inbox 文件夹缺失", e.driver)
	}

	// 1. 真收信管道装配（shadowAccounts 适配+verifier stub+真实 BlobStore/MessageRepo）
	pipeline := mail.NewInboundPipelineService(
		perfVerifier{},
		&perfAccounts{mailboxes: e.repos.Mailboxes, folders: e.repos.Folders},
		e.blobs, e.repos.Messages, "bench.test",
	)

	// 2. inbox 行数探测（随机页上界）
	_, inboxTotal, err := e.repos.Messages.PageList(ctx, storage.ListQuery{
		MailboxID: e.mailboxID, FolderID: inbox, Limit: 1,
	})
	if err != nil || inboxTotal <= 0 {
		t.Fatalf("[%s] inbox 行数探测: total=%d err=%v", e.driver, inboxTotal, err)
	}
	maxPage := int(inboxTotal)/perfPageLimit - 1

	// 3. 内存轮询（5s 间隔；峰值 Sys 判定口径+HeapAlloc 观测口径）
	duration := perfTC018Duration(t)
	deadline := time.Now().Add(duration)
	var peakSys, peakHeap atomic.Int64
	stopPoll := make(chan struct{})
	defer close(stopPoll)
	go func() {
		var ms runtime.MemStats
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stopPoll:
				return
			case <-tick.C:
				runtime.ReadMemStats(&ms)
				if int64(ms.Sys) > peakSys.Load() {
					peakSys.Store(int64(ms.Sys))
				}
				if int64(ms.HeapAlloc) > peakHeap.Load() {
					peakHeap.Store(int64(ms.HeapAlloc))
				}
			}
		}
	}()

	// 4. 典型操作循环（30 分钟：投递限速 1/50 轮+分页+搜索交替+详情+blob 回读+标志翻转）
	rounds, deliveries := 0, 0
	for time.Now().Before(deadline) {
		n := rounds
		if n%50 == 0 { // 投递限速——十万封级基数保持
			raw := perfDeliverRaw(deliveries)
			if err := pipeline.Deliver(ctx, &mail.Delivery{
				Envelope:   auth.Envelope{Helo: "mx.source.example", RemoteIP: net.ParseIP("192.0.2.10"), MailFrom: "sender@source.example"},
				Recipients: []string{"perf@bench.test"},
			}, raw); err != nil {
				t.Fatalf("[%s] 管道投递 %d: %v", e.driver, deliveries, err)
			}
			deliveries++
		}
		page := perfRandIntn(maxPage)
		items, _, err := e.repos.Messages.PageList(ctx, storage.ListQuery{
			MailboxID: e.mailboxID, FolderID: inbox,
			Limit: perfPageLimit, Offset: int32(page * perfPageLimit),
		})
		if err != nil || len(items) == 0 {
			t.Fatalf("[%s] 操作轮分页: err=%v n=%d", e.driver, err, len(items))
		}
		kw := perfHitKeyword
		if n%2 == 1 {
			kw = perfMissKeyword
		}
		if _, _, err = e.repos.Messages.Search(ctx, storage.SearchQuery{
			MailboxID: e.mailboxID, Keyword: kw, Limit: perfPageLimit,
		}); err != nil {
			t.Fatalf("[%s] 操作轮搜索: %v", e.driver, err)
		}
		// 详情+blob 回读（随机取本页一行——原始字节读取路径）
		pick := items[perfRandIntn(len(items))]
		detail, err := e.repos.Messages.GetDetail(ctx, e.mailboxID, pick.ID)
		if err != nil {
			t.Fatalf("[%s] 操作轮详情: %v", e.driver, err)
		}
		if _, err = e.blobs.Read(ctx, detail.BlobKey); err != nil {
			t.Fatalf("[%s] 操作轮 blob 回读: %v", e.driver, err)
		}
		// 标志翻转（写路径——is_read 往返）
		flip := !pick.IsRead
		if err = e.repos.Messages.SetFlags(ctx, pick.ID, storage.FlagPatch{IsRead: &flip}); err != nil {
			t.Fatalf("[%s] 操作轮标志写: %v", e.driver, err)
		}
		rounds++
	}

	// 5. 峰值断言（NFR-002 判定锚——Sys 保守口径）
	peakSysB, peakHeapB := peakSys.Load(), peakHeap.Load()
	t.Logf("[%s] TC-018 采样结果：时长=%v 轮次=%d 投递=%d 峰值Sys=%dMB 峰值HeapAlloc=%dMB",
		e.driver, duration, rounds, deliveries, peakSysB>>20, peakHeapB>>20)
	if peakSysB > perfMemBudget {
		t.Fatalf("[%s] NFR-002 内存峰值超标: Sys=%dMB > 512MB（缺陷数据已落档——计划书 4.2-1 转裁决）",
			e.driver, peakSysB>>20)
	}
}
