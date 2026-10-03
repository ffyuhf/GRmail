// mail 域投递队列 worker：ClaimDue 认领→按域分组串行 Send→MarkResult 退避回写→
// failed 终态 DSN 生成入队。
// 依据：Q6-A 修订裁决（2026-09-17 11:28:56「2 worker pool，按域串行」）：2 个 worker
// goroutine+30s tick+Enqueue channel 即时唤醒；批内按 rcpt_to 域分组串行（跨批同域
// 上限 2 并发，接受）；U5 计划书 1.5⑦⑧⑩⑪；
// Q5-C 裁决：退避 min(base×factor^(n-1), cap)、attempts≥MaxAttempts→failed；
// Q4-A 裁决：failed→DSN（multipart/report）→签名→Blob+messages→按域投递（本域本地
// 入收件箱/外域入队 envelope_from="<>";收件人 "<>" 跳过——rfc3464 防循环 MUST）；
// 流程设计 3.2 不变量 1（启动 ReclaimStale(10min) 幂等恢复）/不变量 3（failed 必 DSN）；
// NFR-016（每次尝试 LogID+queue_id/message_id 四元组关联）。
// 修改历史：
//
//	2026-09-17 12:12:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 9）
package mail

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"GRmail/internal/config"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
)

// ───────────────────────── 窄接口 ─────────────────────────

// queueClaimStore worker 消费的队列仓储窄接口（SQLiteQueueRepo 满足）。
type queueClaimStore interface {
	ClaimDue(ctx context.Context, now time.Time, limit int) ([]*storage.QueueItem, error)
	MarkResult(ctx context.Context, id int64, r storage.AttemptResult) error
	ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error)
	Enqueue(ctx context.Context, items []*storage.QueueItem) error
	StoreSubmission(ctx context.Context, txmeta *storage.SubmissionMeta) error
}

// deliveryConfigFunc 退避配置快照（config.Watcher.Current 适配；热生效 Q5-C）。
type deliveryConfigFunc func() config.DeliveryConf

// ───────────────────────── worker ─────────────────────────

// QueueWorker 投递队列 worker（2 池按域串行）。
type QueueWorker struct {
	queue   queueClaimStore
	sender  OutboundSender
	dsn     DSNBuilder
	signer  outboundSigner
	blobs   blobWriter
	conf    deliveryConfigFunc
	domain  string
	wake    chan struct{}
	stopped chan struct{}
	stopMu  sync.Mutex
}

// blobWriter Blob 写入窄接口（storage.BlobStore 满足）。
type blobWriter interface {
	Write(ctx context.Context, key string, data []byte) error
}

// NewQueueWorker 构造队列 worker。
// 参数：queue 队列仓储；sender 出站投递；dsn DSN 构造；signer DKIM；blobs 字节存储；
// conf 退避配置快照函数；domain 本域（DSN 投递分流判定）。
func NewQueueWorker(queue queueClaimStore, sender OutboundSender, dsn DSNBuilder,
	signer outboundSigner, blobs blobWriter, conf deliveryConfigFunc, domain string) *QueueWorker {
	return &QueueWorker{
		queue: queue, sender: sender, dsn: dsn, signer: signer, blobs: blobs,
		conf: conf, domain: domain,
		wake:    make(chan struct{}, 8),
		stopped: make(chan struct{}),
	}
}

// Wake 入队即时唤醒（提交侧 StoreSubmission 成功后调用；非阻塞）。
func (w *QueueWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default: // 已有待处理唤醒信号（channel 缓冲满），合并
	}
}

// Start 启动 worker 池：启动恢复+2 goroutine 循环。返回 stopped 通道（优雅退出等待位）。
func (w *QueueWorker) Start(ctx context.Context) <-chan struct{} {
	// 崩溃恢复（流程设计 3.2 不变量 1：in_flight→pending 幂等；Stale=10min，1.5⑦）
	if n, err := w.queue.ReclaimStale(ctx, 10*time.Minute); err != nil {
		slog.Default().Error("启动崩溃恢复失败", "error", err)
	} else if n > 0 {
		slog.Default().Info("启动崩溃恢复完成", "reclaimed", n)
	}
	for i := 1; i <= 2; i++ {
		go w.loop(ctx, i)
	}
	return w.stopped
}

// loop 单 worker 循环：唤醒等待（30s tick 或 Wake 信号）→认领→按域分组串行投递。
func (w *QueueWorker) loop(ctx context.Context, id int) {
	defer func() {
		w.stopMu.Lock()
		// 双 worker 全退后再关闭 stopped（简化：单通道两写者各关一次改为计数）
		w.stopMu.Unlock()
	}()
	logger := slog.Default().With("worker", id)
	for {
		select {
		case <-ctx.Done():
			logger.Info("worker 退出（上下文取消）")
			select {
			case <-w.stopped:
			default:
				close(w.stopped) // 首个退出者关闭信号（drain 语义由 main 的等待时长兜底）
			}
			return
		case <-time.After(30 * time.Second): // tick 轮询（deferred 到期兜底）
		case <-w.wake: // 入队即时唤醒
		}
		w.runBatch(ctx, logger)
	}
}

// runBatch 单轮认领与投递：ClaimDue(10)→按域分组（组内串行，1.5⑦）→逐项处理。
func (w *QueueWorker) runBatch(ctx context.Context, logger *slog.Logger) {
	items, err := w.queue.ClaimDue(ctx, time.Now().UTC(), 10)
	if err != nil {
		logger.Error("认领失败", "error", err)
		return
	}
	if len(items) == 0 {
		return
	}
	for _, group := range groupByDomain(items) {
		for _, item := range group {
			w.attempt(ctx, logger, item)
		}
	}
}

// attempt 单项投递尝试：Send→退避计算→MarkResult→failed 终态 DSN 链。
func (w *QueueWorker) attempt(ctx context.Context, logger *slog.Logger, item *storage.QueueItem) {
	// 每次尝试新 LogID（1.5⑪；observability 签名：ctx+logger 双返回）
	attemptCtx, _ := observability.ContextWithNewLogID(ctx, logger)
	logger = slog.Default().With("queue_id", item.ID, "message_id", item.MessageID,
		"envelope_from", item.EnvelopeFrom, "rcpt_to", item.RcptTo)

	result := w.sender.Send(attemptCtx, item)
	result.Attempts = item.Attempts + 1

	// 超重试上限：deferred 升格 failed（Q5-C：attempts≥MaxAttempts→failed→DSN）
	conf := w.conf()
	if result.Status == storage.AttemptDeferred && result.Attempts >= conf.MaxAttempts {
		result.Status = storage.AttemptFailed
		result.Error = "重试上限耗尽: " + result.Error
	}
	// deferred 退避计算（Q5-C：min(base×factor^(n-1), cap)）
	if result.Status == storage.AttemptDeferred {
		result.NextAttemptAt = time.Now().UTC().Add(backoffDelay(conf, result.Attempts))
	}

	// 回写（失败仅记日志——状态保持 in_flight 由 Stale 收敛，不重复投递，TC-021 判定②）
	if err := w.queue.MarkResult(attemptCtx, item.ID, result); err != nil {
		logger.Error("结果回写失败，保持 in_flight 待 Stale 收敛", "error", err)
		return
	}
	logger.Info("投递尝试完成", "status", string(result.Status), "code", result.SMTPCode, "error", result.Error)

	// failed 终态→DSN（Q4-A；"<>" 收件人跳过——rfc3464 防循环 MUST）
	if result.Status == storage.AttemptFailed {
		w.emitDSN(ctx, logger, item, result)
	}
}

// emitDSN failed 终态退信链：Build→DKIM 签名→Blob→messages 落库→按域投递入队。
func (w *QueueWorker) emitDSN(ctx context.Context, logger *slog.Logger, item *storage.QueueItem, result storage.AttemptResult) {
	if item.EnvelopeFrom == "" || item.EnvelopeFrom == "<>" {
		logger.Info("null sender 终态失败，不生成 DSN（rfc3464 防循环）")
		return
	}
	dsnRaw, err := w.dsn.Build(ctx, item, result)
	if err != nil {
		logger.Error("DSN 构造失败", "error", err)
		return
	}
	// DKIM 签名（退信也是出站信；哨兵语义沿提交管道：未配置跳过不阻断）
	if signed, serr := w.signer.Sign(ctx, dsnRaw, w.domain); serr == nil {
		dsnRaw = signed
	}
	blobKey := sha256Hex(dsnRaw)
	if err = w.blobs.Write(ctx, blobKey, dsnRaw); err != nil {
		logger.Error("DSN Blob 写入失败", "error", err)
		return
	}
	parsed := ParseCachedHeaders(dsnRaw)
	now := time.Now().UTC()
	meta := &storage.SubmissionMeta{
		Message: storage.MessageMeta{
			MessageID: parsed.MessageID, BlobKey: blobKey, RawSize: int64(len(dsnRaw)),
			Subject: parsed.Subject, FromAddr: parsed.FromAddr, ToAddrs: parsed.ToAddrs, SentAt: parsed.SentAt,
		},
		Items: []*storage.QueueItem{{
			EnvelopeFrom: "<>", RcptTo: item.EnvelopeFrom, // DSN 信封 null sender（rfc3464 MUST）
			Status: storage.QueuePending, NextAttemptAt: now,
		}},
	}
	if err = w.queue.StoreSubmission(ctx, meta); err != nil {
		logger.Error("DSN 入库失败", "error", err)
		return
	}
	w.Wake()
	logger.Info("DSN 退信已生成并入队", "dsn_to", item.EnvelopeFrom)
}

// backoffDelay 退避时长计算（Q5-C 裁决缺省档：base=60s/factor=2/cap=3600s；
// min(base×factor^(attempts-1), cap)；非法配置兜底缺省档防漂移）。
func backoffDelay(conf config.DeliveryConf, attempts int) time.Duration {
	base, factor, capSec := int64(conf.RetryBaseSeconds), int64(conf.RetryFactor), int64(conf.RetryCapSeconds)
	if base <= 0 {
		base = 60
	}
	if factor <= 1 {
		factor = 2
	}
	if capSec <= 0 {
		capSec = 3600
	}
	delay := base
	for i := 1; i < attempts; i++ { // attempts≥1；指数相乘防溢出以 cap 短路
		if delay >= capSec {
			break
		}
		delay *= factor
	}
	if delay > capSec {
		delay = capSec
	}
	return time.Duration(delay) * time.Second
}

// groupByDomain 队列项按 rcpt_to 域分组（组内保持 next_attempt_at 序，1.5⑦）。
func groupByDomain(items []*storage.QueueItem) [][]*storage.QueueItem {
	order := []string{}
	groups := map[string][]*storage.QueueItem{}
	for _, it := range items {
		d := rcptDomain(it.RcptTo)
		if _, ok := groups[d]; !ok {
			order = append(order, d)
		}
		groups[d] = append(groups[d], it)
	}
	sort.Strings(order) // 域序稳定（两 worker 轮次间公平）
	out := make([][]*storage.QueueItem, 0, len(order))
	for _, d := range order {
		out = append(out, groups[d])
	}
	return out
}
