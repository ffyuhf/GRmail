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
// 队列防丢信收口批（G2 批准 2026-10-07 08:41:07）：
//   - F1（A-14②）：MarkResult 迟到回写（ErrQueueStaleWrite）Warn 丢弃——不覆盖
//     回收后的新状态
//   - F4（A-14①/D1）：Send 前 TouchClaim 心跳续期（claim_token 归属）——在途投递
//     持续续期不被 Stale 回收重投
//   - F5（B-R2）：emitDSN 成功/抑制后 MarkDSNSent 置位；RescanPendingDSNs 重扫
//     （启动+周期消费 ListFailedDSNPending——failed 必产 DSN 强保证）；
//     F6（B-R3）：ErrDSNSuppressed（原信 Auto-Submitted≠no）置位不生成
//   - M7（复核遗漏项）：stopped 通道 close 收敛 sync.Once——双 worker 并发退出
//     双 close panic 根治
//
// 修改历史：
//
//	2026-09-17 12:12:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 9）
//	2026-10-07 09:00:00 | 修正 | 队列防丢信收口批 F1/F4/F5/F6/M7（迁移 00012）
package mail

import (
	"context"
	"errors"
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
// F4/F5 扩展（队列防丢信收口批）：TouchClaim/MarkDSNSent/ListFailedDSNPending——
// 实现=storage.QueueClaimOps 窄视图；契约四方法签名零变更（v1.32.0 注记承载）。
type queueClaimStore interface {
	ClaimDue(ctx context.Context, now time.Time, limit int) ([]*storage.QueueItem, error)
	MarkResult(ctx context.Context, id int64, r storage.AttemptResult) error
	ReclaimStale(ctx context.Context, olderThan time.Duration) (int, error)
	Enqueue(ctx context.Context, items []*storage.QueueItem) error
	StoreSubmission(ctx context.Context, txmeta *storage.SubmissionMeta) error
	// TouchClaim 心跳续期（F4：每 MX 尝试前——claim_token 归属校验）。
	TouchClaim(ctx context.Context, token string) error
	// MarkDSNSent 置位 DSN 回执（F5：emitDSN 成功/抑制后——幂等守卫）。
	MarkDSNSent(ctx context.Context, id int64) error
	// ListFailedDSNPending 重扫批查（F5：failed 且 DSN 未发行）。
	ListFailedDSNPending(ctx context.Context, limit int) ([]*storage.QueueItem, error)
}

// deliveryConfigFunc 退避配置快照（config.Watcher.Current 适配；热生效 Q5-C）。
type deliveryConfigFunc func() config.DeliveryConf

// ───────────────────────── worker ─────────────────────────

// QueueWorker 投递队列 worker（2 池按域串行）。
type QueueWorker struct {
	queue    queueClaimStore
	sender   OutboundSender
	dsn      DSNBuilder
	signer   outboundSigner
	blobs    blobWriter
	conf     deliveryConfigFunc
	domain   string
	wake     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once // M7：并发退出恰一次 close（select-default 竞态根治）
	stopMu   sync.Mutex
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

// Start 启动 worker 池：启动恢复+首轮 DSN 重扫+2 goroutine 循环。
// 返回 stopped 通道（优雅退出等待位——恰关闭一次，M7）。
func (w *QueueWorker) Start(ctx context.Context) <-chan struct{} {
	// 崩溃恢复（流程设计 3.2 不变量 1：in_flight→pending 幂等；Stale=10min，1.5⑦）。
	// F2 附带：回收行经退避阶梯重置 next_attempt_at（storage 侧承载）。
	if n, err := w.queue.ReclaimStale(ctx, 10*time.Minute); err != nil {
		slog.Default().Error("启动崩溃恢复失败", "error", err)
	} else if n > 0 {
		slog.Default().Info("启动崩溃恢复完成", "reclaimed", n)
	}
	// F5（B-R2）首轮重扫：上次进程在 MarkResult(failed) 成功后、emitDSN 完成前崩溃
	// 的行——补发 DSN 收口（沿 runTokenPurgeLoop「首轮即跑」先例）。
	w.RescanPendingDSNs(ctx)
	for i := 1; i <= 2; i++ {
		go w.loop(ctx, i)
	}
	return w.stopped
}

// loop 单 worker 循环：唤醒等待（30s tick 或 Wake 信号）→认领→按域分组串行投递。
func (w *QueueWorker) loop(ctx context.Context, id int) {
	logger := slog.Default().With("worker", id)
	for {
		select {
		case <-ctx.Done():
			logger.Info("worker 退出（上下文取消）")
			// M7：sync.Once 收敛 close——双 worker 同收 ctx.Done 并发退出时
			// 恰执行一次（原 select-default 检测-关闭窗口存在双 close panic）。
			w.stopOnce.Do(func() { close(w.stopped) })
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

// attempt 单项投递尝试：心跳续期→Send→退避计算→MarkResult→failed 终态 DSN 链。
func (w *QueueWorker) attempt(ctx context.Context, logger *slog.Logger, item *storage.QueueItem) {
	// 每次尝试新 LogID（1.5⑪；observability 签名：ctx+logger 双返回）
	attemptCtx, _ := observability.ContextWithNewLogID(ctx, logger)
	logger = slog.Default().With("queue_id", item.ID, "message_id", item.MessageID,
		"envelope_from", item.EnvelopeFrom, "rcpt_to", item.RcptTo)

	// F4（A-14①/D1）：投递期心跳经 sender 注入回调承载（每 MX 尝试前
	// TouchClaim(item.ClaimToken)——main 装配侧绑定；此处不前置重设：首个 MX 前
	// sender 回调即完成首次续期，零 host 场景无投递无续期必要）。

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
	// F1（A-14②）：ErrQueueStaleWrite=迟到回写（行已被 Stale 回收进入新一轮投递）——
	// 本次结果自然作废 Warn 丢弃，禁止覆盖回收后的新状态。
	if err := w.queue.MarkResult(attemptCtx, item.ID, result); err != nil {
		if errors.Is(err, storage.ErrQueueStaleWrite) {
			logger.Warn("迟到回写已丢弃（行已被回收重投，本次结果作废）",
				"status", string(result.Status))
			return
		}
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
// F5：成功或抑制（F6）后置位 dsn_sent——重扫不再命中（failed 必产 DSN 强保证的
// 完成侧锚点；置位失败仅日志，由周期重扫收敛补位）。
func (w *QueueWorker) emitDSN(ctx context.Context, logger *slog.Logger, item *storage.QueueItem, result storage.AttemptResult) {
	if item.EnvelopeFrom == "" || item.EnvelopeFrom == "<>" {
		logger.Info("null sender 终态失败，不生成 DSN（rfc3464 防循环）")
		// F5：null sender 跳过亦为终态——置位防重扫空转
		if err := w.queue.MarkDSNSent(ctx, item.ID); err != nil {
			logger.Warn("null sender DSN 回执置位失败（重扫将重试）", "error", err)
		}
		return
	}
	dsnRaw, err := w.dsn.Build(ctx, item, result)
	if err != nil {
		// F6（B-R3）：原信为自动消息（Auto-Submitted≠no）——抑制生成，置位终态
		// （自动消息永不回应；不置位将导致重扫死循环）。
		if errors.Is(err, ErrDSNSuppressed) {
			logger.Info("原信为自动消息（Auto-Submitted≠no），DSN 抑制不生成（rfc3834 §2）")
			if markErr := w.queue.MarkDSNSent(ctx, item.ID); markErr != nil {
				logger.Warn("DSN 抑制回执置位失败（重扫将重试）", "error", markErr)
			}
			return
		}
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
	// F5（B-R2）：投递入队成功——置位 dsn_sent（failed 必产 DSN 闭环）。
	if err = w.queue.MarkDSNSent(ctx, item.ID); err != nil {
		logger.Warn("DSN 回执置位失败（周期重扫将收敛补位）", "error", err)
	}
	w.Wake()
	logger.Info("DSN 退信已生成并入队", "dsn_to", item.EnvelopeFrom)
}

// RescanPendingDSNs failed 行 DSN 补发重扫（F5/B-R2：进程崩溃致 failed 已落库而
// emitDSN 未完成——「failed 必产生 DSN」不变量 3 的强保证；启动首轮+main 周期消费）。
// 逐行：Build 防循环跳过（null sender/F6 抑制）→入队→置位；置位失败由下轮收敛。
func (w *QueueWorker) RescanPendingDSNs(ctx context.Context) {
	logger := slog.Default().With("component", "dsn_rescan")
	items, err := w.queue.ListFailedDSNPending(ctx, 100)
	if err != nil {
		logger.Error("重扫 DSN 待发行失败", "error", err)
		return
	}
	if len(items) == 0 {
		return
	}
	for _, item := range items {
		w.emitDSN(ctx, logger, item, storage.AttemptResult{
			Status:   storage.AttemptFailed,
			SMTPCode: item.LastSMTPCode,
			Error:    item.LastError,
		})
	}
	logger.Info("DSN 待发行重扫完成", "pending", len(items))
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
