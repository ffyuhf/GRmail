// mail 域 Sieve 挂接层：SieveRunner 窄接口（契约 v1.8.0 2.3 SieveEvaluator 的管道
// 消费形态）、InboundPipelineService 的 SetSieveRunner 可选注入（沿 v1.3.0 SetObserver
// 先例——构造签名零变更）、redirect 回流通道（StoreSubmission 直达）。
// 依据：SRS FR-005「认证验证→插件链→Sieve→落库」定死 Sieve 位于收件人解析后、落库
// 事务前（建模 7.3 要点 5：P1 落库前触发邮箱级激活脚本；转发动作回流 P2）；rfc5228
// §4.2（redirect 五义务——原始字节保真/Received 计数已由 U4 trace 注入满足/空信封
// MUST 保持/环控制 MUST/数量限制 MUST）；CON-004（Sieve 异常不阻断落库——implicit
// keep 兜底，rfc5228 §2.10.6 对齐）。
// 修改历史：
//
//	2026-09-21 00:50:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 7，G2 批准 2026-09-21 00:36:18）
//	2026-09-30 18:31:00 | 修正 | RFCSHOULD修正批次 RF-E：parseHeaderMap 头值收集
//	①折叠续行展开拼接（F-S23——rfc5228 §2.7.1 L495-496「Header lines are
//	unfolded as described in [IMAIL] section 2.2.3」，原 continue 丢弃续行致折叠
//	头值残缺）②值规范化 TrimLeft→TrimSpace（F-S22——rfc5228 §5.7 L1580-1582
//	「ignoring leading and trailing whitespace」，原仅去首空白尾空白残留）
//	（依据：RFCSHOULD修正计划书 v1.0.0 步骤 2，G2 批准 2026-09-30 18:28:20）
package mail

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// ───────────────────────── 契约接口（v1.8.0 2.3 承载形态） ─────────────────────────

// SieveRunner Sieve 执行器窄接口（管道消费侧——sieve 包实现注入；求值纯函数在 sieve
// 包，本接口承载「取激活脚本求值+产出投递动作」的编排）。
// 求值语义：implicit keep 状态机（rfc5228 §2.10.2——fileinto/keep/redirect/discard 取消；
// 被策略忽略的 redirect 不取消）+错误即停+implicit keep 兜底（§2.10.6）；
// 词法/语法错误在脚本保存/激活期校验拒绝（PUTSCRIPT/CHECKSCRIPT/Web——运行期出现
// 时按运行时错误同径兜底）。
type SieveRunner interface {
	// RunForMailbox 对单收件邮箱执行其激活脚本。
	// 参数：ctx 上下文；mailboxID 收件邮箱；evalCtx 求值上下文（信封+头缓存+大小+收件人）。
	// 返回：投递动作（目标文件夹覆盖/标志初值/redirect 目标集）；无激活脚本返回
	// nil（=直达 INBOX 原语义）；错误=运行时错误（调用方按 implicit keep 兜底——
	// 不阻断落库，CON-004）
	RunForMailbox(ctx context.Context, mailboxID int64, evalCtx *EvalContext) (*SieveDelivery, error)
}

// EvalContext 求值上下文（契约 v1.8.0——纯数据零 IO；rfc5228 §5 测试输入的邮件侧映射）。
type EvalContext struct {
	Envelope      auth.Envelope       // 信封（envelope 测试 from/to 语义——§5.4）
	Recipient     string              // 当前收件人（envelope "to" 的「导致投递给该用户的 RCPT」——§5.4 L1502-1506）
	Headers       map[string][]string // 解析头缓存（小写键——header/address/exists 测试）
	RawSize       int64               // size 测试八位组（§5.9）
	ReceivedCount int                 // redirect 环控（§4.2 Received 计数）
}

// SieveDelivery 单收件人的 Sieve 投递动作（求值产物→管道落库目标变更）。
type SieveDelivery struct {
	Discard     bool     // discard 已执行（该收件人移除落库目标——不影响其他收件人）
	FileInto    string   // fileinto 目标文件夹名（空=keep/implicit keep→INBOX 原语义）
	Redirects   []string // redirect 目标地址集（上限 MaxRedirects——超限为运行时错误）
	FlagSeen    bool     // imap4flags \Seen→is_read 初值
	FlagFlagged bool     // imap4flags \Flagged→is_flagged 初值
}

// redirectStore redirect 回流出站窄接口（QueueStore 子集——StoreSubmission 直达）。
type redirectStore interface {
	StoreSubmission(ctx context.Context, txmeta *storage.SubmissionMeta) error
}

// ───────────────────────── 工程常量（U12 计划书 1.5③，G2 批复生效） ─────────────────────────

// MaxRedirects 单脚本 redirect 数量上限（rfc5228 §4.2「MUST provide means of limiting」
// +rfc5804 MAXREDIRECTS 能力呼应；缺省 5）。
const MaxRedirects = 5

// MaxReceivedHopCount redirect 环控的 Received 计数上限（rfc5228 §4.2 环控制 MUST
// 引 SMTP §6.2 hop count；缺省 30）。
const MaxReceivedHopCount = 30

// ───────────────────────── 可选注入（沿 SetObserver 先例） ─────────────────────────

// SetSieveRunner 可选注入 Sieve 执行器（契约 v1.8.0——构造签名零变更；nil=禁用：
// 测试与渐进部署兼容，管道行为与 U11 末态完全一致）。
// 参数：runner 执行器（nil=清除注入）；submit redirect 回流通道（nil 时 redirect
// 动作记警告跳过——不取消 implicit keep，rfc5228 §4.2「被忽略的 redirect」语义）。
func (s *InboundPipelineService) SetSieveRunner(runner SieveRunner, submit redirectStore) {
	s.sieve = runner
	s.redirects = submit
}

// applySieve 对全部收件目标执行 Sieve（Deliver 编排插入步——收件人解析后、落库前）。
// 语义（计划书 1.5①②③④）：仅 active 邮箱有激活脚本（shadow 无登录无脚本——
// RunForMailbox 内部按 GetActiveScript 判定）；无脚本/nil runner→原目标不变；
// fileinto→目标 FolderName 覆盖（folder_id 解析归 StoreInbound 落库前置）；discard→
// 目标移除；redirect→原始字节经 enqueueRedirect 回流（空信封保持+环控+数量上限在
// 求值器内完成）；任何错误不阻断其余收件人与整体落库（CON-004——日志+implicit
// keep 兜底）。全 discard 时返回空切片（调用方按 250 成功处理——邮件被静默丢弃）。
// 参数：ctx；targets 当前收件目标（逐个可能被改写）；meta 来信元数据（redirect 复用
// 同一 blob 与元数据——原始字节保真）；in 原始投递输入。返回：改写后目标集。
func (s *InboundPipelineService) applySieve(ctx context.Context, targets []storage.RecipientTarget,
	meta *storage.InboundMeta, storedRaw []byte, in *Delivery) []storage.RecipientTarget {
	if s.sieve == nil {
		return targets
	}
	headers := parseHeaderMap(storedRaw)
	kept := make([]storage.RecipientTarget, 0, len(targets))
	for _, tgt := range targets {
		if tgt.Aggregate {
			// U25 聚合副本跳过 Sieve（S3-W Q3 裁决 2026-10-02 19:29:40——管理员聚合
			// 视图稳定：不被 fileinto 移走/redirect 转发/discard 丢弃；影子原行仍
			// 正常走各自激活脚本）
			kept = append(kept, tgt)
			continue
		}
		evalCtx := &EvalContext{
			Envelope:      in.Envelope,
			Recipient:     tgt.Address,
			Headers:       headers,
			RawSize:       meta.Message.RawSize,
			ReceivedCount: countReceived(headers),
		}
		dlv, err := s.sieve.RunForMailbox(ctx, tgt.MailboxID, evalCtx)
		if err != nil {
			// 运行时错误→该收件人 implicit keep 兜底（rfc5228 §2.10.6「MUST notify+
			// implicit keep」——通知工程形态=日志事件；CON-004：不阻断落库）
			slog.WarnContext(ctx, "sieve 运行时错误，收件人按 implicit keep 兜底",
				"error", err, "mailboxID", tgt.MailboxID, "recipient", tgt.Address)
			kept = append(kept, tgt)
			continue
		}
		if dlv == nil {
			kept = append(kept, tgt)
			continue
		}
		if dlv.Discard {
			continue // 静默丢弃该收件人（不影响他人——rfc5228 §4.4）
		}
		if dlv.FileInto != "" {
			tgt.FolderName = dlv.FileInto // folder_id 解析归 StoreInbound（mailbox_id+name 查询）
		}
		tgt.FlagSeen = dlv.FlagSeen
		tgt.FlagFlagged = dlv.FlagFlagged
		kept = append(kept, tgt)
		// redirect 回流（§4.2 五义务：原始字节复用已写 blob——消息不改、Received 已注入、
		// 空信封保持；环控与上限校验在求值器内完成）
		for _, rcpt := range dlv.Redirects {
			if err = s.enqueueRedirect(ctx, meta, in, rcpt); err != nil {
				slog.WarnContext(ctx, "sieve redirect 入队失败（忽略，不取消落库）",
					"error", err, "rcpt", rcpt)
			}
		}
	}
	return kept
}

// enqueueRedirect redirect 回流出站（StoreSubmission 直达——绕过 authorizeSender 用户
// 授权判定：Sieve 为系统行为非会话提交；DKIM 零重签：原始字节保真已含原域签名）。
// 信封 from=原 MAIL FROM（空则 `<>` 字面量——rfc5228 §4.2 空信封 MUST 保持，防退信环）。
func (s *InboundPipelineService) enqueueRedirect(ctx context.Context, meta *storage.InboundMeta,
	in *Delivery, rcpt string) error {
	if s.redirects == nil {
		return fmt.Errorf("redirect 通道未装配（SetSieveRunner 未注入提交仓储）")
	}
	from := in.Envelope.MailFrom
	if from == "" {
		from = "<>" // null path 字面量（数据模型 3.7 NOT NULL 兼容——U5/Q4-A 先例）
	}
	return s.redirects.StoreSubmission(ctx, &storage.SubmissionMeta{
		Message: meta.Message,
		Items: []*storage.QueueItem{{
			EnvelopeFrom:  from,
			RcptTo:        rcpt,
			Status:        storage.QueuePending,
			NextAttemptAt: meta.Message.SentAt, // Enqueue 侧统一调度初始化（StoreSubmission 默认档）
		}},
	})
}

// countReceived 统计 Received 头数（环控输入——headers 小写键）。
func countReceived(headers map[string][]string) int {
	return len(headers["received"])
}

// parseHeaderMap 自存储字节提取小写头 map（Sieve 求值上下文输入——header/address/
// exists 测试；简单 RFC5322 头段解析：冒号前小写名、值 TrimSpace 规范化、多值同名
// 追加、折叠续行展开拼接（rfc5228 §2.7.1——F-S23）、空行止；畸形行容忍跳过——与
// ParseCachedHeaders 的畸形容忍口径一致）。
func parseHeaderMap(raw []byte) map[string][]string {
	out := make(map[string][]string)
	lastName := "" // 最近一条头名（折叠续行归属——rfc5322 §2.2.3 展开语义）
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break // 头段结束（空行后为正文）
		}
		if line[0] == ' ' || line[0] == '\t' {
			// 折叠续行：展开拼接到最近头值（F-S23——rfc5228 §2.7.1 L495-496「Header
			// lines are unfolded」；rfc5322 §2.2.3 CRLF 移除后以单 SP 连接）
			if lastName != "" {
				vals := out[lastName]
				if cont := strings.TrimSpace(line); cont != "" {
					vals[len(vals)-1] += " " + cont
				}
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimRight(line[:i], " \t"))
		out[name] = append(out[name], strings.TrimSpace(line[i+1:])) // F-S22：首尾空白同忽略（rfc5228 §5.7 L1580-1582）
		lastName = name
	}
	return out
}
