// mail 域收信管道：InboundPipeline 实现（验证→trace 注入→CAS 双写→影子判定→通知→事务落库）。
// 依据：模块接口契约 v1.1.0 2.3 节（Deliver 签名逐字，Q1-A）；
// 关键流程设计 v1.0.0 第一章（收信时序：DATA 后 Verify→Blob 先写→DB 事务→影子判定+通知）
// ＋第二章（RCPT 三态：active 正常/shadow 归档/不存在建影子+通知）＋第四章（CAS 对账前提）；
// 数据库表结构 v1.0.0 1.3 节（写入顺序固定：BlobStore.Write 先、元数据事务后；
// Blob 失败或 DB 失败均不得回 250——451 促对端重试）；
// SRS v1.0.0 FR-003/004/005/008、NFR-004/007、CON-004。
// trace 注入（rfc5321bis 原文对照 2026-09-17，规范纠偏后补齐）：
// 4.4.1 Received——接收服务器 MUST 在消息内容开头插入 trace 头（from 子句 SHOULD 含
// EHLO 名+IP 地址字面量；FOR 子句若有 MUST 恰一个 path；日期 SHOULD 本地时间+数字偏移）；
// 4.4.2 Return-path——final delivery（落库到邮箱即本项目收信形态）MUST 在邮件数据最前
// 插入；4.4.5 最终头序：Return-path → Received → （A-R）→ 原消息。
// 实现口径（U4 计划书 1.5）：①注入后的字节流为存储字节（blob_key 与 IMAP/Webmail 读到的
// 均为含完整 trace 消息）；③影子邮箱建行先行独立事务（两步间崩溃由对端重试收敛）；
// ④postmaster 通知邮件与来信元数据同事务、通知投递不再递归判定。
// 修改历史：
//
//	2026-10-03 06:35:00 | 扩展 | U25影子邮箱聚合可达（G2 批准 2026-10-02 19:41:00）：
//	  Deliver 步 5.5 聚合副本 target（影子目标存在→postmaster 聚合文件夹副本行——
//	  FR-003 承载扩展）；resolveRecipients 增 shadowPresent 返回；ensureAggregateTarget
//	  目标解析；窄接口增 EnsureAggregateFolder（S3-W Q1-B/Q2-B1/Q3 裁决）
//
//	2026-09-17 03:40:00 | 新建 | U4 SMTP 收信（计划书步骤 8）
package mail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// inboundStore 收信路径仓储窄接口（消费侧接口最小化惯例；SQLiteMessageRepo 满足。
// 契约 2.1 MessageRepo 完整接口由 U6/U9 补齐六方法后作为注入宽接口启用——U4 计划书 1.5⑤）。
type inboundStore interface {
	StoreInbound(ctx context.Context, txmeta *storage.InboundMeta) error
}

// authResultsHeaderPrefix 入站删除匹配前缀（大小写不敏感——rfc5322 头名大小写无关）。
const authResultsHeaderPrefix = "Authentication-Results:"

// stripInboundAuthResults 删除消息头区全部 Authentication-Results 头行及其折叠续行
// （F-A6——rfc8601 §5 边界 MTA 义务）。逐行扫描：命中头名行删除，其后以 SP/HTAB
// 开头的续行（rfc5322 §2.2.3 折叠形态）一并删除；空行后的体区不扫描（头/体以首个
// 空行分界）。
// 参数：raw 原始消息字节。返回：删除后的消息字节（无命中时原样返回）。
func stripInboundAuthResults(raw []byte) []byte {
	if !strings.Contains(string(raw), authResultsHeaderPrefix[:len(authResultsHeaderPrefix)-1]) {
		return raw // 快速路径：不含头名前缀（去冒号宽松匹配）零改动
	}
	lines := strings.Split(string(raw), "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	inBody := false
	for _, ln := range lines {
		trimmed := strings.TrimLeft(ln, " \t")
		if inBody {
			out = append(out, ln)
			continue
		}
		if trimmed == "" || trimmed == "\r" { // 头/体分界空行
			inBody = true
			out = append(out, ln)
			continue
		}
		folded := strings.HasPrefix(ln, " ") || strings.HasPrefix(ln, "\t")
		if skipping && folded { // 被删头行的折叠续行
			continue
		}
		skipping = false
		if len(trimmed) >= len(authResultsHeaderPrefix) &&
			strings.EqualFold(trimmed[:len(authResultsHeaderPrefix)], authResultsHeaderPrefix) {
			skipping = true
			continue
		}
		out = append(out, ln)
	}
	return []byte(strings.Join(out, "\n"))
}

// shadowAccounts 影子判定路径的账号服务窄接口（测试 stub 注入位，NFR-015；
// U25 增 EnsureAggregateFolder——聚合副本目标的文件夹确保位）。
type shadowAccounts interface {
	GetMailbox(ctx context.Context, addr string) (*storage.Mailbox, error)
	EnsureAggregateFolder(ctx context.Context, mailboxID int64) error
	CreateShadowMailbox(ctx context.Context, addr string) (*storage.Mailbox, error)
}

// DeliverObserver 落库通知观察者（契约 v1.3.0 2.3，Q2-A 裁决 2026-09-18 00:01:30：
// U6 IDLE 事件驱动——rfc2177 §3 IDLE 激活期服务器可随时发送 EXISTS）。
// 尽力语义：实现方吸收回调错误，禁止影响投递结果与 SMTP 应答。
type DeliverObserver interface {
	// OnDelivered 收信事务提交成功后回调（mailboxIDs=本次落库命中的邮箱，含通知目标）。
	OnDelivered(mailboxIDs []int64)
}

// InboundPipelineService 收信管道域服务（SMTP 服务端注入消费）。
type InboundPipelineService struct {
	verifier    auth.Verifier     // U3 四项验证器
	accounts    shadowAccounts    // RCPT 目标解析与影子建立（U2）
	blobs       storage.BlobStore // CAS 字节存储（U1，Write 幂等含 fsync）
	messages    inboundStore      // 元数据事务（StoreInbound）
	domain      string            // 主域名（postmaster 通知目标与 Message-ID 域）
	observer    DeliverObserver   // 落库通知（v1.3.0，nil=未注入；U6 IDLE 事件源）
	sieve       SieveRunner       // Sieve 执行器（v1.8.0/U12，nil=未注入；SetSieveRunner）
	redirects   redirectStore     // redirect 回流出站（v1.8.0/U12，nil=redirect 动作忽略）
	pluginHooks []InboundHook     // 收信插件链（v1.11.0/U15，nil/空=未注入；SetPluginHooks）
}

// SetObserver 可选注入落库观察者（构造签名零变更——契约 v1.3.0 增量扩展形态；
// cmd 装配层桥接 imap 广播器，U6 计划书步骤 4/7）。
// 参数：observer 观察者（nil=清除注入）。
func (s *InboundPipelineService) SetObserver(observer DeliverObserver) {
	s.observer = observer
}

// NewInboundPipelineService 构造收信管道。
// 参数：verifier 验证器；accounts 账号服务；blobs 字节存储；messages 邮件仓储；domain 主域名。
func NewInboundPipelineService(verifier auth.Verifier, accounts shadowAccounts,
	blobs storage.BlobStore, messages inboundStore, domain string) *InboundPipelineService {
	return &InboundPipelineService{
		verifier: verifier, accounts: accounts, blobs: blobs, messages: messages, domain: domain,
	}
}

// 编译期断言：契约 v1.1.0 2.3 接口实现锁定。
var _ InboundPipeline = (*InboundPipelineService)(nil)

// Deliver 收信投递（契约 v1.1.0 2.3：多收件人单事务；落库失败 RetryableError→451）。
// 编排（流程设计第一章）：Verify→A-R 前置注入→SHA-256→Blob 写（先）→缓存列解析→
// 收件人三态解析（不存在者建影子，1.5③）→影子通知邮件生成（Q4-A）→StoreInbound（后）。
// 参数：ctx 上下文（携带 LogID logger）；in 投递输入（Q1-A Delivery）；raw DATA 完成后的原始字节。
// 返回：nil=可回 250；ErrRetryable=应回 451（CON-004）；其他错误=管道异常（同样不得回 250）。
func (s *InboundPipelineService) Deliver(ctx context.Context, in *Delivery, raw []byte) error {
	logger := slog.Default()

	// 1. 四项验证（U3：单项失败不影响其余项；DNS 瞬时故障在结论位以 temperror 呈现）
	res, err := s.verifier.Verify(ctx, &auth.IncomingMail{Envelope: in.Envelope, Raw: raw})
	if err != nil {
		return fmt.Errorf("验证器调用失败: %w", err) // 非 Retryable：SMTP 层按 451 兜底（不回 250）
	}

	// 1.5 插件链（v1.11.0/U15：FR-005「认证验证→插件链→Sieve→落库」——四项验证后
	// 立即执行；REJECT→PluginRejectError 对端可见（计划偏离裁决 A 2026-09-24 10:53:12）；
	// 插件 RPC 失败/超时降级放行（CON-004——applyInboundHooks 内承载）；nil/空链
	// =U14b 末态等价零调用）
	if rej := s.applyInboundHooks(ctx, in, raw, res); rej != nil {
		return rej
	}

	// 2. trace 头前置注入（rfc5321bis 4.4.1/4.4.2/4.4.5 + rfc8601）：
	// F-A6（RFC规范修正 RF-E，G2 批准 2026-09-28 22:16:57）：注入前删除原消息全部入站
	// Authentication-Results 头（rfc8601 §5 L1521-1529「MUST delete any discovered
	// instance of this header field that claims...to have been added within its trust
	// boundary」——边界 MTA 最简路径；防伪造 A-R 欺骗下游，删除先于本域 A-R 注入）
	raw = stripInboundAuthResults(raw)
	received := buildReceivedHeader(s.domain, in)
	storedRaw := prependHeaders(raw,
		"Return-path: <"+in.Envelope.MailFrom+">",
		received,
		res.AuthResultsHeader, // U3 产物（无 CRLF 结尾，prependHeaders 统一补尾）
	)
	blobKey := sha256Hex(storedRaw)

	// 3. Blob 先写（数据模型 1.3：fsync 持久化先行；失败 451 促重试，禁止无字节回 250）
	if err = s.blobs.Write(ctx, blobKey, storedRaw); err != nil {
		return fmt.Errorf("%w: blob 写入: %v", ErrRetryable, err)
	}

	// 4. 缓存列解析（畸形头容忍：尽力而为，不阻断）
	parsed := ParseCachedHeaders(storedRaw)

	// 5. 收件人三态解析：active/shadow 直接归档；不存在建影子（1.5③：先行独立事务，
	// 两步间崩溃由对端重试收敛——重试时地址已存在(shadow)直达归档）
	targets, newShadows, shadowPresent, err := s.resolveRecipients(ctx, in.Recipients)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("无有效收件人（%d 个候选全被跳过）", len(in.Recipients))
	}

	// 5.5 U25 聚合副本 target（FR-003「转交管理员」承载扩展——存在影子目标即向
	// postmaster 聚合文件夹追加副本行：同一 messages 主体+blob CAS 复用零字节重复；
	// StoreInbound 同事务落库〔CON-004〕；Sieve 跳过由 Aggregate 标记承载——S3-W
	// Q1-B/Q3 裁决 2026-10-02 19:26:39/19:29:40）
	if shadowPresent {
		agg, aerr := s.ensureAggregateTarget(ctx)
		if aerr != nil {
			return aerr
		}
		targets = append(targets, *agg)
	}

	// 6. 影子通知邮件（Q4-A：本次投递触发了影子建立才生成；1.5④：通知直接归档
	// postmaster 邮箱，不再递归判定——通知邮件是落库数据而非一次新的投递）
	var notice *storage.NoticeMeta
	if len(newShadows) > 0 {
		if notice, err = s.buildShadowNotice(ctx, newShadows); err != nil {
			return err
		}
	}

	// 7. 元数据事务（后）：来信行+全部关联行+通知行同事务原子提交（1.5②/④）
	meta := &storage.InboundMeta{
		Message: storage.MessageMeta{
			MessageID:         parsed.MessageID,
			BlobKey:           blobKey,
			RawSize:           int64(len(storedRaw)),
			Subject:           parsed.Subject,
			FromAddr:          parsed.FromAddr,
			ToAddrs:           parsed.ToAddrs,
			CcAddrs:           parsed.CcAddrs,
			BodyCache:         BodyCacheOf(storedRaw), // U16 Q3-A：正文缓存（与 CAS 键同源字节）
			SentAt:            parsed.SentAt,
			SPFResult:         res.SPF,
			DKIMResult:        res.DKIM,
			DMARCResult:       res.DMARC,
			ARCResult:         res.ARC,
			AuthResultsHeader: res.AuthResultsHeader,
		},
		Recipients: targets,
		Notice:     notice,
	}
	// 7.5 Sieve 执行（v1.8.0/U12：FR-005「认证验证→插件链→Sieve→落库」定死位——
	// 收件人解析后、落库事务前逐收件邮箱执行激活脚本；CON-004：任何 Sieve 异常
	// 按 implicit keep 兜底不阻断落库；redirect 回流经 StoreSubmission 直达；
	// 全部收件人被 discard 时仅落影子通知行（若有）——rfc5228 §4.4 静默语义）
	if s.sieve != nil {
		targets = s.applySieve(ctx, targets, meta, storedRaw, in)
		meta.Recipients = targets
	}
	if len(targets) == 0 {
		if notice == nil {
			// 候选全跳过（Sieve 前原判定已拦截常规场景；此处防御性兜底）
			return fmt.Errorf("无有效收件人（%d 个候选全被跳过或 discard）", len(in.Recipients))
		}
		meta.Recipients = nil // 全 discard+有影子通知：仅落通知行
	}
	if err = s.messages.StoreInbound(ctx, meta); err != nil {
		// Blob 已落但事务回滚=孤儿 Blob，由对账清理（数据模型 1.3 场景 2）；451 促重试
		logger.WarnContext(ctx, "收信事务失败（孤儿 blob 待对账清理）", "error", err, "blobKey", blobKey)
		return fmt.Errorf("%w: 元数据事务: %v", ErrRetryable, err)
	}
	logger.InfoContext(ctx, "来信落库完成", "recipients", len(targets),
		"spf", res.SPF, "dkim", res.DKIM, "dmarc", res.DMARC, "arc", res.ARC)

	// 8. 落库通知（v1.3.0，Q2-A：U6 IDLE 事件源；尽力语义——回调异常仅告警不回滚）
	if s.observer != nil {
		ids := make([]int64, 0, len(targets)+1)
		for _, t := range targets {
			ids = append(ids, t.MailboxID)
		}
		if notice != nil {
			ids = append(ids, notice.MailboxID)
		}
		s.observer.OnDelivered(ids)
	}
	return nil
}

// resolveRecipients 逐收件人三态解析（流程设计第二章）。
// 返回：归档目标列表、本次新建的影子地址列表、是否存在影子目标（U25 聚合副本
// 触发位——新建与既有影子均置位：FR-003 catch-all 全量转交语义）；失败返回错误。
// disabled 到达此层视为防御性场景（SMTP 层 RCPT 已 550 拦截）：跳过并告警。
func (s *InboundPipelineService) resolveRecipients(ctx context.Context, recipients []string) ([]storage.RecipientTarget, []string, bool, error) {
	targets := make([]storage.RecipientTarget, 0, len(recipients))
	var newShadows []string
	shadowPresent := false
	for _, addr := range recipients {
		m, err := s.accounts.GetMailbox(ctx, addr)
		switch {
		case err == nil && m.Status == storage.MailboxStatusActive:
			targets = append(targets, storage.RecipientTarget{MailboxID: m.ID, Address: addr})
		case err == nil && m.Status == storage.MailboxStatusShadow:
			targets = append(targets, storage.RecipientTarget{MailboxID: m.ID, Address: addr})
			shadowPresent = true // 既有影子新来信——聚合副本同样触达（FR-003 全量语义）
		case errors.Is(err, storage.ErrMailboxNotFound):
			// 不存在→建影子（FR-004 判定①；CatchAll 关闭场景 SMTP 层已 550，到达即开启态）
			shadow, cerr := s.accounts.CreateShadowMailbox(ctx, addr)
			if cerr != nil {
				return nil, nil, false, fmt.Errorf("建立影子邮箱 %s: %w", addr, cerr)
			}
			targets = append(targets, storage.RecipientTarget{MailboxID: shadow.ID, Address: addr})
			newShadows = append(newShadows, addr)
			shadowPresent = true
		case err != nil:
			return nil, nil, false, fmt.Errorf("查询收件邮箱 %s: %w", addr, err)
		default:
			slog.WarnContext(ctx, "收件邮箱状态不可投递（已跳过）", "addr", addr, "status", m.Status)
		}
	}
	return targets, newShadows, shadowPresent, nil
}

// aggregateFolderName 聚合文件夹存储名（U25——与迁移 00010/InsertAggregateFolder
// SQL 字面量一致；系统文件夹不可改名，名称即稳定键）。
const aggregateFolderName = "Unregistered"

// ensureAggregateTarget 聚合副本目标解析（U25——postmaster 邮箱确保+聚合文件夹
// 确保+目标构造）。postmaster 不存在时建影子归档（沿 buildShadowNotice 1.5④ 不递归
// 判定先例）；文件夹确保幂等（迁移 00010 存量兜底之上的运行期防御双保险）。
func (s *InboundPipelineService) ensureAggregateTarget(ctx context.Context) (*storage.RecipientTarget, error) {
	postmaster := "postmaster@" + s.domain
	m, err := s.accounts.GetMailbox(ctx, postmaster)
	if err != nil {
		if !errors.Is(err, storage.ErrMailboxNotFound) {
			return nil, fmt.Errorf("查询 postmaster 邮箱: %w", err)
		}
		if m, err = s.accounts.CreateShadowMailbox(ctx, postmaster); err != nil {
			return nil, fmt.Errorf("建立 postmaster 影子邮箱: %w", err)
		}
	}
	if err = s.accounts.EnsureAggregateFolder(ctx, m.ID); err != nil {
		return nil, err
	}
	return &storage.RecipientTarget{
		MailboxID: m.ID, Address: postmaster,
		FolderName: aggregateFolderName, Aggregate: true,
	}, nil
}

// buildShadowNotice 生成影子建立通知邮件（Q4-A：目标 postmaster@主域）。
// 通知邮件字节同样先写 Blob（数据模型 1.3 顺序对全部邮件一致），元数据与来信同事务。
func (s *InboundPipelineService) buildShadowNotice(ctx context.Context, newShadows []string) (*storage.NoticeMeta, error) {
	postmaster := "postmaster@" + s.domain
	m, err := s.accounts.GetMailbox(ctx, postmaster)
	if err != nil {
		if !errors.Is(err, storage.ErrMailboxNotFound) {
			return nil, fmt.Errorf("查询 postmaster 邮箱: %w", err)
		}
		// postmaster 未注册：同样建影子归档（首封信即其归档信；1.5④ 不递归通知）
		if m, err = s.accounts.CreateShadowMailbox(ctx, postmaster); err != nil {
			return nil, fmt.Errorf("建立 postmaster 影子邮箱: %w", err)
		}
	}

	raw := s.renderShadowNotice(postmaster, newShadows)
	key := sha256Hex(raw)
	if err = s.blobs.Write(ctx, key, raw); err != nil {
		return nil, fmt.Errorf("%w: 通知邮件 blob 写入: %v", ErrRetryable, err)
	}
	now := time.Now().UTC()
	return &storage.NoticeMeta{
		Message: storage.MessageMeta{
			MessageID: generateMessageID(s.domain),
			BlobKey:   key,
			RawSize:   int64(len(raw)),
			Subject:   fmt.Sprintf("[GRmail] 新影子邮箱：%s", strings.Join(newShadows, ", ")),
			FromAddr:  "mailer-daemon@" + s.domain,
			ToAddrs:   fmt.Sprintf(`["%s"]`, postmaster),
			BodyCache: BodyCacheOf(raw), // U16 Q3-A：通知正文缓存（同一致性）
			SentAt:    now,
		},
		MailboxID: m.ID,
	}, nil
}

// renderShadowNotice 渲染通知邮件 RFC 5322 字节（CRLF 行尾；UTF-8 正文）。
func (s *InboundPipelineService) renderShadowNotice(postmaster string, newShadows []string) []byte {
	now := time.Now().UTC().Format(time.RFC1123Z)
	var b strings.Builder
	fmt.Fprintf(&b, "Message-ID: %s\r\n", generateMessageID(s.domain))
	fmt.Fprintf(&b, "From: GRmail <mailer-daemon@%s>\r\n", s.domain)
	fmt.Fprintf(&b, "To: postmaster <+%s>\r\n", postmaster)
	fmt.Fprintf(&b, "Subject: [GRmail] 新影子邮箱：%s\r\n", strings.Join(newShadows, ", "))
	fmt.Fprintf(&b, "Date: %s\r\n", now)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&b, "以下未注册地址收到首封来信，已自动建立影子邮箱并归档：\r\n")
	for _, addr := range newShadows {
		fmt.Fprintf(&b, "  - %s\r\n", addr)
	}
	b.WriteString("登录 Webmail 管理后台（影子邮箱面板）可查看来信并为地址激活设置凭据。\r\n")
	return []byte(b.String())
}

// ───────────────────────── 字节辅助 ─────────────────────────

// prependHeaders 将多个完整头行（无 CRLF 结尾）自上而下前置到消息字节最前
// （注入形态 1.5①：headers[0] 为最顶头）。
func prependHeaders(raw []byte, headers ...string) []byte {
	var head []byte
	for _, h := range headers {
		if h == "" {
			continue
		}
		head = append(head, h...)
		head = append(head, '\r', '\n')
	}
	if len(head) == 0 {
		return raw
	}
	out := make([]byte, 0, len(head)+len(raw))
	out = append(out, head...)
	return append(out, raw...)
}

// buildReceivedHeader 构造 Received trace 头（rfc5321bis 4.4.1：接收 MUST 插入）。
// from 子句：EHLO 名 + IP 地址字面量（4.4.1 SHOULD 双要素）；
// FOR 子句：仅单收件人时出现（4.4.1：若有 MUST 恰一个 path，多收件人省略）；
// 日期：本地时间+数字偏移（4.4.1 SHOULD；偏移由运行环境时区决定）。
// with 子句统一 ESMTP（信封未携带 EHLO/HELO 标志，现代 MTA 均为 EHLO；token 非必选字段）。
func buildReceivedHeader(domain string, in *Delivery) string {
	helo := in.Envelope.Helo
	ip := ""
	if in.Envelope.RemoteIP != nil {
		ip = in.Envelope.RemoteIP.String()
	}
	var b strings.Builder
	b.WriteString("Received: from ")
	b.WriteString(helo)
	fmt.Fprintf(&b, " ([%s])", ip)
	fmt.Fprintf(&b, " by %s (GRmail) with ESMTP", domain)
	if len(in.Recipients) == 1 {
		fmt.Fprintf(&b, " for <%s>", in.Recipients[0])
	}
	fmt.Fprintf(&b, "; %s", time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	return b.String()
}

// sha256Hex SHA-256 十六进制（64 位小写，Q13 CAS 键）。
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// generateMessageID 域内唯一 Message-ID（<grmail-<hex16>-<unixnano>@domain>）。
func generateMessageID(domain string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// CSPRNG 失败极罕见：以时间戳兜底保证唯一性构造不中断
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(now >> (i * 8))
		}
	}
	return fmt.Sprintf("<grmail-%s-%d@%s>", hex.EncodeToString(b[:]), time.Now().UnixNano(), domain)
}
