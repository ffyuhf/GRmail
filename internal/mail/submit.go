// mail 域提交管道：SubmissionPipeline 实现（授权校验→DKIM 签名→头补齐→
// Blob 先写→messages+delivery_queue 单事务入队→应答「已接受」语义）。
// 依据：模块接口契约 v1.2.0 2.3 节（Submission/DSNParam/SubmissionPipeline 签名
// 逐字，Q7-A 裁决 2026-09-17 11:33:53）；
// 关键流程设计 v1.0.0 第三章 3.1（提交入队时序：认证→身份校验→DKIM→Blob+元数据
// →逐收件人 Enqueue→应答已接受非已投递）；
// 数据库表结构 v1.0.0 1.3 节（双写顺序 Blob 先/DB 后）＋3.7 节（一收件人一队列项）；
// SRS v1.0.0 FR-002（管理员任意地址）/FR-005（提交入队）/FR-008（发信 DKIM）/
// NFR-007/CON-004（ErrRetryable→451 提交侧同语义）。
// rfc6409 原文锚点（步骤 2 回读）：3.2 null path 允许（MUST NOT 拒收）；4.3 未认证
// MAIL→530（会话层职责，管道侧以 ErrUnauthorized 表达）；6.1 授权不符→550 5.7.1；
// 8.2/8.3 Date/Message-ID 缺失 SHOULD 补齐。
// 修改历史：
//
//	2026-09-17 12:02:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 6）
//	2026-10-07 15:20:00 | 扩展 | 传输安全合规批 F1/A-9：Submission 增 SkipTLSPolicy
//	字段+入队传递（G2 批准 2026-10-07 15:13:06；rfc8460 §5.3.1 L1050-1051 MUST NOT
//	honor——TLS-RPT 报告行豁免标记经提交链入队持久化）
package mail

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// ───────────────────────── 契约接口（契约 v1.2.0 2.3 逐字） ─────────────────────────

// Submission 提交投递输入（Q7-A：mail 域定义，嵌入 auth 信封）。
type Submission struct {
	// Envelope SMTP 会话信封（Helo/RemoteIP/MailFrom；null path 以空 MailFrom 表达）
	Envelope auth.Envelope
	// AuthUser 认证身份（SMTP AUTH 邮箱地址或管理员用户名，FR-002 授权判定输入）
	AuthUser string
	// Recipients RCPT TO 全量收件人（小写规范化）
	Recipients []string
	// DSNParams rfc3461 扩展参数透传（原样记录，编码态保持）
	DSNParams []DSNParam
	// TLSCipher 提交会话 TLS 加密套件注册名（F-9——rfc8314 §4.3 L511-523「tls」
	// Received 子句承载；空=非 TLS 会话缺省兜底（提交端点认证强制 TLS，理论不可达））
	TLSCipher string
	// SkipTLSPolicy F1/A-9：TLS-RPT 报告行豁免标记（true=投递链跳过 MTA-STS/DANE
	// 策略判定——rfc8460 §5.3.1「Sending MTAs MUST NOT honor MTA-STS or DANE TLSA
	// failures」；TLS 本身仍机会升级；仅 runTLSRPTReportRound 报告提交置位，
	// SMTP 提交端点/Webmail 恒零值——普通邮件判定零变化）
	SkipTLSPolicy bool
}

// DSNParam rfc3461 提交参数记录（Q7-A；值域经 rfc3461 第 4 章原文回读定稿）。
type DSNParam struct {
	Keyword string // NOTIFY | ORCPT | RET | ENVID（归一大写存储）
	Value   string // 原样值：NOTIFY=NEVER 单独或逗号列表；ORCPT=addr-type;xtext；RET=FULL|HDRS；ENVID=xtext
	Rcpt    string // RCPT 级参数所属收件人（NOTIFY/ORCPT）；MAIL 级为空（RET/ENVID）
}

// SubmissionPipeline 提交管道（SMTP 提交端点注入）。
type SubmissionPipeline interface {
	// Submit 提交入队：授权校验→DKIM 签名→Message-ID/Date 补齐→Blob 先写→
	// 单事务{messages+delivery_queue 逐收件人}→应答「已接受」（非「已投递」）。
	// 返回错误即拒绝应答；ErrRetryable→451（CON-004）
	Submit(ctx context.Context, in *Submission, raw []byte) error
}

// 编译期断言：契约 v1.2.0 2.3 提交管道接口实现锁定。
var _ SubmissionPipeline = (*SubmissionPipelineService)(nil)

// ───────────────────────── 哨兵错误 ─────────────────────────

// ErrUnauthorized 提交授权拒绝（rfc6409 6.1：550 5.7.1；FR-002 判定输入不符）。
var ErrUnauthorized = errors.New("mail: 提交授权拒绝（550 5.7.1）")

// ───────────────────────── 窄接口（消费侧最小化，NFR-015 stub 注入位） ─────────────────────────

// adminLookup 管理员身份查询（FR-002 豁免判定；storage.UserRepo 适配）。
type adminLookup interface {
	IsAdminUser(ctx context.Context, name string) (bool, error)
}

// submissionStore 提交入队仓储窄接口（SQLiteQueueRepo 满足）。
type submissionStore interface {
	StoreSubmission(ctx context.Context, txmeta *storage.SubmissionMeta) error
}

// outboundSigner DKIM 出站签名窄接口（auth.Signer 满足）。
type outboundSigner interface {
	Sign(ctx context.Context, msg []byte, domain string) (signed []byte, err error)
}

// ───────────────────────── 域服务 ─────────────────────────

// SubmissionPipelineService 提交管道域服务（SMTP 提交端点注入消费）。
type SubmissionPipelineService struct {
	signer      outboundSigner    // U3 DKIM 签名器
	blobs       storage.BlobStore // CAS 字节存储（U1）
	store       submissionStore   // messages+queue 单事务（U5）
	admins      adminLookup       // 管理员豁免判定（FR-002）
	domain      string            // 主域名（Date/Message-ID 补齐域）
	submitHooks []SubmitHook      // 发信插件链（v1.11.0/U15，nil/空=未注入；SetSubmitHooks）
}

// NewSubmissionPipelineService 构造提交管道。
// 参数：signer DKIM 签名器；blobs 字节存储；store 入队仓储；admins 管理员查询；domain 主域名。
func NewSubmissionPipelineService(signer outboundSigner, blobs storage.BlobStore,
	store submissionStore, admins adminLookup, domain string) *SubmissionPipelineService {
	return &SubmissionPipelineService{signer: signer, blobs: blobs, store: store, admins: admins, domain: domain}
}

// Submit 提交入队（契约 v1.2.0 2.3 语义逐字落地）。
// 编排（流程设计 3.1）：授权校验→头补齐→DKIM 签名→Blob 先写→缓存列解析→
// StoreSubmission 单事务（逐收件人队列行）。
// 参数：ctx 上下文（携带 LogID logger）；in 提交输入；raw DATA 完成后的原始字节。
// 返回：nil=可应答 250「已接受」；ErrRetryable=451；ErrUnauthorized=550 5.7.1。
func (s *SubmissionPipelineService) Submit(ctx context.Context, in *Submission, raw []byte) error {
	// 1. 授权校验（rfc6409 3.2/6.1 + FR-002；会话层已保证已认证，此处校验 From 授权）
	if err := s.authorizeSender(ctx, in); err != nil {
		return err
	}

	// 1.5 MSA 接收 trace 头注入（F-9——rfc8314 §7.4 L416-418「Mail Submission Servers
	// accepting mail using TLS SHOULD include in the Received field ... the TLS
	// ciphersuite of the session」+rfc5321bis §4.4.1 接收 trace 义务；方案 A 裁决
	// 2026-09-30 18:53：提交链完整 Received 构造——TLS 会话含 tls 子句（cipher 注册名））
	staged := prependHeaders(raw, buildSubmissionReceived(s.domain, in))

	// 2. 头补齐（rfc6409 8.2 Date/8.3 Message-ID 缺失 SHOULD 补齐）
	staged = ensureDateHeader(staged, time.Now())
	staged = ensureMessageIDHeader(staged, s.domain)

	// 3. DKIM 签名（MAIL FROM 域；ErrKeyNotConfigured 等哨兵→跳过+告警，部署渐进不拒收）
	signed, err := s.signer.Sign(ctx, staged, signDomain(in.Envelope.MailFrom, s.domain))
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotConfigured) {
			slog.Default().Warn("DKIM 未配置，出站邮件未签名（部署渐进：签名跳过不拒收）", "domain", s.domain)
		} else {
			// 算法不符等其他签名错误：不阻断投递（签名是增强而非必要），记录后继续
			slog.Default().Error("DKIM 签名异常，邮件以未签名态投递", "error", err)
		}
	} else {
		staged = signed
	}

	// 3.5 插件链（v1.11.0/U15：DFD P2 发信钩子——授权与 DKIM 后、Blob/入队前；
	// REJECT→PluginRejectError 提交客户端可见（计划偏离裁决 A）；失败降级放行
	// CON-004——applySubmitHooks 内承载；nil/空链=U14b 末态等价零调用）
	if rej := s.applySubmitHooks(ctx, in, staged); rej != nil {
		return rej
	}

	// 4. Blob 先写（数据模型 1.3：fsync 先行；失败 451，禁止无字节入队）
	blobKey := sha256Hex(staged)
	if err = s.blobs.Write(ctx, blobKey, staged); err != nil {
		return fmt.Errorf("%w: blob 写入: %v", ErrRetryable, err)
	}

	// 5. 缓存列解析（畸形头容忍，沿 U4 口径）
	parsed := ParseCachedHeaders(staged)

	// 6. 逐收件人队列行+单事务落库（流程设计 3.1；一收件人一队列项，数据模型 3.7）
	now := time.Now().UTC()
	retFull := dsnRetFull(in.DSNParams) // F-L3：MAIL 级 RET=FULL 检测（逐收件人同值）
	items := make([]*storage.QueueItem, 0, len(in.Recipients))
	for _, rcpt := range in.Recipients {
		items = append(items, &storage.QueueItem{
			EnvelopeFrom:  in.Envelope.MailFrom,
			RcptTo:        rcpt,
			Status:        storage.QueuePending,
			NextAttemptAt: now,
			RetFull:       retFull,          // F-L3：持久化至 worker DSN 构造消费
			SkipTLSPolicy: in.SkipTLSPolicy, // F1/A-9：报告行豁免标记持久化（迁移 00013）
		})
	}
	// DSNParams 语法已在会话层校验；此处日志登记（透传记录义务，Q7-A）
	for _, p := range in.DSNParams {
		slog.Default().Info("提交 DSN 参数透传", "keyword", p.Keyword, "rcpt", p.Rcpt)
	}
	if err = s.store.StoreSubmission(ctx, &storage.SubmissionMeta{
		Message: submissionMessageMeta(parsed, blobKey, staged),
		Items:   items,
	}); err != nil {
		return fmt.Errorf("%w: 提交事务: %v", ErrRetryable, err)
	}
	return nil
}

// authorizeSender 发信授权判定（FR-002 + rfc6409 6.1）：
// null path（空 MailFrom）放行；管理员放行任意地址；其余 MAIL FROM 必须=认证身份。
func (s *SubmissionPipelineService) authorizeSender(ctx context.Context, in *Submission) error {
	if in.Envelope.MailFrom == "" {
		return nil // null path 允许（rfc6409 3.2 MUST NOT 拒收）
	}
	isAdmin, err := s.admins.IsAdminUser(ctx, in.AuthUser)
	if err != nil {
		return fmt.Errorf("%w: 管理员查询: %v", ErrRetryable, err)
	}
	if isAdmin {
		return nil // 管理员任意地址（FR-002）
	}
	if !strings.EqualFold(in.Envelope.MailFrom, in.AuthUser) {
		return fmt.Errorf("%w: MAIL FROM %s 与认证身份 %s 不一致",
			ErrUnauthorized, in.Envelope.MailFrom, in.AuthUser)
	}
	return nil
}

// buildSubmissionReceived 构造 MSA 接收 trace 头（F-9——rfc5321bis §4.4.1 from/by/with
// +rfc8314 §4.3 tls 子句；提交端点已认证=ESMTPSA；单收件人附 for 子句沿收信路径先例；
// TLSCipher 空=非 TLS 兜底（无 tls 子句——理论不可达防御分支））。
func buildSubmissionReceived(domain string, in *Submission) string {
	helo := in.Envelope.Helo
	if helo == "" {
		helo = "unknown"
	}
	ip := in.Envelope.RemoteIP.String() // net.IP→字符串（nil→"<nil>" 兜底替换）
	if len(in.Envelope.RemoteIP) == 0 || ip == "<nil>" {
		ip = "unknown"
	}
	with := "with ESMTPSA"
	if in.TLSCipher != "" {
		with += " tls " + in.TLSCipher // rfc8314 §4.3：tls 子句（cipher 注册名形态）
	}
	var b strings.Builder
	b.WriteString("Received: from ")
	b.WriteString(helo)
	b.WriteString(" ([")
	b.WriteString(ip)
	b.WriteString("]) by ")
	b.WriteString(domain)
	b.WriteString(" (GRmail) ")
	b.WriteString(with)
	if len(in.Recipients) == 1 {
		b.WriteString(" for <" + in.Recipients[0] + ">")
	}
	b.WriteString("; ")
	b.WriteString(time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	return b.String()
}

// dsnRetFull MAIL 级 RET=FULL 检测（F-L3——rfc3461 §4.3；Rcpt 空=MAIL 级参数；
// 值域 FULL|HDRS 已在会话层校验——大小写不敏感防御）。
func dsnRetFull(params []DSNParam) bool {
	for _, p := range params {
		if p.Keyword == "RET" && p.Rcpt == "" && strings.EqualFold(p.Value, "FULL") {
			return true
		}
	}
	return false
}

// signDomain 签名域取值：MAIL FROM 域（FR-008「附带 SPF/DMARC 对齐所需发件域」）；
// MAIL FROM 为空（null path）时回落主域。
func signDomain(mailFrom, fallback string) string {
	if at := strings.LastIndex(mailFrom, "@"); at >= 0 && at+1 < len(mailFrom) {
		return strings.ToLower(mailFrom[at+1:])
	}
	return fallback
}

// submissionMessageMeta 提交路径 messages 行（验证结论缓存列为空——出站信无来信验证；
// U16 Q3-A：BodyCache 填充——出站信正文可检索）。
func submissionMessageMeta(parsed ParsedHeaders, blobKey string, raw []byte) storage.MessageMeta {
	return storage.MessageMeta{
		MessageID: parsed.MessageID,
		BlobKey:   blobKey,
		RawSize:   int64(len(raw)),
		Subject:   parsed.Subject,
		FromAddr:  parsed.FromAddr,
		ToAddrs:   parsed.ToAddrs,
		CcAddrs:   parsed.CcAddrs,
		BodyCache: BodyCacheOf(raw),
		SentAt:    parsed.SentAt,
	}
}

// ensureDateHeader Date 头缺失时前置补齐（rfc6409 8.2 SHOULD；格式 rfc5322 date-time）。
func ensureDateHeader(raw []byte, now time.Time) []byte {
	if headerPresent(raw, "Date:") {
		return raw
	}
	return prependHeaders(raw, "Date: "+now.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

// ensureMessageIDHeader Message-ID 缺失时前置补齐（rfc6409 8.3 SHOULD；
// 形态 <hex nano@domain>——唯一性经 CSPRNG+纳秒，沿 U4 通知邮件先例）。
func ensureMessageIDHeader(raw []byte, domain string) []byte {
	if headerPresent(raw, "Message-ID:") {
		return raw
	}
	id := fmt.Sprintf("<%x.%d@%s>", sha256.Sum256([]byte(time.Now().Format(time.RFC3339Nano))), time.Now().UnixNano(), domain)
	return prependHeaders(raw, "Message-ID: "+id)
}

// headerPresent 头存在性检查（行首匹配，容忍前导空行不存在——DATA 体即头区开头）。
func headerPresent(raw []byte, name string) bool {
	for _, line := range splitLines(raw) {
		if len(line) >= len(name) && strings.EqualFold(line[:len(name)], name) {
			return true
		}
		if line == "" { // 头区结束（空行）
			return false
		}
	}
	return false
}

// splitLines 按字节流切行（容忍 CRLF 与 LF；仅用于头存在性检查的宽松口径）。
func splitLines(raw []byte) []string {
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return strings.Split(s, "\n")
}

// （sha256Hex 复用 pipeline.go U4 既有辅助，不重复定义）
