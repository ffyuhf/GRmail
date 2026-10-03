// mail 域出站投递：OutboundSender 实现（本域分流→MX 解析→TLS 策略（DANE 三态
// U13+MTA-STS 发送侧 L-A）→SMTP 客户端投递→结果分类+TLS-RPT 结果采集（L-B））。
// 依据：模块接口契约 v1.9.0 2.3 节（OutboundSender 签名逐字，v1.0.0 定义 U5 落地；
// DaneValidator 构造注入 U13 增量——nil=U12b 末态等价）；
// Q3-A 裁决（2026-09-17 11:28:56）：worker 消费侧本域分流——rcpt 域=本域复用 U4
// 收信链路本地投递不出网；
// Q2-A 裁决（Opportunistic TLS）：对端通告 STARTTLS→升级验证（系统根 CA+MX 主机名）；
// 握手/验证失败→deferred 不降级明文重投（防降级，NFR-006 精神）；无 STARTTLS→明文；
// U13（G2 批准 2026-09-23 08:19:32）：DaneValidator 注入后 TLS 策略步三态——
// RequireDANE（rfc7672 §3：SNI=TLSA 基域+InsecureSkipVerify+握手后 TLSA 匹配，
// 认证失败 MUST NOT 投递）/RequireTLSOnly（secure 承诺态无 STARTTLS 拒明文——§2.2
// 第二分支）/Opportunistic（现状——insecure 降级不阻塞，NFR-008）；MX 遍历优先级
// 保持（§2.2.1——Check 错误经 deferred 转移下一台，§2.1.2 MX 不可达语义）；
// rfc5321bis 5.1（无 MX 时 A 记录回退）；PMail 全景 E6 先例（逐 MX 故障转移）；
// SRS FR-005（MX 解析→TLS 策略→投递）/FR-010（发送侧 DANE）/NFR-006/007/008/016。
// 修改历史：
//
//	2026-09-17 12:08:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 8）
//	2026-09-23 08:35:00 | 扩展 | U13 传输安全全量：DaneValidator 构造注入+TLS 策略
//	三态分支+RequireDANE 握手后认证（计划书步骤 7/1.5⑦⑨；契约 v1.9.0 2.3/2.4）
//	2026-09-28 09:32:00 | 重构 | R5R6收敛：SetMessageSource 进程级单例废除——
//	messages MessageSource 构造注入（架构总览 v1.0.3 8.2 R5+契约 v1.14.0 2.4 注记；
//	依据：R5R6收敛计划书 v1.0.0 步骤 2，G2 批准 2026-09-28 09:31:53）
//	2026-09-29 17:25:00 | 修正 | RFC候选修正批次 RF-H：F-L2/F-L8 出站声明面——
//	MAIL FROM 参数化（非 ASCII 信封 SMTPUTF8——rfc6531 §3.3 L428-429 客户端 MUST
//	声明/未通告不可投递；8bit 内容 BODY=8BITMIME——rfc6152 §2 未通告 MUST NOT 发送）
//	+STARTTLS 后重 EHLO 能力集保留（rfc3207 §4.2 能力重置后以第二次为准）
//	2026-10-01 23:16:00 | 扩展 | 传输安全与日志增强批次 L-A/L-B：MTA-STS 发送侧
//	验证（SetSTSValidator 可选注入——nil=末态等价，沿 SetSieveRunner 先例构造签名
//	零变更）+TLS-RPT 结果采集（SetTLSReporter 可选注入——enforce 拒投递/STARTTLS
//	失败/无 STARTTLS/成功四采集点；rfc8461 §5.1 enforce 候选失败 continue 下一台+
//	§5 临时错误语义由既有 deferred 链承载）
//	（来源：G2 批准 2026-10-01 22:54:41，传输安全与日志增强计划书 v1.0.0 步骤 2/3）
package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"GRmail/internal/auth"
	"GRmail/internal/storage"
)

// ───────────────────────── 契约接口（契约 2.3 逐字） ─────────────────────────

// OutboundSender 出站投递（队列 worker 消费）。
type OutboundSender interface {
	Send(ctx context.Context, item *storage.QueueItem) storage.AttemptResult // MX→TLS 策略→投递→结果分类
}

// 编译期断言。
var _ OutboundSender = (*OutboundSenderService)(nil)

// ───────────────────────── 窄接口（stub 注入位，NFR-015） ─────────────────────────

// MXResolver 收件域邮件交换解析（生产=miekg/dns Q10；测试=内存 stub）。
type MXResolver interface {
	// LookupMX 按优先级返回 MX 主机（无 MX 记录时返回空切片非错误——触发 A 回退）。
	LookupMX(ctx context.Context, domain string) ([]string, error)
	// LookupHost A/AAAA 解析（MX 缺失回退路径，rfc5321bis 5.1）。
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// ConnDialer TCP 连接工厂（生产=net.Dialer；测试=net.Pipe 注入模拟对端）。
type ConnDialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
}

// ───────────────────────── U13 窄接口（契约 v1.9.0 2.3——mail 侧视图） ─────────────────────────

// DaneMode 发送侧 DANE 三态决策（契约 v1.9.0——mail 消费视图；实现归 transport 域，
// 本包零 transport import，main 装配桥接做类型适配）。
type DaneMode int

const (
	DaneOpportunistic  DaneMode = iota // insecure/无 secure TLSA→机会 TLS（NFR-008 降级锚）
	DaneRequireTLSOnly                 // secure RRset 全 unusable→MUST TLS 免认证（rfc7672 §2.2 第二分支）
	DaneRequireDANE                    // secure RRset 含 usable→MUST TLS+TLSA 认证（rfc7672 §2.2 第一分支）
)

// DaneDecision DANE 决策（mail 消费子集——VerifyPeer 闭包由实现侧捕获完整决策
// （Records/RefNames）后注入，握手后认证零类型泄漏）。
type DaneDecision struct {
	Mode          DaneMode                              // 三态决策
	BaseTLSDomain string                                // TLSA 基域（RequireDANE 态 SNI——rfc7672 §8.1）
	VerifyPeer    func(certs []*x509.Certificate) error // 握手后 TLSA 匹配（失败=MUST NOT 投递）
}

// DaneValidator 发送侧 DANE 决策窄接口（契约 v1.9.0 2.3 逐字签名；nil 注入=U12b
// 末态等价——全量 Opportunistic，既有出站行为完全保持，测试渐进锚）。
type DaneValidator interface {
	// Check 对单台 MX 主机产出 DANE 决策。
	// 参数：ctx 上下文；mxHost MX 主机名；nextHopDomain 原始下一跳域。返回：决策；
	// 错误=DNSSEC/TLSA 查询失败（调用方按「MX 不可达」跳过——禁止投递，防降级）。
	Check(ctx context.Context, mxHost, nextHopDomain string) (*DaneDecision, error)
}

// ── 传输安全与日志增强批次窄接口（契约 v1.21.0 2.3——mail 侧视图，L-A/L-B） ──

// STSValidator 发送侧 MTA-STS 判定窄接口（rfc8461 §4/§5；实现归 transport 域
// STSSenderService，本包零 transport import——main 装配桥接做类型适配，沿
// DaneValidator 先例；SetSTSValidator nil 注入=批次前末态等价——既有出站行为完全保持）。
type STSValidator interface {
	// Check 对单个投递目标产出 MTA-STS 判定。
	// 参数：ctx 上下文；policyDomain 收件策略域；mxHost 目标 MX 主机。返回：决策
	// （Mode 空串=对端无 MTA-STS 放行）；错误=发现层内部异常（放行降级——MTA-STS
	// 发现失败按无策略处理，rfc8461 §3.3 链路级语义）。
	Check(ctx context.Context, policyDomain, mxHost string) (*STSDecision, error)
}

// STSDecision MTA-STS 判定结果（mail 消费视图——transport.STSSenderDecision 适配）。
type STSDecision struct {
	Mode      string // enforce | testing | none | 空串（无策略）
	MXMatched bool   // 目标 MX 是否匹配策略 mx 模式（§4.1）
}

// TLSResultRecorder TLS 投递结果采集窄接口（rfc8460 §4 聚合输入；实现归 transport
// 域 TLSRPTAggregator——main 桥接；nil 注入=不采集末态等价）。
// 约定：resultType 空串=成功会话计数；其余为 rfc8460 §4.3 注册值。
type TLSResultRecorder interface {
	Record(domain, mxHost, resultType string)
}

// ───────────────────────── 生产实现 ─────────────────────────

// DNSMXResolver miekg/dns 生产解析器（Q10 统一复用裁决；A/AAAA 经系统解析器）。
type DNSMXResolver struct{}

// LookupMX 查询 MX 记录（优先级升序）；NXDOMAIN 类错误返回空切片（触发 A 回退判定）。
func (DNSMXResolver) LookupMX(ctx context.Context, domain string) ([]string, error) {
	// miekg/dns 完整查询链较重；本单元经 net.Resolver 的 LookupMX 薄封装承载
	// （net.Resolver 底层即 miekg 同源系统解析；U6+ 需 DNSSEC 时切换 miekg 全量 API——
	// 架构总览 #11 的分批落地口径，修改文档第三章登记）
	mx, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, nil // 域不存在/查询失败→A 回退（E6 先例：MX 失败+A 失败组合为临时错误）
	}
	hosts := make([]string, 0, len(mx))
	for _, r := range mx {
		hosts = append(hosts, strings.TrimSuffix(r.Host, "."))
	}
	return hosts, nil
}

// LookupHost A/AAAA 系统解析。
func (DNSMXResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// NetDialer 生产 TCP 连接（10s 拨号超时，PMail 全景 K3 先例档位）。
type NetDialer struct{}

// Dial 拨号并返回连接。
func (NetDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// ───────────────────────── 域服务 ─────────────────────────

// OutboundSenderService 出站投递域服务。
type OutboundSenderService struct {
	domain   string          // 本域（Q3-A 分流判定）
	local    InboundPipeline // 本域分流落库链路（U4 复用）
	mx       MXResolver
	dial     ConnDialer
	dane     DaneValidator     // U13：发送侧 DANE 决策（nil=U12b 末态等价——契约 v1.9.0 2.3）
	messages MessageSource     // R5：出站原信读取源（构造注入——原进程级单例收敛，架构 8.2）
	sts      STSValidator      // L-A：发送侧 MTA-STS 判定（nil=批次前末态等价——SetSTSValidator 注入）
	tlsrpt   TLSResultRecorder // L-B：TLS 投递结果采集（nil=不采集——SetTLSReporter 注入）
}

// NewOutboundSenderService 构造出站投递器。
// 参数：domain 本域；local 收信管道（分流复用）；mx 域名解析；dial 连接工厂；
// dane DANE 决策器（U13——nil=禁用：既有 Opportunistic 行为，渐进部署与测试兼容）；
// messages 出站原信读取源（R5 收敛——构造注入；nil=未注入：readItemRaw 显式报错）。
func NewOutboundSenderService(domain string, local InboundPipeline, mx MXResolver, dial ConnDialer, dane DaneValidator, messages MessageSource) *OutboundSenderService {
	return &OutboundSenderService{domain: domain, local: local, mx: mx, dial: dial, dane: dane, messages: messages}
}

// SetSTSValidator 可选注入发送侧 MTA-STS 验证器（L-A——沿 v1.8.0 SetSieveRunner
// 先例：构造签名零变更；nil/未调用=批次前末态等价，渐进部署与测试兼容）。
func (s *OutboundSenderService) SetSTSValidator(v STSValidator) { s.sts = v }

// SetTLSReporter 可选注入 TLS-RPT 结果采集器（L-B——同上先例；nil/未调用=不采集）。
func (s *OutboundSenderService) SetTLSReporter(r TLSResultRecorder) { s.tlsrpt = r }

// recordTLS TLS-RPT 采集出口（nil 容错——未注入零开销）。
// 参数：rcpt 收件地址（提取策略域）；mxHost 目标主机；resultType 结果类型（空串=成功）。
func (s *OutboundSenderService) recordTLS(rcpt, mxHost, resultType string) {
	if s.tlsrpt != nil {
		s.tlsrpt.Record(rcptDomain(rcpt), mxHost, resultType)
	}
}

// Send 单收件人投递（契约 2.3：MX→TLS 策略→投递→结果分类）。
// 参数：ctx 上下文；item 队列项（in_flight 态）。返回：尝试结果（sent/deferred/failed）。
func (s *OutboundSenderService) Send(ctx context.Context, item *storage.QueueItem) storage.AttemptResult {
	logger := slog.Default()

	// 1. 本域分流（Q3-A）：rcpt 域=本域→复用收信链路本地落库（含影子判定），不出网
	if strings.EqualFold(rcptDomain(item.RcptTo), s.domain) {
		return s.deliverLocal(ctx, item)
	}

	// 2. MX 解析（+A 回退，rfc5321bis 5.1；E6 先例：双失败组合为临时错误）
	hosts, err := s.resolveHosts(ctx, item.RcptTo)
	if err != nil || len(hosts) == 0 {
		return storage.AttemptResult{Status: storage.AttemptDeferred, Error: fmt.Sprintf("MX 解析失败: %v", err)}
	}

	// 3. 逐 MX 故障转移（E6：主 MX 失败尝试备用）
	var last storage.AttemptResult
	for _, host := range hosts {
		last = s.deliverToHost(ctx, host, item)
		if last.Status != storage.AttemptDeferred {
			return last // sent/failed 终止转移（5xx 换 MX 无意义）
		}
		logger.Info("MX 投递失败转移下一台", "host", host, "error", last.Error)
	}
	return last
}

// resolveHosts 收件域投递目标解析：MX 优先；无 MX→域本身 A 记录（隐式 MX）。
func (s *OutboundSenderService) resolveHosts(ctx context.Context, rcpt string) ([]string, error) {
	domain := rcptDomain(rcpt)
	mxHosts, _ := s.mx.LookupMX(ctx, domain)
	if len(mxHosts) > 0 {
		return mxHosts, nil
	}
	ips, err := s.mx.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("A 回退解析: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("域 %s 无 MX/A 记录", domain)
	}
	return []string{domain}, nil // 返回域名（隐式 MX；连接时再解析 A——dial 侧处理）
}

// deliverLocal 本域分流投递（Q3-A）：构造收信 Delivery 走 U4 管道（验证/trace/影子/落库）。
func (s *OutboundSenderService) deliverLocal(ctx context.Context, item *storage.QueueItem) storage.AttemptResult {
	raw, err := s.readItemRaw(ctx, item)
	if err != nil {
		return storage.AttemptResult{Status: storage.AttemptDeferred, Error: "原信读取失败: " + err.Error()}
	}
	err = s.local.Deliver(ctx, &Delivery{
		Envelope:   envelopeFor(item),
		Recipients: []string{item.RcptTo},
	}, raw)
	if err != nil {
		// 本域落库失败多为瞬时错误（busy/磁盘）→deferred 重试；不 failed（防误退信）
		return storage.AttemptResult{Status: storage.AttemptDeferred, Error: "本域投递: " + err.Error()}
	}
	return storage.AttemptResult{Status: storage.AttemptSent}
}

// readItemRaw 队列项→原信字节（R5 收敛：经构造注入的 messages 源解析——
// 原进程级单例 outboundMessages/SetMessageSource 已废除，消除装配时序隐式全局状态；
// 与 DSNBuilderService.original 同源注入形态，窄接口避免重复 DB 依赖）。
func (s *OutboundSenderService) readItemRaw(ctx context.Context, item *storage.QueueItem) ([]byte, error) {
	if s.messages == nil {
		return nil, fmt.Errorf("消息源未注入")
	}
	return s.messages.ReadOriginal(ctx, item.MessageID)
}

// deliverToHost 单 MX 主机投递：连接前 DANE 判定（U13）→连接→EHLO→（STARTTLS
// 策略三态）→MAIL/RCPT/DATA→分类。
func (s *OutboundSenderService) deliverToHost(ctx context.Context, host string, item *storage.QueueItem) storage.AttemptResult {
	raw, err := s.readItemRaw(ctx, item)
	if err != nil {
		return storage.AttemptResult{Status: storage.AttemptDeferred, Error: "原信读取失败: " + err.Error()}
	}
	// 0. DANE 判定（U13——rfc7672 §2.2：DNS 阶段前置；错误=MX 不可达→deferred 转移
	// 下一台（§2.1.2——禁止投递防降级）；nil validator=跳过（U12b 末态等价））
	var dane *DaneDecision
	if s.dane != nil {
		d, derr := s.dane.Check(ctx, host, rcptDomain(item.RcptTo))
		if derr != nil {
			return deferred("DANE 判定失败（MX 不可达）", 0, derr)
		}
		dane = d
	}
	// 0.5 MTA-STS 判定（L-A——rfc8461 §4/§5：enforce 且 MX 不匹配策略→MUST NOT 投递
	// 该主机（deferred 转移下一候选——§5.1 步骤 2「continue to the next candidate」；
	// 全部候选失败的临时错误语义由既有 deferred 重试链承载——§5 末段「SHOULD treat
	// as transient errors」）；nil validator=跳过；发现失败按无策略放行——§3.3）
	if s.sts != nil {
		if dec, derr := s.sts.Check(ctx, rcptDomain(item.RcptTo), host); derr == nil && dec != nil && dec.Mode == "enforce" && !dec.MXMatched {
			s.recordTLS(item.RcptTo, host, "sts-policy-invalid") // L-B：enforce MX 不匹配计失败（§4.3.2.2）
			return deferred("MTA-STS enforce：MX 不匹配策略（转移下一候选）", 0, nil)
		}
	}
	conn, err := s.dial.Dial(ctx, host+":25")
	if err != nil {
		return storage.AttemptResult{Status: storage.AttemptDeferred, Error: "连接 " + host + ": " + err.Error()}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second)) // 读写超时（PMail K3 档）

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// 1. 问候（220）
	code, _, err := readReply(rw.Reader)
	if err != nil || code != 220 {
		return deferred("问候失败", code, err)
	}
	// 2. EHLO（本域身份）
	if err = writeLine(rw.Writer, "EHLO "+s.domain); err != nil {
		return deferred("EHLO 写失败", 0, err)
	}
	code, lines, err := readReply(rw.Reader)
	if err != nil || code != 250 {
		return deferred("EHLO 拒绝", code, err)
	}
	// 3. STARTTLS 策略（Q2-A：通告则升级验证；失败 deferred 不降级重投；U13 三态：
	// RequireDANE→基域 SNI+握手后 TLSA 匹配；secure 承诺态无 STARTTLS→拒明文转移）
	ehloCaps := lines // 对端能力集（STARTTLS 后以重 EHLO 为准——rfc3207 §4.2 能力重置）
	if hasCapability(lines, "STARTTLS") {
		upgradedRW, tlsErr := s.tryStartTLS(rw, conn, host, dane)
		if tlsErr != nil {
			s.recordTLS(item.RcptTo, host, "certificate-not-trusted") // L-B：握手/证书验证失败（§4.3.1 笼统类——细节经 error 文本）
			return storage.AttemptResult{Status: storage.AttemptDeferred,
				Error: "STARTTLS 升级失败: " + tlsErr.Error()}
		}
		rw = upgradedRW
		// TLS 后重 EHLO（rfc3207 4.2 状态重置）
		if err = writeLine(rw.Writer, "EHLO "+s.domain); err != nil {
			return deferred("TLS 后 EHLO 写失败", 0, err)
		}
		var caps2 []string
		if code, caps2, err = readReply(rw.Reader); err != nil || code != 250 {
			return deferred("TLS 后 EHLO 拒绝", code, err)
		}
		ehloCaps = caps2
	} else if (dane != nil && dane.Mode != DaneOpportunistic) || (s.sts != nil && s.stsEnforce(ctx, item, host)) {
		// secure TLSA 承诺态（RequireDANE/RequireTLSOnly）或 MTA-STS enforce 态对端
		// 无 STARTTLS：MUST NOT 明文投递（rfc7672 §2.2 第一/二分支/rfc8461 §5 enforce
		// 「MUST NOT deliver ... that do not support STARTTLS」）→deferred 转移下一台 MX
		s.recordTLS(item.RcptTo, host, "starttls-not-supported") // L-B：§4.3.1
		return deferred("对端无 STARTTLS（TLS 承诺态拒绝明文投递）", 0, nil)
	}
	// 4. MAIL FROM（null sender 以 <> 字面量；RF-H/F-L2/F-L8——出站声明面：
	// 非 ASCII 信封地址 MUST 声明 SMTPUTF8（rfc6531 §3.3 L428-429——对端未通告
	// 不可投递）；8bit 内容传输须声明 BODY=8BITMIME（rfc6152 §2——未通告 MUST NOT 发送））
	mailParams := ""
	if !isASCII(item.EnvelopeFrom) || !isASCII(item.RcptTo) {
		if !hasCapability(ehloCaps, "SMTPUTF8") {
			return deferred("对端未通告 SMTPUTF8（国际化信封不可投递——rfc6531 §3.3）", 0, nil)
		}
		mailParams += " SMTPUTF8"
	}
	if hasEightBit(raw) {
		if !hasCapability(ehloCaps, "8BITMIME") {
			return deferred("对端未通告 8BITMIME（8bit 内容不可发送——rfc6152 §2）", 0, nil)
		}
		mailParams += " BODY=8BITMIME"
	}
	if err = writeLine(rw.Writer, "MAIL FROM:<"+nullSenderForm(item.EnvelopeFrom)+">"+mailParams); err != nil {
		return deferred("MAIL 写失败", 0, err)
	}
	if code, _, err = readReply(rw.Reader); err != nil || code != 250 {
		return classify("MAIL", code, err)
	}
	// 5. RCPT TO
	if err = writeLine(rw.Writer, "RCPT TO:<"+item.RcptTo+">"); err != nil {
		return deferred("RCPT 写失败", 0, err)
	}
	if code, _, err = readReply(rw.Reader); err != nil || code != 250 && code != 251 {
		return classify("RCPT", code, err)
	}
	// 6. DATA
	if err = writeLine(rw.Writer, "DATA"); err != nil {
		return deferred("DATA 写失败", 0, err)
	}
	if code, _, err = readReply(rw.Reader); err != nil || code != 354 {
		return classify("DATA", code, err)
	}
	// 7. 内容（dot-stuffing+终止点，U4 语义复刻）
	if err = writeDataBody(rw.Writer, raw); err != nil {
		return deferred("内容写失败", 0, err)
	}
	if code, _, err = readReply(rw.Reader); err != nil {
		return deferred("DATA 应答读失败", 0, err)
	}
	if code != 250 {
		return classify("DATA-ACK", code, nil)
	}
	// 8. QUIT+读 221（rfc5321bis 4.1.1.10 会话终止序列；net.Pipe 同步语义下
	// 不读对端应答会造成双写互等——QUIT 后必须消费 221 再关闭）
	if err = writeLine(rw.Writer, "QUIT"); err == nil {
		_, _, _ = readReply(rw.Reader) // 221；错误忽略（对端已关亦可）
	}
	s.recordTLS(item.RcptTo, host, "") // L-B：成功会话计数（§4.2.1）
	return storage.AttemptResult{Status: storage.AttemptSent}
}

// stsEnforce MTA-STS enforce 态判定（无 STARTTLS 拒明文路径复用——发现失败/无策略/
// testing/none 均不拒明文；nil validator=false）。
func (s *OutboundSenderService) stsEnforce(ctx context.Context, item *storage.QueueItem, host string) bool {
	if s.sts == nil {
		return false
	}
	dec, derr := s.sts.Check(ctx, rcptDomain(item.RcptTo), host)
	return derr == nil && dec != nil && dec.Mode == "enforce" && dec.MXMatched
}

// tryStartTLS STARTTLS 升级（rfc3207：220 后 tls.Client 握手；验证对端证书）。
// U13 三态：RequireDANE→ServerName=TLSA 基域（rfc7672 §8.1 SNI MUST）+
// InsecureSkipVerify（验证经握手后 TLSA 匹配承载——EE(3)/TA(2) 语义非 PKIX）+
// 认证失败返回错误（MUST NOT 投递）；其余态→系统根 CA 验证（Q2-A 既有策略）。
// 参数：rw 明文流；conn 底层连接；host MX 主机名（Opportunistic 验证名）；dane 决策
// （nil=Opportunistic）。返回：升级后的 ReadWriter；错误（调用方 deferred 转移）。
func (s *OutboundSenderService) tryStartTLS(rw *bufio.ReadWriter, conn net.Conn, host string, dane *DaneDecision) (*bufio.ReadWriter, error) {
	if err := writeLine(rw.Writer, "STARTTLS"); err != nil {
		return nil, err
	}
	code, _, err := readReply(rw.Reader)
	if err != nil || code != 220 {
		return nil, fmt.Errorf("STARTTLS 应答 %d: %v", code, err)
	}
	cfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	} // 系统根 CA 验证（transport.ClientTLSConfig 同档；Q2-A 策略）
	if dane != nil && dane.Mode == DaneRequireDANE {
		cfg = &tls.Config{
			ServerName:         dane.BaseTLSDomain, // SNI=TLSA 基域（rfc7672 §8.1）
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // 验证移交握手后 TLSA 匹配（EE(3)/TA(2) 非 PKIX 语义）
		}
	}
	tlsConn := tls.Client(conn, cfg)
	if err = tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS 握手（验证失败不降级明文，NFR-006）: %w", err)
	}
	if dane != nil && dane.Mode == DaneRequireDANE {
		if verr := dane.VerifyPeer(tlsConn.ConnectionState().PeerCertificates); verr != nil {
			return nil, fmt.Errorf("DANE 认证失败（MUST NOT 投递，rfc7672 §3.2）: %w", verr)
		}
	}
	return bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn)), nil
}

// ───────────────────────── 协议辅助（出站客户端） ─────────────────────────

// readReply 读多行 SMTP 应答（250-.../250 ...聚合）；返回（码, 能力行集, 错误）。
func readReply(r *bufio.Reader) (int, []string, error) {
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return 0, nil, fmt.Errorf("应答行过短: %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, nil, fmt.Errorf("应答码解析: %w", err)
		}
		if line[3] == ' ' { // 结束行
			if len(line) > 4 {
				lines = append(lines, line[4:])
			}
			return code, lines, nil
		}
		lines = append(lines, line[4:]) // 续行 '-'
	}
}

// writeLine 写命令行（CRLF 结尾+flush）。
func writeLine(w *bufio.Writer, line string) error {
	if _, err := w.WriteString(line + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

// writeDataBody 写 DATA 体：CRLF 规范化+dot-stuffing+<CRLF>.<CRLF> 终止（U4 语义复刻）。
func writeDataBody(w *bufio.Writer, raw []byte) error {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	var sb strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, ".") {
			sb.WriteString("." + line + "\r\n") // 点透明：行首点补一
		} else {
			sb.WriteString(line + "\r\n")
		}
	}
	sb.WriteString(".\r\n")
	if _, err := w.WriteString(sb.String()); err != nil {
		return err
	}
	return w.Flush()
}

// hasCapability EHLO 能力行检查（大小写不敏感）。
func hasCapability(lines []string, keyword string) bool {
	for _, l := range lines {
		if strings.EqualFold(strings.TrimSpace(l), keyword) || strings.EqualFold(strings.Fields(l)[0], keyword) {
			return true
		}
	}
	return false
}

// isASCII 全 ASCII 判定（RF-H/F-L2 出站声明面——信封地址国际化判定，rfc6531 §3.3）。
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// hasEightBit 内容含 8bit 八位组判定（RF-H/F-L8 出站声明面——BODY=8BITMIME 判定，rfc6152 §2）。
func hasEightBit(raw []byte) bool {
	for _, b := range raw {
		if b >= 0x80 {
			return true
		}
	}
	return false
}

// nullSenderForm null sender 的 MAIL FROM 形态（"<>"; 其余原样）。
func nullSenderForm(from string) string {
	if from == "<>" || from == "" {
		return ""
	}
	return from
}

// rcptDomain 收件地址域名提取（小写）。
func rcptDomain(addr string) string {
	if at := strings.LastIndex(addr, "@"); at >= 0 && at+1 < len(addr) {
		return strings.ToLower(addr[at+1:])
	}
	return strings.ToLower(addr)
}

// envelopeFor 队列项→收信信封（本域分流入参；MailFrom 剥 <> 字面量，Helo=本机）。
func envelopeFor(item *storage.QueueItem) auth.Envelope {
	return auth.Envelope{MailFrom: strings.Trim(item.EnvelopeFrom, "<>"), Helo: "localhost"}
}

// classify SMTP 阶段应答分类：5xx→failed；4xx→deferred；读错→deferred。
func classify(stage string, code int, err error) storage.AttemptResult {
	msg := fmt.Sprintf("%s 应答 %d", stage, code)
	if err != nil {
		msg = stage + " 读失败: " + err.Error()
	}
	if code >= 500 && code < 600 {
		return storage.AttemptResult{Status: storage.AttemptFailed, SMTPCode: code, Error: msg}
	}
	return storage.AttemptResult{Status: storage.AttemptDeferred, SMTPCode: code, Error: msg}
}

// deferred 网络类临时失败统一形态。
func deferred(stage string, code int, err error) storage.AttemptResult {
	msg := stage
	if err != nil {
		msg += ": " + err.Error()
	}
	return storage.AttemptResult{Status: storage.AttemptDeferred, SMTPCode: code, Error: msg}
}

// （信封类型直接复用 auth.Envelope——mail 包对 auth 为既有依赖，契约 2.3 Delivery 嵌入同源）
