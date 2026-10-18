// auth 来信验证器：SPF/DKIM/ARC（raven）+ DMARC（自研包）四项编排、
// Authentication-Results 头组装（rfc8601）与认证栈开关热加载订阅（TC-009）。
// 依据：SRS FR-008（四项验证+A-R 头＋判定③ permerror 不触发拒收——permerror可见性批）/FR-009（开关热加载，订阅侧）/NFR-004/NFR-005；
// 模块接口契约 v1.57.0 2.2 节（Verifier/VerifyResults 签名逐字落地，compile-time 断言锁定）；
// 关键流程设计 v1.0.0 第一章（验证在 DATA 后、落库前，A-R 注入）；
// rfc8601 2.2（authres-header-field ABNF）/2.7.1（dkim=header.d）/2.7.2（spf=smtp.mailfrom）；
// 架构总览 v1.0.0 5.2（组件禁止缓存旧配置指针——开关经 RWMutex 快照读取）。
// 修改历史：
//
//	2026-10-18 10-32-00 | 修正 | permerror可见性批（G2 批准 2026-10-18 10:28:07
//	  「E-1 A / E-2 A / E-3 A / F-1 B」；V批 G3 遗留登记①/S4-W Q1=B）：①aggregateDKIM
//	  增 permerror 显式分支——解析失败〔Signature=nil〕不再落 none、公钥/参数永久
//	  错误〔Signature 非 nil〕不再落 fail（SRS v1.3.0 FR-008 判定③「permerror 不触发
//	  拒收」实施态收敛——硬档误拒与 soft 档误拒双路径收口）；聚合序 pass→temperror→
//	  fail→permerror→none（E-1-A fail 优先——伪造 b= 验签失败路径拒收臂输入最大化，
//	  与解析失败 permerror 区分）②buildAuthResultsHeader permerror 呈现（E-2-A——
//	  有签名上下文取 header.d〔沿 B-S批 F5 temperror 先例〕；全 nil 裸
//	  dkim=permerror〔rfc8601 §2.2 propspec 可选合法形态〕）——消费者可见性收口
//	2026-10-18 00-40-00 | 修正 | DMARC收尾批：头注契约版本引用刷新 v1.37.0→v1.55.0
//	  （注释漂移收口——纯注释零行为）
//	2026-10-18 06:20:00 | 扩展 | V批核查修复批 E-3（G2 批准 2026-10-18 05:13→
//	  05:48:30 三段终态；S4-W 材料更正链 06:14/06:19「B B」闭合）：VerifyResults
//	  增 FromHeaderViolation 字段＋DMARC 块三段判定（rfc9989 §5.3.1 L1640-1644
//	  「If zero or more than one domain is extracted ... DMARC validation is
//	  not possible and the process terminates」＋§11.5 L2495-2504 逐域评估最
//	  严格策略＋rfc5322bis §3.6.2 L1263-1265 多地址 MUST 携带 Sender）——
//	  ①单地址=既有单域路径零变化②多地址无 Sender（或多 From 头行）=violation
//	  拒收档（DMARC=permerror 不评估，管道 550）③多地址有 Sender=§11.5 L2501-
//	  2504「apply the DMARC mechanism to each domain found in the RFC5322.From
//	  field as the Author Domain and apply the most strict policy selected
//	  among the checks that fail」逐域评估聚合（maxFromDomains=8 DoS 限数——
//	  L2506-2510）；V-006 核查定论=拒收臂有效（渗透方载荷缺陷误报——零代码）
//	2026-09-17 02:40:00 | 新建 | U3 auth 基础（计划书步骤 6）
//	2026-10-08 13:10:00 | 修正 | 文档治理批 C1：头注契约版本引用刷新 v1.0.0→v1.37.0（注释漂移收口；纯注释零行为变更）
//	2026-10-17 22:58:00 | 扩展 | DMARC处置实施批（G2 批准 2026-10-17 22:46「全A批准」；
//	  SRS v1.3.0 FR-008 判定③ DMARC p 值处置＋E-1-A）：VerifyResults 增 DMARCDisposition
//	  字段——Evaluate 返回的 Discovery p 值消费（结论 fail 且 p=reject|quarantine 预计算
//	  分派结论；空=不分派）；A-R 头零变化（disposition 不入头——照收格零变化锚）
package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"

	"GRmail/internal/auth/dmarc"
	"GRmail/internal/config"

	ravenarc "github.com/synqronlabs/raven/arc"
	ravendkim "github.com/synqronlabs/raven/dkim"
	ravendns "github.com/synqronlabs/raven/dns"
	ravenspf "github.com/synqronlabs/raven/spf"
)

// ───────────────────────── 契约接口（模块接口契约 2.2 逐字） ─────────────────────────

// Verifier 来信四项验证（raven: SPF/DKIM/ARC；自研 dmarc 包: DMARCbis）。
type Verifier interface {
	Verify(ctx context.Context, msg *IncomingMail) (*VerifyResults, error)
}

// VerifyResults 四元组 + A-R 序列化（rfc8601）。
type VerifyResults struct {
	SPF, DKIM, DMARC, ARC string // none|pass|fail|softfail|temperror|permerror...
	AuthResultsHeader     string // 序列化后的 Authentication-Results 头
	// DMARCDisposition DMARC 处置分派结论（DMARC处置实施批 E-1-A——SRS v1.3.0 FR-008
	// 判定③/REQ-20261017-005）：值域 "reject"|"quarantine"|""（空=不分派——结论非
	// fail、p=none、无记录、未启用项四种情形恒空；none/temperror/permerror 恒照收
	// 仅 A-R 标注——REQ-20261017-006）；预计算仅结论 fail 且发现记录 p=reject|
	// quarantine 时置位；管道消费（拒收短路/隔离落 Junk 三终态分派）；零值=现状
	// 等价（既有 stub/测试构造零影响）；不入 A-R 头（头内容零变化锚）
	DMARCDisposition string
	// FromHeaderViolation 多地址 From 无 Sender 头或多 From 头行标记（V批核查修复批
	// E-3②——G2 批准 2026-10-18 05:47「Sender 头 没有了，直接拒收」）：rfc5322bis
	// §3.6.2 L1263-1265「If the from field contains more than one mailbox
	// specification in the mailbox-list, then the sender field ... MUST appear
	// in the message」违规事实＋rfc9989 §11.5 L2488-2493 威胁识别与妥善处理＋
	// L2498-2499「may make a negative disposition decision for the message prior
	// to and instead of its being subjected to DMARC processing」授权否定处置；
	// 置位时 DMARC 结论=permerror（§5.3.1 L1640-1644 验证不可能终止）、处置不
	// 预计算（恒空）；管道 checkRejectionPolicy 空路径豁免后优先拒收（550 通用
	// 文案——R-006/E-5-A 口径）；零值=现状等价（单地址 From 场景恒 false）
	FromHeaderViolation bool
}

// ───────────────────────── 哨兵错误 ─────────────────────────

// ErrMissingFrom RFC5322 From 头缺失或不可解析（rfc9989 4.2：此类消息处理超出规范范围；
// 本项目定档：DMARC 置 permerror，其余三项照常评估）。
var ErrMissingFrom = errors.New("auth: From 头缺失或不可解析")

// ───────────────────────── DMARC 适配器 ─────────────────────────

// txtResolverAdapter 将 Resolver 适配为 dmarc.TXTResolver（错误分类映射——
// 安全原子性批 F6 2026-10-06 对齐 rfc7208 §4.4 L819-821：仅 NXDOMAIN
// 〔ravendns.IsNotFound〕映射 dmarc.ErrNoRecord〔→ none〕；其余一切错误
// 〔SERVFAIL/超时/REFUSED/NOTIMP 等 RCODE≠0/3〕一律 dmarc.ErrTemporary
// 〔→ temperror〕——解析器故障不得呈现为"无策略"绕过 DMARC 评估呈现）。
type txtResolverAdapter struct{ r Resolver }

// LookupTXT 查询并映射错误分类（dmarc 包错误分类约定）。
func (a txtResolverAdapter) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	res, err := a.r.LookupTXT(ctx, domain)
	if err != nil {
		if ravendns.IsNotFound(err) {
			return nil, dmarc.ErrNoRecord // RCODE 3（NXDOMAIN）→ 无记录 → none
		}
		return nil, dmarc.ErrTemporary // 其余错误 → temperror（rfc7208 §4.4）
	}
	return res.Records, nil
}

// ───────────────────────── 验证器服务 ─────────────────────────

// VerifierService 四项验证编排域服务（U4 收信管道注入消费）。
type VerifierService struct {
	resolver Resolver
	mu       sync.RWMutex
	stack    config.AuthStack // 认证栈开关快照（热加载回调刷新，5.2 禁缓存旧指针）
	authserv string           // A-R authserv-id（config.Server.Domain，计划书 1.5 口径②）
}

// NewVerifierService 构造验证器。
// 参数：resolver DNS 解析器（生产 NewResolver/测试 stub）；authservID A-R authserv-id
// （取 config.Server.Domain）；initial 初始认证栈配置。
func NewVerifierService(resolver Resolver, authservID string, initial config.AuthStack) *VerifierService {
	return &VerifierService{resolver: resolver, stack: initial, authserv: authservID}
}

// OnConfigChange 实现 config.Subscriber（FR-009/NFR-005 订阅侧：
// 开关变更即时生效，下一封来信 A-R 头不再含已关闭项——TC-009 判定链）。
func (v *VerifierService) OnConfigChange(newCfg *config.Config) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stack = newCfg.Auth
}

// 编译期断言：契约接口实现锁定 + config.Subscriber 实现
var (
	_ Verifier          = (*VerifierService)(nil)
	_ config.Subscriber = (*VerifierService)(nil)
)

// Verify 执行四项验证并组装 A-R 头（FR-008 判定：A-R 含四项结论）。
// 单项失败不影响其余项（各结论独立呈现）；DNS 瞬时故障在对应结论位以 temperror 呈现。
// 参数：ctx 上下文（携带 LogID logger）；msg 来信（信封+原始字节，U4 构造）。
// 返回：四元组与 A-R 头。
func (v *VerifierService) Verify(ctx context.Context, msg *IncomingMail) (*VerifyResults, error) {
	v.mu.RLock()
	stack := v.stack
	v.mu.RUnlock()

	res := &VerifyResults{SPF: "none", DKIM: "none", DMARC: "none", ARC: "none"}

	// SPF（rfc7208，raven）：信封 MAIL FROM 身份判定。
	// 实测修正（2026-09-17 02:46）：结论以 received.Result 为准——fail 时 err=nil、
	// temperror 时 Result 已为 StatusTemperror（err 仅伴随错误详情，源码 spf.go Verify 尾段）；
	// 空反向路径（HELO 判定）时 A-R 域取 verify 返回的实际判定域。
	var spfPass bool
	var spfDomain string
	spfProp := "smtp.mailfrom" // B-S批 F5：A-R SPF 属性名（空反向路径场景改 smtp.helo——下方分支）
	if stack.SPFEnabled {
		args := spfArgs(msg, v.authserv)
		recvd, checkedDomain, _, _, _ := ravenspf.Verify(ctx, asSPFResolver(v.resolver), args)
		res.SPF = string(recvd.Result)
		spfPass = recvd.Result == ravenspf.StatusPass
		if checkedDomain != "" {
			spfDomain = checkedDomain
		} else {
			spfDomain = args.MailFromDomain
		}
		// B-S批 F5：空反向路径（MAIL FROM <>）时 SPF 以 HELO 身份判定（checkedDomain
		// 即 HELO 判定域）——A-R 属性名须 smtp.helo（rfc8601 §2.7.2 L1051-1054
		// 「the property is either "mailfrom" or "helo"」——空路径场景 mailfrom 无值可引用）
		if args.MailFromDomain == "" {
			spfProp = "smtp.helo"
		}
	}

	// DKIM（rfc6376，raven）：原始字节直验；聚合结论（计划书口径：任一 pass→pass；
	// 任一 temperror→temperror；存在签名但无 pass→fail；无签名→none）
	var dkimSigs []dmarc.SigResult
	var dkimReportDomain string
	if stack.DKIMEnabled {
		results, err := ravendkim.Verify(ctx, v.resolver, msg.Raw)
		if err != nil && ravendns.IsTemporary(err) {
			res.DKIM = "temperror"
		} else {
			res.DKIM, dkimReportDomain = aggregateDKIM(results)
			for _, r := range results {
				if r.Signature != nil {
					dkimSigs = append(dkimSigs, dmarc.SigResult{
						Domain: r.Signature.Domain,
						Pass:   r.Status == ravendkim.StatusPass,
					})
				}
			}
		}
	}

	// DMARC（rfc9989 DMARCbis，自研包）：策略发现 + SPF/DKIM 对齐判定。
	// V批核查修复批 E-3（G2 批准 2026-10-18 05:13→05:48:30 三段终态——rfc9989
	// §5.3.1 L1640-1644「If zero or more than one domain is extracted from the
	// RFC5322.From header field, then DMARC validation is not possible and the
	// process terminates. In the case where more than one domain is retrieved,
	// the Mail Receiver MAY choose to go forward with DMARC validation anyway.
	// See Section 11.5」＋§11.5 L2495-2504 逐域评估最严格策略＋rfc5322bis
	// §3.6.2 多地址 From MUST 携带 Sender）：①单地址=既有单域路径（零变化锚）
	// ②多地址无 Sender（或多 From 头行）=violation 拒收档（不评估，§5.3.1 终止）
	// ③多地址有 Sender（5322 合法）=§11.5 L2501-2504「apply the DMARC mechanism
	// to each domain found in the RFC5322.From field as the Author Domain and
	// apply the most strict policy selected among the checks that fail」逐域
	// 评估＋失败检查中最严格策略聚合；L2506-2510 DoS 限数（超 maxFromDomains
	// 域不评估——评估不完整按已评估集聚合）。
	var fromDomain string
	if stack.DMARCEnabled {
		fi, ferr := extractFromHeader(msg.Raw)
		switch {
		case ferr != nil:
			res.DMARC = "permerror" // From 缺失/畸形（ErrMissingFrom 定档——现行语义保持）
		case fi.violation():
			// E-3②拒收档：5322 MUST 违规（多地址无 Sender/多 From 头行）——§5.3.1
			// 验证不可能流程终止（不评估）；permerror 结论如实标注；管道拒收标记
			res.DMARC = "permerror"
			res.FromHeaderViolation = true
			if len(fi.domains) > 0 {
				fromDomain = fi.domains[0] // A-R header.from 首域呈现（单值限制）
			}
		case len(fi.domains) == 1:
			// ①单地址（零变化锚——既有单域评估路径原样保持）
			fromDomain = fi.domains[0]
			// B-S批 F6（裁决 B 2026-10-09 13:34——仅缓存无总预算）：Tree Walk 请求级
			// 缓存——Verify 单次调用内构造 cachedTXT，Discover 与 OrganizationalDomain
			// 共享同一实例，重复 _dmarc TXT 查询复用；跨调用零共享零污染
			dmResult, disc, _ := dmarc.Evaluate(ctx, &cachedTXT{inner: txtResolverAdapter{r: v.resolver}},
				fromDomain, dkimSigs, spfPass, spfDomain)
			res.DMARC = string(dmResult)
			// DMARC处置实施批（E-1-A——SRS v1.3.0 FR-008 判定③）：p 值分派结论预计算
			// ——仅结论 fail 且发现记录 p=reject|quarantine 时置位（temperror 时
			// disc 可非 nil 但结论非 fail 不置位；none/无记录 disc=nil；开关关闭整块
			// 不达——零值恒不分派）
			if dmResult == dmarc.ResultFail && disc != nil {
				switch disc.Record.Policy {
				case "reject", "quarantine":
					res.DMARCDisposition = disc.Record.Policy
				}
			}
		default:
			// ③多地址有 Sender（5322 合法）：§11.5 L2501-2504 逐域评估——各域
			// Evaluate（dkimSigs/spf 对齐输入共享，§4.4 对齐按各 Author Domain
			// 独立判定）；失败检查中最严格策略（reject>quarantine）聚合为整封
			// 处置；结论按 fail>temperror>pass>none 最严呈现；A-R header.from
			// 首域（rfc8601 单值呈现限制）
			fromDomain = fi.domains[0]
			anyFail, anyTemp, anyPass := false, false, false
			sawReject, sawQuarantine := false, false
			evaluated := fi.domains
			if len(evaluated) > maxFromDomains {
				evaluated = evaluated[:maxFromDomains] // §11.5 L2506-2510 DoS 限数：超限域不评估
			}
			for _, dom := range evaluated {
				dmResult, disc, _ := dmarc.Evaluate(ctx, &cachedTXT{inner: txtResolverAdapter{r: v.resolver}},
					dom, dkimSigs, spfPass, spfDomain)
				switch dmResult {
				case dmarc.ResultFail:
					anyFail = true
					if disc != nil {
						switch disc.Record.Policy {
						case "reject":
							sawReject = true
						case "quarantine":
							sawQuarantine = true
						}
					}
				case dmarc.ResultTemperror:
					anyTemp = true
				case dmarc.ResultPass:
					anyPass = true
				}
			}
			switch {
			case anyFail:
				res.DMARC = "fail"
			case anyTemp:
				res.DMARC = "temperror"
			case anyPass:
				res.DMARC = "pass"
			default:
				res.DMARC = "none"
			}
			switch {
			case sawReject:
				res.DMARCDisposition = "reject"
			case sawQuarantine:
				res.DMARCDisposition = "quarantine"
			}
		}
	}

	// ARC（rfc8617，raven）：链验证
	var arcOldestPass int
	if stack.ARCEnabled {
		verifier := &ravenarc.Verifier{Resolver: v.resolver}
		arcRes, err := verifier.Verify(ctx, msg.Raw)
		switch {
		case err != nil:
			res.ARC = "temperror"
		default:
			res.ARC = string(arcRes.Status)
			arcOldestPass = arcRes.OldestPass
		}
	}

	res.AuthResultsHeader = buildAuthResultsHeader(v.authserv, stack, res,
		spfDomain, spfProp, dkimReportDomain, fromDomain, arcOldestPass)
	return res, nil
}

// spfArgs 组装 raven SPF 判定入参（字段对应：Envelope 三元组 → spf.Args；
// Q2-A 实测定档，见 types.go）。
func spfArgs(msg *IncomingMail, localHostname string) ravenspf.Args {
	return ravenspf.Args{
		RemoteIP:       msg.Envelope.RemoteIP,
		MailFromDomain: msg.Envelope.MailFromDomain(),
		MailFromLocal:  msg.Envelope.MailFromLocal(),
		HelloDomain:    msg.Envelope.Helo,
		HelloIsIP:      net.ParseIP(trimBrackets(msg.Envelope.Helo)) != nil,
		LocalHostname:  localHostname, // r= 宏（接收方主机名=authserv-id）
	}
}

// trimBrackets 去除 HELO IP 字面量的方括号（IPv6 形如 [::1]）。
func trimBrackets(s string) string { return strings.Trim(s, "[]") }

// aggregateDKIM 聚合多签名 DKIM 结论（聚合口径登记于 U3 修改文档第 3 章＋permerror可见性批）：
// 任一 pass→pass（报告域取首个通过签名的 d=）；任一 temperror→temperror（B-S批 F5）；
// 任一验签失败（fail）→fail（E-1-A——fail 优先于 permerror：伪造 b= 验签失败路径为
// 拒收臂输入，TC-029「有签名且验证失败拒收」语义输入面最大化）；
// 任一 permerror→permerror（permerror可见性批 E-3-A——SRS v1.3.0 FR-008 判定③
// 「验证临时故障（temperror）与 permerror 不触发拒收」：解析失败〔Signature=nil，
// raven ParseSignature 错误路径〕与公钥/参数永久错误〔Signature 非 nil——checkSignatureParams/
// lookup 永久错/公钥吊销等〕两路径均不再落 none/fail——报告域沿 B-S批 F5 先例取首个
// 含签名结果的 d=，全 nil 时空〔呈现层裸条目承载〕）；无签名→none。
func aggregateDKIM(results []ravendkim.Result) (conclusion, reportDomain string) {
	if len(results) == 0 {
		return "none", ""
	}
	for _, r := range results {
		if r.Status == ravendkim.StatusPass && r.Signature != nil {
			return "pass", r.Signature.Domain
		}
	}
	for _, r := range results {
		if r.Status == ravendkim.StatusTemperror {
			// B-S批 F5：temperror 报告域取首个含签名结果的 d=（DKIM 验证故障对
			// 消费者可见——原空串致 buildAuthResultsHeader 判空丢弃整条 resinfo）；
			// 无签名上下文维持空（调用方按现状不呈现该条）
			dom := ""
			for _, r2 := range results {
				if r2.Signature != nil {
					dom = r2.Signature.Domain
					break
				}
			}
			return "temperror", dom
		}
	}
	for _, r := range results {
		// permerror可见性批：fail 判定收紧为 Status==Fail（携签名）——带签名的
		// permerror 不再落入本分支（原「存在签名即 fail」口径致公钥永久错误被拒）
		if r.Signature != nil && r.Status == ravendkim.StatusFail {
			return "fail", r.Signature.Domain
		}
	}
	for _, r := range results {
		if r.Status == ravendkim.StatusPermerror {
			// permerror可见性批 E-3-A/E-2-A：报告域沿 B-S批 F5 先例——有签名上下文
			// 取首个含签名结果的 d=（含 permerror 自身携签名形态）；全部 Signature=nil
			// （解析失败）则空——buildAuthResultsHeader 裸条目呈现承载
			dom := ""
			for _, r2 := range results {
				if r2.Signature != nil {
					dom = r2.Signature.Domain
					break
				}
			}
			return "permerror", dom
		}
	}
	for _, r := range results {
		// 防御兜底（零变化锚）：带签名的其余状态（policy/neutral——GRmail 未设
		// Verifier.Policy，实际不可达）维持原「存在签名即 fail」归类——本批仅收拢
		// permerror 两路径，其余状态归制不变
		if r.Signature != nil {
			return "fail", r.Signature.Domain
		}
	}
	return "none", ""
}

// maxFromDomains 多地址 From 逐域评估的域数上限（V批 E-3③——rfc9989 §11.5
// L2506-2510「Limiting the number of Author Domains processed will avoid this
// risk. If not all Author Domains are processed, then the DMARC evaluation
// is incomplete」：大量域的逐一 DNS Tree Walk 构成 DoS 攻击面；超限域不参与
// 评估〔评估不完整——按已评估集聚合终态〕。8=DKIM 签名数/SPF 查询链常见工程
// 上限档）。
const maxFromDomains = 8

// fromHeaderInfo RFC5322 From 头提取产物（V批 E-3——rfc5322bis §3.6.2+rfc9989
// §5.3.1/§11.5 锚定）。
type fromHeaderInfo struct {
	domains   []string // From 头各地址的域（小写规范化；单地址=单元素）
	hasSender bool     // Sender 头存在（多地址 From 时 rfc5322 §3.6.2 L1263-1265 MUST 携带）
	multiFrom bool     // 多个 From 头行（rfc9989 §11.5 L2490「precisely one From: header field」〔引 RFC5322〕违反）
}

// violation 多地址 From 缺 Sender 头或多个 From 头行——rfc5322 §3.6.2 MUST 违规
// （E-3② 拒收档判定；单地址场景恒 false——SHOULD NOT 使用 Sender，缺失正常）。
func (f *fromHeaderInfo) violation() bool {
	return f.multiFrom || (len(f.domains) > 1 && !f.hasSender)
}

// extractFromHeader 提取 From 头信息（From 缺失/不可解析返回 ErrMissingFrom——
// 现行 FromDomain 定档语义保持）。
// 参数：raw 原始消息字节。返回：提取产物；错误=From 头层不可用。
func extractFromHeader(raw []byte) (*fromHeaderInfo, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingFrom, err)
	}
	fromLines := msg.Header["From"] // net/mail.Header 为 map[string][]string（键经规范化）
	if len(fromLines) == 0 {
		return nil, fmt.Errorf("%w: From 头缺失", ErrMissingFrom)
	}
	addrs, err := mail.ParseAddressList(fromLines[0])
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("%w: From 头不可解析", ErrMissingFrom)
	}
	fi := &fromHeaderInfo{
		hasSender: strings.TrimSpace(msg.Header.Get("Sender")) != "",
		multiFrom: len(fromLines) > 1,
	}
	for _, a := range addrs {
		at := strings.LastIndex(a.Address, "@")
		if at < 0 || at == len(a.Address)-1 {
			return nil, fmt.Errorf("%w: From 地址无域", ErrMissingFrom)
		}
		fi.domains = append(fi.domains, strings.ToLower(a.Address[at+1:]))
	}
	return fi, nil
}

// FromDomain 提取 RFC5322 From 头域（DMARC Author Domain；rfc9989 4.2：
// 取首个地址的域，小写规范化）。参数：raw 原始消息字节。
// 返回：域；From 缺失/不可解析返回 ErrMissingFrom。
// V批 E-3 注：多地址 From 场景本函数返回首域（管道 DMARC reject Reason 的
// 可观测呈现用）；处置主链经 fromHeaderInfo 三段判定承载。
func FromDomain(raw []byte) (string, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMissingFrom, err)
	}
	addrs, err := mail.ParseAddressList(msg.Header.Get("From"))
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("%w: From 头不可解析", ErrMissingFrom)
	}
	at := strings.LastIndex(addrs[0].Address, "@")
	if at < 0 {
		return "", fmt.Errorf("%w: From 地址无域", ErrMissingFrom)
	}
	return strings.ToLower(addrs[0].Address[at+1:]), nil
}

// buildAuthResultsHeader 组装 Authentication-Results 头（rfc8601 2.2 ABNF：
// "Authentication-Results:" authserv-id 1*resinfo；resinfo = ";" method "=" result
// [propspec]）。仅开启项出现（TC-009：关闭项结论不出现在头中）。
// 属性形态：spf→smtp.mailfrom（2.7.2；空反向路径场景 smtp.helo——B-S批 F5，
// spfProp 参数承载）；dkim→header.d（2.7.1）；dmarc→header.from；
// arc→arc.oldest-pass（rfc8617 注册属性，oldest-pass>0 时附注）。
func buildAuthResultsHeader(authservID string, stack config.AuthStack, res *VerifyResults,
	spfDomain, spfProp, dkimDomain, fromDomain string, arcOldestPass int) string {
	var b strings.Builder
	b.WriteString("Authentication-Results: ")
	b.WriteString(authservID)
	// F-A1（RFC规范修正 RF-E，G2 批准 2026-09-28 22:16:57）：resinfo 分隔 CRLF+HTAB
	// 折叠（rfc8601 §2.2 L577-581——authres-payload 以 CRLF 终结、CFWS 引 rfc5322
	// §2.2.3 折叠语义；原裸 "\n\t" 致头体含独立 LF，存储态非合规形态）
	if stack.SPFEnabled && spfDomain != "" {
		fmt.Fprintf(&b, ";\r\n\tspf=%s %s=%s", res.SPF, spfProp, spfDomain)
	}
	if stack.DKIMEnabled && (dkimDomain != "" || res.DKIM == "permerror") {
		// permerror可见性批 E-2-A：permerror 无签名上下文（全 nil 解析失败）时以裸
		// resinfo 呈现——rfc8601 §2.2 ABNF「resinfo = ";" method "=" result [propspec]」
		// propspec 可选，裸 dkim=permerror 为合法形态（消费者可见性——dkim=none 与
		// 签名损坏可区分）；其余结论（pass/fail/temperror 带上下文）既有形态零变化
		if dkimDomain != "" {
			fmt.Fprintf(&b, ";\r\n\tdkim=%s header.d=%s", res.DKIM, dkimDomain)
		} else {
			fmt.Fprintf(&b, ";\r\n\tdkim=%s", res.DKIM)
		}
	}
	if stack.DMARCEnabled && fromDomain != "" {
		fmt.Fprintf(&b, ";\r\n\tdmarc=%s header.from=%s", res.DMARC, fromDomain)
	}
	if stack.ARCEnabled {
		if arcOldestPass > 0 {
			fmt.Fprintf(&b, ";\r\n\tarc=%s arc.oldest-pass=%d", res.ARC, arcOldestPass)
		} else {
			fmt.Fprintf(&b, ";\r\n\tarc=%s", res.ARC)
		}
	}
	return b.String()
}

// ───────────────────────── B-S批 F6：DMARC Tree Walk 请求级缓存 ─────────────────────────
//
// 规范原文锚（rfc9989 §4.10 L1211-1233 泛型步骤——步骤 1「Query the DNS for a TXT
// record ... at the starting point for the Tree Walk. A possibly empty set of
// records is returned」：查询为按域纯函数〔同域同结果集，含空集〕，按 domain 记忆化
// 与逐次独立查询语义一致；§4.10.2 L1351-1352「It may be necessary to perform
// multiple DNS Tree Walks to determine if an Authenticated Identifier and an
// Author Domain are in alignment」：对齐判定与组织域选择构成同域重复查询面——
// 正是本缓存覆盖对象。缓存条目含错误形态原样记忆（ErrTemporary/ErrNoRecord），
// 不改变 walk 停走与记录筛选语义〔步骤 2 的筛选在 queryLevel 逐次执行〕）。

// cachedTXTEntry 缓存条目（txts/err 原样记忆——含错误形态，同域重复查询语义
// 与无缓存一致）。
type cachedTXTEntry struct {
	txts []string
	err  error
}

// cachedTXT DMARC Tree Walk 请求级缓存解析器（B-S批 F6——干系人裁决 B〔2026-10-09
// 13:34〕：仅缓存无总预算）：Verify 单次调用内构造，Discover 与 OrganizationalDomain
// 共享同一实例——对齐判定与组织域选择的重复 _dmarc TXT 查询复用（复核场景查询计数
// 减半）；生命周期=单次验证（跨调用零共享零污染——失败判定第 7 条守卫）。
type cachedTXT struct {
	inner dmarc.TXTResolver
	mu    sync.Mutex
	m     map[string]cachedTXTEntry
}

// LookupTXT 按 domain 记忆化查询（首次穿透 inner，后续命中缓存）。
func (c *cachedTXT) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]cachedTXTEntry)
	}
	if e, ok := c.m[domain]; ok {
		c.mu.Unlock()
		return e.txts, e.err
	}
	c.mu.Unlock()
	txts, err := c.inner.LookupTXT(ctx, domain)
	c.mu.Lock()
	c.m[domain] = cachedTXTEntry{txts: txts, err: err}
	c.mu.Unlock()
	return txts, err
}
