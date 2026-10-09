// auth 来信验证器：SPF/DKIM/ARC（raven）+ DMARC（自研包）四项编排、
// Authentication-Results 头组装（rfc8601）与认证栈开关热加载订阅（TC-009）。
// 依据：SRS FR-008（四项验证+A-R 头）/FR-009（开关热加载，订阅侧）/NFR-004/NFR-005；
// 模块接口契约 v1.37.0 2.2 节（Verifier/VerifyResults 签名逐字落地，compile-time 断言锁定）；
// 关键流程设计 v1.0.0 第一章（验证在 DATA 后、落库前，A-R 注入）；
// rfc8601 2.2（authres-header-field ABNF）/2.7.1（dkim=header.d）/2.7.2（spf=smtp.mailfrom）；
// 架构总览 v1.0.0 5.2（组件禁止缓存旧配置指针——开关经 RWMutex 快照读取）。
// 修改历史：
//
//	2026-09-17 02:40:00 | 新建 | U3 auth 基础（计划书步骤 6）
//	2026-10-08 13:10:00 | 修正 | 文档治理批 C1：头注契约版本引用刷新 v1.0.0→v1.37.0（注释漂移收口；纯注释零行为变更）
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

	// DMARC（rfc9989 DMARCbis，自研包）：策略发现 + SPF/DKIM 对齐判定
	var fromDomain string
	if stack.DMARCEnabled {
		fd, ferr := FromDomain(msg.Raw)
		if ferr != nil {
			res.DMARC = "permerror" // From 缺失/畸形（ErrMissingFrom 定档）
		} else {
			fromDomain = fd
			// B-S批 F6（裁决 B 2026-10-09 13:34——仅缓存无总预算）：Tree Walk 请求级
			// 缓存——Verify 单次调用内构造 cachedTXT，Discover 与 OrganizationalDomain
			// 共享同一实例，重复 _dmarc TXT 查询复用；跨调用零共享零污染
			dmResult, _, _ := dmarc.Evaluate(ctx, &cachedTXT{inner: txtResolverAdapter{r: v.resolver}},
				fromDomain, dkimSigs, spfPass, spfDomain)
			res.DMARC = string(dmResult)
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

// aggregateDKIM 聚合多签名 DKIM 结论（聚合口径登记于 U3 修改文档第 3 章）：
// 任一 pass→pass（报告域取首个通过签名的 d=）；无签名→none；
// 任一 temperror→temperror；存在签名但均未通过→fail（报告域取首个签名 d=）。
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
		if r.Signature != nil {
			return "fail", r.Signature.Domain
		}
	}
	return "none", ""
}

// FromDomain 提取 RFC5322 From 头域（DMARC Author Domain；rfc9989 4.2：
// 取首个地址的域，小写规范化）。参数：raw 原始消息字节。
// 返回：域；From 缺失/不可解析返回 ErrMissingFrom。
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
	if stack.DKIMEnabled && dkimDomain != "" {
		fmt.Fprintf(&b, ";\r\n\tdkim=%s header.d=%s", res.DKIM, dkimDomain)
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
