// auth 来信验证器：SPF/DKIM/ARC（raven）+ DMARC（自研包）四项编排、
// Authentication-Results 头组装（rfc8601）与认证栈开关热加载订阅（TC-009）。
// 依据：SRS FR-008（四项验证+A-R 头）/FR-009（开关热加载，订阅侧）/NFR-004/NFR-005；
// 模块接口契约 v1.0.0 2.2 节（Verifier/VerifyResults 签名逐字落地，compile-time 断言锁定）；
// 关键流程设计 v1.0.0 第一章（验证在 DATA 后、落库前，A-R 注入）；
// rfc8601 2.2（authres-header-field ABNF）/2.7.1（dkim=header.d）/2.7.2（spf=smtp.mailfrom）；
// 架构总览 v1.0.0 5.2（组件禁止缓存旧配置指针——开关经 RWMutex 快照读取）。
// 修改历史：
//
//	2026-09-17 02:40:00 | 新建 | U3 auth 基础（计划书步骤 6）
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

// txtResolverAdapter 将 Resolver 适配为 dmarc.TXTResolver（错误分类映射：
// ravendns.IsNotFound→dmarc.ErrNoRecord；IsTemporary→dmarc.ErrTemporary）。
type txtResolverAdapter struct{ r Resolver }

// LookupTXT 查询并映射错误分类（dmarc 包错误分类约定）。
func (a txtResolverAdapter) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	res, err := a.r.LookupTXT(ctx, domain)
	if err != nil {
		if ravendns.IsTemporary(err) {
			return nil, dmarc.ErrTemporary
		}
		return nil, dmarc.ErrNoRecord
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
			dmResult, _, _ := dmarc.Evaluate(ctx, txtResolverAdapter{r: v.resolver},
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
		spfDomain, dkimReportDomain, fromDomain, arcOldestPass)
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
			return "temperror", ""
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
// 属性形态：spf→smtp.mailfrom（2.7.2）；dkim→header.d（2.7.1）；
// dmarc→header.from；arc→arc.oldest-pass（rfc8617 注册属性，oldest-pass>0 时附注）。
func buildAuthResultsHeader(authservID string, stack config.AuthStack, res *VerifyResults,
	spfDomain, dkimDomain, fromDomain string, arcOldestPass int) string {
	var b strings.Builder
	b.WriteString("Authentication-Results: ")
	b.WriteString(authservID)
	// F-A1（RFC规范修正 RF-E，G2 批准 2026-09-28 22:16:57）：resinfo 分隔 CRLF+HTAB
	// 折叠（rfc8601 §2.2 L577-581——authres-payload 以 CRLF 终结、CFWS 引 rfc5322
	// §2.2.3 折叠语义；原裸 "\n\t" 致头体含独立 LF，存储态非合规形态）
	if stack.SPFEnabled && spfDomain != "" {
		fmt.Fprintf(&b, ";\r\n\tspf=%s smtp.mailfrom=%s", res.SPF, spfDomain)
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
