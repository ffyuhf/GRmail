// Package dmarc 自研 DMARC 验证侧实现（Q6 裁决 2026-09-16 02:39:35：
// 「使用 raven 解决认证反伪造栈……不导入 raven/dmarc，改为导入自研编写的包」）。
// 范围（U3 计划书 1.5 口径③）：策略发现 + SPF/DKIM 对齐判定 + 验证结论枚举；
// rua 聚合报告不在 SRS 38 条范围（不承诺）；处置动作（p/sp/np）消费归后续策略层。
// 规范依据（RFC 库 04 类，逐节对照）：rfc9989 4.4（对齐）/4.7（记录格式）/
// 4.10（DNS Tree Walk 八步）/4.10.1（策略发现）/4.10.2（组织域选择与对齐快捷路径）；
// rfc9990/9991（报告，验证侧不实现）。
// 修改历史：
//
//	2026-09-17 02:26:00 | 初写 | U3 auth 基础（计划书步骤 5）
//	2026-09-17 02:34:00 | 重写 | 首版误用 RFC7489 旧算法（PSL 两级上探）；
//	对照 rfc9989 原文 4.10/4.10.1/4.10.2 重写为 DNS Tree Walk + psd 选择规则
//	（触发：用户纠偏「不看规范吗？」2026-09-17 02:22:52——规范对照前置违规自省）
package dmarc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrNoRecord 策略发现全程无 DMARC 记录（rfc9989 4.10.1：不适用 DMARC）→ 结论 none
	ErrNoRecord = errors.New("dmarc: 无 DMARC 记录")
	// ErrTemporary DNS 临时故障（瞬时错误处置由接收方自主——rfc9989 4.10.1 尾段；
	// 本项目定档 temperror：A-R 如实呈现，不虚假成功，处置归上层）→ 结论 temperror
	ErrTemporary = errors.New("dmarc: DNS 临时故障")
)

// Result DMARC 验证结论枚举（契约 2.2 注释口径：none|pass|fail|softfail|temperror|permerror）。
type Result string

const (
	ResultPass      Result = "pass"
	ResultFail      Result = "fail"
	ResultNone      Result = "none"
	ResultTemperror Result = "temperror"
	ResultPermerror Result = "permerror"
)

// TXTResolver DMARC 所需最小 DNS 依赖（auth 层适配 ravendns.Resolver 后注入；
// 错误分类约定：无记录/NXDOMAIN→ErrNoRecord；瞬时故障→ErrTemporary）。
type TXTResolver interface {
	// LookupTXT 返回域名 TXT 记录；err 分类见接口注释
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

// Record DMARC 策略记录解析结果（rfc9989 4.7 核心标签）。
type Record struct {
	Version   string // v= 恒为 DMARC1
	Policy    string // p= none|quarantine|reject（处置归策略层，验证侧透传）
	SubPolicy string // sp= 组织域子域策略（可空）
	NoPolicy  string // np= 不存在域策略（可空，DMARCbis 新标签）
	ADKIM     string // adkim= 对齐模式 r（relaxed，缺省）| s（strict）
	ASPF      string // aspf= 对齐模式 r | s
	Pct       *int   // pct= 适用百分比（可空）
	RUA       string // rua= 聚合报告地址（解析保留，本包不发送）
	RUF       string // ruf= 失败报告地址（同上）
	PSD       string // psd= y|n|u（DMARCbis 新标签；Tree Walk 停走与组织域选择输入）
}

// ParseRecord 解析单条 DMARC 策略记录（rfc9989 4.7：tag-value 语法；未知标签 MUST 忽略）。
// 参数：txt 单条 TXT 记录。返回：解析结果；非 v=DMARC1 前缀返回 ErrNoRecord（调用方按
// 「该记录非 DMARC」丢弃）；标签语法非法返回包装错误。
func ParseRecord(txt string) (*Record, error) {
	txt = strings.TrimSpace(txt)
	if !strings.HasPrefix(txt, "v=DMARC1") {
		return nil, ErrNoRecord
	}
	rec := &Record{Version: "DMARC1", ADKIM: "r", ASPF: "r", PSD: "u"}
	for _, kv := range strings.Split(txt, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.Index(kv, "=")
		if eq < 0 {
			return nil, fmt.Errorf("dmarc: 非法标签 %q", kv)
		}
		key, val := strings.TrimSpace(kv[:eq]), strings.TrimSpace(kv[eq+1:])
		switch strings.ToLower(key) {
		case "v":
			if val != "DMARC1" {
				return nil, fmt.Errorf("dmarc: 版本非法 %q", val)
			}
		case "p":
			rec.Policy = strings.ToLower(val)
		case "sp":
			rec.SubPolicy = strings.ToLower(val)
		case "np":
			rec.NoPolicy = strings.ToLower(val)
		case "adkim":
			rec.ADKIM = strings.ToLower(val)
		case "aspf":
			rec.ASPF = strings.ToLower(val)
		case "pct":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("dmarc: pct 非法 %q", val)
			}
			rec.Pct = &n
		case "rua":
			rec.RUA = val
		case "ruf":
			rec.RUF = val
		case "psd":
			rec.PSD = strings.ToLower(val)
		default:
			// 未知标签忽略（rfc9989 4.7：Only tags defined in that registry are to be processed; unknown tags MUST be ignored）
		}
	}
	if rec.Policy == "" {
		return nil, fmt.Errorf("dmarc: 记录缺 p= 标签")
	}
	return rec, nil
}

// ───────────────────────── DNS Tree Walk（rfc9989 4.10） ─────────────────────────

// walkHit Tree Walk 单级命中（有效记录及其所在域）。
type walkHit struct {
	Domain string
	Record *Record
}

// queryLevel 查询单级 _dmarc.<domain>（4.10 步骤 1-2/5-6 的单级形态）：
// 非 v=DMARC1 记录丢弃；多条 DMARC 记录全部丢弃（rfc9989 4.10 步骤 2 明文）；
// 单条但语法解析失败按该级无有效命中处理（验证侧简化口径：对齐模式无法提取，
// 上探更高级记录可得保守正确的判定；登记于修改文档第 3 章）。
// 参数：ctx 上下文；resolver TXT 解析器；domain 本级域（不含 _dmarc 前缀）。
// 返回：命中（nil=无）；found 是否命中；tempErr 是否瞬时 DNS 故障。
func queryLevel(ctx context.Context, resolver TXTResolver, domain string) (hit *walkHit, found, tempErr bool) {
	txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		if errors.Is(err, ErrTemporary) {
			return nil, false, true
		}
		return nil, false, false // 无记录/NXDOMAIN：本级无命中，继续上探
	}
	count := 0
	var rec *Record
	for _, t := range txts {
		r, perr := ParseRecord(t)
		if perr != nil {
			continue // 非 DMARC 前缀或语法坏：丢弃
		}
		count++
		rec = r
	}
	if count != 1 {
		return nil, false, false // 零条或 >1 条（4.10 步骤 2）：全丢弃
	}
	return &walkHit{Domain: domain, Record: rec}, true, false
}

// walkStart 计算 Tree Walk 上探起始标签索引（4.10 步骤 3-4）：
// 标签数 <8：去最左 1 标签（父域起）；≥8：削至 7 标签起（8 查询上限保障）。
func walkStart(labelCount int) int {
	if labelCount >= 8 {
		return labelCount - 7
	}
	return 1
}

// walkUp 自父域（或削标签产物）逐级上探收集命中（4.10 步骤 5-7），
// 命中含 psd=n/y 的级别立即停走（步骤 6）。参数：domain 起始评估域（自身已首查过）。
// 追加命中至 hits 并返回；瞬时故障返回 ErrTemporary。
func walkUp(ctx context.Context, resolver TXTResolver, domain string, hits []walkHit) ([]walkHit, error) {
	labels := strings.Split(domain, ".")
	for i := walkStart(len(labels)); i < len(labels); i++ {
		target := strings.Join(labels[i:], ".")
		hit, found, tempErr := queryLevel(ctx, resolver, target)
		if tempErr {
			return hits, ErrTemporary
		}
		if found {
			hits = append(hits, *hit)
			if hit.Record.PSD == "n" || hit.Record.PSD == "y" {
				return hits, nil // 4.10 步骤 6：psd=n/y 停走
			}
		}
	}
	return hits, nil
}

// firstQueryHit 域自身首查（策略发现与组织域求值的公共第一步）。
func firstQueryHit(ctx context.Context, resolver TXTResolver, domain string) (hit *walkHit, tempErr bool) {
	h, found, temp := queryLevel(ctx, resolver, domain)
	if temp {
		return nil, true
	}
	if found {
		return h, false
	}
	return nil, false
}

// ───────────────────────── 策略发现（rfc9989 4.10.1） ─────────────────────────

// Discovery 策略发现产物：适用记录与记录所在域。
type Discovery struct {
	Record       *Record
	RecordDomain string
}

// Discover DMARC 策略发现（4.10.1：首查 Author Domain，未命中则 Tree Walk）。
// 参数：ctx 上下文；resolver TXT 解析器；authorDomain RFC5322 From 头域。
// 返回：Discovery；全程无记录返回 ErrNoRecord；瞬时故障返回 ErrTemporary。
func Discover(ctx context.Context, resolver TXTResolver, authorDomain string) (*Discovery, error) {
	authorDomain = strings.ToLower(strings.Trim(authorDomain, "."))
	if hit, temp := firstQueryHit(ctx, resolver, authorDomain); temp {
		return nil, ErrTemporary
	} else if hit != nil {
		return &Discovery{Record: hit.Record, RecordDomain: hit.Domain}, nil
	}
	labels := strings.Split(authorDomain, ".")
	for i := walkStart(len(labels)); i < len(labels); i++ {
		target := strings.Join(labels[i:], ".")
		hit, found, tempErr := queryLevel(ctx, resolver, target)
		if tempErr {
			return nil, ErrTemporary
		}
		if found {
			return &Discovery{Record: hit.Record, RecordDomain: hit.Domain}, nil
		}
	}
	return nil, ErrNoRecord
}

// ───────────────────────── 组织域与对齐（rfc9989 4.10.2） ─────────────────────────

// OrganizationalDomain 求 domain 的组织域（4.10.2 选择规则，经 Tree Walk）：
// ①命中记录 psd=n → 该域即组织域；②非 walk 起点命中 psd=y → 其下一标签域；
// ③否则取标签数最少的命中域；④无任何命中 → 起点域自身（4.10.2 末段）。
// 参数：ctx；resolver；domain 起始域。返回：组织域；瞬时故障返回 ErrTemporary。
func OrganizationalDomain(ctx context.Context, resolver TXTResolver, domain string) (string, error) {
	domain = strings.ToLower(strings.Trim(domain, "."))
	var hits []walkHit
	if hit, temp := firstQueryHit(ctx, resolver, domain); temp {
		return "", ErrTemporary
	} else if hit != nil {
		hits = append(hits, *hit)
		if hit.Record.PSD == "n" || hit.Record.PSD == "y" {
			// 4.10 步骤 2：首查单条含 psd=n/y 即停走（起点命中，选择规则①或③处理）
			return selectOrganizationalDomain(hits, domain), nil
		}
	}
	hits, err := walkUp(ctx, resolver, domain, hits)
	if err != nil {
		return "", err
	}
	return selectOrganizationalDomain(hits, domain), nil
}

// selectOrganizationalDomain 4.10.2 三选一规则（hits 为空时返回起点域）。
// 规则②语义（4.10.2 原文例证）：psd=y 的域为 PSD，组织域为「PSD 朝 walk 起点方向
// 下一标签的域」——如起点 a.mail.example.com 命中 _dmarc.com 且 psd=y → org=example.com；
// 起点 mail.example.com 命中 _dmarc.example.com 且 psd=y → org=mail.example.com。
func selectOrganizationalDomain(hits []walkHit, startDomain string) string {
	if len(hits) == 0 {
		return startDomain // 规则④：无命中→起点域
	}
	var best string
	bestLabels := 1 << 30
	for _, h := range hits {
		switch {
		case h.Record.PSD == "n": // 规则①：psd=n → 该域即组织域，完成选择
			return h.Domain
		case h.Record.PSD == "y" && h.Domain != startDomain: // 规则②：非起点 psd=y
			return domainOneLabelAbove(startDomain, h.Domain)
		}
		if n := labelCount(h.Domain); n < bestLabels { // 规则③：标签最少
			best, bestLabels = h.Domain, n
		}
	}
	return best
}

// domainOneLabelAbove 求 PSD 域朝起点方向上一标签的域（规则②专用）：
// startDomain 以 ".psd" 为后缀时，取紧贴 PSD 的标签拼接；否则退化为 PSD 域（防御）。
// 例：("a.mail.example.com", "com") → "example.com"。
func domainOneLabelAbove(startDomain, psdDomain string) string {
	suffix := "." + psdDomain
	if strings.HasSuffix(startDomain, suffix) {
		rest := strings.TrimSuffix(startDomain, suffix)
		parts := strings.Split(rest, ".")
		return parts[len(parts)-1] + "." + psdDomain
	}
	return psdDomain
}

// labelCount 域名标签数（用于规则③比较）。
func labelCount(domain string) int { return len(strings.Split(domain, ".")) }

// aligned 标识对齐判定（4.4 + 4.10.2 快捷路径）。
// strict（s）：精确相等（大小写不敏感，rfc4343——4.10.2 捷径：无需 Tree Walk）。
// relaxed（r）：快捷路径①（两域相同→公共域即组织域）；否则两域各自组织域比较。
// 参数：ctx；resolver；authDomain 认证标识域（DKIM d= 或 SPF MAIL FROM 域）；
// fromDomain Author Domain；mode r|s。返回：是否对齐；瞬时故障返回 ErrTemporary。
func aligned(ctx context.Context, resolver TXTResolver, authDomain, fromDomain, mode string) (bool, error) {
	a := strings.ToLower(strings.Trim(authDomain, "."))
	f := strings.ToLower(strings.Trim(fromDomain, "."))
	if a == "" || f == "" {
		return false, nil
	}
	if mode == "s" {
		return a == f, nil
	}
	if a == f { // 4.10.2 捷径①：全同域且有记录（调用上下文 Discover 已命中）→ 公共域即组织域
		return true, nil
	}
	authOrg, err := OrganizationalDomain(ctx, resolver, a)
	if err != nil {
		return false, err
	}
	fromOrg, err := OrganizationalDomain(ctx, resolver, f)
	if err != nil {
		return false, err
	}
	return authOrg == fromOrg, nil
}

// ───────────────────────── 验证评估 ─────────────────────────

// SigResult 单个 DKIM 签名的评估输入（d= 域与验证结论）。
type SigResult struct {
	Domain string // DKIM d= 标签域
	Pass   bool   // 该签名是否验证通过
}

// Evaluate DMARC 验证评估（4.1 判定：pass ⇔ 存在通过且对齐的 DKIM 标识或 SPF 标识）。
// 流程：策略发现（Discover）→ 按记录 adkim/aspf 逐签名/SPF 对齐判定（aligned）。
// 参数：ctx；resolver；fromDomain RFC5322 From 头域；dkimSigs 全部 DKIM 签名结果；
// spfPass SPF 是否通过；spfDomain SPF 认证域（信封 MAIL FROM 域——4.4.2：仅此身份参与）。
// 返回：结论（pass|fail|none|temperror|permerror 防御位）；发现产物（结论为 pass/fail 时非 nil）。
func Evaluate(ctx context.Context, resolver TXTResolver, fromDomain string, dkimSigs []SigResult, spfPass bool, spfDomain string) (Result, *Discovery, error) {
	disc, err := Discover(ctx, resolver, fromDomain)
	if err != nil {
		switch {
		case errors.Is(err, ErrTemporary):
			return ResultTemperror, nil, nil
		case errors.Is(err, ErrNoRecord):
			return ResultNone, nil, nil // 4.10.1：MUST NOT 应用 DMARC
		default:
			return ResultPermerror, nil, nil // 防御位（语法坏已在 queryLevel 消解）
		}
	}
	for _, sig := range dkimSigs {
		if !sig.Pass {
			continue
		}
		ok, aerr := aligned(ctx, resolver, sig.Domain, fromDomain, disc.Record.ADKIM)
		if aerr != nil {
			return ResultTemperror, disc, nil
		}
		if ok {
			return ResultPass, disc, nil
		}
	}
	if spfPass {
		ok, aerr := aligned(ctx, resolver, spfDomain, fromDomain, disc.Record.ASPF)
		if aerr != nil {
			return ResultTemperror, disc, nil
		}
		if ok {
			return ResultPass, disc, nil
		}
	}
	return ResultFail, disc, nil
}
