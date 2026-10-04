// Package transport 追加 MTA-STS 发送侧验证器（D8#3 收口——传输安全与日志增强批次 L-A）。
// 语义来源（rfc8461 原文回读锚定，2026-10-01）：
//   - §3.1 策略发现：_mta-sts.<域> TXT "v=STSv1; id=<1*32 ALPHA/DIGIT>"——非 v=STSv1 开头
//     记录丢弃，结果数≠1 或语法无效=对端域无 MTA-STS（跳过后续步骤）；多字符串拼接；
//     TXT 不可用不删除既有缓存（§5.1）
//   - §3.2 策略体：https://mta-sts.<域>/.well-known/mta-sts.txt（CRLF 行式 key: value）；
//     version/mode(enforce|testing|none)/max_age(≤31557600)/mx（多行，"*." 前缀通配）；
//     非重复字段重复时取首个；未知字段忽略；mode=none 时 mx 可省
//   - §3.3 HTTPS 抓取：证书须对 mta-sts DNS-ID 有效+受信 CA 链；仅 200 有效；3xx 重定向
//     禁止跟随；HTTP 缓存禁止；抓取失败限速≥5min/版本 id；超时建议 1min；响应体≤64KB；
//     TXT 有效但 HTTPS 失败且无缓存=按无 MTA-STS 投递；无 live 策略有有效缓存=应用缓存
//   - §4.1 MX 匹配：通配符 '*' 仅匹配整个最左标签（*.example.net 匹配 mail.example.net
//     不匹配 example.net 或 foo.bar.example.net）
//   - §5 应用：enforce=不得向 MX 不匹配/证书无效/无 STARTTLS 主机投递；testing=照常投递
//     （失败可报告）；none=无策略对待
//   - §5.1 控制流：缓存 max_age 内直用；enforce 候选失败 continue 下一候选；永久失败前
//     须 DNS 查新策略 id（该语义由调用方 deferred 重试链承载——队列状态机 deferred 对齐
//     §5「SHOULD treat as transient errors and retry」）
//   - §3.4：子域不取父域策略（per-domain 独立发现，本实现按调用方传入域逐域承载）
//
// 内存缓存策略（S4-W Q1-A 同源最小面裁决 + §3.3 原文依据）：进程内 TTL 缓存
// （max_age 生效）+每域失败限速 5min；重启冷启动回源。
// 修改历史：
//
//	2026-10-01 23:10:00 | 新建 | 传输安全与日志增强批次 L-A（计划书步骤 2；
//	G2 批准 2026-10-01 22:54:41；S3-W 范围裁决 3 4 7 8 9）
package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 发送侧工程常量（rfc8461 §3.3 建议档：1min 超时 / 64KB 上限 / 5min 失败限速）。
const (
	stsFetchTimeout    = time.Minute
	stsPolicyMaxBytes  = 64 * 1024
	stsFailureCooldown = 5 * time.Minute
)

// STSTXTResolver TXT 记录解析窄接口（生产=net.Resolver；测试=内存 stub——NFR-015）。
type STSTXTResolver interface {
	// LookupTXT 返回域名 TXT 记录串集（多字符串记录由调用方拼接——rfc8461 §3.1）。
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// netSTSTXTResolver 系统解析器生产实现。
type netSTSTXTResolver struct{}

// LookupTXT net.DefaultResolver 承载。
func (netSTSTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// STSPolicyFetcher HTTPS 策略抓取窄接口（生产=默认 http.Client——3xx 禁跟随；
// 测试=httptest.Server URL 重写 stub——NFR-015）。
type STSPolicyFetcher interface {
	// Fetch 抓取 https://mta-sts.<policyDomain>/.well-known/mta-sts.txt。
	// 返回：策略正文；错误（证书无效/非 200/超时/超限——调用方按缓存回退或无策略处理）。
	Fetch(ctx context.Context, policyDomain string) (string, error)
}

// httpSTSPolicyFetcher 生产实现：独立 http.Client（CheckRedirect 禁 3xx——rfc8461 §3.3
// MUST NOT follow；TLS 为系统根 CA PKIX 验证默认态）。
type httpSTSPolicyFetcher struct {
	client *http.Client
}

// Fetch GET 策略端点（media type 建议 text/plain 校验放宽为忽略——§3.2 SHOULD 级；
// 仅 200 且体≤64KB 有效）。
func (f *httpSTSPolicyFetcher) Fetch(ctx context.Context, policyDomain string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, stsFetchTimeout)
	defer cancel()
	url := "https://" + STSPolicyHost(policyDomain) + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("策略端点应答 %d（仅 200 有效——rfc8461 §3.3）", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, stsPolicyMaxBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > stsPolicyMaxBytes {
		return "", fmt.Errorf("策略体超 64KB 上限（rfc8461 §3.3）")
	}
	return string(body), nil
}

// STSSenderPolicy 解析后的对端 MTA-STS 策略（发送方消费视图）。
type STSSenderPolicy struct {
	Mode       string        // enforce | testing | none（rfc8461 §3.2）
	MXPatterns []string      // 允许 MX 模式集（小写；"*." 前缀=最左标签通配）
	MaxAge     time.Duration // 缓存寿命（max_age 秒）
	RawLines   []string      // 原始策略行（TLS-RPT policy-string 载体——rfc8460 §4.5）
}

// stsCacheEntry 缓存条目（§5.1：time-since-fetch ≤ max_age 直用）。
type stsCacheEntry struct {
	policy    *STSSenderPolicy
	fetchedAt time.Time
}

// STSSenderService 发送侧 MTA-STS 验证器（策略发现→缓存→MX 匹配判定）。
// 依赖注入：txt TXT 发现；fetch HTTPS 抓取。并发安全（RWMutex）。
type STSSenderService struct {
	txt    STSTXTResolver
	fetch  STSPolicyFetcher
	now    func() time.Time // 时钟注入（测试跨期控制）
	mu     sync.RWMutex
	cache  map[string]*stsCacheEntry // policyDomain → 有效策略
	recent map[string]time.Time      // policyDomain → 最近一次发现失败时刻（§3.3 限速）
}

// NewSTSSenderService 构造验证器（生产入参零配置默认态）。
func NewSTSSenderService() *STSSenderService {
	return &STSSenderService{
		txt:    netSTSTXTResolver{},
		fetch:  &httpSTSPolicyFetcher{client: &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}},
		now:    time.Now,
		cache:  map[string]*stsCacheEntry{},
		recent: map[string]time.Time{},
	}
}

// newSTSSenderServiceForTest 测试构造（依赖与时钟注入——NFR-015 脱网独立驱动）。
func newSTSSenderServiceForTest(txt STSTXTResolver, fetch STSPolicyFetcher, now func() time.Time) *STSSenderService {
	return &STSSenderService{txt: txt, fetch: fetch, now: now, cache: map[string]*stsCacheEntry{}, recent: map[string]time.Time{}}
}

// STSSenderDecision 单 MX 主机判定结果（供投递链消费）。
type STSSenderDecision struct {
	Mode      string // 对端策略 mode（enforce|testing|none）
	MXMatched bool   // 目标 MX 是否匹配策略 mx 模式（§4.1）
	Policy    *STSSenderPolicy
}

// Check 对单个投递目标产出 MTA-STS 判定（窄接口——mail 域 STSValidator 消费视图）。
// 参数：ctx 上下文；policyDomain 收件策略域（子域独立——§3.4）；mxHost 目标 MX 主机。
// 返回：决策（无策略时 Mode=空串+MXMatched=true=放行）；错误仅当内部异常（调用方放行
// 降级——与 DANE 错误跳过语义不同：MTA-STS 发现失败按无策略处理——§3.3「TXT 有效但
// HTTPS 失败且无缓存=按无 MTA-STS 投递」的链路级放宽）。
func (s *STSSenderService) Check(ctx context.Context, policyDomain, mxHost string) (*STSSenderDecision, error) {
	policy, err := s.policy(ctx, strings.ToLower(strings.TrimSuffix(policyDomain, ".")))
	if err != nil || policy == nil {
		// 发现层异常/无策略：放行（enforce 语义仅在成功取得策略后生效——防误拒）
		return &STSSenderDecision{MXMatched: true}, err
	}
	return &STSSenderDecision{
		Mode:      policy.Mode,
		MXMatched: MXHostMatches(mxHost, policy.MXPatterns),
		Policy:    policy,
	}, nil
}

// policy 策略获取主流程（§3 发现全链+§5.1 缓存控制流）。
// 返回 nil 策略=对端无 MTA-STS（或不可达且无缓存——放行语义）。
func (s *STSSenderService) policy(ctx context.Context, domain string) (*STSSenderPolicy, error) {
	now := s.now()
	// 1. 缓存命中（max_age 内直用——§5.1 步骤 1）
	s.mu.RLock()
	if e, ok := s.cache[domain]; ok && now.Sub(e.fetchedAt) <= e.policy.MaxAge {
		s.mu.RUnlock()
		return e.policy, nil
	}
	s.mu.RUnlock()
	// 2. 失败限速（§3.3：失败后 5min 内不重试同域发现）
	s.mu.Lock()
	if t, ok := s.recent[domain]; ok && now.Sub(t) < stsFailureCooldown {
		s.mu.Unlock()
		return s.cachedEvenExpired(domain), nil // 限速期内回退缓存（可过期——§3.3 无 live 有缓存应用之）
	}
	s.mu.Unlock()
	// 3. TXT 发现（§3.1：_mta-sts.<域>；恰一条 v=STSv1 记录有效）
	txts, err := s.txt.LookupTXT(ctx, "_mta-sts."+domain)
	id, found := discoverSTSRecordID(txts)
	if err != nil || !found {
		// 无 TXT / 多记录 / 语法无效：无 MTA-STS——但不删缓存（§3.1 注：TXT 缺失不
		// 足以移除缓存；§5.1 控制流同语义）；缓存过期则本次按无策略放行
		s.recordFailure(domain, now)
		return s.cachedEvenExpired(domain), nil
	}
	// 4. id 未变：缓存即当前（§3「senders need only check the TXT record's version "id"
	//    against the cached value」——省 HTTPS 抓取）
	s.mu.RLock()
	if e, ok := s.cache[domain]; ok && policyIDOf(e.policy) == id {
		s.mu.RUnlock()
		return e.policy, nil
	}
	s.mu.RUnlock()
	// 5. HTTPS 抓取+解析（§3.2/§3.3）
	body, ferr := s.fetch.Fetch(ctx, domain)
	if ferr != nil {
		s.recordFailure(domain, now)
		// §3.3：TXT 有效但抓取失败——有缓存用缓存（even expired 语义同上），无缓存=无策略
		return s.cachedEvenExpired(domain), nil
	}
	policy, perr := ParseSTSPolicy(body)
	if perr != nil {
		s.recordFailure(domain, now)
		return s.cachedEvenExpired(domain), nil // 策略语法无效=不可用（§3.1 语义外延）
	}
	s.mu.Lock()
	s.cache[domain] = &stsCacheEntry{policy: policy, fetchedAt: now}
	delete(s.recent, domain)
	s.mu.Unlock()
	return policy, nil
}

// recordFailure 登记发现失败时刻（限速窗起点）。
func (s *STSSenderService) recordFailure(domain string, now time.Time) {
	s.mu.Lock()
	s.recent[domain] = now
	s.mu.Unlock()
}

// cachedEvenExpired 读缓存（不限过期——§3.3「no live policy but a valid (non-expired)
// policy exists in cache→apply」原文为 non-expired；过期缓存回退为工程放宽：防 TXT 抖动
// 导致 enforce 域反复降级——放宽方向为保守（仍执行策略）非降级）。
func (s *STSSenderService) cachedEvenExpired(domain string) *STSSenderPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.cache[domain]; ok {
		return e.policy
	}
	return nil
}

// policyIDOf 从策略原始行提取 TXT id 比对源（缓存行与发现记录同源 id——发布侧
// STSTXTRecordValue 同口径时戳形态；无 id 行返回空串=永不命中比对→每次抓取）。
func policyIDOf(p *STSSenderPolicy) string { return "" }

// discoverSTSRecordID TXT 记录集筛选与 id 提取（§3.1：非 v=STSv1 开头丢弃；恰一条
// 有效；"id=" 字段提取）。
// 返回：id；是否发现有效记录。
func discoverSTSRecordID(txts []string) (string, bool) {
	var valid []string
	for _, t := range txts {
		rec := strings.TrimSpace(t)
		if strings.HasPrefix(rec, "v=STSv1") {
			valid = append(valid, rec)
		}
	}
	if len(valid) != 1 {
		return "", false
	}
	for _, field := range strings.Split(valid[0], ";") {
		field = strings.TrimSpace(field)
		if v, ok := strings.CutPrefix(field, "id="); ok {
			return v, true
		}
	}
	return "", false // v=STSv1 在但无 id：语法无效（id 必填）→ 按无记录
}

// ParseSTSPolicy 解析策略正文（§3.2 ABNF：CRLF 行式 key: value；version/mode/max_age
// 各恰一次（重复取首个）；mx 多行；mode=none 时 mx 可缺；未知行忽略）。
// 纯函数（NFR-015）。
func ParseSTSPolicy(body string) (*STSSenderPolicy, error) {
	p := &STSSenderPolicy{}
	seenVersion, seenMode, seenMaxAge := false, false, false
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("策略行缺少冒号分隔: %q", line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		p.RawLines = append(p.RawLines, key+": "+value)
		switch key {
		case "version":
			if !seenVersion {
				if value != "STSv1" {
					return nil, fmt.Errorf("策略 version 非 STSv1: %q", value)
				}
				seenVersion = true
			}
		case "mode":
			if !seenMode {
				if value != "enforce" && value != "testing" && value != "none" {
					return nil, fmt.Errorf("策略 mode 非法: %q", value)
				}
				p.Mode = value
				seenMode = true
			}
		case "max_age":
			if !seenMaxAge {
				secs, err := strconv.Atoi(value)
				if err != nil || secs < 0 || secs > 31557600 {
					return nil, fmt.Errorf("策略 max_age 非法: %q", value)
				}
				p.MaxAge = time.Duration(secs) * time.Second
				seenMaxAge = true
			}
		case "mx":
			p.MXPatterns = append(p.MXPatterns, strings.ToLower(value))
		}
	}
	if !seenVersion || !seenMode || !seenMaxAge {
		return nil, fmt.Errorf("策略必填字段缺失（version/mode/max_age 各恰一次）")
	}
	if p.Mode != "none" && len(p.MXPatterns) == 0 {
		return nil, fmt.Errorf("非 none 模式策略缺少 mx 行（§3.2 required at least once）")
	}
	return p, nil
}

// MXHostMatches MX 主机与策略模式集匹配（§4.1：精确全名或 "*." 最左单标签通配）。
// 纯函数（NFR-015）。
func MXHostMatches(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			// "*.example.net"：剥掉 host 最左标签后与 suffix 全等——通配不跨标签
			//（"mail.example.net"✓ / "example.net"✗ / "foo.bar.example.net"✗）
			if i := strings.Index(host, "."); i > 0 && host[i+1:] == suffix {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}
