// Package transport 追加 TLS-RPT 报告生成器（D8#4 收口——传输安全与日志增强批次 L-B）。
// 语义来源（rfc8460 原文回读锚定，2026-10-01）：
//   - §3 报告策略发现：_smtp._tls.<域> TXT "v=TLSRPTv1; rua=<uri>[,uri]"——mailto/https
//     两 scheme；非 v=TLSRPTv1 开头丢弃，结果数≠1=对端不实现 TLSRPT；多 rua 逗号列表
//     （至少投递其一即视为成功）
//   - §4.1 报告时间窗：全天 00:00-24:00 UTC；发送前建议随机延迟（1s~4h）平滑负载
//   - §4.2 聚合计数：total-successful-session-count / total-failure-session-count
//   - §4.3 结果类型枚举：starttls-not-supported / certificate-host-mismatch /
//     certificate-expired / certificate-not-trusted / validation-failure（协商类）；
//     tlsa-invalid / dnssec-invalid / dane-required（DANE 类）；
//     sts-policy-fetch-error / sts-policy-invalid / sts-webpki-invalid（MTA-STS 类）；
//     瞬态失败（网络忙/超时）不要求报告
//   - §4.4 JSON 结构：organization-name / date-range{start,end}（RFC3339） / contact-info
//     / report-id / policies[{policy{policy-type, policy-string[], policy-domain,
//     mx-host-pattern[]}, summary{两计数}, failure-details[{result-type, sending-mta-ip,
//     receiving-mx-hostname, receiving-mx-helo?, receiving-ip?, failed-session-count,
//     additional-information-uri?, failure-reason-code?}]}]——policies 恒数组
//   - §4.5 policy-string：MTA-STS=策略行数组（每 mx 独立元素）；DANE=TLSA RDATA 数组
//   - §5.1 文件名 ABNF：sender!policy-domain!begin!end[!unique].json[.gz]
//   - §5.2 gzip SHOULD；§5.3 邮件形态：multipart/report; report-type="tlsrpt"，两 part
//     （text/plain 人类可读+application/tlsrpt+gzip 机器可读）+两新头
//     TLS-Report-Domain/TLS-Report-Submitter+Subject"Report Domain: X Submitter: Y
//     Report-ID: <id>"；报告 SMTP 投递 MUST NOT honor MTA-STS/DANE 失败（由既有队列
//     deferred 重试链承载——不因 TLS 失败永久拒发）；mailto 报告 MUST DKIM 签名
//     （报告域=提交域——经 SubmissionPipeline.Submit 既有 DKIM 链自动承载）
//
// 聚合形态：S4-W Q1-A 裁决（2026-10-01 23:05:16）——内存态聚合（重启丢当期统计，
// 对每日报告粒度可接受；零表改动）。
// 修改历史：
//
//	2026-10-01 23:12:00 | 新建 | 传输安全与日志增强批次 L-B（计划书步骤 3；
//	G2 批准 2026-10-01 22:54:41；S4-W Q1-A 内存聚合裁决）
package transport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TLS-RPT 结果类型常量（rfc8460 §4.3——注册表初集）。
const (
	TLSRPTStarttlsNotSupported    = "starttls-not-supported"    // §4.3.1 对端无 STARTTLS
	TLSRPTCertificateHostMismatch = "certificate-host-mismatch" // §4.3.1 证书不符策略约束
	TLSRPTCertificateExpired      = "certificate-expired"       // §4.3.1 证书过期
	TLSRPTCertificateNotTrusted   = "certificate-not-trusted"   // §4.3.1 不可信 CA/链错误
	TLSRPTValidationFailure       = "validation-failure"        // §4.3.1/§4.3.3 一般失败
	TLSRPTStsPolicyFetchError     = "sts-policy-fetch-error"    // §4.3.2.2 策略抓取失败
	TLSRPTStsPolicyInvalid        = "sts-policy-invalid"        // §4.3.2.2 策略校验错误
	TLSRPTStsWebpkiInvalid        = "sts-webpki-invalid"        // §4.3.2.2 PKIX 验证失败
	TLSRPTDaneInvalid             = "tlsa-invalid"              // §4.3.2.1 DANE TLSA 无效
	TLSRPTDnssecInvalid           = "dnssec-invalid"            // §4.3.2.1 DNSSEC 无有效记录
	TLSRPTDaneRequired            = "dane-required"             // §4.3.2.1 强制 DANE 缺失
)

// TLSRPTSuccess 成功计数哨兵（空串区分成功/失败——Record 入口约定）。
const TLSRPTSuccess = ""

// tlsrptFailureKey 聚合粒度键（result-type@mx-host——rfc8460 §4.4 failure-details
// 按 result-type+接收主机聚合）。
type tlsrptFailureKey struct {
	ResultType string
	MXHost     string
}

// TLSRPTDomainStats 单策略域统计快照（SnapshotAndReset 返回值）。
type TLSRPTDomainStats struct {
	Success  int64                      // total-successful-session-count
	Failures map[tlsrptFailureKey]int64 // result-type×mx-host → failed-session-count
}

// TLSRPTAggregator TLS 投递结果内存聚合器（S4-W Q1-A——并发安全；零表承载）。
type TLSRPTAggregator struct {
	mu      sync.Mutex
	domains map[string]*tlsrptDomainAgg
}

type tlsrptDomainAgg struct {
	success  int64
	failures map[tlsrptFailureKey]int64
}

// NewTLSRPTAggregator 构造聚合器。
func NewTLSRPTAggregator() *TLSRPTAggregator {
	return &TLSRPTAggregator{domains: map[string]*tlsrptDomainAgg{}}
}

// Record 记录一次投递 TLS 结果（mail 域 TLSResultRecorder 消费视图）。
// 参数：domain 对端策略域（小写规范化）；mxHost 接收 MX 主机；resultType 结果类型
// （TLSRPTSuccess=""=成功会话）。瞬态网络失败不记录（§4.3.4 不要求）。
func (a *TLSRPTAggregator) Record(domain, mxHost, resultType string) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	a.mu.Lock()
	defer a.mu.Unlock()
	agg, ok := a.domains[domain]
	if !ok {
		agg = &tlsrptDomainAgg{failures: map[tlsrptFailureKey]int64{}}
		a.domains[domain] = agg
	}
	if resultType == TLSRPTSuccess {
		agg.success++
		return
	}
	agg.failures[tlsrptFailureKey{ResultType: resultType, MXHost: strings.ToLower(mxHost)}]++
}

// SnapshotAndReset 读出全部统计并清零（周期报告任务消费——读后即清保证窗口不重叠）。
// 返回：policyDomain → 统计快照（空 map=本周期零流量零报告）。
func (a *TLSRPTAggregator) SnapshotAndReset() map[string]TLSRPTDomainStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]TLSRPTDomainStats, len(a.domains))
	for domain, agg := range a.domains {
		out[domain] = TLSRPTDomainStats{Success: agg.success, Failures: agg.failures}
	}
	a.domains = map[string]*tlsrptDomainAgg{}
	return out
}

// ───────────────────────── JSON 报告构造（§4.4 结构字段级锚定） ─────────────────────────

// tlsrptJSONReport rfc8460 §4.4 JSON Report Format 结构化载体（序列化字段名逐字）。
type tlsrptJSONReport struct {
	OrganizationName string              `json:"organization-name"`
	DateRange        tlsrptJSONDateRange `json:"date-range"`
	ContactInfo      string              `json:"contact-info"`
	ReportID         string              `json:"report-id"`
	Policies         []tlsrptJSONPolicy  `json:"policies"`
}

type tlsrptJSONDateRange struct {
	StartDatetime string `json:"start-datetime"` // RFC3339（§4.4 date-time）
	EndDatetime   string `json:"end-datetime"`
}

type tlsrptJSONPolicy struct {
	Policy struct {
		PolicyType   string   `json:"policy-type"`   // sts | tlsa | no-policy-found（§4.4）
		PolicyString []string `json:"policy-string"` // §4.5：策略行/TLSA RDATA 数组
		PolicyDomain string   `json:"policy-domain"`
		MXHosts      []string `json:"mx-host-pattern"` // sts 态策略 mx 模式集
	} `json:"policy"`
	Summary struct {
		TotalSuccessfulSessionCount int64 `json:"total-successful-session-count"`
		TotalFailureSessionCount    int64 `json:"total-failure-session-count"`
	} `json:"summary"`
	FailureDetails []tlsrptJSONFailure `json:"failure-details,omitempty"` // 无失败时省略（§4.4 可选）
}

type tlsrptJSONFailure struct {
	ResultType          string `json:"result-type"`
	SendingMTAIP        string `json:"sending-mta-ip"`
	ReceivingMXHostname string `json:"receiving-mx-hostname"`
	FailedSessionCount  int64  `json:"failed-session-count"`
	FailureReasonCode   string `json:"failure-reason-code,omitempty"`
}

// TLSRPTReportInput 报告构造输入（BuildTLSRPTReport 纯函数参数——NFR-015）。
type TLSRPTReportInput struct {
	OrganizationName string    // 报告组织名（本域）
	ContactEmail     string    // 责任联系人（ Addr-Spec——tlsrpt@<本域> 形态）
	ReportID         string    // 唯一标识（调用方生成——文件名同源）
	WindowStart      time.Time // 报告窗起点（UTC）
	WindowEnd        time.Time // 报告窗终点（UTC）
	PolicyDomain     string    // 对端策略域
	PolicyType       string    // sts | tlsa | no-policy-found
	PolicyString     []string  // 策略原文行集
	MXHostPatterns   []string  // sts 态 mx 模式集
	SendingMTAIP     string    // 本侧发送 IP（§4.4 ip-address）
	Stats            TLSRPTDomainStats
}

// BuildTLSRPTReport 构造 JSON 报告（gzip 由调用方承载——§5.2）。
// 纯函数。返回：JSON 字节。
func BuildTLSRPTReport(in TLSRPTReportInput) []byte {
	report := tlsrptJSONReport{
		OrganizationName: in.OrganizationName,
		DateRange: tlsrptJSONDateRange{
			StartDatetime: in.WindowStart.UTC().Format(time.RFC3339),
			EndDatetime:   in.WindowEnd.UTC().Format(time.RFC3339),
		},
		ContactInfo: in.ContactEmail,
		ReportID:    in.ReportID,
	}
	pol := tlsrptJSONPolicy{}
	pol.Policy.PolicyType = in.PolicyType
	pol.Policy.PolicyString = in.PolicyString
	pol.Policy.PolicyDomain = in.PolicyDomain
	pol.Policy.MXHosts = in.MXHostPatterns
	pol.Summary.TotalSuccessfulSessionCount = in.Stats.Success
	var totalFail int64
	for _, count := range in.Stats.Failures {
		totalFail += count
	}
	pol.Summary.TotalFailureSessionCount = totalFail
	// failure-details 按 result-type×mx-host 展开为单条目数组（§4.4 每条自帘认数）
	for key, count := range in.Stats.Failures {
		pol.FailureDetails = append(pol.FailureDetails, tlsrptJSONFailure{
			ResultType:          key.ResultType,
			SendingMTAIP:        in.SendingMTAIP,
			ReceivingMXHostname: key.MXHost,
			FailedSessionCount:  count,
		})
	}
	report.Policies = []tlsrptJSONPolicy{pol} // §4：policies 恒数组（MUST）
	data, _ := json.MarshalIndent(report, "", "  ")
	return data
}

// TLSRPTReportFilename 报告附件文件名（§5.1 ABNF：sender!policy-domain!begin!end!unique
// .json.gz——unique 恒含入此形态；时间戳取报告窗起止的 Unix 秒）。
func TLSRPTReportFilename(senderDomain, policyDomain string, windowStart, windowEnd time.Time, uniqueID string) string {
	return fmt.Sprintf("%s!%s!%d!%d!%s.json.gz",
		senderDomain, policyDomain, windowStart.UTC().Unix(), windowEnd.UTC().Unix(), uniqueID)
}

// ───────────────────────── 报告邮件构造（§5.3 Email Transport） ─────────────────────────

// BuildTLSRPTReportEmail 构造完整报告邮件（RFC5322 字节）。
// 参数：submitterDomain 提交域（TLS-Report-Submitter+contact-info 域一致性锚——§5.3）；
// policyDomain 对端策略域；ruaAddress 收件聚合地址；filename 附件文件名（§5.1）；
// reportID 报告标识（Subject Report-ID 同源）；jsonGz gzip 压缩后的 JSON 报告字节。
// 返回：完整邮件字节（multipart/report 两 part——text/plain+application/tlsrpt+gzip）。
// 附件 base64 76 列折行（rfc2045 §6.3 形态）。纯函数。
func BuildTLSRPTReportEmail(submitterDomain, policyDomain, ruaAddress, filename, reportID string, jsonGz []byte) []byte {
	var b strings.Builder
	fromAddr := "tlsrpt@" + submitterDomain
	b.WriteString("From: " + fromAddr + "\r\n")
	b.WriteString("To: " + ruaAddress + "\r\n")
	b.WriteString("Subject: Report Domain: " + policyDomain +
		" Submitter: " + submitterDomain +
		" Report-ID: <" + reportID + ">\r\n") // §5.3 Subject ABNF
	b.WriteString("TLS-Report-Domain: " + policyDomain + "\r\n") // §5.3 两新头（MUST）
	b.WriteString("TLS-Report-Submitter: " + submitterDomain + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	const boundary = "----=_GRmailTLSRPT"
	b.WriteString("Content-Type: multipart/report; report-type=\"tlsrpt\";\r\n" +
		"    boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("This is a multipart message in MIME format.\r\n\r\n")
	// part 1：人类可读摘要（§5.3 text/plain）
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"us-ascii\"\r\n")
	b.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	b.WriteString("This is an aggregate TLS report from " + submitterDomain + "\r\n\r\n")
	// part 2：机器可读 gzip JSON（§5.3 application/tlsrpt+gzip）
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: application/tlsrpt+gzip\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("Content-Disposition: attachment;\r\n    filename=\"" + filename + "\"\r\n\r\n")
	b.WriteString(base64Wrap(jsonGz))
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return []byte(b.String())
}

// base64Wrap base64 编码+76 字符行折（rfc2045 §6.3——附件 CTE 形态；标准库承载）。
func base64Wrap(data []byte) string {
	const lineWidth = 76
	encoded := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for i := 0; i < len(encoded); i += lineWidth {
		end := i + lineWidth
		if end > len(encoded) {
			end = len(encoded)
		}
		out.WriteString(encoded[i:end])
		out.WriteString("\r\n")
	}
	return out.String()
}

// ───────────────────────── rua 地址发现（§3 报告策略） ─────────────────────────

// DiscoverTLSRPTRua 从 _smtp._tls TXT 记录集提取 rua 地址（§3：恰一条 v=TLSRPTv1
// 有效；rua 逗号列表取首个 mailto: URI——多端点至少投递其一语义；无 mailto（纯 https）
// 返回空串由调用方跳过邮件通道）。
// 纯函数（NFR-015）。返回：mailto 地址（不含 "mailto:" 前缀）；是否发现。
func DiscoverTLSRPTRua(txts []string) (string, bool) {
	var valid []string
	for _, t := range txts {
		rec := strings.TrimSpace(t)
		if strings.HasPrefix(rec, "v=TLSRPTv1") {
			valid = append(valid, rec)
		}
	}
	if len(valid) != 1 {
		return "", false // 结果数≠1：对端不实现 TLSRPT（§3）
	}
	for _, field := range strings.Split(valid[0], ";") {
		field = strings.TrimSpace(field)
		if v, ok := strings.CutPrefix(field, "rua="); ok {
			for _, uri := range strings.Split(v, ",") { // 多 rua：取首个 mailto
				uri = strings.TrimSpace(uri)
				if addr, ok := strings.CutPrefix(uri, "mailto:"); ok && addr != "" {
					return addr, true
				}
			}
			return "", false // 仅 https 端点——邮件通道跳过（HTTPS POST 归部署域增强，登记）
		}
	}
	return "", false // 无 rua 字段：语法无效
}
