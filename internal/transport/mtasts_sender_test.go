// transport 域传输安全与日志增强批次定向测试（L-A 发送侧 MTA-STS 验证+L-B TLS-RPT
// 聚合与报告构造——NFR-015 纯函数/stub 注入全离线驱动；rfc8461 §3/§4/§5 与
// rfc8460 §3/§4/§5 原文锚定断言）。
// 依据：传输安全与日志增强计划书 v1.0.0 步骤 2/3 检查点（G2 批准 2026-10-01 22:54:41）。
// 修改历史：
//
//	2026-10-01 23:34:00 | 新建 | 传输安全与日志增强批次（计划书步骤 2/3 定向锚）
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// ───────────────────────── L-A：策略解析与 MX 匹配（纯函数） ─────────────────────────

// TestParseSTSPolicyValid 合法策略全字段解析（§3.2：version/mode/max_age 恰一次+mx 多行）。
func TestParseSTSPolicyValid(t *testing.T) {
	body := "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n"
	p, err := ParseSTSPolicy(body)
	if err != nil {
		t.Fatalf("合法策略应解析: %v", err)
	}
	if p.Mode != "enforce" || p.MaxAge != 604800*time.Second || len(p.MXPatterns) != 2 {
		t.Fatalf("字段不符: %+v", p)
	}
	if len(p.RawLines) != 5 {
		t.Fatalf("原始行数不符（报告 policy-string 载体）: %d", len(p.RawLines))
	}
}

// TestParseSTSPolicyInvalid 非法形态拒绝集：缺必填/version 非 STSv1/mode 非法/非 none 无 mx/重复字段取首个。
func TestParseSTSPolicyInvalid(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"缺 version", "mode: enforce\r\nmx: a.b\r\nmax_age: 1\r\n"},
		{"version 非 STSv1", "version: STSv2\r\nmode: enforce\r\nmx: a.b\r\nmax_age: 1\r\n"},
		{"mode 非法", "version: STSv1\r\nmode: strict\r\nmx: a.b\r\nmax_age: 1\r\n"},
		{"max_age 越界", "version: STSv1\r\nmode: enforce\r\nmx: a.b\r\nmax_age: 99999999\r\n"},
		{"非 none 无 mx", "version: STSv1\r\nmode: enforce\r\nmax_age: 1\r\n"},
		{"行缺冒号", "version STSv1\r\n"},
	}
	for _, c := range cases {
		if _, err := ParseSTSPolicy(c.body); err == nil {
			t.Errorf("%s 应拒绝", c.name)
		}
	}
	// mode=none 无 mx 合法（§3.2 required at least once except when mode is none）
	if p, err := ParseSTSPolicy("version: STSv1\r\nmode: none\r\nmax_age: 1\r\n"); err != nil || p.Mode != "none" {
		t.Errorf("none 无 mx 应合法: %v %+v", err, p)
	}
	// 重复非重复字段取首个（§3.2 Parsers MUST ... all entries except for the first SHALL be ignored）
	p, err := ParseSTSPolicy("version: STSv1\r\nmode: enforce\r\nmode: testing\r\nmx: a.b\r\nmax_age: 1\r\nmax_age: 2\r\n")
	if err != nil || p.Mode != "enforce" || p.MaxAge != time.Second {
		t.Fatalf("重复字段应取首个: %v %+v", err, p)
	}
}

// TestMXHostMatches §4.1 通配语义：* 仅匹配整个最左标签。
func TestMXHostMatches(t *testing.T) {
	pats := []string{"mail.example.com", "*.example.net"}
	cases := []struct {
		host string
		want bool
	}{
		{"mail.example.com", true},     // 精确全名
		{"MAIL.EXAMPLE.COM", true},     // 大小写不敏感
		{"other.example.com", false},   // 非精确
		{"mail.example.net", true},     // *.example.net 匹配最左单标签
		{"example.net", false},         // 通配不匹配裸后缀
		{"foo.bar.example.net", false}, // 通配不跨标签（§4.1 明示反例）
		{"mail.example.net.", true},    // 尾点容忍
	}
	for _, c := range cases {
		if got := MXHostMatches(c.host, pats); got != c.want {
			t.Errorf("MXHostMatches(%q)=%v want %v", c.host, got, c.want)
		}
	}
}

// TestDiscoverSTSRecordID §3.1 记录筛选：非 v=STSv1 丢弃/恰一有效/id 提取。
func TestDiscoverSTSRecordID(t *testing.T) {
	if id, ok := discoverSTSRecordID([]string{"v=STSv1; id=20160831;"}); !ok || id != "20160831" {
		t.Fatalf("单有效记录应提取 id: %q %v", id, ok)
	}
	if _, ok := discoverSTSRecordID([]string{"v=STSv1; id=a;", "v=STSv1; id=b;"}); ok {
		t.Error("两条有效记录应判无（结果数≠1）")
	}
	if _, ok := discoverSTSRecordID([]string{"v=spf1 -all"}); ok {
		t.Error("非 v=STSv1 记录应丢弃后判无")
	}
	if _, ok := discoverSTSRecordID([]string{"v=STSv1;"}); ok {
		t.Error("v=STSv1 无 id 语法无效应判无")
	}
}

// ───────────────────────── L-A：验证器全链（stub 注入） ─────────────────────────

// stubSTSTXT 内存 TXT 解析 stub。
type stubSTSTXT struct {
	txts    map[string][]string
	calls   int
	failAll bool
}

func (s *stubSTSTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	s.calls++
	if s.failAll {
		return nil, io.ErrClosedPipe
	}
	return s.txts[name], nil
}

// stubSTSFetch 内存策略抓取 stub（成功正文/失败开关）。
type stubSTSFetch struct {
	body  string
	fail  bool
	calls int
}

func (s *stubSTSFetch) Fetch(_ context.Context, _ string) (string, error) {
	s.calls++
	if s.fail {
		return "", io.ErrUnexpectedEOF
	}
	return s.body, nil
}

const testSTSPolicyBody = "version: STSv1\r\nmode: enforce\r\nmx: mx1.ext.io\r\nmax_age: 3600\r\n"

// newSTSTestSvc 测试三件套装配（固定起点时钟）。
func newSTSTestSvc(txt *stubSTSTXT, fetch *stubSTSFetch) *STSSenderService {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return newSTSSenderServiceForTest(txt, fetch, func() time.Time { return now })
}

// TestSTSSenderCheckEnforceMismatch enforce 且 MX 不匹配：MXMatched=false（调用方拒投递）。
func TestSTSSenderCheckEnforceMismatch(t *testing.T) {
	txt := &stubSTSTXT{txts: map[string][]string{"_mta-sts.ext.io": {"v=STSv1; id=1;"}}}
	fetch := &stubSTSFetch{body: testSTSPolicyBody}
	svc := newSTSTestSvc(txt, fetch)
	dec, err := svc.Check(context.Background(), "ext.io", "evil.other.io")
	if err != nil || dec.Mode != "enforce" || dec.MXMatched {
		t.Fatalf("enforce 不匹配判定失败: %+v %v", dec, err)
	}
}

// TestSTSSenderCheckEnforceMatch enforce 且 MX 匹配：放行（MXMatched=true）。
func TestSTSSenderCheckEnforceMatch(t *testing.T) {
	txt := &stubSTSTXT{txts: map[string][]string{"_mta-sts.ext.io": {"v=STSv1; id=1;"}}}
	fetch := &stubSTSFetch{body: testSTSPolicyBody}
	svc := newSTSTestSvc(txt, fetch)
	dec, err := svc.Check(context.Background(), "ext.io", "mx1.ext.io")
	if err != nil || !dec.MXMatched {
		t.Fatalf("enforce 匹配应放行: %+v %v", dec, err)
	}
}

// TestSTSSenderNoPolicy 无 TXT：无策略放行（Mode 空串）。
func TestSTSSenderNoPolicy(t *testing.T) {
	svc := newSTSTestSvc(&stubSTSTXT{txts: map[string][]string{}}, &stubSTSFetch{body: testSTSPolicyBody})
	dec, err := svc.Check(context.Background(), "ext.io", "mx1.ext.io")
	if err != nil || dec.Mode != "" || !dec.MXMatched {
		t.Fatalf("无策略应放行: %+v %v", dec, err)
	}
}

// TestSTSSenderCacheHit 缓存命中不重复抓取（§5.1 max_age 内直用）。
func TestSTSSenderCacheHit(t *testing.T) {
	txt := &stubSTSTXT{txts: map[string][]string{"_mta-sts.ext.io": {"v=STSv1; id=1;"}}}
	fetch := &stubSTSFetch{body: testSTSPolicyBody}
	svc := newSTSTestSvc(txt, fetch)
	for i := 0; i < 3; i++ {
		if _, err := svc.Check(context.Background(), "ext.io", "mx1.ext.io"); err != nil {
			t.Fatalf("第 %d 次判定失败: %v", i, err)
		}
	}
	if fetch.calls != 1 {
		t.Fatalf("缓存命中应仅抓取一次: %d", fetch.calls)
	}
}

// TestSTSSenderFetchFailFallback HTTPS 失败回退缓存（§3.3：有缓存应用缓存）。
func TestSTSSenderFetchFailFallback(t *testing.T) {
	txt := &stubSTSTXT{txts: map[string][]string{"_mta-sts.ext.io": {"v=STSv1; id=1;"}}}
	fetch := &stubSTSFetch{body: testSTSPolicyBody}
	svc := newSTSTestSvc(txt, fetch)
	if _, err := svc.Check(context.Background(), "ext.io", "mx1.ext.io"); err != nil {
		t.Fatal(err)
	}
	fetch.fail = true  // 首取后转失败
	txt.failAll = true // TXT 也失败——限速期内回退缓存路径
	dec, err := svc.Check(context.Background(), "ext.io", "evil.x.io")
	if err != nil || dec.Mode != "enforce" {
		t.Fatalf("抓取失败应回退缓存（enforce 仍生效）: %+v %v", dec, err)
	}
}

// ───────────────────────── L-B：聚合与报告构造（纯函数+内存聚合） ─────────────────────────

// TestTLSRPTAggregatorRecordAndSnapshot 聚合→快照→清零往返。
func TestTLSRPTAggregatorRecordAndSnapshot(t *testing.T) {
	agg := NewTLSRPTAggregator()
	agg.Record("Ext.IO", "mx1.ext.io", TLSRPTSuccess)
	agg.Record("ext.io", "mx1.ext.io", TLSRPTSuccess)
	agg.Record("ext.io", "mx2.ext.io", TLSRPTStarttlsNotSupported)
	agg.Record("ext.io", "mx2.ext.io", TLSRPTStarttlsNotSupported)
	snap := agg.SnapshotAndReset()
	st, ok := snap["ext.io"]
	if !ok || st.Success != 2 {
		t.Fatalf("成功计数（含域名小写归一）: %+v", st)
	}
	if st.Failures[tlsrptFailureKey{ResultType: TLSRPTStarttlsNotSupported, MXHost: "mx2.ext.io"}] != 2 {
		t.Fatalf("失败聚合计数不符: %+v", st.Failures)
	}
	if again := agg.SnapshotAndReset(); len(again) != 0 {
		t.Fatalf("读出后应清零: %+v", again)
	}
}

// TestBuildTLSRPTReport JSON 结构字段级断言（§4.4：policies 恒数组+计数+failure-details 展开）。
func TestBuildTLSRPTReport(t *testing.T) {
	stats := TLSRPTDomainStats{
		Success: 10,
		Failures: map[tlsrptFailureKey]int64{
			{ResultType: TLSRPTCertificateNotTrusted, MXHost: "mx2.ext.io"}: 3,
		},
	}
	data := BuildTLSRPTReport(TLSRPTReportInput{
		OrganizationName: "t.io", ContactEmail: "tlsrpt@t.io", ReportID: "rid-1",
		WindowStart:  time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:    time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
		PolicyDomain: "ext.io", PolicyType: "no-policy-found", Stats: stats,
	})
	s := string(data)
	for _, want := range []string{
		`"organization-name": "t.io"`,
		`"start-datetime": "2026-10-01T00:00:00Z"`,
		`"end-datetime": "2026-10-02T00:00:00Z"`,
		`"contact-info": "tlsrpt@t.io"`,
		`"report-id": "rid-1"`,
		`"policy-type": "no-policy-found"`,
		`"policy-domain": "ext.io"`,
		`"total-successful-session-count": 10`,
		`"total-failure-session-count": 3`,
		`"result-type": "certificate-not-trusted"`,
		`"receiving-mx-hostname": "mx2.ext.io"`,
		`"failed-session-count": 3`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON 缺字段 %s", want)
		}
	}
}

// TestDiscoverTLSRPTRua rua 发现：mailto 提取/多 URI 取 mailto/纯 https 跳过/多记录判无。
func TestDiscoverTLSRPTRua(t *testing.T) {
	if addr, ok := DiscoverTLSRPTRua([]string{"v=TLSRPTv1; rua=mailto:reports@example.com"}); !ok || addr != "reports@example.com" {
		t.Fatalf("mailto 提取失败: %q %v", addr, ok)
	}
	if addr, ok := DiscoverTLSRPTRua([]string{"v=TLSRPTv1; rua=https://r.example/x, mailto:r2@example.com"}); !ok || addr != "r2@example.com" {
		t.Fatalf("多 rua 应取首个 mailto: %q %v", addr, ok)
	}
	if _, ok := DiscoverTLSRPTRua([]string{"v=TLSRPTv1; rua=https://r.example/x"}); ok {
		t.Error("纯 https 应判无邮件通道")
	}
	if _, ok := DiscoverTLSRPTRua([]string{"v=TLSRPTv1; rua=mailto:a@x", "v=TLSRPTv1; rua=mailto:b@x"}); ok {
		t.Error("多记录应判不实现 TLSRPT")
	}
}

// TestTLSRPTReportFilename §5.1 ABNF 形态断言。
func TestTLSRPTReportFilename(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	name := TLSRPTReportFilename("mail.t.io", "ext.io", start, end, "abc12345")
	want := "mail.t.io!ext.io!1790812800!1790899200!abc12345.json.gz" // 2026-10-01/02 00:00 UTC Unix 秒
	if name != want {
		t.Fatalf("文件名不符: %q want %q", name, want)
	}
}

// TestBuildTLSRPTReportEmail 邮件形态断言（§5.3：两新头+Subject+multipart/report+tlsrpt+gzip 附件）。
func TestBuildTLSRPTReportEmail(t *testing.T) {
	gzPayload := gzipBytes(t, []byte(`{"report-id":"r"}`))
	email := string(BuildTLSRPTReportEmail("t.io", "ext.io", "rpt@ext.io", "t.io!ext.io!1!2!u.json.gz", "rid-9", gzPayload))
	for _, want := range []string{
		"From: tlsrpt@t.io",
		"To: rpt@ext.io",
		"Subject: Report Domain: ext.io Submitter: t.io Report-ID: <rid-9>",
		"TLS-Report-Domain: ext.io",
		"TLS-Report-Submitter: t.io",
		`Content-Type: multipart/report; report-type="tlsrpt"`,
		"Content-Type: text/plain",
		"Content-Type: application/tlsrpt+gzip",
		`filename="t.io!ext.io!1!2!u.json.gz"`,
	} {
		if !strings.Contains(email, want) {
			t.Errorf("报告邮件缺形态 %s", want)
		}
	}
	if !strings.Contains(email, base64Wrap(gzPayload)) {
		t.Error("附件 base64 折行体缺失")
	}
}

// TestBase64Wrap 76 列折行与标准库一致性。
func TestBase64Wrap(t *testing.T) {
	data := bytes.Repeat([]byte("GRmail-TLSRPT"), 60) // >76 编码列
	wrapped := base64Wrap(data)
	for _, line := range strings.Split(strings.TrimRight(wrapped, "\r\n"), "\r\n") {
		if len(line) > 76 {
			t.Fatalf("折行超 76 列: %d", len(line))
		}
	}
}

// gzipBytes 测试辅助：gzip 压缩。
func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
