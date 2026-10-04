// web 包 U13 mta-sts 端点单测（NFR-015：httptest 全离线——engine 直驱零库依赖）。
// 依据：U13 计划书 v1.0.0 步骤 4 检查点（G2 批准 2026-09-23 08:19:32）——
// Host 判定/开关停发（FR-010 判定③=TC-010 判定④锚）/策略文本呈现/Content-Type。
// 修改历史：
//
//	2026-09-23 09:15:00 | 新建 | U13 传输安全全量（计划书步骤 4 检查点）
package web

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newSTSVarServer 构造带 MTA-STS 供给的最小 server（公开端点路由经 engine 直驱——
// 匿名 GET 无会话查询，repos nil 安全）。
// 参数：t 测试；domain 主域；enabled 发布开关。返回：httptest 服务。
func newSTSVarServer(t *testing.T, domain string, enabled bool) *httptest.Server {
	t.Helper()
	srv := NewServer(ServerConfig{
		Domain:    domain,
		TLSConfig: func() *tls.Config { return nil },
		STSPolicy: func() (string, bool) {
			return "version: STSv1\r\nmode: enforce\r\nmx: " + domain + "\r\nmax_age: 604800", enabled
		},
	}, nil, nil, nil, nil)
	ts := httptest.NewServer(srv.engine)
	t.Cleanup(ts.Close)
	return ts
}

// stsGet 带 Host 头的 GET（策略端点请求形态——Host 判定输入）。
func stsGet(t *testing.T, ts *httptest.Server, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	return resp
}

// TestU13MTAStsEndpointServeAndStop 发布端点三态：Host 命中 200+文本/Host 不符 404/
// 开关关闭 404（rfc8461 §3.2/§3.3——Q2-A 路由级承载判定③锚）。
func TestU13MTAStsEndpointServeAndStop(t *testing.T) {
	// 1. Host 命中+开关开：200+text/plain+策略正文
	ts := newSTSVarServer(t, "x.io", true)
	resp := stsGet(t, ts, "mta-sts.x.io")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Host 命中应 200，得 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type 应 text/plain，得 %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "version: STSv1") || !strings.Contains(string(body), "mx: x.io") {
		t.Fatalf("策略正文不符: %q", body)
	}

	// 2. Host 不匹配（跨 Host 误答防线）：404
	resp2 := stsGet(t, ts, "evil.example")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("Host 不匹配应 404，得 %d", resp2.StatusCode)
	}

	// 3. 开关关闭：404 停发（FR-010 判定③——TC-010 判定④锚）
	tsOff := newSTSVarServer(t, "x.io", false)
	resp3 := stsGet(t, tsOff, "mta-sts.x.io")
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("开关关闭应 404 停发，得 %d", resp3.StatusCode)
	}
}

// TestU13STSHostMatch Host 判定辅助（端口后缀容忍+大小写）。
func TestU13STSHostMatch(t *testing.T) {
	if !stsHostMatch("mta-sts.x.io:443", "x.io") {
		t.Fatal("带端口 Host 应命中")
	}
	if !stsHostMatch("MTA-STS.X.IO", "x.io") {
		t.Fatal("大小写不敏感应命中")
	}
	if stsHostMatch("x.io", "x.io") || stsHostMatch("a.mta-sts.x.io", "x.io") {
		t.Fatal("非 Policy Host 精确形态不应命中")
	}
}
