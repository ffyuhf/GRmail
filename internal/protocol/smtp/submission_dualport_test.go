// A（生产缺陷修复批，G2 批准 2026-10-17 02:30「批准，乙 C」）：双端口并行监听
// 回归锚——原顺序阻塞形态下 serveListener(":587") 的 Accept 循环永不返回，
// ":465" 分支为死代码（465 从未监听的生产根因：config 配 465 而 ss 零监听实证）。
package smtp

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestSubmissionDualPortListen 双端口均监听且 Shutdown 双关；TLS 未配置时 465
// 跳过而 587 正常（既有缺省形态保持）。
func TestSubmissionDualPortListen(t *testing.T) {
	// 形态一：TLSConfig 非 nil——465+587 双监听。
	srv := NewSubmissionServer(SubmissionConfig{
		Domain:    "t.io",
		TLSConfig: func() *tls.Config { return &tls.Config{} }, // 监听层不校验证书（握手归连接期——测试仅验证监听可达）
	}, &stubSubmitPipeline{}, &stubVerifier{})
	p465, p587 := pickFreePort(t), pickFreePort(t)
	if err := srv.ListenAndServe(":"+p465, ":"+p587); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	for _, p := range []string{p465, p587} {
		conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+p, time.Second)
		if derr != nil {
			t.Fatalf("端口 %s 未监听（A 修复失效——465 死代码回归）: %v", p, derr)
		}
		_ = conn.Close()
	}
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // 关停传播
	for _, p := range []string{p465, p587} {
		if conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+p, 200*time.Millisecond); derr == nil {
			_ = conn.Close()
			t.Fatalf("端口 %s 在 Shutdown 后仍监听", p)
		}
	}

	// 形态二：TLSConfig nil——465 跳过+587 正常（U5 计划书 1.5⑫ 既有语义保持）。
	// TLSConfig 注入返回 nil 的快照函数（证书未就绪的契约正确形态——字段零值
	// 属非法构造，生产恒经 NewSubmissionServer 后注入；首版测试零值构造触发
	// panic 的缺陷修正）。
	srv2 := NewSubmissionServer(SubmissionConfig{Domain: "t.io", TLSConfig: func() *tls.Config { return nil }}, &stubSubmitPipeline{}, &stubVerifier{})
	p587b := pickFreePort(t)
	if err := srv2.ListenAndServe(":0", ":"+p587b); err != nil { // TLS 未就绪——465 跳过
		t.Fatalf("ListenAndServe(无TLS): %v", err)
	}
	if conn, derr := net.DialTimeout("tcp", "127.0.0.1:"+p587b, time.Second); derr != nil {
		t.Fatalf("587 端口在无 TLS 形态下未监听: %v", derr)
	} else {
		_ = conn.Close()
	}
	if err := srv2.Shutdown(); err != nil {
		t.Fatalf("Shutdown(无TLS): %v", err)
	}
}

// pickFreePort 取一个空闲端口（避免固定端口冲突/并行测试竞态）。
func pickFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}
