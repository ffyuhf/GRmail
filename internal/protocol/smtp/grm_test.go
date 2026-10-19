// GRM高危处置批 GRM-003（DATA 超限停累积）/GRM-004（提交端点连接上限）smtp 层测试。
// 覆盖：readData 超限后停止累积（内存上界锚——滑窗终止检测保持协议同步+tooBig 终态）/
// 提交端点连接上限（MaxConns 快照——第 N+1 连接即时关闭）。
// 依据：GRM高危处置批计划书 v1.0.0 步骤 4/5（G2 批准 2026-10-19 07:06:11；GRM-004
// 附加指示「必须在后台管理设置里可设置」——MaxConns 快照注入形态承载）；
// rfc1870 §4（server discards the transferred message）/§6.3（may reject after DATA
// transfer）+§6 NOTE（SIZE 不用于判定内容结束——终止检测独立承载）；
// rfc5321bis §4.1.1.4（<CRLF>.<CRLF> 终止+全有全无应答）。
// 修改历史：
//
//	2026-10-19 09-55-00 | 新建 | GRM高危处置批（T1 红线：零既有断言触碰）
package smtp

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestGRM003ReadDataStopsAccumulating 超限后停止累积锚：MaxMessageSize=16，
// 写入 64 字节超限数据+终止序列——tooBig 终态返回（552 语义由调用方应答——cmdData 既有）
// 且不因持续数据累积（滑窗仅保留终止检测窗口；返回 nil 消息体——超限丢弃符合 rfc1870 §4）。
func TestGRM003ReadDataStopsAccumulating(t *testing.T) {
	client, srvConn := net.Pipe()
	defer func() { _ = client.Close() }()
	srv := &Server{cfg: ServerConfig{MaxMessageSize: func() int64 { return 16 }}}
	sess := &session{
		srv:  srv,
		conn: srvConn,
		r:    bufio.NewReader(srvConn),
		w:    bufio.NewWriter(srvConn),
	}
	payload := strings.Repeat("A", 64) // 64B > 16B 限额（跨超限标记点）
	terminator := "\r\n.\r\n"

	go func() {
		_, _ = client.Write([]byte(payload))
		_, _ = client.Write([]byte(terminator))
	}()

	done := make(chan struct{})
	var msg []byte
	var tooBig bool
	var err error
	go func() {
		msg, tooBig, err = sess.readData()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readData 超时——滑窗终止检测失效")
	}
	if err != nil {
		t.Fatalf("readData: %v", err)
	}
	if !tooBig {
		t.Fatal("超限数据应 tooBig=true（552 终态锚——终止序列后返回）")
	}
	if len(msg) != 0 {
		t.Fatalf("超限态应丢弃内容（nil 消息体——rfc1870 §4 discards），得 %d 字节", len(msg))
	}
}

// TestGRM004SubmissionConnLimit 提交端点连接上限锚：MaxConns=2——
// 前两连接收到 220 横幅（正常服务），第三连接被即时关闭（读错误——连接拒绝语义）。
func TestGRM004SubmissionConnLimit(t *testing.T) {
	srv := NewSubmissionServer(SubmissionConfig{
		Domain:         "test.example",
		MaxMessageSize: func() int64 { return 1024 },
		MaxConns:       func() int { return 2 },
	}, nil, nil)
	if err := srv.ListenAndServe("", "127.0.0.1:0"); err != nil {
		t.Fatalf("监听: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	srv.mu.Lock()
	addr := srv.lns[0].Addr().String()
	srv.mu.Unlock()

	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatalf("拨号: %v", err)
		}
		return c
	}
	// 前两连接：各收 220 横幅（正常服务锚）
	for i := 0; i < 2; i++ {
		c := dial()
		defer func() { _ = c.Close() }()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "220") {
			t.Fatalf("连接 %d 应收 220 横幅，得 %q err=%v", i+1, line, err)
		}
	}
	// 第三连接：Accept 即关（读得 EOF/错误——上限拒绝锚）
	third := dial()
	defer func() { _ = third.Close() }()
	third.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(third)
	if line, err := br.ReadString('\n'); err == nil && strings.HasPrefix(line, "220") {
		t.Fatalf("第三连接应被上限拒绝（不得收到 220），得 %q", line)
	}
}
