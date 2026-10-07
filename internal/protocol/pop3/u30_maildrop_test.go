// pop3 maildrop 独占锁单测（访问协议资源限制批 u30——F4/A-13④）：
// 锁表三态语义（获取/互斥/释放幂等）+ 会话生命周期释放 + 双连接端到端互斥
// （第二连接同邮箱认证 -ERR unable to lock maildrop——rfc1939 §4 L213-234；
// 首连接 QUIT 释放后可再锁）。
// 修改历史：
//
//	2026-10-07 14:12:00 | 新建 | 访问协议资源限制批（计划书 v1.0.0 步骤 4，
//	G2 批准 2026-10-07 14:00:02）
package pop3

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
)

// TestMaildropLocksTable F4 锁表三态：获取/互斥/释放后可再获取/释放幂等。
func TestMaildropLocksTable(t *testing.T) {
	l := newMaildropLocks()
	if !l.tryLock(1) {
		t.Fatal("首次获取应成功")
	}
	if l.tryLock(1) {
		t.Fatal("同邮箱二次获取应被拒（独占）")
	}
	if !l.tryLock(2) {
		t.Fatal("不同邮箱获取应成功（互不阻塞）")
	}
	l.unlock(1)
	if !l.tryLock(1) {
		t.Fatal("释放后应可再获取")
	}
	l.unlock(1)
	l.unlock(1)  // 幂等
	l.unlock(99) // 未持有释放幂等
}

// TestSessionReleaseMaildropIdempotent F4：会话释放路径幂等。
func TestSessionReleaseMaildropIdempotent(t *testing.T) {
	srv := NewServer(ServerConfig{}, nil, nil, nil, nil)
	ss := &session{server: srv}
	ss.lockedMailbox = 7
	if !srv.locks.tryLock(7) {
		t.Fatal("预置失败")
	}
	ss.releaseMaildrop()
	if ss.lockedMailbox != 0 {
		t.Fatal("释放后应清零")
	}
	if !srv.locks.tryLock(7) {
		t.Fatal("释放后锁表应可再获取")
	}
	srv.locks.unlock(7)
	ss.releaseMaildrop() // 二次释放（lockedMailbox=0）——零副作用
}

// u30Dial 建立测试 TLS 连接（复用 u7 自签证书配置——InsecureSkipVerify 客户端）。
func u30Dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS 连接: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	r := bufio.NewReader(conn)
	greet, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(greet, "+OK") {
		t.Fatalf("greeting 异常: %q err=%v", greet, err)
	}
	return conn, r
}

// u30Auth 发送 AUTH PLAIN 并读取应答。
func u30Auth(t *testing.T, conn net.Conn, r *bufio.Reader, user, pass string) string {
	t.Helper()
	cred := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	if _, err := fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", cred); err != nil {
		t.Fatalf("发送 AUTH: %v", err)
	}
	resp, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("读 AUTH 应答: %v", err)
	}
	return strings.TrimRight(resp, "\r\n")
}

// TestMaildropExclusiveSessions F4 端到端主锚：双连接同邮箱认证互斥。
func TestMaildropExclusiveSessions(t *testing.T) {
	env := newTestEnv(t)

	c1, r1 := u30Dial(t, env.addr)
	if resp := u30Auth(t, c1, r1, "u@t.io", "pw123456"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("首连接认证应成功: %q", resp)
	}
	c2, r2 := u30Dial(t, env.addr)
	resp := u30Auth(t, c2, r2, "u@t.io", "pw123456")
	if !strings.Contains(resp, "unable to lock maildrop") {
		t.Fatalf("第二连接同邮箱认证应被锁拒绝（rfc1939 §4），得 %q", resp)
	}
	// 首连接 QUIT 释放锁
	if _, err := fmt.Fprintf(c1, "QUIT\r\n"); err != nil {
		t.Fatalf("发送 QUIT: %v", err)
	}
	if _, err := r1.ReadString('\n'); err != nil {
		t.Fatalf("读 QUIT 应答: %v", err)
	}
	_ = c1.Close()
	// 第二连接（保持打开）重新认证——锁已释放应成功
	if resp := u30Auth(t, c2, r2, "u@t.io", "pw123456"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("锁释放后再认证应成功: %q", resp)
	}
}
