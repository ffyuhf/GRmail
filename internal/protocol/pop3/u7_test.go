// pop3 端到端单测（FR-007 判定锚点：下载/删除流程+明文连接拒绝认证；
// TC-006 POP 格/TC-001 POP 入口/TC-024 POP 格离线半场）。
// NFR-015：TCP loopback + 临时 SQLite 库 + 内存自签证书全离线（对齐 U5/U6 先例）。
// 覆盖裁决：Q1-A QUIT=HardDelete（重登不可见锚定）/Q2-A 仅 AUTH PLAIN（CAPA 无 USER tag）/
// Q3-A UIDL=uid+TOP 截断+PIPELINING/Q4-A 非 TLS 连接 AUTH 一律 -ERR。
// 修改历史：
//
//	2026-09-19 04:09:01 | 新建 | U7 POP3 自研（计划书 v1.0.0 步骤 5，G2 批准）
//	2026-09-29 12:20:00 | 修正 | RFC规范修正批次 G3 整改（审计项 10 补测试锚——计划书
//	  v1.0.0 G2 批准 2026-09-28 22:16:57+G3 审计 4.3 整改要求+整改批准 2026-09-29 12:18:52）：
//	  F-P1 收敛锚（POP3 size=CRLF 存储字节——rfc1939 §11）用例落本文件（import mail 构造收敛态）
package pop3

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// sha256Hex 测试本地 CAS 键（mail 域私有函数测试态复刻，沿 U6 先例）。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testEnv 端到端测试环境（服务端+仓储+凭据）。
type testEnv struct {
	server   *Server
	addr     string
	msgs     *storage.SQLiteMessageRepo
	blobs    storage.BlobStore
	mailbox  *storage.Mailbox
	accounts *account.Service
}

// newTestEnv 组装环境：临时库+账号（含五系统文件夹）+两封来信（第二封正文含
// "." 开头行——byte-stuffing 断言载体）+TLS 服务端。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u7.db")})
	if err != nil {
		t.Fatalf("打开测试库: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	accounts := account.NewService(storage.NewSQLiteMailboxRepo(db), storage.NewSQLiteFolderRepo(db))
	mailbox, err := accounts.CreateMailbox(ctx, "u@t.io", "pw123456")
	if err != nil {
		t.Fatalf("建账号: %v", err)
	}
	msgs := storage.NewSQLiteMessageRepo(db)
	blobs := storage.NewFileSystemBlobStore(filepath.Join(t.TempDir(), "blobs"))

	raw1 := []byte("From: boss@corp.io\r\nTo: u@t.io\r\nSubject: 季度报告\r\n" +
		"Message-ID: <u7-1@corp.io>\r\nDate: Thu, 18 Sep 2026 10:00:00 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n第一封正文\r\n第二行\r\n")
	storeInbound(t, ctx, msgs, blobs, mailbox.ID, raw1, "<u7-1@corp.io>", "季度报告")
	raw2 := []byte("From: dot@corp.io\r\nTo: u@t.io\r\nSubject: 点行测试\r\n" +
		"Message-ID: <u7-2@corp.io>\r\nDate: Thu, 18 Sep 2026 11:00:00 +0000\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n..被填充的点行\r\n.单点行\r\n")
	storeInbound(t, ctx, msgs, blobs, mailbox.ID, raw2, "<u7-2@corp.io>", "点行测试")

	srv := NewServer(ServerConfig{
		Domain:    "t.io",
		TLSConfig: func() *tls.Config { return selfSignedTLSConfig(t) },
	}, accounts, msgs, storage.NewSQLiteFolderRepo(db), blobs)
	go func() {
		if err := srv.ListenAndServeTLS("127.0.0.1:0"); err != nil {
			t.Logf("POP3 测试服务退出: %v", err)
		}
	}()
	waitServerReady(t, srv)
	return &testEnv{server: srv, addr: srv.Addr().String(), msgs: msgs, blobs: blobs, mailbox: mailbox, accounts: accounts}
}

// storeInbound 写一封来信（Blob 先写——数据模型 1.3 双写顺序）。
func storeInbound(t *testing.T, ctx context.Context, msgs *storage.SQLiteMessageRepo, blobs storage.BlobStore, mailboxID int64, raw []byte, msgID, subject string) {
	t.Helper()
	if err := blobs.Write(ctx, sha256Hex(raw), raw); err != nil {
		t.Fatalf("写 blob: %v", err)
	}
	if err := msgs.StoreInbound(ctx, &storage.InboundMeta{
		Message: storage.MessageMeta{
			MessageID: msgID, BlobKey: sha256Hex(raw), RawSize: int64(len(raw)),
			Subject: subject, FromAddr: "boss@corp.io", ToAddrs: `["u@t.io"]`,
			SentAt: time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		},
		Recipients: []storage.RecipientTarget{{MailboxID: mailboxID}},
	}); err != nil {
		t.Fatalf("收信 %s: %v", msgID, err)
	}
}

// waitServerReady 等待监听器就绪。
func waitServerReady(t *testing.T, srv *Server) {
	t.Helper()
	for i := 0; i < 50 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("测试服务未就绪")
	}
}

// pop3Client 测试客户端（协议文本交互——POP3 无项目内客户端库，自研协议手写驱动）。
type pop3Client struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	t    *testing.T
}

// dialPOP3 TLS 拨号并读 greeting（自签跳过校验——通道完整性由握手保证，沿 U6 先例）。
func dialPOP3(t *testing.T, addr string) *pop3Client {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS 拨号: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &pop3Client{conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn), t: t}
	c.readLine() // greeting（rfc1939 §4）
	return c
}

// dialPOP3Plain 明文拨号（Q4-A 明文拒绝判定驱动路径——经 Serve(明文 listener)；
// 注意：地址取明文 listener 自身——srv.Addr() 返回 listeners 末位（TLS 已占用））。
func dialPOP3Plain(t *testing.T, srv *Server) *pop3Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("明文监听: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("明文拨号: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &pop3Client{conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn), t: t}
	c.readLine()
	return c
}

// readLine 读单行应答（去 CRLF）。
func (c *pop3Client) readLine() string {
	c.t.Helper()
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("读应答: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// send 写命令（自动补 CRLF）。
func (c *pop3Client) send(cmd string) {
	c.t.Helper()
	if _, err := c.w.WriteString(cmd + "\r\n"); err != nil {
		c.t.Fatalf("写命令 %q: %v", cmd, err)
	}
	if err := c.w.Flush(); err != nil {
		c.t.Fatalf("刷新: %v", err)
	}
}

// cmd 发送命令并返回首行应答。
func (c *pop3Client) cmd(cmd string) string {
	c.t.Helper()
	c.send(cmd)
	return c.readLine()
}

// readMulti 收集多行响应体（至 "." 终止；返回原始行——含 byte-stuffing 形态）。
func (c *pop3Client) readMulti() []string {
	c.t.Helper()
	var lines []string
	for {
		line := c.readLine()
		if line == "." {
			return lines
		}
		lines = append(lines, line)
	}
}

// authPlain 认证（initial-response 形态）。返回首行应答。
func (c *pop3Client) authPlain(user, pass string) string {
	c.t.Helper()
	ir := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	return c.cmd("AUTH PLAIN " + ir)
}

// TestPOP3PlaintextAuthRejected 明文连接 AUTH 一律 -ERR（Q4-A 判定锚——
// FR-007 判定标准「非 TLS 连接提交凭据时收到拒绝应答」；生产仅 995 隐式 TLS，
// 本用例经明文 loopback 驱动会话层 TLS 判定）。
func TestPOP3PlaintextAuthRejected(t *testing.T) {
	env := newTestEnv(t)
	c := dialPOP3Plain(t, env.server)
	got := c.cmd("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00u@t.io\x00pw123456")))
	if !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("明文 AUTH 应拒绝（Q4-A）: %q", got)
	}
	quit := c.cmd("QUIT")
	if !strings.HasPrefix(quit, "+OK") {
		t.Fatalf("QUIT 应 +OK: %q", quit)
	}
}

// TestPOP3FullFlow TLS 全流程（下载/删除/UIDL/TOP/PIPELINING/RSET/QUIT 提交 HardDelete）。
func TestPOP3FullFlow(t *testing.T) {
	env := newTestEnv(t)
	c := dialPOP3(t, env.addr)

	// CAPA：Q3-A 全量+Q2-A 无 USER tag（rfc5034 §3 SASL 能力+rfc2449 §6.1/6.8/6.6）
	c.send("CAPA")
	if head := c.readLine(); !strings.HasPrefix(head, "+OK") {
		t.Fatalf("CAPA 应 +OK: %q", head)
	}
	var caps []string
	for _, line := range c.readMulti() {
		caps = append(caps, strings.Fields(line)[0])
	}
	joined := strings.Join(caps, " ")
	for _, want := range []string{"TOP", "UIDL", "PIPELINING", "SASL", "IMPLEMENTATION"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("CAPA 缺能力 %q: %v", want, caps)
		}
	}
	if strings.Contains(joined, "USER") {
		t.Fatalf("Q2-A：不应通告 USER 能力: %v", caps)
	}

	// AUTHORIZATION 态命令状态错误（rfc1939 §3）
	if got := c.cmd("STAT"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("AUTHORIZATION 态 STAT 应 -ERR: %q", got)
	}

	// 认证失败统一拒绝（防枚举——U2 口径）
	if got := c.authPlain("u@t.io", "wrong"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("错误密码应 -ERR: %q", got)
	}

	// 认证成功（initial-response）
	if got := c.authPlain("u@t.io", "pw123456"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("AUTH PLAIN 应 +OK: %q", got)
	}

	// 成功后再 AUTH（rfc5034 §4 MUST -ERR）
	if got := c.cmd("AUTH PLAIN dGVzdA=="); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("重复 AUTH 应 -ERR: %q", got)
	}

	// STAT：两封（drop listing "+OK nn mm"——rfc1939 §5）
	stat := c.cmd("STAT")
	if stat != "+OK 2 320" && !strings.HasPrefix(stat, "+OK 2 ") {
		t.Fatalf("STAT 期望两封: %q", stat)
	}

	// LIST 单条+全量
	if got := c.cmd("LIST 2"); !strings.HasPrefix(got, "+OK 2 ") {
		t.Fatalf("LIST 2 应 +OK: %q", got)
	}
	c.send("LIST")
	if head := c.readLine(); !strings.HasPrefix(head, "+OK") {
		t.Fatalf("LIST 应 +OK: %q", head)
	}
	if lines := c.readMulti(); len(lines) != 2 {
		t.Fatalf("LIST 应两行: %v", lines)
	}
	if got := c.cmd("LIST 9"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("LIST 9 应 -ERR: %q", got)
	}

	// RETR 1：字节对照（去 stuff 后与原文行一致）
	c.send("RETR 1")
	if head := c.readLine(); !strings.HasPrefix(head, "+OK") {
		t.Fatalf("RETR 1 应 +OK: %q", head)
	}
	body1 := c.readMulti()
	if len(body1) < 7 || body1[0] != "From: boss@corp.io" || body1[len(body1)-1] != "第二行" {
		t.Fatalf("RETR 1 内容不符: %v", body1)
	}

	// RETR 2：byte-stuffing 断言（"." 开头行填充为 ".."——rfc1939 §3）
	c.send("RETR 2")
	if head := c.readLine(); !strings.HasPrefix(head, "+OK") {
		t.Fatalf("RETR 2 应 +OK: %q", head)
	}
	body2 := c.readMulti()
	var stuffed bool
	for _, l := range body2 {
		if strings.HasPrefix(l, "..") {
			stuffed = true
			break
		}
	}
	if !stuffed {
		t.Fatalf("RETR 2 应含 byte-stuffed 点行: %v", body2)
	}

	// UIDL：值=uid（Q3-A；单调非零）
	c.send("UIDL")
	if head := c.readLine(); !strings.HasPrefix(head, "+OK") {
		t.Fatalf("UIDL 应 +OK: %q", head)
	}
	uidLines := c.readMulti()
	if len(uidLines) != 2 {
		t.Fatalf("UIDL 应两行: %v", uidLines)
	}
	fields := strings.Fields(uidLines[0])
	if len(fields) != 2 || fields[0] != "1" || fields[1] == "0" {
		t.Fatalf("UIDL 行格式应为 \"n uid\": %v", uidLines)
	}

	// TOP 1 0：仅头（rfc1939 §8——头+空行+零行体）
	c.send("TOP 1 0")
	if head := c.readLine(); !strings.HasPrefix(head, "+OK") {
		t.Fatalf("TOP 应 +OK: %q", head)
	}
	topLines := c.readMulti()
	var sawBlank bool
	for _, l := range topLines {
		if l == "" {
			sawBlank = true
		}
	}
	if !sawBlank || topLines[len(topLines)-1] != "" {
		t.Fatalf("TOP 0 行应止于头后空行: %v", topLines)
	}

	// PIPELINING：两条命令一次写出，逐条应答（rfc2449 §6.6）
	if _, err := c.w.WriteString("NOOP\r\nSTAT\r\n"); err != nil {
		t.Fatalf("批量写: %v", err)
	}
	if err := c.w.Flush(); err != nil {
		t.Fatalf("刷新: %v", err)
	}
	if got := c.readLine(); got != "+OK" {
		t.Fatalf("NOOP 应 +OK: %q", got)
	}
	if got := c.readLine(); !strings.HasPrefix(got, "+OK 2 ") {
		t.Fatalf("批量 STAT 应 +OK 2: %q", got)
	}

	// DELE 1 → 已删引用 -ERR（rfc1939 §5）
	if got := c.cmd("DELE 1"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("DELE 1 应 +OK: %q", got)
	}
	if got := c.cmd("RETR 1"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("已删引用应 -ERR: %q", got)
	}
	if got := c.cmd("DELE 1"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("重复 DELE 应 -ERR: %q", got)
	}

	// RSET 撤销（rfc1939 §5）
	if got := c.cmd("RSET"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("RSET 应 +OK: %q", got)
	}
	if got := c.cmd("STAT"); !strings.HasPrefix(got, "+OK 2 ") {
		t.Fatalf("RSET 后 STAT 应两封: %q", got)
	}

	// QUIT 提交：DELE 2 → QUIT → 重登仅剩一封（Q1-A HardDelete 锚定）
	if got := c.cmd("DELE 2"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("DELE 2 应 +OK: %q", got)
	}
	if got := c.cmd("QUIT"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("QUIT 应 +OK: %q", got)
	}

	c2 := dialPOP3(t, env.addr)
	if got := c2.authPlain("u@t.io", "pw123456"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("重登 AUTH 应 +OK: %q", got)
	}
	if got := c2.cmd("STAT"); !strings.HasPrefix(got, "+OK 1 ") {
		t.Fatalf("QUIT 提交后应仅一封（Q1-A）: %q", got)
	}
	_ = c2.cmd("QUIT")
}

// TestPOP3AuthChallenge AUTH PLAIN 挑战形态（无 initial-response——rfc5034 §4：
// '+ ' challenge 一轮；含 '*' 取消路径）。
func TestPOP3AuthChallenge(t *testing.T) {
	env := newTestEnv(t)
	c := dialPOP3(t, env.addr)

	// '*' 取消（rfc5034 §4）
	c.send("AUTH PLAIN")
	if got := c.readLine(); got != "+ " {
		t.Fatalf("challenge 应为 '+ ': %q", got)
	}
	if got := c.cmd("*"); !strings.HasPrefix(got, "-ERR") {
		t.Fatalf("取消应 -ERR: %q", got)
	}

	// 挑战完成认证
	c.send("AUTH PLAIN")
	if got := c.readLine(); got != "+ " {
		t.Fatalf("challenge 应为 '+ ': %q", got)
	}
	ir := base64.StdEncoding.EncodeToString([]byte("\x00u@t.io\x00pw123456"))
	if got := c.cmd(ir); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("挑战完成应 +OK: %q", got)
	}
	_ = c.cmd("QUIT")
}

// TestPOP3QuitInAuthorizationState AUTHORIZATION 态 QUIT 不进 UPDATE 不删除
// （rfc1939 §6——未认证断开场景删除保护）。
func TestPOP3QuitInAuthorizationState(t *testing.T) {
	env := newTestEnv(t)
	c := dialPOP3(t, env.addr)
	if got := c.cmd("QUIT"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("QUIT 应 +OK: %q", got)
	}
	c2 := dialPOP3(t, env.addr)
	if got := c2.authPlain("u@t.io", "pw123456"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("重登应 +OK: %q", got)
	}
	if got := c2.cmd("STAT"); !strings.HasPrefix(got, "+OK 2 ") {
		t.Fatalf("未认证 QUIT 不应删除: %q", got)
	}
	_ = c2.cmd("QUIT")
}

// TestU7POP3SizeConvergence F-P1（RFC规范修正 RF-A）：POP3 size 口径与 CRLF 存储
// 字节收敛锚——mail.BuildOutgoingMail 构造 LF 正文邮件（F-L1 收敛后即提交路径
// 存储态）→ StoreInbound（RawSize=len(raw)——submit.go 同口径）→ LIST 应答 size
// 与 CRLF 字节数一致（rfc1939 §11 L1056-1058 octet 计数=存储字节；session.go
// size=RawSize）。
// SRS：FR-007（3.3.2）/FR-005（3.2）；TC：TC-006/TC-005。G3 整改锚③（审计项 10）。
func TestU7POP3SizeConvergence(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	// LF 正文经构造层 CRLF 收敛（F-L1）——产物即提交路径存储态（RawSize=len 口径源）
	raw, err := mail.BuildOutgoingMail("boss@corp.io", "u@t.io", "", "size收敛", "LF正文行一\n行二\n", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if !strings.Contains(string(raw), "LF正文行一\r\n行二\r\n") {
		t.Fatalf("构造产物非 CRLF 收敛态（F-L1/F-P1 前置）:\n%q", raw)
	}
	// 第三封（newTestEnv 预置两封后追加）——RawSize=len(raw)（CRLF 字节）
	storeInbound(t, ctx, env.msgs, env.blobs, env.mailbox.ID, raw, "<u7-rf-p1@corp.io>", "size收敛")

	c := dialPOP3(t, env.addr)
	if got := c.authPlain("u@t.io", "pw123456"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("AUTH 应 +OK: %q", got)
	}
	want := fmt.Sprintf("+OK 3 %d", len(raw))
	if got := c.cmd("LIST 3"); got != want {
		t.Fatalf("LIST 3 size 应收敛为 CRLF 存储字节（F-P1）: 得 %q 期 %q", got, want)
	}
	if got := c.cmd("QUIT"); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("QUIT 应 +OK: %q", got)
	}
}

// selfSignedTLSConfig 内存自签证书（ECDSA P-256——沿 U6 先例；TLS1.2 下限=NFR-006）。
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "t.io"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"t.io"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // rfc8314 §4：MUST TLS1.2+
	}
}

// 编译期防未用导入（fmt 保留给断言扩展）。
var _ = fmt.Sprintf
