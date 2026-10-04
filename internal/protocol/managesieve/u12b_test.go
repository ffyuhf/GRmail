// managesieve loopback 集成测试（U12b——U12 修改文档登记项②收口，TC-011 判定②离线半场）。
// 矩阵（U12b 计划书 1.5⑤）：能力三项断言/STARTTLS 矩阵（升级+能力重推/454 无证书/
// 503 TLS 中重复）/AUTHENTICATE 双形态（initial-response+挑战两轮+`*` 取消+明文 NO——
// NFR-006）/PUTSCRIPT→LISTSCRIPTS→SETACTIVE→GETSCRIPT 回读一致/CHECKSCRIPT 语法拒绝/
// DELETESCRIPT 激活连带清/HAVESPACE 配额/字面量 {n+} 大脚本往返。
// 驱动形态：Server.Serve(net.Listener) 可测入口+TCP loopback+临时 SQLite 库+内存自签证书
// （NFR-015 全离线；沿 pop3/u7_test.go、web/u8_test.go、smtp/u10_starttls_test.go 先例）。
// 修改历史：
//
//	2026-09-23 12:56:00 | 新建 | U12b 装配收口（U12b 计划书 v1.0.0 步骤 3，G2 批准
//	2026-09-23 12:49:06；SRS FR-011 判定②/IR-004 rfc5804/NFR-015/NFR-006）
package managesieve

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/sieve"
	"GRmail/internal/storage"
)

// ───────────────────────── 测试基础设施（临时库+自签证书+可测服务端） ─────────────────────────

// u12bFixture 每用例独立夹具：临时 SQLite 库（迁移+active 邮箱）+注入齐备的服务端。
type u12bFixture struct {
	srv      *Server
	addr     string
	accounts *account.Service
	scripts  storage.SieveScriptRepo
	cleanup  func()
}

// newU12bFixture 构造夹具。参数 withTLS=true 时注入内存自签证书快照（STARTTLS 可用态），
// false 为无证书态（454 矩阵+部署缺陷显性化路径）。
func newU12bFixture(t *testing.T, withTLS bool) *u12bFixture {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(ctx, config.DatabaseConf{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "u12b.db")})
	if err != nil {
		t.Fatalf("打开临时库: %v", err)
	}
	if err := storage.MigrateUp(ctx, db, "sqlite"); err != nil {
		t.Fatalf("迁移: %v", err)
	}
	mailboxRepo := storage.NewMailboxRepoFor("sqlite", db)
	folderRepo := storage.NewFolderRepoFor("sqlite", db)
	accounts := account.NewService(mailboxRepo, folderRepo)
	if _, err := accounts.CreateMailbox(ctx, "alice@u12b.test", "s3cret-pass"); err != nil {
		t.Fatalf("创建 active 邮箱: %v", err)
	}
	scripts := storage.NewSieveScriptRepoFor("sqlite", db)

	cfg := ServerConfig{
		Accounts: accounts,
		Scripts:  scripts,
		Validate: func(src string) error { _, perr := sieve.Parse(src); return perr },
		Domain:   "u12b.test",
	}
	if withTLS {
		cert := u12bSelfSignedCert(t)
		cfg.TLSConfig = func() *tls.Config {
			return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
	}
	srv := NewServer(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback 监听: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	return &u12bFixture{
		srv: srv, addr: ln.Addr().String(), accounts: accounts, scripts: scripts,
		cleanup: func() { _ = ln.Close(); _ = db.Close() },
	}
}

// u12bSelfSignedCert 内存自签证书（loopback STARTTLS 测试态——InsecureSkipVerify 客户端；
// 沿 U10 smtp STARTTLS 测试先例）。
func u12bSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("自签证书: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ───────────────────────── 测试客户端（能力/应答/字面量基元） ─────────────────────────

// u12bClient loopback 测试客户端（明文形态；STARTTLS 后经 upgradeTLS 换装 TLS 流）。
type u12bClient struct {
	c  net.Conn
	br *bufio.Reader
	t  *testing.T
}

func u12bDial(t *testing.T, addr string) *u12bClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("连接 %s: %v", addr, err)
	}
	return &u12bClient{c: conn, br: bufio.NewReader(conn), t: t}
}

// send 写一行命令（追加 \r\n）。
func (u *u12bClient) send(line string) {
	u.t.Helper()
	if _, err := fmt.Fprintf(u.c, "%s\r\n", line); err != nil {
		u.t.Fatalf("发送 %q: %v", line, err)
	}
}

// sendRaw 写原始字节（字面量正文行——PUTSCRIPT {n+} 后的内容与行界）。
func (u *u12bClient) sendRaw(raw string) {
	u.t.Helper()
	if _, err := u.c.Write([]byte(raw)); err != nil {
		u.t.Fatalf("发送原始字节: %v", err)
	}
}

// readLine 读一行（去掉行界）。
func (u *u12bClient) readLine() string {
	u.t.Helper()
	line, err := u.br.ReadString('\n')
	if err != nil {
		u.t.Fatalf("读行失败: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// readUntilResult 读到 OK/NO/BYE 结果行为止，返回（中间行列表, 结果行）。
// 能力推送（连接即推/STARTTLS/AUTH 后）与 LISTSCRIPTS 多行均适用（VERSION 行在结果前）。
func (u *u12bClient) readUntilResult() ([]string, string) {
	u.t.Helper()
	var mid []string
	for {
		line := u.readLine()
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			return mid, line
		}
		mid = append(mid, line)
	}
}

// capsText 中间行合并文本（能力断言用）。
func capsText(mid []string) string { return strings.Join(mid, "\n") }

// expectOK 断言结果行为 OK。
func (u *u12bClient) expectOK(what string) {
	u.t.Helper()
	mid, res := u.readUntilResult()
	if !strings.HasPrefix(res, "OK") {
		u.t.Fatalf("%s 期望 OK 实得 %q（中间行 %q）", what, res, capsText(mid))
	}
}

// expectNO 断言结果行为 NO。
func (u *u12bClient) expectNO(what string) string {
	u.t.Helper()
	mid, res := u.readUntilResult()
	if !strings.HasPrefix(res, "NO") {
		u.t.Fatalf("%s 期望 NO 实得 %q（中间行 %q）", what, res, capsText(mid))
	}
	return res
}

// upgradeTLS STARTTLS 已获 OK 后换装 TLS 客户端流（InsecureSkipVerify 测试态）。
func (u *u12bClient) upgradeTLS() {
	u.t.Helper()
	tconn := tls.Client(u.c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tconn.Handshake(); err != nil {
		u.t.Fatalf("TLS 握手: %v", err)
	}
	u.c, u.br = tconn, bufio.NewReader(tconn)
}

// authPlain 认证（initial-response 形态；成功后能力重推含 OWNER+OK）。
func (u *u12bClient) authPlain(addr, pass string) []string {
	u.t.Helper()
	ir := base64Plain(addr, pass)
	u.send(fmt.Sprintf("AUTHENTICATE \"PLAIN\" %s", ir))
	mid, res := u.readUntilResult()
	if !strings.HasPrefix(res, "OK") {
		u.t.Fatalf("AUTHENTICATE PLAIN 期望 OK 实得 %q（中间行 %q）", res, capsText(mid))
	}
	return mid
}

// base64Plain rfc4616 三段式：authzid(空) NUL authcid NUL passwd。
func base64Plain(addr, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + addr + "\x00" + pass))
}

// putScriptWithLiteral PUTSCRIPT <name> {n+} 字面量两段式发送。
func (u *u12bClient) putScriptWithLiteral(name, content string) {
	u.t.Helper()
	u.send(fmt.Sprintf("PUTSCRIPT %s {%d+}", strconv.Quote(name), len(content)))
	u.sendRaw(content + "\r\n")
}

// getScriptBody GETSCRIPT 回读：{n+} 头行→n 字节正文→行界→OK 行；返回正文。
func (u *u12bClient) getScriptBody(name string) string {
	u.t.Helper()
	u.send("GETSCRIPT " + strconv.Quote(name))
	head := u.readLine()
	if !strings.HasPrefix(head, "{") || !strings.HasSuffix(head, "+}") {
		u.t.Fatalf("GETSCRIPT 期望 {n+} 字面量头实得 %q", head)
	}
	nStr := strings.TrimSuffix(strings.TrimPrefix(head, "{"), "+}")
	n, err := strconv.Atoi(nStr)
	if err != nil {
		u.t.Fatalf("字面量长度解析 %q: %v", head, err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(u.br, buf); err != nil {
		u.t.Fatalf("读字面量 %d 字节: %v", n, err)
	}
	u.expectOK("GETSCRIPT 完成") // 正文后的补位行界（content 无 \r\n 尾时服务端补写）作为空行被 readUntilResult 归入中间行
	return string(buf)
}

// ───────────────────────── 测试矩阵 ─────────────────────────

// TestU12bCapsBlock 能力块直读（连接即推/重推——以 VERSION "1.0" 行收尾的实现形态）。
// 覆盖：连接即推三 MUST（IMPLEMENTATION/SIEVE/VERSION）+MAXREDIRECTS+SASL iff 规则
// （TLS 就绪未升级=SASL 空）；升级成功（OK→握手→能力重推 SASL "PLAIN"）；TLS 中
// 重复 STARTTLS 拒绝（503 语义）。
func TestU12bCapsBlock(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()

	c := u12bDial(t, fx.addr)
	caps := readCapsBlock(c)
	for _, must := range []string{`"IMPLEMENTATION"`, `"SIEVE"`, `"VERSION" "1.0"`, `"MAXREDIRECTS" "5"`, `"STARTTLS"`, `"SASL" ""`} {
		if !strings.Contains(caps, must) {
			t.Fatalf("能力块缺 %s：\n%s", must, caps)
		}
	}

	// STARTTLS 升级：OK→握手→能力重推（SASL "PLAIN"+协议状态重置语义）
	c.send("STARTTLS")
	c.expectOK("STARTTLS 升级")
	c.upgradeTLS()
	caps2 := readCapsBlock(c)
	if !strings.Contains(caps2, `"SASL" "PLAIN"`) {
		t.Fatalf("升级后能力应含 SASL \"PLAIN\"：\n%s", caps2)
	}

	// TLS 中重复 STARTTLS 拒绝（503 语义）
	c.send("STARTTLS")
	if res := c.expectNO("TLS 中重复 STARTTLS"); !strings.Contains(res, "503") {
		t.Fatalf("重复 STARTTLS 应含 503 语义: %q", res)
	}
}

// TestU12bStartTLSUnavailable 无证书态：STARTTLS 拒绝（454 语义）+能力无 STARTTLS 通告
// +SASL 空（部署缺陷显性化——只读不可认证）。
func TestU12bStartTLSUnavailable(t *testing.T) {
	fx := newU12bFixture(t, false)
	defer fx.cleanup()

	c := u12bDial(t, fx.addr)
	caps := readCapsBlock(c)
	if strings.Contains(caps, `"STARTTLS"`) {
		t.Fatalf("无证书态不应通告 STARTTLS：\n%s", caps)
	}
	c.send("STARTTLS")
	if res := c.expectNO("无证书 STARTTLS"); !strings.Contains(res, "454") {
		t.Fatalf("无证书 STARTTLS 应含 454 语义: %q", res)
	}
	// 明文无 TLS 态认证仍拒绝（NFR-006 全端点口径）
	c.send(fmt.Sprintf("AUTHENTICATE \"PLAIN\" %s", base64Plain("alice@u12b.test", "s3cret-pass")))
	c.expectNO("无 TLS 态 AUTHENTICATE")
}

// readCapsBlock 读能力块（多行，以 "VERSION" 行收尾——实现形态；rfc5804 §1.7 顺序）。
func readCapsBlock(c *u12bClient) string {
	var b strings.Builder
	for {
		line := c.readLine()
		b.WriteString(line)
		b.WriteString("\n")
		if strings.HasPrefix(line, `"VERSION"`) {
			return b.String()
		}
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			c.t.Fatalf("能力块中不应出现结果行 %q（块文本 %q）", line, b.String())
		}
	}
}

// TestU12bAuthPlainForms AUTHENTICATE 双形态+取消+明文拒绝+错误凭据（§2+rfc4616+NFR-006）。
func TestU12bAuthPlainForms(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()

	// 明文连接（TLS 就绪未升级）：AUTHENTICATE 一律 NO（NFR-006）
	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send(fmt.Sprintf("AUTHENTICATE \"PLAIN\" %s", base64Plain("alice@u12b.test", "s3cret-pass")))
	c.expectNO("明文连接 AUTHENTICATE")

	// 升级后 initial-response 形态：成功+能力重推含 OWNER
	c.send("STARTTLS")
	c.expectOK("STARTTLS")
	c.upgradeTLS()
	readCapsBlock(c)
	authedCaps := strings.Join(c.authPlain("alice@u12b.test", "s3cret-pass"), "\n")
	if !strings.Contains(authedCaps, `"OWNER" "alice@u12b.test"`) {
		t.Fatalf("认证后能力应含 OWNER：\n%s", authedCaps)
	}

	// 已认证重复 AUTHENTICATE 拒绝
	c.send("AUTHENTICATE \"PLAIN\" " + base64Plain("alice@u12b.test", "s3cret-pass"))
	c.expectNO("已认证重复 AUTHENTICATE")

	// 新连接：挑战两轮形态（无 initial-response）
	c2 := u12bDial(t, fx.addr)
	readCapsBlock(c2)
	c2.send("STARTTLS")
	c2.expectOK("STARTTLS")
	c2.upgradeTLS()
	readCapsBlock(c2)
	c2.send("AUTHENTICATE \"PLAIN\"")
	challenge := c2.readLine() // 服务端挑战行（"" "请输入..."）
	if !strings.HasPrefix(challenge, `""`) {
		t.Fatalf("期望挑战行实得 %q", challenge)
	}
	c2.sendRaw(base64Plain("alice@u12b.test", "s3cret-pass") + "\r\n")
	mid, res := c2.readUntilResult()
	if !strings.HasPrefix(res, "OK") {
		t.Fatalf("挑战两轮认证期望 OK 实得 %q（中间行 %q）", res, capsText(mid))
	}

	// `*` 取消
	c3 := u12bDial(t, fx.addr)
	readCapsBlock(c3)
	c3.send("STARTTLS")
	c3.expectOK("STARTTLS")
	c3.upgradeTLS()
	readCapsBlock(c3)
	c3.send("AUTHENTICATE \"PLAIN\"")
	c3.readLine() // 挑战
	c3.send("*")
	c3.expectNO("`*` 取消")

	// 不支持机制+错误凭据（统一文本防枚举）
	c4 := u12bDial(t, fx.addr)
	readCapsBlock(c4)
	c4.send("STARTTLS")
	c4.expectOK("STARTTLS")
	c4.upgradeTLS()
	readCapsBlock(c4)
	c4.send(`AUTHENTICATE "LOGIN" x`)
	c4.expectNO("非 PLAIN 机制")
	c4.send("AUTHENTICATE \"PLAIN\" " + base64Plain("alice@u12b.test", "wrong-pass"))
	if res := c4.expectNO("错误凭据"); strings.Contains(res, "不存在") {
		t.Fatalf("错误凭据应统一文本防枚举: %q", res)
	}
}

// TestU12bScriptLifecycle 脚本全生命周期：CHECKSCRIPT 双态→PUTSCRIPT 双态→LISTSCRIPTS→
// SETACTIVE→GETSCRIPT 回读一致→HAVESPACE→DELETESCRIPT 激活连带清（TC-011 判定②主链）。
func TestU12bScriptLifecycle(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()

	ctx := context.Background()
	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send("STARTTLS")
	c.expectOK("STARTTLS")
	c.upgradeTLS()
	readCapsBlock(c)
	c.authPlain("alice@u12b.test", "s3cret-pass")

	// 未认证态脚本命令拒绝（新连接验证——会话级门卫）
	c0 := u12bDial(t, fx.addr)
	readCapsBlock(c0)
	c0.send("LISTSCRIPTS")
	c0.expectNO("未认证 LISTSCRIPTS")

	const goodScript = "require [\"fileinto\"];\nif header :contains \"Subject\" \"news\" {\n  fileinto \"Newsletter\";\n}\n"
	const badScript = "require [\"vacation\"];\n" // 未实现能力——编译期拒绝

	// CHECKSCRIPT：合法通过+非法拒绝（语法校验不落库）
	c.send(fmt.Sprintf("CHECKSCRIPT {%d+}", len(badScript)))
	c.sendRaw(badScript + "\r\n")
	if res := c.expectNO("CHECKSCRIPT 非法脚本"); !strings.Contains(res, "语法") {
		t.Fatalf("非法脚本应含语法语义: %q", res)
	}
	c.send(fmt.Sprintf("CHECKSCRIPT {%d+}", len(goodScript)))
	c.sendRaw(goodScript + "\r\n")
	c.expectOK("CHECKSCRIPT 合法脚本")

	// PUTSCRIPT：非法拒绝+合法保存
	c.putScriptWithLiteral("newsletter", badScript)
	c.expectNO("PUTSCRIPT 非法脚本")
	c.putScriptWithLiteral("newsletter", goodScript)
	c.expectOK("PUTSCRIPT 合法脚本")

	// LISTSCRIPTS：单脚本无 ACTIVE
	c.send("LISTSCRIPTS")
	mid, res := c.readUntilResult()
	if !strings.HasPrefix(res, "OK") || !strings.Contains(capsText(mid), `"newsletter"`) || strings.Contains(capsText(mid), "ACTIVE") {
		t.Fatalf("LISTSCRIPTS 期望 \"newsletter\" 无 ACTIVE：行=%q 结果=%q", capsText(mid), res)
	}

	// SETACTIVE→LISTSCRIPTS 带 ACTIVE→GETSCRIPT 回读字节一致
	c.send("SETACTIVE \"newsletter\"")
	c.expectOK("SETACTIVE")
	c.send("LISTSCRIPTS")
	mid, res = c.readUntilResult()
	if !strings.Contains(capsText(mid), `"newsletter" ACTIVE`) {
		t.Fatalf("LISTSCRIPTS 期望 ACTIVE 标：行=%q 结果=%q", capsText(mid), res)
	}
	if got := c.getScriptBody("newsletter"); got != goodScript {
		t.Fatalf("GETSCRIPT 回读不一致:\n得 %q\n期 %q", got, goodScript)
	}

	// 激活位直查（repo 侧锚——管道 GetActiveScript 同路径）
	active, err := fx.scripts.GetActiveScript(ctx, 1)
	if err != nil || active == nil || active.Name != "newsletter" {
		t.Fatalf("GetActiveScript 期望 newsletter 实得 (%v, %v)", active, err)
	}

	// HAVESPACE：配额内 OK+超单脚本上限 NO
	c.send("HAVESPACE \"any\" 1024")
	c.expectOK("HAVESPACE 配额内")
	c.send("HAVESPACE \"any\" 1048576")
	c.expectNO("HAVESPACE 超限")

	// DELETESCRIPT：激活脚本 NO (ACTIVE) 拒绝（F-M3——rfc5804 §2.10 L1379-1381
	// 「MUST NOT allow the client to delete an active script」；原连带清激活语义废止）
	c.send("DELETESCRIPT \"newsletter\"")
	c.expectNO("激活脚本拒绝删除")
	// 取消激活后删除放行（SETACTIVE "" → DELETESCRIPT OK——收尾语义完整覆盖）
	c.send("SETACTIVE \"\"")
	c.expectOK("SETACTIVE 取消激活")
	c.send("DELETESCRIPT \"newsletter\"")
	c.expectOK("DELETESCRIPT")
	if _, err := fx.scripts.GetActiveScript(ctx, 1); err != storage.ErrNoActiveScript {
		t.Fatalf("删除后应无激活: err=%v", err)
	}
	c.send("GETSCRIPT \"newsletter\"")
	c.expectNO("GETSCRIPT 已删脚本")
}

// TestU12bLargeLiteralRoundtrip 字面量 {n+} 大脚本往返（多行+中文注释+~3KB——
// §1.2 非同步字面量路径的字节级完整性）。
func TestU12bLargeLiteralRoundtrip(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()

	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send("STARTTLS")
	c.expectOK("STARTTLS")
	c.upgradeTLS()
	readCapsBlock(c)
	c.authPlain("alice@u12b.test", "s3cret-pass")

	var b strings.Builder
	b.WriteString("# 大脚本往返测试（中文注释行）\n")
	b.WriteString("require [\"fileinto\"];\n")
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&b, "if header :contains \"X-Loop\" \"kw-%03d\" { fileinto \"Box-%03d\"; stop; }\n", i, i)
	}
	b.WriteString("keep;\n")
	large := b.String()
	if len(large) < 2048 {
		t.Fatalf("大脚本应 ≥2048 字节实得 %d", len(large))
	}

	c.putScriptWithLiteral("large", large)
	c.expectOK("PUTSCRIPT 大脚本")
	if got := c.getScriptBody("large"); got != large {
		t.Fatalf("大脚本回读不一致：得 %d 字节期 %d 字节", len(got), len(large))
	}
}
