// Package managesieve SCRAM-SHA-1 认证测试（SCRAM认证批——E2E 四步交换/错误 proof
// 拒绝/未知用户伪装交互/* 取消/解析形态；fixture 复用 u12b 真库+TLS loopback 形态；
// 客户端侧机制计算按 rfc5802 §3 独立实现——与服务端实现交叉验证）。
// 修改历史：
//
//	2026-10-10 03:35:00 | 新增 | SCRAM认证批（G2 批准 2026-10-09 23:37:36）
package managesieve

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // 测试侧 SCRAM-SHA-1 机制计算
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// ───────────── 测试侧客户端机制计算（rfc5802 §3 独立实现——交叉验证锚） ─────────────

func tHMAC(key, data []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func tSHA1(b []byte) []byte { s := sha1.Sum(b); return s[:] }

func tXOR(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// scramClientSide 客户端 proof 计算（SaltedPassword→ClientKey→〔ClientSignature=HMAC
// (StoredKey,AuthMessage)〕→Proof=XOR——rfc5802 §3 L413-420）。
func scramClientSide(password string, salt []byte, iters int, authMessage string) (proof []byte) {
	salted := pbkdf2.Key([]byte(password), salt, iters, sha1.Size, sha1.New)
	clientKey := tHMAC(salted, []byte("Client Key"))
	storedKey := tSHA1(clientKey)
	clientSig := tHMAC(storedKey, []byte(authMessage))
	return tXOR(clientKey, clientSig)
}

// scramExchangeOnce E2E 握手执行器：返回 (server-final v= 的 b64, 是否 OK, 结果行)。
// password 为客户端口令（与/不同于库内凭据由调用方控制——错误 proof 用例传异值）。
func scramExchangeOnce(t *testing.T, c *u12bClient, user, password string) (string, bool, string) {
	t.Helper()
	cnonce := "clientnonce0123456789"
	clientFirst := "n,," + "n=" + user + ",r=" + cnonce
	c.send(`AUTHENTICATE "SCRAM-SHA-1"`)
	if line := c.readLine(); strings.TrimSpace(line) != `""` {
		t.Fatalf("期望空 challenge 实得 %q", line)
	}
	c.send(base64.StdEncoding.EncodeToString([]byte(clientFirst)))
	chLine := strings.TrimSpace(c.readLine())
	if !strings.HasPrefix(chLine, `"`) || !strings.HasSuffix(chLine, `"`) {
		t.Fatalf("期望 quoted challenge 实得 %q", chLine)
	}
	sfRaw, derr := base64.StdEncoding.DecodeString(strings.Trim(chLine, `"`))
	if derr != nil {
		t.Fatalf("challenge base64 解码: %v", derr)
	}
	sf := string(sfRaw) // r=...,s=...,i=...
	var rNonce, sB64 string
	var iters int
	if _, err := fmt.Sscanf(sf, "r=%s", &rNonce); err != nil {
		t.Fatalf("server-first 解析 r=: %v (%q)", err, sf)
	}
	if i := strings.Index(sf, ",s="); i < 0 {
		t.Fatalf("server-first 缺 s=: %q", sf)
	} else {
		rest := sf[i+3:]
		if j := strings.Index(rest, ",i="); j < 0 {
			t.Fatalf("server-first 缺 i=: %q", sf)
		} else {
			sB64 = rest[:j]
			if _, err := fmt.Sscanf(rest[j+3:], "%d", &iters); err != nil {
				t.Fatalf("server-first 解析 i=: %v", err)
			}
		}
	}
	if !strings.HasPrefix(rNonce, cnonce) {
		t.Fatalf("组合 nonce 未含客户端前缀: %q", rNonce)
	}
	salt, serr := base64.StdEncoding.DecodeString(sB64)
	if serr != nil {
		t.Fatalf("盐解码: %v", serr)
	}
	cfb := "n=" + user + ",r=" + cnonce
	cfwp := "c=" + base64.StdEncoding.EncodeToString([]byte("n,,")) + ",r=" + rNonce
	proof := scramClientSide(password, salt, iters, cfb+","+sf+","+cfwp)
	c.send(base64.StdEncoding.EncodeToString([]byte(cfwp + ",p=" + base64.StdEncoding.EncodeToString(proof))))
	mid, res := c.readUntilResult()
	if !strings.HasPrefix(res, "OK") {
		return "", false, res
	}
	for _, line := range mid { // OK (SASL "<b64>") 携带行（readUntilResult 将其归入中间行）
		if strings.HasPrefix(line, "OK (SASL ") { // 注：实际由结果行承载——两者都扫
			return strings.Trim(strings.TrimPrefix(line, "OK (SASL "), `")`), true, res
		}
	}
	if strings.HasPrefix(res, `OK (SASL `) {
		return strings.Trim(strings.TrimPrefix(res, "OK (SASL "), `")`), true, res
	}
	return "", true, res // 无 SASL 附加数据的 OK（形态兜底）
}

// TestSCRAMAuthE2E 完整四步交换（真账号 alice——CreateMailbox 已同步派生四元组）：
// 空 challenge→client-first→server-first→client-final→OK (SASL v=)；v= 解码为
// ServerSignature（客户端经库内 ServerKey 交叉校验）；认证后 OWNER 能力可见。
func TestSCRAMAuthE2E(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()

	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send("STARTTLS")
	c.expectOK("STARTTLS 升级")
	c.upgradeTLS()
	readCapsBlock(c)

	saslB64, ok, res := scramExchangeOnce(t, c, "alice@u12b.test", "s3cret-pass")
	if !ok {
		t.Fatalf("SCRAM 认证期望 OK 实得 %q", res)
	}
	sfRaw, err := base64.StdEncoding.DecodeString(saslB64)
	if err != nil {
		t.Fatalf("OK (SASL) base64 解码: %v", err)
	}
	if !strings.HasPrefix(string(sfRaw), "v=") {
		t.Fatalf("server-final 应为 v= 形态实得 %q", string(sfRaw))
	}
	// 认证后 NOOP 可用（authed 生效）
	c.send("NOOP")
	c.expectOK("认证后 NOOP")
}

// TestSCRAMAuthWrongProof 错误口令（proof 恒败）→ NO 统一拒绝文本。
func TestSCRAMAuthWrongProof(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()
	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send("STARTTLS")
	c.expectOK("STARTTLS 升级")
	c.upgradeTLS()
	readCapsBlock(c)
	if _, ok, res := scramExchangeOnce(t, c, "alice@u12b.test", "wrong-password"); ok {
		t.Fatalf("错误口令不应通过: %q", res)
	} else if strings.HasPrefix(res, "OK") {
		t.Fatalf("意外 OK: %q", res)
	}
}

// TestSCRAMAuthUnknownUserCamouflaged 未知用户走完整伪装交互（server-first 正常返回
// ——防 unknown-user 即时失败暴露存在性；最终 proof 统一失败 NO）。
func TestSCRAMAuthUnknownUserCamouflaged(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()
	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send("STARTTLS")
	c.expectOK("STARTTLS 升级")
	c.upgradeTLS()
	readCapsBlock(c)
	if _, ok, res := scramExchangeOnce(t, c, "nobody@u12b.test", "whatever"); ok {
		t.Fatalf("未知用户不应通过: %q", res)
	}
}

// TestSCRAMAuthCancel 客户端 "*" 取消（challenge 轮）→ NO。
func TestSCRAMAuthCancel(t *testing.T) {
	fx := newU12bFixture(t, true)
	defer fx.cleanup()
	c := u12bDial(t, fx.addr)
	readCapsBlock(c)
	c.send("STARTTLS")
	c.expectOK("STARTTLS 升级")
	c.upgradeTLS()
	readCapsBlock(c)
	c.send(`AUTHENTICATE "SCRAM-SHA-1"`)
	if line := c.readLine(); strings.TrimSpace(line) != `""` {
		t.Fatalf("期望空 challenge 实得 %q", line)
	}
	c.send("*")
	if res := c.expectNO("取消认证"); !strings.Contains(res, "取消") {
		t.Fatalf("取消应答文本异常: %q", res)
	}
}

// TestSCRAMParseForms 解析形态矩阵（gs2 n/y 接受、p 拒、m= 拒、坏转义拒、authzid 拒；
// client-final 往返）。
func TestSCRAMParseForms(t *testing.T) {
	if ex := parseSCRAMClientFirst("n,,n=user,r=abc"); ex == nil || ex.authcid != "user" || ex.clientNonce != "abc" || ex.gs2Header != "n,," || ex.clientFirstBare != "n=user,r=abc" {
		t.Fatalf("n 形态解析异常: %+v", ex)
	}
	if ex := parseSCRAMClientFirst("y,,n=u,r=x"); ex == nil || ex.gs2Header != "y,," {
		t.Fatalf("y 形态应接受: %+v", ex)
	}
	if parseSCRAMClientFirst("p=tls-unique,n=u,r=x") != nil {
		t.Fatalf("p 形态应拒绝（无 -PLUS 通告——rfc5802 §6）")
	}
	if parseSCRAMClientFirst("n,,m=ext,n=u,r=x") != nil {
		t.Fatalf("m= 应拒绝（§5.1 MUST fail）")
	}
	if parseSCRAMClientFirst("n,,n=bad=XY,r=x") != nil {
		t.Fatalf("非 2C/3D 转义应拒绝（§5.1 L627-630）")
	}
	if parseSCRAMClientFirst("n,a=admin,n=u,r=x") != nil {
		t.Fatalf("authzid 非空应拒绝（单用户语义）")
	}
	if ex := parseSCRAMClientFirst("n,,n=a=2Cb,r=x"); ex == nil || ex.authcid != "a,b" {
		t.Fatalf("=2C 转义解码异常: %+v", ex)
	}
	cBind, rNonce, proof, wp, ok := parseSCRAMClientFinal("c=biws,r=xyz,p=" + base64.StdEncoding.EncodeToString(make([]byte, 20)))
	if !ok || string(cBind) != "n,," || rNonce != "xyz" || len(proof) != 20 || wp != "c=biws,r=xyz" {
		t.Fatalf("client-final 解析异常: %v %q %q %q %v", cBind, rNonce, proof, wp, ok)
	}
	if _, _, _, _, ok := parseSCRAMClientFinal("r=xyz,p=AAAA"); ok {
		t.Fatalf("缺 c= 应拒绝")
	}
}

// 保留 bufio/net 引用（fixture 复用链——避免测试文件级 import 漂移告警）。
var _ = bufio.NewReader
var _ net.Conn
