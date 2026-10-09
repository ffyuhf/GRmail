// Package account SCRAM-SHA-1 纯函数测试（SCRAM认证批——rfc5802 官方示例向量为
// 金标准锚：§5 L496-501 user/pencil/s=QSXCR+Q6sek8bf92/i=4096/
// p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=/v=rmF9pqV8S7suAoZWja4dJRkFsKQ=）。
// 修改历史：
//
//	2026-10-10 03:35:00 | 新增 | SCRAM认证批（G2 批准 2026-10-09 23:37:36）
package account

import (
	"encoding/base64"
	"testing"
)

// TestSCRAMRFC5802Vector 官方测试向量闭环（rfc5802 §5 L496-501 逐字）：
// 服务端四元组由 SCRAMDerive 自 pencil/官方盐/4096 派生；官方 AuthMessage 三段
// 拼接（client-first-bare "," server-first "," client-final-without-proof）后
// SCRAMServerVerify 必须接受官方 proof 且产出的 ServerSignature 与官方 v= 逐字节
// 一致——派生/验证/HMAC 链全数学闭环。
func TestSCRAMRFC5802Vector(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("QSXCR+Q6sek8bf92")
	if err != nil || len(salt) != 12 {
		t.Fatalf("官方盐解码: %v (len=%d)", err, len(salt))
	}
	const (
		cfb  = "n=user,r=fyko+d2lbbFgONRv9qkxdawL"                                      // client-first-bare
		sf   = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096" // server-first
		cfwp = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"                    // client-final-without-proof
	)
	proof, perr := base64.StdEncoding.DecodeString("v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
	if perr != nil {
		t.Fatalf("官方 proof 解码: %v", perr)
	}
	storedKey, serverKey := SCRAMDerive("pencil", salt, 4096)
	authMessage := cfb + "," + sf + "," + cfwp
	ok, serverSig := SCRAMServerVerify(storedKey, serverKey, []byte(authMessage), proof)
	if !ok {
		t.Fatalf("官方 proof 验证失败（机制数学偏离 rfc5802 §3）")
	}
	if got := base64.StdEncoding.EncodeToString(serverSig); got != "rmF9pqV8S7suAoZWja4dJRkFsKQ=" {
		t.Fatalf("ServerSignature 偏离官方 v=：got %s want rmF9pqV8S7suAoZWja4dJRkFsKQ=", got)
	}
}

// TestSCRAMVerifyRejectsWrongProof 篡改 proof 任一字节必须拒绝（invalid-proof 统一口径）。
func TestSCRAMVerifyRejectsWrongProof(t *testing.T) {
	salt := make([]byte, 16)
	stored, server := SCRAMDerive("pw", salt, SCRAMIterations)
	proof := make([]byte, 20)
	// 由正确 proof 翻转一字节构造篡改形态（直接以伪值承载——验证拒绝路径）
	proof[0] ^= 0xFF
	if ok, _ := SCRAMServerVerify(stored, server, []byte("a,b,c"), proof); ok {
		t.Fatalf("篡改 proof 不应通过")
	}
	if ok, _ := SCRAMServerVerify(stored, server, []byte("a,b,c"), proof[:19]); ok {
		t.Fatalf("短 proof（长度异常）不应通过")
	}
}
