// account 域安全原子性批 F5 单测：argon2id PHC 参数防御界（版本比对/t 上限/
// m≥8p/键长下界——恶意 PHC 串防御；存量档位零误拒）。
// 依据：安全原子性批计划书 v1.0.1 F5（G2 批准 2026-10-06 18:12:59）；SRS FR-001。
// 修改历史：
//
//	2026-10-06 18:45:00 | 新建 | 安全原子性批（评审修复批次 1/8）
package account

import (
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// phcOf 按给定参数构造 PHC 串（盐/键定长固定值——参数段为被测对象）。
func phcOf(t *testing.T, version int, m, iter uint32, threads uint8, keyLen int) string {
	t.Helper()
	salt := make([]byte, 16)
	key := make([]byte, keyLen)
	return strings.Join([]string{
		"", "argon2id",
		"v=" + itoa(version),
		"m=" + itoa(int(m)) + ",t=" + itoa(int(iter)) + ",p=" + itoa(int(threads)),
		b64Raw(salt), b64Raw(key),
	}, "$")
}

// itoa/b64Raw 避免引入额外 import 分支的小辅助（与 encoding/base64 等价输出）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func b64Raw(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		sb.WriteByte(alphabet[chunk[0]>>2])
		sb.WriteByte(alphabet[(chunk[0]&0x3)<<4|chunk[1]>>4])
		if n > 1 {
			sb.WriteByte(alphabet[(chunk[1]&0xf)<<2|chunk[2]>>6])
		}
		if n > 2 {
			sb.WriteByte(alphabet[chunk[2]&0x3f])
		}
	}
	return sb.String()
}

// TestPasswordPHCGuardBounds F5：越界参数全部拒绝（不 panic），存量档位全通过。
func TestPasswordPHCGuardBounds(t *testing.T) {
	ok := func(phc string) { t.Helper() }
	_ = ok

	// 存量档位（v=19,m=19456,t=2,p=1,key=32）——解析与校验通过（哈希比对结果非本测重点）
	legit := phcOf(t, int(argon2.Version), 19456, 2, 1, 32)
	if _, err := VerifyPassword("any", legit); err != nil {
		t.Fatalf("存量档位应通过校验: %v", err)
	}

	// 版本不匹配（v=16 旧版）——拒绝
	if _, err := VerifyPassword("x", phcOf(t, 16, 19456, 2, 1, 32)); err == nil {
		t.Fatalf("版本不匹配应拒绝")
	}
	// t 超上限（65）——拒绝（CPU DoS 防御界）
	if _, err := VerifyPassword("x", phcOf(t, int(argon2.Version), 19456, 65, 1, 32)); err == nil {
		t.Fatalf("t=65 应拒绝")
	}
	// m < 8*p——拒绝（argon2 规范下界）
	if _, err := VerifyPassword("x", phcOf(t, int(argon2.Version), 4, 2, 2, 32)); err == nil {
		t.Fatalf("m<8p 应拒绝")
	}
	// 派生键过短（<4）——拒绝
	if _, err := VerifyPassword("x", phcOf(t, int(argon2.Version), 19456, 2, 1, 2)); err == nil {
		t.Fatalf("key<4 应拒绝")
	}
}
