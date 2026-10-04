// Package account 单测：argon2id 凭据哈希（NFR-015：脱离网络端点独立驱动）。
// 覆盖条目：FR-001 凭据基础（Q1-A 档位 m=19MiB,t=2,p=1，来源：用户确认 2026-09-17 01:09:48）。
// 修改历史：
//
//	2026-09-17 01:46:00 | 新建 | U2 account 模块（计划书步骤 6，G2 批准 2026-09-17 01:31:40）
package account

import (
	"strings"
	"testing"
)

// TestHashVerifyRoundTrip 哈希→校验往返 + PHC 结构前缀（档位参数出现在串内）
func TestHashVerifyRoundTrip(t *testing.T) {
	const password = "correct horse battery staple 中文密码Ω"
	phc, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// Q1-A 档位断言：PHC 串内嵌 m=19456,t=2,p=1（档位变更将导致本断言失败，保护裁决不被静默漂移）
	wantPrefix := "$argon2id$v=19$m=19456,t=2,p=1$"
	if !strings.HasPrefix(phc, wantPrefix) {
		t.Fatalf("PHC 前缀不符（档位漂移）：got %q want prefix %q", phc, wantPrefix)
	}
	ok, err := VerifyPassword(password, phc)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword 往返失败: ok=%v err=%v", ok, err)
	}
}

// TestVerifyWrongPassword 错误密码必须拒绝（且不报解析错误）
func TestVerifyWrongPassword(t *testing.T) {
	phc, err := HashPassword("right-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword("wrong-password", phc)
	if err != nil {
		t.Fatalf("VerifyPassword 不应报错: %v", err)
	}
	if ok {
		t.Fatal("错误密码被判为通过")
	}
}

// TestHashUniqueSalts 同密码两次哈希必须产出不同串（盐随机性），且均可通过校验
func TestHashUniqueSalts(t *testing.T) {
	h1, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("第一次 HashPassword: %v", err)
	}
	h2, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("第二次 HashPassword: %v", err)
	}
	if h1 == h2 {
		t.Fatal("两次哈希产出相同串（盐未随机化）")
	}
	for i, phc := range []string{h1, h2} {
		if ok, err := VerifyPassword("same-password", phc); err != nil || !ok {
			t.Fatalf("第 %d 个哈希校验失败: ok=%v err=%v", i+1, ok, err)
		}
	}
}

// TestVerifyMalformedPHC 非法 PHC 结构必须报错（非误判为匹配）
func TestVerifyMalformedPHC(t *testing.T) {
	cases := []string{
		"",
		"not-a-phc",
		"$argon2i$v=19$m=1024,t=1,p=1$abc$def",   // 算法不符（argon2i ≠ argon2id）
		"$argon2id$v=19$m=bad,t=2,p=1$abc$def",   // 参数段非数字
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$def", // 盐非 base64
		"$argon2id$v=19$m=19456,t=2,p=1$abc$???", // 键非 base64
		"$argon2id$v=19$m=19456,t=2,p=1$abc",     // 缺键段
	}
	for _, phc := range cases {
		if ok, err := VerifyPassword("x", phc); err == nil {
			t.Errorf("PHC %q 应报格式错误，却返回 ok=%v", phc, ok)
		}
	}
}

// TestVerifyHostileParams 串内恶意参数（触发巨量内存分配的 DoS 向量）必须被参数越界防护拒绝
func TestVerifyHostileParams(t *testing.T) {
	// m=1<<30（1TiB）超出防护上限 1<<22（4GiB 档）；t/p 为 0 同属越界
	cases := []string{
		"$argon2id$v=19$m=1073741824,t=2,p=1$YWJj$ZGVm",
		"$argon2id$v=19$m=19456,t=0,p=1$YWJj$ZGVm",
		"$argon2id$v=19$m=19456,t=2,p=0$YWJj$ZGVm",
	}
	for _, phc := range cases {
		if _, err := VerifyPassword("x", phc); err == nil {
			t.Errorf("恶意参数 PHC %q 未被越界防护拒绝", phc)
		}
	}
}

// TestHashRejectsEmptyAndHuge 空密码与超长密码输入拒绝
func TestHashRejectsEmptyAndHuge(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Error("空密码未被拒绝")
	}
	if _, err := HashPassword(strings.Repeat("a", passwordMaxLen+1)); err == nil {
		t.Errorf("超长密码（%d+1）未被拒绝", passwordMaxLen)
	}
}
