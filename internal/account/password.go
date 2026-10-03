// Package account 实现邮箱账号域：argon2id 凭据、地址规范化、邮箱生命周期域服务。
// 依据：SRS v1.0.0 FR-001/002/003/004/012；系统架构总览 v1.0.0 第二章 #14（密码哈希 argon2id，
// Q12 裁决 2026-09-16 03:27:20：OWASP 首荐、抗 GPU、参数可控）；
// 模块接口契约 v1.0.0 2.1（经 storage.Repository 接口族访问数据）。
// 修改历史：
//
//	2026-09-17 01:44:00 | 新建 | U2 account 模块（计划书步骤 4/5，G2 批准 2026-09-17 01:31:40）
package account

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id 参数档位（来源：用户确认 Q1-A 2026-09-17 01:09:48，R3 闭环，
// OWASP Password Storage Cheat Sheet 当前首推默认档；枚举总览第八章 R3 登记项就此关闭）
const (
	argon2idMemoryKiB uint32 = 19 * 1024 // m=19456 KiB（19 MiB），与 NFR-002（整机 ≤512MB）兼容
	argon2idTime      uint32 = 2         // t=2 迭代
	argon2idThreads   uint8  = 1         // p=1 并行度
	argon2idKeyLen    uint32 = 32        // 派生密钥 32 字节
	argon2idSaltLen          = 16        // 盐 16 字节（CSPRNG）
	// passwordMaxLen 明文长度上限：拒绝超长输入防哈希 DoS（内存放大），工程防护基线，
	// 非 SRS 密码策略（SRS 未定义复杂度规则，不自行发明）
	passwordMaxLen = 1024
)

// HashPassword 生成 argon2id PHC 格式哈希串。
// 参数：password 明文（非空且 ≤1024 字节）。
// 返回：形如 $argon2id$v=19$m=19456,t=2,p=1$<b64盐>$<b64派生键> 的 PHC 串；输入非法或 CSPRNG 故障返回 error。
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password: 明文不能为空")
	}
	if len(password) > passwordMaxLen {
		return "", fmt.Errorf("password: 明文长度超上限 %d", passwordMaxLen)
	}
	salt := make([]byte, argon2idSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: 盐生成失败（CSPRNG）: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2idTime, argon2idMemoryKiB, argon2idThreads, argon2idKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2idMemoryKiB, argon2idTime, argon2idThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword 按存储串内嵌参数校验明文（存量哈希可变参校验，不依赖当前常量档位）。
// 参数：password 明文；phc 存储 PHC 串。返回：匹配判定；phc 格式非法/参数越界返回 error。
// 安全语义：比较采用 subtle.ConstantTimeCompare（常数时间，防时序侧信道）。
func VerifyPassword(password, phc string) (bool, error) {
	var (
		version   int
		memoryKiB uint32
		timeIter  uint32
		threads   uint8
		saltB64   string
		keyB64    string
	)
	// PHC 段拆分：$argon2id$v=..$m=..,t=..,p=..$salt$key（首段为空前缀，共 6 段）
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("password: 非法 PHC 结构")
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("password: 非法 PHC 版本段: %w", err)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &timeIter, &threads); err != nil {
		return false, fmt.Errorf("password: 非法 PHC 参数段: %w", err)
	}
	saltB64, keyB64 = parts[4], parts[5]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("password: 非法盐编码: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(keyB64)
	if err != nil {
		return false, fmt.Errorf("password: 非法键编码: %w", err)
	}
	// 参数越界防护：恶意串内参数可触发巨量内存分配（复现 argon2 DoS 向量）
	if memoryKiB == 0 || memoryKiB > 1<<22 || timeIter == 0 || threads == 0 || threads > 255 {
		return false, fmt.Errorf("password: PHC 参数越界（m=%d,t=%d,p=%d）", memoryKiB, timeIter, threads)
	}
	got := argon2.IDKey([]byte(password), salt, timeIter, memoryKiB, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
