// Package account SCRAM-SHA-1 凭据派生与服务端验证纯函数（rfc5802——SCRAM认证批；
// 自研承载沿 R1-A 全自研先例，Hi 伪随机函数复用 golang.org/x/crypto/pbkdf2〔INV-06〕，
// 零新外部依赖）。
// 规范锚点（rfc5802.txt 2026-10-09 入库，原文精读）：
//   - §3 L413-422 机制全公式：SaltedPassword:=Hi(Normalize(password),salt,i)；
//     ClientKey:=HMAC(SaltedPassword,"Client Key")；StoredKey:=H(ClientKey)；
//     ServerKey:=HMAC(SaltedPassword,"Server Key")；ClientSignature:=
//     HMAC(StoredKey,AuthMessage)；ClientProof:=ClientKey XOR ClientSignature；
//     ServerSignature:=HMAC(ServerKey,AuthMessage)
//   - §2.2 L353-369 Hi 定义（U1:=HMAC(str,salt+INT(1))…Ui:=HMAC(str,Ui-1)，
//     Hi:=异或链——即 PBKDF2-HMAC，dkLen==HMAC 输出长〔SHA-1=20 字节〕）
//   - §3 L424-429 服务端验证：ClientKey=ClientProof⊕ClientSignature 后
//     H(ClientKey)==StoredKey 即证明客户端持有口令
//   - §5.1 L679-680「servers SHOULD announce a hash iteration-count of at least
//     4096」——本实现定档 4096（G2 候选 3.3-A 裁决 2026-10-09 23:37:36；握手验证
//     为 StoredKey 的 HMAC 常数时间操作，迭代成本仅在派生〔设密〕时刻）
//   - §5 L496-501 官方示例向量（user/pencil/s=QSXCR+Q6sek8bf92/i=4096——测试金
//     标准锚：p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=/v=rmF9pqV8S7suAoZWja4dJRkFsKQ=）
//   - §7 server-error-value 注「the server may substitute the real reason with
//     "other-error"」——防信息披露口径（消费点统一拒绝文本防枚举）
//
// SRS 条目：FR-011（ManageSieve 规范合规——rfc5804 §1.6 L692-694 MUST implement
// SCRAM-SHA-1）；契约 v1.39.0 2.1 SCRAMCredentials 注记（G2 批准 2026-10-09
// 23:37:36 含四设计物升版授权——INV-24）。
// 修改历史：
//
//	2026-10-09 23:46:00 | 新增 | SCRAM认证批（G2 批准 2026-10-09 23:37:36）
package account

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SCRAM-SHA-1 为 rfc5804 §1.6 L692 强制机制（协议密钥推导用途，非通用摘要）
	"crypto/subtle"

	"golang.org/x/crypto/pbkdf2"
)

// SCRAM 机制常量（rfc5802 §3——HMAC 输入串逐字）。
const (
	scramClientKeyInput = "Client Key"
	scramServerKeyInput = "Server Key"
	// SCRAMIterations 迭代档位 4096（rfc5802 §5.1 L679-680 SHOULD ≥4096——G2 候选
	// 3.3-A 裁决 2026-10-09 23:37:36；设密期派生一次，握手期零迭代成本）。
	SCRAMIterations = 4096
	// SCRAMSaltLen 盐长 16 字节（CSPRNG——沿 argon2idSaltLen 档位先例）。
	SCRAMSaltLen = 16
	// scramKeyLen StoredKey/ServerKey 长 20 字节（SHA-1 输出长——rfc5802 §2.2 HMAC 注）。
	scramKeyLen = sha1.Size
)

// SCRAMDummySalt 防枚举伪装盐（16B 全零固定值）：用户不存在或未配备 SCRAM 凭据时，
// 服务端以该盐+缺省迭代数继续 server-first 交互（响应形态与真实用户一致），最终在
// proof 验证步统一失败——防 unknown-user 即时失败暴露用户名存在性（rfc5802 §7 防
// 信息披露口径与本项目 PLAIN 统一拒绝文本同语义；仅伪装交互零安全敏感）。
var SCRAMDummySalt = make([]byte, SCRAMSaltLen)

// SCRAMDerive 由明文口令派生服务端存储键两部（salt/iterations 由调用方持有——
// 与两部键共同组成 storage.SCRAMCredentials 四元组）。SaltedPassword=Hi(password,
// salt,i)（pbkdf2-SHA1 承载——§2.2「Hi() is, essentially, PBKDF2 [RFC2898] with
// HMAC() as the pseudorandom function」）；ClientKey=HMAC(SaltedPassword,
// "Client Key")；StoredKey=H(ClientKey)；ServerKey=HMAC(SaltedPassword,
// "Server Key")（§3 L413-421）。仅在设密/激活/改密路径调用（明文经手窗口与
// argon2id 哈希同域——不落日志零持久化）。
// 参数：password 明文口令；salt 盐（16B）；iterations 迭代数。
// 返回：StoredKey 与 ServerKey（各 20B）。
func SCRAMDerive(password string, salt []byte, iterations int) (storedKey, serverKey []byte) {
	salted := pbkdf2.Key([]byte(password), salt, iterations, scramKeyLen, sha1.New)
	clientKey := hmacSHA1(salted, []byte(scramClientKeyInput))
	storedKey = sha1Sum(clientKey)
	serverKey = hmacSHA1(salted, []byte(scramServerKeyInput))
	return storedKey, serverKey
}

// SCRAMServerVerify 服务端验证 client-final（§3 L419-429）：ClientSignature=
// HMAC(StoredKey,AuthMessage)；ClientKey=ClientProof⊕ClientSignature；常数时间
// 比对 H(ClientKey)==StoredKey——通过即证明客户端持有口令派生的 ClientKey；随后
// 产出 ServerSignature=HMAC(ServerKey,AuthMessage) 供 server-final（v=）回发
// （客户端校验该值以认证服务端——双向认证语义）。
// 参数：storedKey/serverKey 服务端存储键（20B）；authMessage 按 §3 L416-418 构造
// （client-first-bare+","+server-first+","+client-final-without-proof——协议层逐字
// 拼接）；clientProof 客户端证明（20B）。
// 返回：验证是否通过；ServerSignature（20B——仅通过时有效，供 v= 回发）。
func SCRAMServerVerify(storedKey, serverKey, authMessage, clientProof []byte) (bool, []byte) {
	if len(clientProof) != scramKeyLen || len(storedKey) != scramKeyLen {
		return false, nil // 长度异常按验证失败（invalid-proof 统一口径）
	}
	clientSignature := hmacSHA1(storedKey, authMessage)
	clientKey := xorBytes(clientProof, clientSignature)
	if subtle.ConstantTimeCompare(sha1Sum(clientKey), storedKey) != 1 {
		return false, nil // invalid-proof——调用方统一拒绝文本防枚举（§7 口径）
	}
	return true, hmacSHA1(serverKey, authMessage)
}

// ───────────────────────── 私有辅助（纯函数——NFR-015 可独立测试） ─────────────────────────

// hmacSHA1 HMAC-SHA1（rfc5802 §2.2 L328-332 记号 HMAC(key,str)——key 为键）。
func hmacSHA1(key, data []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// sha1Sum SHA-1 摘要（§2.2 L343 记号 H(str)——StoredKey=H(ClientKey) 承载）。
func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}

// xorBytes 等长异或（§2.2 L348-351 记号 XOR——ClientProof/ClientKey 推导承载）。
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
