// Package transport 追加 MTA-STS 发布侧生成器：策略文本（rfc8461 §3.2）与
// DNS 记录建议值（rfc8461 §3.1 _mta-sts TXT / rfc8460 §3 _smtp._tls TXT）。
// 依据：U13 计划书 v1.0.0 步骤 3/1.5②③（G2 批准 2026-09-23 08:19:32，含契约
// v1.9.0 升版授权——2.4 节 web 注入形态：策略由 web /.well-known/mta-sts.txt
// 端点按快照即时生成输出，本包零状态零 IO（NFR-015 纯函数）；
// FR-010「发布 MTA-STS 策略与 TLS-RPT 记录（二者默认启用、Web 可关闭）」。
// 单 MX 形态：本系统 MX=主域自身（SRS 2.2 单服务器部署——mx 行=主域名，
// rfc8461 附录 A 单 MX 先例）；id=UTC 时间戳（rfc8461 §3.1——1*32 ALPHA/DIGIT）。
// 修改历史：
//
//	2026-09-23 08:26:00 | 新建 | U13 传输安全全量（计划书步骤 3）
package transport

import (
	"fmt"
	"strings"
	"time"

	"GRmail/internal/config"
)

// stsPolicyIDFormat MTA-STS 策略 id 的时间戳格式（rfc8461 §3.1 sts-id：
// 1*32(ALPHA/DIGIT)——UTC 紧凑格式 14 位数字合规；附录 A 先例同形态）。
const stsPolicyIDFormat = "20060102150405Z"

// STSPolicyText 生成 MTA-STS 策略文件正文（rfc8461 §3.2 ABNF 逐字段：
// version: STSv1 / mode: enforce|testing / mx: <主域> / max_age: <秒>——
// CRLF 分隔；非重复字段唯一，mx 单条=单 MX 部署形态）。
// 参数：domain 主域名（mx 行与策略归属域）；sts MTA-STS 配置快照（Mode/MaxAgeSeconds
// 已由 config.Load/设置页校验兜底——此处不再防御）。返回：策略文本（无尾随空行）。
func STSPolicyText(domain string, sts config.MTAStsConf) string {
	var b strings.Builder
	b.WriteString("version: STSv1\r\n")
	fmt.Fprintf(&b, "mode: %s\r\n", sts.Mode)
	fmt.Fprintf(&b, "mx: %s\r\n", domain)
	fmt.Fprintf(&b, "max_age: %d", sts.MaxAgeSeconds)
	return b.String()
}

// STSTXTRecordValue 生成 _mta-sts.<domain> TXT 记录建议值（rfc8461 §3.1：
// "v=STSv1; id=<id>"——id 唯一标识策略实例，供发送方比对缓存新旧）。
// 参数：at 策略发布时刻（id 源）；返回：记录值字符串（不含记录名与 TTL）。
func STSTXTRecordValue(at time.Time) string {
	return fmt.Sprintf("v=STSv1; id=%s;", at.UTC().Format(stsPolicyIDFormat))
}

// TLSRPTTXTRecordValue 生成 _smtp._tls.<domain> TXT 记录建议值（rfc8460 §3：
// "v=TLSRPTv1; rua=<uri>"——rua 支持逗号列表，本形态单地址）。
// 参数：domain 主域名（rua 缺省地址 postmaster@<domain> 的域部分）；sts 配置快照
// （RuaAddress 空值兜底 postmaster@<domain>——1.5①）。返回：记录值字符串。
func TLSRPTTXTRecordValue(domain string, sts config.MTAStsConf) string {
	rua := sts.RuaAddress
	if rua == "" {
		rua = "postmaster@" + domain // 缺省聚合报告地址（收信路径既有承载，零接收侧开发）
	}
	return fmt.Sprintf("v=TLSRPTv1; rua=mailto:%s", rua)
}

// STSPolicyHost Policy Host（rfc8461 §3.2——"mta-sts" 前缀+主域；web 端点
// Host 头判定与 ACME 域名清单共用此口径）。
// 参数：domain 主域名。返回：策略宿主名（如 mta-sts.example.com）。
func STSPolicyHost(domain string) string {
	return "mta-sts." + domain
}
