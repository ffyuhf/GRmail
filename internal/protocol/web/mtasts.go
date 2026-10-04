// GRmail MTA-STS 策略发布端点（U13：rfc8461 §3.2 Policy Host 承载——Q2-A 裁决
// 2026-09-23 08:16:33：443 既有监听路由级承载，零新监听器）。
// 语义：GET /.well-known/mta-sts.txt——Host 头精确匹配 mta-sts.<主域>（不匹配 404
// ——防跨 Host 误答）；MTA-STS 开关关闭→404 停发（FR-010 判定③/TC-010 判定④锚——
// 热加载生效：config.MTASts.Enabled 经供给闭包每请求快照）；响应 text/plain;
// charset=utf-8（rfc8461 §3.2 media type 建议）。公开只读资源——无会话/CSRF 承载
// （rfc8461 §3.3 获取方语义）；80 完成态 301 归 HTTPS（U10 既有双态承载）。
// 依赖边界：web 零 transport import（架构第四章——策略文本生成经供给闭包注入，
// main 桥接 transport.STSPolicyText，沿 ChallengeLookup 先例）。
// 依据：契约 v1.9.0 2.4 web U13 注入形态/3.1 端点行；U13 计划书步骤 4/1.5③。
// 修改历史：
//
//	2026-09-23 08:40:00 | 新建 | U13 传输安全全量（计划书步骤 4）
package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// STSPolicyProvider MTA-STS 策略文本供给（main 桥接 transport 生成器——每请求
// 快照热生效；返回：策略正文；发布开关（false=端点停发——判定③））。
type STSPolicyProvider func() (text string, enabled bool)

// stsPolicyPath MTA-STS 策略路径（rfc8461 §3.2 固定 well-known 路径）。
const stsPolicyPath = "/.well-known/mta-sts.txt"

// mtaStsGET 策略发布端点（GET /.well-known/mta-sts.txt）。
// Host 判定+开关停发+文本输出；供给未注入（nil）等同停发（渐进部署形态）。
func (s *Server) mtaStsGET(c *gin.Context) {
	if s.stsPolicy == nil {
		c.Status(http.StatusNotFound)
		return
	}
	// Host 头精确匹配 Policy Host（rfc8461 §3.2——"mta-sts"+主域；端口后缀容忍）
	if !stsHostMatch(c.Request.Host, s.cfg.Domain) {
		c.Status(http.StatusNotFound)
		return
	}
	text, enabled := s.stsPolicy()
	if !enabled {
		c.Status(http.StatusNotFound) // FR-010 判定③：Web 关闭→端点停发
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(text))
}

// stsHostMatch Host 头判定（mta-sts.<主域> 精确匹配；Host 可能携带 :port 后缀——
// 剥离后比对，大小写不敏感——DNS 域名语义）。
// 参数：host 请求 Host 头；domain 主域名。返回：是否 Policy Host。
func stsHostMatch(host, domain string) bool {
	if at := lastColonIndex(host); at >= 0 {
		host = host[:at] // 剥端口（IPv6 字面量不作为 Host 形态出现在本判定——域名语境）
	}
	return len(host) > 0 && equalFoldASCII(host, "mta-sts."+domain)
}

// lastColonIndex 查找最后一个冒号下标（无则 -1）。
func lastColonIndex(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// equalFoldASCII ASCII 大小写不敏感相等（域名比对——Host/DNS 均为 ASCII 语义，
// Punycode 形态无非 ASCII 字符）。
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
