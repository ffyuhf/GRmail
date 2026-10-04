// mail 域正文缓存提取单点（U16，Q3-A 裁决 2026-09-24 11:47:58——正文缓存列写入
// 路径统一填充；数据模型 v1.3.0 3.4 body_cache 列）。
// 语义：ParseDisplay 纯文本正文截断（bodyCacheMaxBytes=65536B 工程上限——纯文本
// 检索语义足够，防超大正文撑库）；解析失败返回空串（列写 NULL——无正文邮件保持
// 不命中，回填任务同语义）；缓存为派生维度可重建（非权威数据——数据模型 1.3 第 6 条）。
// 消费方：收信管道（Deliver meta）/提交管道（submissionMessageMeta）/IMAP APPEND
// （session meta）/Webmail 草稿与 Sent 副本（compose）——四写入路径（计划书 1.5③）。
// SRS 条目：FR-013（3.8 正文检索子项）；TC-013；契约 v1.12.0 v1.12.0 变更注释。
// 修改历史：
//
//	2026-09-24 16:40:00 | 新建 | U16 Webmail 体验收尾（计划书步骤 3，G2 批准 2026-09-24 11:51:57）
package mail

// bodyCacheMaxBytes 正文缓存截断上限（64KB——计划书 1.5③ 工程常量）。
const bodyCacheMaxBytes = 65536

// BodyCacheOf 从原始邮件字节提取正文缓存（纯文本截断）。
// 参数：raw RFC 5322 原始字节（与 Blob 写入同源——缓存与 CAS 键对应同内容）。
// 返回：截断纯文本（解析失败/无正文返回空串——调用方空串映射 NULL）。
func BodyCacheOf(raw []byte) string {
	display, err := ParseDisplay(raw)
	if err != nil {
		return ""
	}
	body := display.BodyText
	if len(body) > bodyCacheMaxBytes {
		body = body[:bodyCacheMaxBytes]
	}
	return body
}
