// auth 域验证输入类型：SMTP 信封与来信载体。
// 依据：模块接口契约 v1.0.0 2.2 节 Verifier.Verify(ctx, msg *IncomingMail) 引用类型
// （契约未定义字段——用户裁决 Q2-A 2026-09-17 02:10:47：同意定义于 internal/auth，
// 字段以 go doc 实测 raven 验证入参为准；U4 收信管道构造后传入）；
// 关键流程设计 v1.0.0 第一章「S→P: Envelope+原始字节流」「MTA->>S: EHLO/MAIL FROM」；
// 实测定档来源：raven v1.6.1 spf.Args{RemoteIP, MailFromDomain, MailFromLocal, HelloDomain}。
// 修改历史：
//
//	2026-09-17 02:24:00 | 新建 | U3 auth 基础（计划书步骤 4，Q2-A 裁决落码）
package auth

import (
	"net"
	"strings"
)

// Envelope SMTP 信封（RFC 5321 会话参数；U4 协议层在 RCPT/DATA 完成后组装）。
type Envelope struct {
	// Helo EHLO/HELO 域名或 IP 字面量（spf.Args.HelloDomain 对应位）
	Helo string
	// RemoteIP 对端连接 IP（SPF 客户端 IP 判定输入，spf.Args.RemoteIP 对应位）
	RemoteIP net.IP
	// MailFrom RFC 5321 反向路径（MAIL FROM；空字符串表示空路径 <> 退信场景）
	MailFrom string
}

// MailFromDomain 提取信封发件域（小写规范化；空路径返回空串——SPF 按 HELO 域判定，rfc7208 2.4）。
func (e Envelope) MailFromDomain() string {
	if e.MailFrom == "" {
		return ""
	}
	at := strings.LastIndex(e.MailFrom, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(e.MailFrom[at+1:])
}

// MailFromLocal 提取信封本地部分（SPF 宏展开输入，spf.Args.MailFromLocal 对应位）。
func (e Envelope) MailFromLocal() string {
	if e.MailFrom == "" {
		return "postmaster" // rfc7208 4.3：空路径宏展开本地部分取 postmaster
	}
	at := strings.LastIndex(e.MailFrom, "@")
	if at < 0 {
		return e.MailFrom
	}
	return e.MailFrom[:at]
}

// IncomingMail 来信验证输入（契约 2.2 Verify 入参的载体类型，Q2-A）。
// 字段定档（raven v1.6.1 实测）：信封三元组喂 spf.Args；Raw 喂 dkim.Verify /
// arc.Verifier.Verify（两者均接收完整 RFC 5322 消息字节）。
type IncomingMail struct {
	// Envelope SMTP 信封
	Envelope Envelope
	// Raw RFC 5322 原始消息字节（头+体；流程设计第一章 DATA 完成后的完整字节流）
	Raw []byte
}
