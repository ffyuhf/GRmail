// mail 域 DSN 退信构造：DSNBuilder 实现（multipart/report 三分量，rfc3464 第 2 章）。
// 依据：模块接口契约 v1.2.0 2.3 节（DSNBuilder 签名逐字，v1.0.0 定义 U5 落地）；
// rfc3464 原文锚点（步骤 2 回读）：2 节（multipart/report; report-type=delivery-status；
// 三分量=人类可读+message/delivery-status+原信；DSN 收件人=原信封 return address；
// DSN 自身信封 MUST NULL「<>」防循环；From SHOULD postmaster）；2.2 节（per-message：
// Reporting-MTA 必需 dns;域名；Arrival-Date 数字时区）；2.3 节（per-recipient：
// Final-Recipient 必需 rfc822;地址；Action 必需五值域；Status 必需三段无前导零；
// Diagnostic-Code smtp;码）；rfc3463（增强状态码）；
// Q4-A 裁决（2026-09-17 11:28:56）：DSN 作完整邮件走标准链路。
// PMail 全景 E2 先例：Auto-Submitted: auto-replied 头；原信已含 Auto-Submitted 不生成。
// 修改历史：
//
//	2026-09-17 12:06:00 | 新建 | U5 SMTP 提交与投递（计划书步骤 7）
package mail

import (
	"context"
	"fmt"
	"strings"
	"time"

	"GRmail/internal/storage"
)

// ───────────────────────── 契约接口（契约 2.3 逐字） ─────────────────────────

// DSNBuilder 退信构造（rfc3461/3464）。
type DSNBuilder interface {
	Build(ctx context.Context, item *storage.QueueItem, r storage.AttemptResult) ([]byte, error)
}

// 编译期断言。
var _ DSNBuilder = (*DSNBuilderService)(nil)

// ───────────────────────── 窄接口 ─────────────────────────

// MessageSource 原信字节读取位（封装 messages 行→blob_key→BlobStore.Read 两步；
// worker 侧以 DB 查询实现，测试 stub 注入——NFR-015）。
type MessageSource interface {
	ReadOriginal(ctx context.Context, messageID int64) ([]byte, error)
}

// ───────────────────────── 域服务 ─────────────────────────

// DSNBuilderService DSN 构造域服务（worker failed 终态消费）。
type DSNBuilderService struct {
	domain   string        // 主域名（Reporting-MTA 与 From postmaster 域）
	original MessageSource // 原信读取（第三分量；读失败降级为空不阻断）
}

// NewDSNBuilderService 构造 DSN 构造器。
// 参数：domain 主域名；original 原信读取源。
func NewDSNBuilderService(domain string, original MessageSource) *DSNBuilderService {
	return &DSNBuilderService{domain: domain, original: original}
}

// Build 构造 failed DSN 邮件字节（完整 RFC 5322 消息，信封约定归调用方：
// EnvelopeFrom 恒 "<>"、收件人=原信封 return address——Q4-A+rfc3464 第 2 章）。
// 参数：ctx 上下文；item 终态队列行（原信封与 message_id）；r 失败尝试结果。
// 返回：DSN 消息字节；原信不可读时第三分量降级为空（构造不失败——退信可达性优先）。
func (b *DSNBuilderService) Build(ctx context.Context, item *storage.QueueItem, r storage.AttemptResult) ([]byte, error) {
	now := time.Now()

	// per-message 字段（rfc3464 2.2：Reporting-MTA 必需；Arrival-Date 可选补齐）
	perMessage := strings.Join([]string{
		"Reporting-MTA: dns; " + b.domain,
		"Arrival-Date: " + now.Format("Mon, 02 Jan 2006 15:04:05 -0700"),
	}, "\r\n")

	// per-recipient 字段（rfc3464 2.3：Final-Recipient/Action/Status 必需）
	// Action=failed（终态放弃投递）；Status 由末次 SMTP 码映射（无码→4.4.2 网络故障类）
	status := mapStatus(r)
	diag := ""
	if r.SMTPCode > 0 {
		diag = "Diagnostic-Code: smtp; " + fmt.Sprintf("%d %s", r.SMTPCode, strings.TrimSpace(r.Error))
	}
	perRcptLines := []string{
		"Final-Recipient: rfc822; " + item.RcptTo,
		"Action: failed",
		"Status: " + status,
		"Last-Attempt-Date: " + now.Format("Mon, 02 Jan 2006 15:04:05 -0700"),
	}
	if diag != "" {
		perRcptLines = append(perRcptLines, diag)
	}
	perRecipient := strings.Join(perRcptLines, "\r\n")

	// 第三分量（F-L3——rfc3461 §5.2.10 L1108-1114：RET=FULL 时全文 SHOULD 返回；
	// HDRS/缺省=text/rfc822-headers 既有缺省口径；长度上限 MAY 豁免口保留未设限）
	origHeaders := b.originalHeaders(ctx, item)

	// 人类可读分量（text/plain；编码 7bit 语义）
	human := "Delivery to the following recipient failed permanently:\r\n\r\n\t" +
		item.RcptTo + "\r\n\r\nReporting-MTA: " + b.domain + "\r\n"

	boundary := fmt.Sprintf("dsn-%x", now.UnixNano())
	var sb strings.Builder
	sb.WriteString("From: MAILER-DAEMON <postmaster@" + b.domain + ">\r\n") // rfc3464 2：From SHOULD postmaster
	sb.WriteString("To: <" + dsnRecipientOf(item) + ">\r\n")                // 原信封 return address
	sb.WriteString("Subject: Delivery Status Notification (Failure)\r\n")
	sb.WriteString("Date: " + now.Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	sb.WriteString("Auto-Submitted: auto-replied\r\n") // 防退信循环（PMail E2 先例+rfc3834 语义）
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"" + boundary + "\"\r\n\r\n")
	sb.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	sb.WriteString(human)
	sb.WriteString("\r\n--" + boundary + "\r\nContent-Type: message/delivery-status\r\n\r\n")
	sb.WriteString(perMessage + "\r\n\r\n" + perRecipient + "\r\n")
	if origHeaders != "" {
		if item.RetFull {
			// RET=FULL：message/rfc822 全文（rfc3464 第 3.1.3 节第三分量全量形态）
			if raw, rerr := b.original.ReadOriginal(ctx, item.MessageID); rerr == nil && len(raw) > 0 {
				sb.WriteString("\r\n--" + boundary + "\r\nContent-Type: message/rfc822\r\n\r\n")
				sb.Write(raw)
				origHeaders = "" // 已消费
			}
		}
		if origHeaders != "" {
			sb.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/rfc822-headers\r\n\r\n")
			sb.WriteString(origHeaders)
		}
	}
	sb.WriteString("\r\n--" + boundary + "--\r\n")
	return []byte(sb.String()), nil
}

// originalHeaders 读取原信并截取头区（第三分量降级口径：读失败返回空，构造不失败）。
func (b *DSNBuilderService) originalHeaders(ctx context.Context, item *storage.QueueItem) string {
	raw, err := b.original.ReadOriginal(ctx, item.MessageID)
	if err != nil || len(raw) == 0 {
		return "" // 降级：原信不可达时不阻断 DSN 生成（退信可达性优先）
	}
	text := string(raw)
	if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
		return text[:idx]
	}
	return text
}

// dsnRecipientOf DSN 收件人（原信封 return address；null sender 特判——
// 调用方对 "<>" 已跳过生成，此处兜底防御）。
func dsnRecipientOf(item *storage.QueueItem) string {
	if item.EnvelopeFrom == "" || item.EnvelopeFrom == "<>" {
		return "postmaster@localhost" // 防御分支：不应到达（worker 已过滤）
	}
	return item.EnvelopeFrom
}

// mapStatus 末次尝试结果 → rfc3463 增强状态码（rfc3464 2.3.4：三段无前导零）。
func mapStatus(r storage.AttemptResult) string {
	switch {
	case r.SMTPCode >= 500 && r.SMTPCode < 600:
		if r.SMTPCode == 550 {
			return "5.1.1" // 邮箱不存在（rfc3463 5.1.1）
		}
		return "5.0.0" // 通用永久失败（对端增强码未解析的保守映射）
	case r.SMTPCode > 0:
		return "4.0.0" // 4xx 耗尽重试上限转 failed
	default:
		return "4.4.2" // 网络故障类（rfc3463 4.4.2）
	}
}
