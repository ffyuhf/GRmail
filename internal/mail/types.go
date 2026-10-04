// mail 域收信管道类型：投递输入载体与契约接口。
// 依据：模块接口契约 v1.1.0 2.3 节（Q1-A 裁决 2026-09-17 03:06:39：
// Deliver 入参由 env *Envelope 变更为 in *Delivery——v1.0.0 的 Envelope 无收件人
// 字段致投递判定无法进行；Delivery 嵌入 auth.Envelope 信封三元组+收件人列表，
// 多收件人单事务语义由本结构承载）；
// 关键流程设计 v1.0.0 第一章（收信时序与 451 语义）＋第二章（RCPT 三态判定）；
// SRS v1.0.0 FR-005/CON-004/NFR-007（防丢信：落库失败 RetryableError→451，禁虚假 250）。
// 修改历史：
//
//	2026-09-17 03:25:00 | 新建 | U4 SMTP 收信（计划书步骤 4，Q1-A 裁决落码）
package mail

import (
	"context"
	"errors"

	"GRmail/internal/auth"
)

// ───────────────────────── 契约接口（模块接口契约 v1.1.0 2.3 逐字） ─────────────────────────

// InboundPipeline 收信管道（SMTP 服务端注入）。
type InboundPipeline interface {
	// Deliver 多收件人单事务投递：RCPT 三态判定（active→正常；shadow→影子归档；
	// 不存在→建影子+通知，REQ-019/020）；一次 Blob 写入（CAS 去重）+ 单条 messages 行
	// +多条 mailbox_messages 行 + 影子通知邮件行同事务（关键流程设计第一章要点 4）。
	// 返回 SMTP 应答语义：落库失败→RetryableError（451），禁止虚假 250（CON-004）
	Deliver(ctx context.Context, in *Delivery, raw []byte) error
}

// ───────────────────────── 哨兵错误 ─────────────────────────

// ErrRetryable 可重试投递失败（SMTP 451 临时拒绝语义；CON-004：对端可重试，
// 禁止虚假 250——TC-021 判定①的管道侧锚点）。
var ErrRetryable = errors.New("mail: 落库失败（可重试，SMTP 451）")

// ───────────────────────── 投递输入（Q1-A：契约 v1.1.0 Delivery 结构） ─────────────────────────

// Delivery 收信投递输入（Q1-A：mail 域定义，嵌入 auth 信封）。
type Delivery struct {
	// Envelope SMTP 会话信封（Helo/RemoteIP/MailFrom；auth 域既有类型，
	// 经 smtp 服务端在 MAIL FROM/RCPT TO/DATA 完成后组装）
	Envelope auth.Envelope
	// Recipients RCPT TO 全量收件人（本域地址，小写规范化；SMTP 服务端 RCPT
	// 三态判定通过的地址集合——非本域/禁用/CatchAll 关闭时的不存在者已被 550 拒绝）
	Recipients []string
}
