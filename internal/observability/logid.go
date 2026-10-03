// LogID 生成器：邮件处理全链路关联键（NFR-016）。
// 语义：每个 SMTP 会话 / IMAP 连接 / POP3 会话 / HTTP 请求入口生成一次，
// 以 logger 属性 log_id 绑定 ctx 后随调用链传播，日志统一输出 [log_id]。
// 修改历史：
//
//	2026-09-16 04:34:00 | 新建 | U1 工程骨架（依据：系统架构总览 v1.0.0 第 5.1 节）
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
)

// logIDBytes LogID 随机字节数（16 字节 = 128bit 熵，防猜解与碰撞）
const logIDBytes = 16

// NewLogID 生成全局唯一日志关联键（CSPRNG 128bit hex，32 字符）。
// 返回：32 字符十六进制字符串；CSPRNG 失败属不可恢复系统级故障，panic 上抛。
func NewLogID() string {
	buf := make([]byte, logIDBytes)
	if _, err := rand.Read(buf); err != nil {
		panic("LogID 生成失败（CSPRNG 不可用）: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// logIDCtxKey LogID 独立 ctx 键（slog logger 属性不可逆读——SQL 注释注入〔传输安全
// 与日志增强批次 L-C〕需消费侧直接取值，经独立 key 并行承载）。
type logIDCtxKey struct{}

// ContextWithNewLogID 生成 LogID 并以 logger 属性绑定 ctx（入口统一调用点）。
// 参数：ctx 原上下文；logger 基准 logger（通常为 LoggerFromContext 取出的当前 logger）。
// 返回：携带「带 log_id 属性 logger」的新上下文与 LogID 本体。
func ContextWithNewLogID(ctx context.Context, logger *slog.Logger) (context.Context, string) {
	id := NewLogID()
	if logger == nil {
		logger = slog.Default()
	}
	ctx = context.WithValue(ctx, logIDCtxKey{}, id) // L-C：独立键并行承载（属性绑定之外）
	return LoggerIntoContext(ctx, logger.With(slog.String("log_id", id))), id
}

// LogIDFromContext 从 ctx 提取 LogID（未绑定时返回空串——消费侧自行兜底）。
// 用途：SQL 注释注入（L-C）等需 LogID 原值的观测联动点。
func LogIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(logIDCtxKey{}).(string); ok {
		return id
	}
	return ""
}
