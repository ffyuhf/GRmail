// Package observability 提供日志装配与 LogID 全链路传播。
// 依据：Q11 裁决（slog 门面 + phuslu/log Handler 后端 + slog-context 上下文传播）、
// NFR-016（LogID 贯穿邮件处理全链路）、系统架构总览 v1.0.0 第 5.1 节。
// 集成方式：phuslu/log v1.0.133 官方 Logger.Slog() 提供 slog.Logger 适配（复用优先，
// 不自写桥接 Handler）。
// U23 增量（日志文件落地与轮转——U21 登记项④收口，Q1-B 裁决）：logFile 空=
// ConsoleWriter 单写（逐字节等价 U22 末态）；非空=MultiEntryWriter 并行双写
// （ConsoleWriter+FileWriter——后者自带按大小/备份数轮转，源码核对 v1.0.133
// multi.go L102 遍历分发+writer.go MaxSize 字节单位+EnsureFolder 自建目录）。
// 传输安全与日志增强批次增量（L-D/L-E，G2 批准 2026-10-01 22:54:41）：
// L-E——文件侧升级为 DailyRotateWriter（按日切分+异步 gzip+保留窗——S4-W Q2-A
// 自研裁决；当日内按大小轮转仍由内层 FileWriter 承载）；L-D——新增
// ReconfigureLogger 热重建（logFile/level 类键变更经 config 订阅即时生效，无重启——
// U23「重启生效」登记口径刷新；已绑定 ctx 的旧 logger 引用在请求生命周期内继续
// 有效〔写旧 writer〕，新日志走新装配——尽力热切换语义）。
// 修改历史：
//
//	2026-09-16 04:34:00 | 新建 | U1 工程骨架
//	2026-09-16 04:41:00 | 重写 | 桥接改用官方 Slog() 入口（v1.0.133 实测 API）
//	2026-09-27 13:28:00 | 扩展 | U23 可观测性扩展：日志文件落地与轮转（Console+File
//	双写 MultiEntryWriter 并行——Q1-B；logFile 空值路径 Console 单写零变化等价锚）
//	（来源：G2 批准 2026-09-27 13:20:53，U23 计划书 v1.0.0 步骤 3/1.5①③）
package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/phuslu/log"
	slogctx "github.com/veqryn/slog-context"
)

// logFileCloser 当前文件侧 writer（热重建时关闭旧文件句柄；空值=Console 单写态）。
var (
	logCloserMu sync.Mutex
	logCloser   io.Closer
)

// SetupLogger 装配全局日志：phuslu logger → 官方 Slog() 适配为 slog.Logger → 设为 slog.Default()。
// 参数：level 日志级别字符串（debug/info/warn/error，非法值回退 info）；
// logFile 日志文件基础路径（空=仅 Console stderr 单写——逐字节等价既有形态；非空=
// Console+File 双写并行——文件侧 DailyRotateWriter 按日切分压缩 L-E）；maxMB 当日
// 按大小轮转阈值 MB（0=不按大小轮转）；backups 大小轮转备份保留份数（0=不限制）；
// retainDays 压缩归档保留天数（0=不清理）。
// 返回：根 logger。
// 配置并发批 F3②：装配段（含 SetDefault）纳入 logCloserMu——与 ReconfigureLogger
// 的关旧+重建全程互斥（消除锁外窗口内并发装配的句柄错配）。
func SetupLogger(level, logFile string, maxMB, backups, retainDays int) *slog.Logger {
	logCloserMu.Lock()
	defer logCloserMu.Unlock()
	root := buildLoggerLocked(level, logFile, maxMB, backups, retainDays)
	slog.SetDefault(root)
	return root
}

// ReconfigureLogger 热重建全局日志（L-D——logFile/level/maxMB/backups/retainDays
// 键变更经 config 订阅调用；关闭旧文件句柄→重建→SetDefault；返回新根 logger）。
// 已绑定 ctx 的 logger 引用请求生命周期内继续写旧装配（尽力热切换语义——
// 接入层每会话/每请求经 LoggerFromContext 回退 slog.Default() 即时取新）。
// 配置并发批 F3②（B-C4）：关旧+重建全程持锁——原「锁内关旧/锁外重建」两步
// 在锁外窗口内并发写经旧 writer 触达已关句柄（句柄错配）——现原子化收口。
func ReconfigureLogger(level, logFile string, maxMB, backups, retainDays int) *slog.Logger {
	logCloserMu.Lock()
	defer logCloserMu.Unlock()
	if logCloser != nil {
		_ = logCloser.Close() // 关旧文件（压缩归档由 DailyRotateWriter.Close 承载）
		logCloser = nil
	}
	root := buildLoggerLocked(level, logFile, maxMB, backups, retainDays)
	slog.SetDefault(root)
	return root
}

// buildLoggerLocked 构造 logger（文件侧 writer 登记包级可关闭句柄；调用方须已持
// logCloserMu——配置并发批 F3② 锁序统一）。
func buildLoggerLocked(level, logFile string, maxMB, backups, retainDays int) *slog.Logger {
	var writer log.Writer = &log.ConsoleWriter{ColorOutput: true} // 输出目的地默认包装 os.Stderr
	if logFile != "" {
		// Q1-B 双写：MultiEntryWriter 遍历分发全部 Writer（multi.go L102 实证）——
		// Console（终端彩色）与 File（无色落盘+轮转）各自独立格式化互不污染；
		// L-E 文件侧=DailyRotateWriter（io.Writer 契约——Entry.buf 跨包不可达，经
		// phuslu IOWriter 桥取出字节后回调；按日切分+gzip+保留窗+当日大小轮转自管）。
		fileWriter := NewDailyRotateWriter(logFile, maxMB, backups, retainDays)
		logCloser = fileWriter
		writer = &log.MultiEntryWriter{
			&log.ConsoleWriter{ColorOutput: true},
			log.IOWriter{Writer: fileWriter},
		}
	}
	phusluLogger := &log.Logger{
		Level:  phusluLevel(parseLevel(level)),
		Writer: writer,
	}
	return phusluLogger.Slog()
}

// LoggerIntoContext 将带 LogID 的 logger 绑定到 ctx（全链路传播入口，slogctx 实现）。
// 参数：ctx 原上下文；logger 待绑定 logger；返回：携带 logger 的新上下文。
func LoggerIntoContext(ctx context.Context, logger *slog.Logger) context.Context {
	return slogctx.NewCtx(ctx, logger)
}

// LoggerFromContext 从 ctx 提取 logger；未绑定时回退 slog.Default()（禁止因缺绑定而丢日志）。
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l := slogctx.FromCtx(ctx); l != nil {
		return l
	}
	return slog.Default()
}

// parseLevel 字符串级别 → slog.Level（非法值回退 info）
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// phusluLevel slog 级别 → phuslu 级别（Slog() 适配层的过滤阈值）
func phusluLevel(l slog.Level) log.Level {
	switch {
	case l <= slog.LevelDebug:
		return log.DebugLevel
	case l <= slog.LevelInfo:
		return log.InfoLevel
	case l <= slog.LevelWarn:
		return log.WarnLevel
	default:
		return log.ErrorLevel
	}
}
