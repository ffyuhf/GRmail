// main 包 U10 Setup 引导模式（Q4-A：setupCompleted=false 时仅 80 向导端点——
// 25/465/587/993/995/443 与 worker 全部零启动；完成向导后重启全量拉起）。
// 向导期安全边界（计划书 1.5③）：80 明文承载不签发会话（OWASP 跨协议会话条款）；
// 步 2 限流经 LoginAttemptRepo 复用；向导完成后本进程内 setupGate 即时禁入 /setup
// （Watcher Reload 生效），全量端点仍待重启。
// 修改历史：
//
//	2026-09-20 01:45:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 8）
package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"GRmail/internal/config"
	"GRmail/internal/protocol/web"
	"GRmail/internal/storage"
)

// runSetupMode 引导模式主循环：80 向导端点 + 信号等待 + 优雅退出。
// 参数：ctx 根上下文；logger 进程日志；watcher 配置监听（SetupDone 快照源）；
// saveConfig 配置原子读改写闭包（向导每步保存）；db 已迁移就绪的数据库连接。
func runSetupMode(ctx context.Context, logger *slog.Logger, watcher *config.Watcher,
	saveConfig func(modify func(*config.Config)) error, db *sql.DB) {
	sessions := storage.NewSQLiteSessionRepo(db)
	users := storage.NewSQLiteUserRepo(db)
	attempts := storage.NewSQLiteLoginAttemptRepo(db)

	setupServer := web.NewServer(web.ServerConfig{
		Domain: watcher.Current().Server.Domain,
		// 向导模式注入位（业务五依赖零注入——占位首页/向导不触业务路径）
		SetupDone:       func() bool { return watcher.Current().SetupCompleted },
		CfgSnapshot:     func() *config.Config { return watcher.Current() },
		SaveConfig:      saveConfig,
		SessionSnapshot: func() config.SessionConf { return watcher.Current().Session },
		LimitSnapshot:   func() config.LoginLimitConf { return watcher.Current().LoginLimit },
	}, sessions, users, attempts, nil) // accounts=nil：向导不触账号域（nil 防御沿 U8/U9 形态）

	go func() {
		if err := setupServer.ListenAndServeHTTP(":80"); err != nil {
			logger.Error("Setup 向导 80 端点异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("Setup 未完成：仅启动 80 向导端点（浏览器访问 http://<主机>/setup/1 完成部署；完成后重启进程全量拉起）")

	// 信号等待（引导态无长连接业务——收即退；defer 链负责 watcher/db 清理）
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			logger.Info("收到 SIGHUP：触发配置重载（引导态）")
			_ = watcher.Reload()
			continue
		}
		logger.Info("收到停止信号，引导态退出（向导进度已随每步落盘）", "signal", sig.String())
		break
	}
}
