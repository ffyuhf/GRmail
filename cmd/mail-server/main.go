// Package main 是 GRmail 邮件服务器的程序入口。
// 职责：构建信息横幅输出、配置/日志/存储的启动编排、系统信号处理（Init/Restart/Stop）。
// 协议端点挂载：U4 SMTP 收信（25）/U5 提交（465/587）/U6 IMAP（993）/U7 POP3（995）/
// U8 Web 会话与登录（HTTPS，Q2-B 双端点）；Webmail 业务归 U9、Setup 归 U10。
// 修改历史：
//
//	2026-09-16 04:33:00 | 新建 | U1 工程骨架（依据：系统架构总览 v1.0.0 第三章 cmd 职责）
//	2026-09-17 04:05:00 | 扩展 | U4 SMTP 收信：account/auth/mail 编排与 SMTP 服务端挂载
//	（依据：U4 计划书 v1.0.0 步骤 10，G2 批准 2026-09-17 03:12:40；架构总览第四章依赖方向）
//	2026-09-18 00:44:00 | 扩展 | U6 IMAP 集成：993 端点挂载+落库观察者桥接（IDLE 事件源）
//	（依据：U6 计划书 v1.0.0 步骤 7，G2 批准 2026-09-18 00:09:22；Q1-A 仅 993/Q2-A 事件驱动）
//	2026-09-19 04:09:01 | 扩展 | U7 POP3 自研：995 端点挂载+退出序插入
//	（依据：U7 计划书 v1.0.0 步骤 4，G2 批准 2026-09-19 04:09:01；SRS FR-007/rfc1939/5034）
//	2026-09-19 05:20:00 | 扩展 | U8 Web 会话与登录：HTTPS 端点挂载（Q2-B 双端点登录/
//	Q3-A 未就绪跳过+告警/Q4-B DB 限流/Q5-B 会话绑定 CSRF）+退出序插入
//	2026-09-19 15:26:00 | 扩展 | U9 Webmail 核心：7.7 装配注入业务五依赖
//	（MessageRepo/FolderRepo/MailboxRepo/BlobStore/SubmissionPipeline——契约 v1.5.0 2.4）
//	（依据：U8 计划书 v1.0.0 步骤 8，G2 批准 2026-09-19 04:56:31；SRS FR-001/NFR-006/OWASP）
//	2026-09-20 01:40:00 | 扩展 | U10 Setup 向导与 ACME：启动分流（Q4-A 未完成仅 80 向导端点/
//	完成后全量+80 双态挑战）+ACMEManager 装配与续期 goroutine+saveConfig 原子读改写闭包+
//	25 端点 TLSConfig 注入+adminLookupAdapter 经 UserRepo 收敛（Q9-A/U8 登记项①）
//	（依据：U10 计划书 v1.0.0 步骤 8，G2 批准 2026-09-20 00:32:33；契约 v1.6.0 2.4/3.1/3.3）
//	2026-09-23 12:52:00 | 扩展 | U12b 装配收口：管道 SieveRunner 注入（收信管道 Sieve 插入步
//	运行态激活）+ManageSieve 4190 挂载（七注入项——契约 v1.8.0 2.4 注记形态）+web SieveScripts
//	注入（/sieve 503 渐进态终结）+退出序插入——U12 修改文档登记项①②收口
//	（依据：U12b 计划书 v1.0.0 步骤 2/1.5②③④，G2 批准 2026-09-23 12:49:06；SRS FR-011/FR-005/IR-004）
//	2026-09-23 08:58:00 | 扩展 | U13 传输安全全量：DANE 决策器构造+sender 注入（出站 TLS 策略
//	三态——Q1-A AD 位信任）+ACME 域名清单扩展（Q3-A mta-sts 子域 SAN）+web STSPolicy 供给
//	注入（Q2-A 443 路由级承载——Host 判定+开关停发）
//	（依据：U13 计划书 v1.0.0 步骤 9/1.5①③④⑤⑦，G2 批准 2026-09-23 08:19:32；契约 v1.9.0；SRS FR-010/NFR-008）
//	2026-09-24 03:00:00 | 扩展 | U14 API Token 管理：tokenRepo 构造（For 工厂）+web Tokens
//	注入（Bearer 并列认证通道+/admin/tokens 端点族激活——Q1-A/Q3-B）；过期判定惰性承载
//	（FindValidByHash SQL 判定——沿 sessions 现状口径，PurgeExpired 预留维护接口）
//	（依据：U14 计划书 v1.0.0 步骤 5/1.5⑨，G2 批准 2026-09-24 02:30:51；契约 v1.10.0；SRS FR-013）
//	2026-09-24 03:20:00 | 扩展 | U14b Token 清理：runTokenPurgeLoop 后台任务挂载
//	（7.4.2e 装配段——24h tick 首轮即跑+尽力失败语义+rootCtx 退出联动；零接口变更）
//	（依据：U14b 计划书 v1.0.0 步骤 1/1.5①②③④⑥，G2 批准 2026-09-24 03:12:52；SRS FR-013）
//	2026-09-24 11:06:00 | 扩展 | U15 插件系统：7.4.2f 插件宿主装配（plugins/ 扫描+
//	拉起+崩溃监管——Q3-A Kill+告警+摘除不重拉）+管道双钩子链注入（收信 Verify 后/
//	发信 DKIM 后——FR-005 插件链位）+退出序插入
//	（依据：U15 计划书 v1.0.0 步骤 5/1.5⑥，G2 批准 2026-09-24 10:46:55；SRS FR-016/NFR-009）
//	2026-09-24 16:44:00 | 扩展 | U16 Webmail 体验收尾：7.4.2g 存量正文缓存回填任务
//	（ListBodyCachePending 批查→Blob 读→截断提取→FillBodyCache——Q3-A 迁移前存量
//	行补齐；尽力语义+ctx 退出联动）
//	（依据：U16 计划书 v1.0.0 步骤 3/1.5③⑨，G2 批准 2026-09-24 11:51:57；SRS FR-013）
//	2026-09-26 15:26:00 | 扩展 | U18 登记项收尾：7.4.2h/7.4.2i sessions 与 login_attempts
//	清理任务挂载（U14b 登记项①收口——PurgeExpired/PurgeOld 既有接口运行态接线；Q1-A
//	两独立循环裁决不触 Token 循环）+7.7 仓储变量化（语义等价改写）+两循环函数与保留窗常量
//	（依据：U18 计划书 v1.0.0 步骤 1/1.5①②③，G2 批准 2026-09-26 15:25:47；SRS FR-001 关联；
//	OWASP Session Expiration）
//	2026-09-27 06:21:00 | 扩展 | U21 可观测性增强：SQL 观测配置初始注入+热加载订阅
//	（3.5 步+sqlLogReloadSubscriber）+smtp/imap/pop3 三协议 ProtocolDebug 快照注入
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 2/4/1.5②⑤；阶段三"可以有"档）
//	2026-09-27 13:32:00 | 扩展 | U23 可观测性扩展：SetupLogger 四参（日志文件双写——Q1-B）
//	+submission/managesieve/web 三端点 ProtocolDebug 快照注入（U21 登记项①②④收口）
//	（来源：G2 批准 2026-09-27 13:20:53，U23 计划书 v1.0.0 步骤 7/1.5④⑤⑥⑦）
//	2026-09-28 09:33:00 | 重构 | R5R6收敛：出站装配 msgSrc 构造注入 sender——
//	原 mail.SetMessageSource 进程级单例调用行废除（架构总览 v1.0.3 8.2 R5+契约
//	v1.14.0 2.4 注记；依据：R5R6收敛计划书 v1.0.0 步骤 3，G2 批准 2026-09-28 09:31:53）
//	2026-10-03 17:10:00 | 扩展 | 发布准备批次：--version 参数早退（parseVersionFlag——
//	flag 包标准形态，-version/--version 等价；配置加载前处理，纯静态信息不依赖
//	config.json/数据库；依据：发布准备计划书 v1.0.0 1.2-VB 组，G2 批准 2026-10-03
//	17:09:00；NFR-013 构建产物元数据运维锚/CON-001 守恒）
//	2026-10-04 11:33:00 | 扩展 | HTTP端口参数化批次：-p <port> 指定 HTTP 明文端口
//	（parseHTTPPortFlag——两处 ":80" 硬编码消除：Setup 向导态+完成态 ACME 挑战/301 源；
//	覆盖值仅本次进程生效不持久化〔S3-W Q2 裁决〕；HTTPS/协议端口零触碰〔S3-W Q1 裁决〕；
//	依据：HTTP端口参数化计划书 v1.0.0 1.2-CLI/WA 组，G2 批准 2026-10-04 11:32:10；
//	SRS FR-015 判定标准「无需手工编辑任何配置文件」在无 80 权限设备的可达性收口）
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"GRmail/internal/account"
	"GRmail/internal/auth"
	"GRmail/internal/config"
	"GRmail/internal/mail"
	"GRmail/internal/observability"
	"GRmail/internal/plugin"
	imap "GRmail/internal/protocol/imap"
	"GRmail/internal/protocol/managesieve"
	"GRmail/internal/protocol/pop3"
	"GRmail/internal/protocol/smtp"
	"GRmail/internal/protocol/web"
	"GRmail/internal/sieve"
	"GRmail/internal/storage"
	"GRmail/internal/transport"
)

// 构建信息（Makefile 经 -ldflags -X 注入，CON-001 单二进制产物元数据）
var (
	version   = "dev"
	gitCommit = "unknown"
	buildTime = "unknown"
)

// configPath 运行时配置文件路径（CON-003：单一 config.json）
const configPath = "config.json"

// loginAttemptPurgeWindow login_attempts 记录保留窗（U18——U14b 登记项①收口：
// 限流窗口 15min 的远超上限，窗口外计数行全清防表膨胀；ClearSubject 成功清零
// 与本窗兜底构成双防线——数据模型 v1.3.0 3.10 维护任务语义）
const loginAttemptPurgeWindow = 30 * 24 * time.Hour

// sqlLogReloadSubscriber SQL 观测配置热加载订阅者（U21——config.Log 三键变更刷入
// storage 装饰器快照：sqlSlowMs/sqlDebug 每查询读热生效；protocolDebug 经三协议
// ServerConfig 快照函数独立承载；L-C 增 sqlCommentId 刷入——注释注入开关同链热生效）。
type sqlLogReloadSubscriber struct{}

// OnConfigChange 实现 config.Subscriber（CON-003 热加载链——沿 verifier 订阅先例）。
func (sqlLogReloadSubscriber) OnConfigChange(newCfg *config.Config) {
	storage.SetSQLLogConf(storage.SQLLogConf{SlowMs: newCfg.Log.SqlSlowMs, Debug: newCfg.Log.SqlDebug, CommentID: newCfg.Log.SqlCommentID})
}

// logReloadSubscriber 日志装配热加载订阅者（传输安全与日志增强批次 L-D——
// logFile/level/logFileMaxMB/logFileBackups/logRetainDays 五键变更经
// observability.ReconfigureLogger 热重建，无重启生效；U23「重启生效」登记口径刷新）。
type logReloadSubscriber struct{}

// OnConfigChange 实现 config.Subscriber（重建含旧文件句柄关闭与新 DailyRotateWriter 装配）。
func (logReloadSubscriber) OnConfigChange(newCfg *config.Config) {
	observability.ReconfigureLogger(newCfg.Log.Level, newCfg.Log.LogFile,
		newCfg.Log.LogFileMaxMB, newCfg.Log.LogFileBackups, newCfg.Log.LogRetainDays)
}

// parseVersionFlag 解析命令行参数中的版本查询请求（发布准备批次——计划书 1.2-VB 组）。
// 命中 -version/--version（flag 包标准形态，单双横线等价）时向标准输出打印版本三元组
// 并返回 true，调用方（main）据此早退退出 0；纯静态信息查询——不依赖 config.json
// 存在性与数据库就绪（NFR-013 构建产物元数据的运维查询锚）。解析错误静默返回 false
// （非法参数交由既有启动流程自然处理，服务行为零变化）。
func parseVersionFlag(args []string) bool {
	fs := flag.NewFlagSet("mail-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // 静默解析：usage/错误输出不混入版本查询路径
	showVersion := fs.Bool("version", false, "输出版本信息后退出")
	if err := fs.Parse(args); err != nil {
		return false
	}
	if !*showVersion {
		return false
	}
	fmt.Printf("GRmail %s (commit=%s built=%s)\n", version, gitCommit, buildTime)
	return true
}

// defaultHTTPPlainPort HTTP 明文端口缺省档（两处监听接线的统一兜底值——无 -p 参数
// 时保持既有 80 口径零变化；HTTPS 443 与协议端口不在此列，各归既有承载）。
const defaultHTTPPlainPort = 80

// parseHTTPPortFlag 解析命令行参数中的 HTTP 明文端口覆盖请求（HTTP端口参数化批次——
// 计划书 1.2-CLI 组）。
// -p <port>（flag 包标准形态：-p 8080 / -p=8080）指定 HTTP 明文端口——Setup 向导态与
// 完成态 80 端点（ACME 挑战直答+301 跳转源）统一覆盖；使无 80 绑定权限的设备（容器
// PaaS/非特权用户）可进入 Setup 向导完成引导部署（FR-015 判定标准可达性收口）。
// 参数：args 命令行参数（os.Args[1:]）。返回：端口值（0=未指定不覆盖）；错误=调用方
// 明确使用 -p 但值非法（非数字/越界 1~65535）——main 据此 stderr 提示+退出 2。
// 语义边界（S3-W 两裁决）：仅 HTTP 明文端口（HTTPS 经既有 config.json server.httpPort
// 承载）；覆盖值仅本次进程生效不持久化（config.json 零触碰——CON-003 链路零参与）。
// 非 -p 参数引发的解析错误静默返回 0（沿 parseVersionFlag 未知 flag 先例——交由既有
// 启动流程自然处理，服务行为零变化）。
func parseHTTPPortFlag(args []string) (int, error) {
	fs := flag.NewFlagSet("mail-server-http-port", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // 静默解析：usage/错误输出不混入端口覆盖路径
	port := fs.Int("p", 0, "HTTP 明文端口（Setup 向导/ACME 挑战/301 跳转源；缺省 80）")
	if err := fs.Parse(args); err != nil {
		// 区分错误归属：-p 显式出现但值非法（如 -p abc）按错误上报；其他参数
		// 引发的解析失败静默（未知 flag 沿 parseVersionFlag 先例）。
		if hasPortFlagArg(args) {
			return 0, fmt.Errorf("无效的 -p 参数: %w", err)
		}
		return 0, nil
	}
	// fs.Visit 精确判定 -p 是否被显式设置（0 不可作哨兵——显式 -p=0 为越界值
	// 须报错，与"未指定不覆盖"不可混淆）
	portSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			portSet = true
		}
	})
	if !portSet {
		return 0, nil // 未指定——不覆盖（缺省 80 兜底由 main 接线处承载）
	}
	if *port < 1 || *port > 65535 {
		return 0, fmt.Errorf("-p 端口值 %d 越界（合法范围 1~65535）", *port)
	}
	return *port, nil
}

// hasPortFlagArg 检查参数集中是否显式出现 -p（单双横线与 = 赋值三形态——
// parseHTTPPortFlag 解析失败时的错误归属判定依据）。
func hasPortFlagArg(args []string) bool {
	for _, a := range args {
		if a == "-p" || a == "--p" || strings.HasPrefix(a, "-p=") || strings.HasPrefix(a, "--p=") {
			return true
		}
	}
	return false
}

func main() {
	// 0.5 版本查询早退（发布准备批次）：早于横幅与配置加载——--version 为纯静态信息
	// 查询（NFR-013 产物元数据锚），查询路径不触碰任何启动编排与外部依赖。
	if parseVersionFlag(os.Args[1:]) {
		os.Exit(0)
	}

	// 0.6 HTTP 明文端口覆盖解析（HTTP端口参数化批次）：位于版本早退后、配置加载前——
	// -p <port> 使无 80 绑定权限的设备可进向导（FR-015 可达性收口）；值非法（明确使用
	// -p 但非数字/越界）stderr 提示+退出 2（启动期参数错误标准形态）。覆盖值仅本次进程
	// 生效（S3-W Q2 裁决——不持久化，config.json 零触碰）；缺省兜底 80（无参数零变化）。
	httpPort, err := parseHTTPPortFlag(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "参数错误: %v（用法: mail-server -p <端口 1~65535>）\n", err)
		os.Exit(2)
	}
	if httpPort <= 0 {
		httpPort = defaultHTTPPlainPort
	}

	// 1. 启动横幅：版本/提交/构建时间（可观测性锚点，供运维核对产物）
	fmt.Printf("GRmail %s (commit=%s built=%s)\n", version, gitCommit, buildTime)

	// 2. 配置加载：文件不存在时以默认值引导进入 Setup 流程（FR-015，U10 挂载）
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置加载失败: %v\n", err)
		os.Exit(1)
	}

	// 3. 日志装配：slog 门面 + phuslu/log 后端（Q11 裁决），根 ctx 携带进程级 logger。
	// U23：logFile 空=仅 Console（既有形态）；非空=Console+File 双写（Q1-B——重启生效
	// 口径与 level 同为启动装配项，热切换未承载——计划书 1.5⑦ 登记；
	// 传输安全与日志增强批次 L-D 后：logFile/level 等键热重建生效——下方订阅）。
	logger := observability.SetupLogger(cfg.Log.Level, cfg.Log.LogFile, cfg.Log.LogFileMaxMB, cfg.Log.LogFileBackups, cfg.Log.LogRetainDays)
	rootCtx := observability.LoggerIntoContext(context.Background(), logger)

	// 3.5 U21：SQL 观测配置初始注入（Q3-A——config.Log 三键；热加载订阅随 Watch 建立后刷新）
	storage.SetSQLLogConf(storage.SQLLogConf{SlowMs: cfg.Log.SqlSlowMs, Debug: cfg.Log.SqlDebug})

	// 4. 存储就绪：三库连接 + 内嵌迁移（FR-014；goose 版本化，U1 先落 SQLite 主路径）
	db, err := storage.Open(rootCtx, cfg.Database)
	if err != nil {
		logger.Error("数据库连接失败", "error", err)
		os.Exit(1)
	}
	if err := storage.MigrateUp(rootCtx, db, cfg.Database.Driver); err != nil {
		logger.Error("数据库迁移失败", "error", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// 5. CAS 字节存储：原始邮件外置（Q13 裁决），目录布局 data/blobs/ab/cd/<sha256>
	blobStore := storage.NewFileSystemBlobStore(cfg.Blob.Dir)

	// 6. 配置热加载（CON-003/FR-009：fsnotify 监听 → 去抖 → 订阅者广播）
	configWatcher, err := config.Watch(rootCtx, configPath, cfg)
	if err != nil {
		logger.Error("配置监听启动失败", "error", err)
		os.Exit(1)
	}
	defer configWatcher.Close()
	// U21：SQL 观测配置热加载订阅（config.Log 三键 → 装饰器快照——每查询读热生效；
	// L-C 第四键 sqlCommentId 同链）
	configWatcher.Subscribe(sqlLogReloadSubscriber{})
	// 传输安全与日志增强批次 L-D：日志装配热重建订阅（五键变更无重启生效）
	configWatcher.Subscribe(logReloadSubscriber{})

	// 6.5 U10 配置原子读改写闭包（向导每步+/admin/settings/ACME 回写共用——Q2-A/Q7-C）：
	// Current 快照→modify→Save 原子写→同步 Reload 广播（fsnotify 事件幂等再触发）。
	// 并发注记：单管理员低频写场景，读-改-写竞态窗口可容忍（登记 U10 修改文档第三章）。
	saveConfig := func(modify func(*config.Config)) error {
		fresh := configWatcher.Current()
		modify(fresh)
		if err := config.Save(configPath, fresh); err != nil {
			return err
		}
		return configWatcher.Reload()
	}

	// 6.6 U10 Setup 引导分流（Q4-A：setupCompleted=false=仅 HTTP 向导端点，其余端点零启动；
	// 完成向导后重启全量拉起——「监听器启动期绑定」既有口径。HTTP端口参数化批次：
	// httpPort 为 0.6 段解析值——-p 覆盖向导监听端口〔缺省 80 兜底已在此前完成〕）
	if !cfg.SetupCompleted {
		runSetupMode(rootCtx, logger, configWatcher, saveConfig, db, httpPort)
		return
	}

	// 7. U4 SMTP 收信编排（架构总览第四章：cmd→protocol/smtp→{mail,account,auth}→storage 单向链）
	// 7.1 业务域装配：账号服务（U2）+ 验证器（U3，热加载订阅 FR-009）
	// U11 FR-014：repo 按 driver 分派（三库工厂——契约 2.1 接口形态不变）
	dbDriver := cfg.Database.Driver
	mailboxRepo := storage.NewMailboxRepoFor(dbDriver, db)
	folderRepo := storage.NewFolderRepoFor(dbDriver, db)
	accounts := account.NewService(mailboxRepo, folderRepo)
	userRepo := storage.NewUserRepoFor(dbDriver, db) // U10 Q9-A：adminLookupAdapter 收敛数据源（与 web 同源）
	messageRepo := storage.NewMessageRepoFor(dbDriver, db)
	verifier := auth.NewVerifierService(auth.NewResolver(), cfg.Server.Domain, cfg.Auth)
	configWatcher.Subscribe(verifier) // 认证栈四开关热加载（TC-009 判定链）

	// 7.2 收信管道（契约 v1.1.0 2.3：验证→trace 注入→CAS 双写→影子判定→通知→事务）
	pipeline := mail.NewInboundPipelineService(verifier, accounts, blobStore, messageRepo, cfg.Server.Domain)

	// 7.3 SMTP 服务端（Q3-B：明文 25 收信；SIZE/CatchAll 经快照热生效——U4 计划书 1.5⑪；
	// U10 Q8-A：TLSConfig 快照注入——证书就绪时 EHLO 通告 STARTTLS、可选升级不强制本地投递，
	// rfc3207 §4 L129-136 MUST NOT 锚；tlsMgr 前向声明+闭包延迟解析（7.4.1 赋值））
	var tlsMgr *transport.TLSManager
	smtpServer := smtp.NewServer(smtp.ServerConfig{
		Domain: cfg.Server.Domain,
		MaxMessageSize: func() int64 {
			if n := configWatcher.Current().Mail.MaxMessageSizeBytes; n > 0 {
				return n
			}
			return 36700160 // 35MiB 缺省档（Q2-A；旧格式配置零值兜底）
		},
		CatchAllEnabled: func() bool { return configWatcher.Current().CatchAll },
		ProtocolDebug:   func() bool { return configWatcher.Current().Log.ProtocolDebug }, // U21 协议 debug 快照
		TLSConfig: func() *tls.Config {
			if tlsMgr == nil {
				return nil
			}
			return tlsMgr.ServerTLSConfig(cfg.Server.Domain) // 启动期域名常量（7.4.2 前引用规避）
		},
	}, pipeline, accounts)
	go func() {
		port := configWatcher.Current().Server.SMTPPort
		if port <= 0 {
			port = 25 // 缺省档（Q2-A；监听器启动期绑定——重启生效）
		}
		if err := smtpServer.ListenAndServe(fmt.Sprintf(":%d", port)); err != nil {
			logger.Error("SMTP 收信服务异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("SMTP 收信监听已启动（U4 明文；STARTTLS 归 U10）")

	// 7.4 U5 提交与投递编排（Q2-A/Q3-A/Q4-A/Q5-C/Q6-A 修订/Q7-A 裁决；架构第四章单向链）
	// 7.4.1 transport TLS 证书中心（订阅 config 路径变更热重载+证书文件替换热重载）
	tlsMgr, err = transport.NewTLSManager(cfg.TLS) // var 前向声明于 7.3（U10 25 端点注入）
	if err != nil {
		logger.Error("TLS 证书初始加载失败", "error", err)
		os.Exit(1)
	}
	configWatcher.Subscribe(tlsMgr)
	rootCtxTLS, cancelTLS := context.WithCancel(rootCtx)
	defer cancelTLS()
	if err = tlsMgr.WatchCertFiles(rootCtxTLS); err != nil {
		logger.Error("证书热重载监听启动失败", "error", err)
	}
	// 7.4.2 提交管道（契约 v1.2.0 2.3：授权判定→DKIM→头补齐→Blob+messages+queue 单事务）
	domain := cfg.Server.Domain
	queueRepo := storage.NewQueueStoreFor(dbDriver, db)     // U11：含 StoreSubmission（mail 窄接口超集）
	signerSvc, serr := auth.NewSignerService(cfg.Auth.DKIM) // U3 DKIM 出站签名（Q1-A 键管理）
	var signer outboundSignerAdapter
	if serr != nil {
		logger.Warn("DKIM 签名器未就绪（未配置/键异常——出站信未签名态投递，部署渐进）", "error", serr)
		signer = outboundSignerAdapter{}
	} else {
		signer = outboundSignerAdapter{inner: signerSvc}
	}
	submissionPipeline := mail.NewSubmissionPipelineService(signer, blobStore, queueRepo,
		adminLookupAdapter{users: userRepo}, domain) // U10 Q9-A：经 UserRepo 收敛（U8 登记项①）

	// 7.4.2b U12b Sieve 装配（U12 修改文档登记项①收口——契约 v1.8.0 2.3/2.4 注入形态）：
	// Runner 取激活脚本求值（sieve.NewRunner——收信管道 Sieve 插入步运行态激活，nil 注入终结）；
	// redirect 回流通道=queueRepo（QueueStore 超集满足 redirectStore 窄接口——StoreSubmission
	// 直达，绕授权/零重签/空信封保持，U12 计划书 1.5③ 口径）
	sieveRepo := storage.NewSieveScriptRepoFor(dbDriver, db)
	pipeline.SetSieveRunner(sieve.NewRunner(sieveRepo), queueRepo)
	logger.Info("收信管道 Sieve 插入步已激活（U12b：按收件邮箱执行激活脚本，无脚本直达 INBOX）")

	// 7.4.2d U14 API Token 仓储（FR-013 Token 管理子项——Bearer 并列认证数据源+/admin/tokens
	// 端点族；过期判定惰性承载：FindValidByHash SQL 内 expires_at 判定（沿 sessions 惰性
	// 删除现状口径——PurgeExpired 预留维护接口，与 SessionRepo.PurgeExpired 同现状）
	tokenRepo := storage.NewTokenRepoFor(dbDriver, db)

	// 7.4.2e U14b Token 过期清理后台任务（U14 修改文档登记项③收口——契约 v1.10.0
	// 2.1 PurgeExpired 既有接口运行态接线，零签名变更）：24h tick 首轮即跑（清理
	// U14 交付以来存量过期行——expires_at 索引主路径投入运行态）；尽力失败语义
	// （Warn 不中断——下轮 tick 自愈，沿 TouchLastUsed 尽力先例）；ctx 派生
	// rootCtx——信号退出联动取消（沿 cancelACME/cancelWorker 先例）
	purgeCtx, cancelPurge := context.WithCancel(rootCtx)
	defer cancelPurge()
	go runTokenPurgeLoop(purgeCtx, tokenRepo, 24*time.Hour, logger)
	logger.Info("Token 过期清理任务已启动（U14b：24h 周期，首轮清理存量过期行）")

	// 7.4.2f U15 插件宿主（FR-016：plugins/ 扫描→拉起→崩溃监管——Q3-A 处置=
	// Kill+告警+链路摘除，不自动重拉；零插件/目录缺失=Warn 零插件态正常承载；
	// 钩子链空注入=管道 U14b 末态等价——nil 语义锚）；ctx 派生 rootCtx（监管
	// goroutine 退出联动——沿 cancelPurge/cancelWorker 先例）
	pluginCtx, cancelPlugins := context.WithCancel(rootCtx)
	defer cancelPlugins()
	pluginHost := plugin.NewSupervisor(pluginCtx, "plugins", logger)
	pipeline.SetPluginHooks(pluginHost.InboundHooks())
	submissionPipeline.SetSubmitHooks(pluginHost.SubmitHooks())

	// 7.4.2g U16 存量正文缓存回填任务（Q3-A——迁移 00005 前存量行 body_cache 补齐：
	// 批查 WHERE body_cache IS NULL →Blob 读→BodyCacheOf 截断提取→FillBodyCache；
	// 尽力语义（单行失败跳过计数 Warn——缓存可重建，下轮启动重跑自然收敛）；
	// ctx 派生 rootCtx——信号退出联动（沿 cancelPurge 先例）
	go runBodyCacheBackfill(rootCtx, messageRepo, blobStore, logger)
	logger.Info("正文缓存回填任务已启动（U16：存量行渐进补齐——body_cache 搜索维度全覆盖）")

	// 7.4.2j U25 存量影子归档回填任务（S3-W Q4 裁决 2026-10-02 19:31:14——shadow
	// 邮箱历史归档信补聚合副本：ListShadowBackfill 批查→CopyToAggregateFolder 逐条；
	// NOT EXISTS 幂等——重跑自然跳过；尽力语义+失败熔断+ctx 退出联动沿
	// runBodyCacheBackfill 先例）
	go runAggregateBackfill(rootCtx, accounts, messageRepo, domain, logger)
	logger.Info("影子归档聚合回填任务已启动（U25：存量 shadow 来信补聚合副本）")

	// 7.4.2h U18 sessions 过期清理后台任务（U14b 修改文档登记项①收口——契约 v1.4.0
	// 2.1 PurgeExpired 既有接口运行态接线，零签名变更）：24h tick 首轮即跑（清理
	// 历史累积过期会话——OWASP Session Expiration 服务端强制语义的存储侧配套；
	// 数据模型 3.6「过期清理任务」索引注记兑现）；尽力失败语义（Warn 不中断——
	// 下轮 tick 自愈，沿 runTokenPurgeLoop 先例）；ctx 派生 rootCtx——信号退出联动
	sessionRepo := storage.NewSessionRepoFor(dbDriver, db)
	sessionPurgeCtx, cancelSessionPurge := context.WithCancel(rootCtx)
	defer cancelSessionPurge()
	go runSessionPurgeLoop(sessionPurgeCtx, sessionRepo, 24*time.Hour, logger)
	logger.Info("会话过期清理任务已启动（U18：24h 周期，首轮清理存量过期会话）")

	// 7.4.2i U18 login_attempts 旧记录清理后台任务（U14b 登记项①收口——
	// LoginAttemptRepo.PurgeOld 既有接口运行态接线）：24h tick 首轮即跑；保留窗
	// loginAttemptPurgeWindow=30d 工程常量（限流窗口 15min≪30d——计数功能零影响）；
	// 尽力失败+ctx 联动同上（Q1-A 两独立循环裁决——不触 Token 循环）
	loginAttemptRepo := storage.NewLoginAttemptRepoFor(dbDriver, db)
	loginPurgeCtx, cancelLoginPurge := context.WithCancel(rootCtx)
	defer cancelLoginPurge()
	go runLoginAttemptPurgeLoop(loginPurgeCtx, loginAttemptRepo, 24*time.Hour, logger)
	logger.Info("登录尝试记录清理任务已启动（U18：24h 周期，保留 30 天）")

	// 7.4.2c U13 DANE 决策器（Q1-A AD 位信任——resolv.conf 递归服务器 DO 位查询+AD 位判定；
	// 构造失败（无 resolv.conf 等）降级为 nil 注入=全量机会 TLS——功能不失效（NFR-008 语义），
	// 沿「未就绪跳过+告警」先例）
	var daneVal mail.DaneValidator
	if daneEx, derr := transport.NewProdDNSSECExchange(); derr != nil {
		logger.Warn("DANE 决策器不可用（出站全量机会 TLS 降级——NFR-008 语义）", "error", derr)
	} else {
		daneVal = daneValidatorAdapter{inner: transport.NewDaneService(daneEx)}
	}

	// 7.4.3 出站投递+DSN+worker（2 池按域串行，Q6 修订；U13：TLS 策略步 DANE 三态注入；
	// R5R6收敛：msgSrc 构造注入 sender——原 SetMessageSource 进程级单例废除）
	msgSrc := &dbMessageSource{db: db, blobs: blobStore}
	sender := mail.NewOutboundSenderService(domain, pipeline, mail.DNSMXResolver{}, mail.NetDialer{}, daneVal, msgSrc)
	// ── 传输安全与日志增强批次 L-A/L-B 注入（契约 v1.21.0 2.3——可选 setter，沿
	// SetSieveRunner 先例构造签名零变更；rfc8461 §4/§5 发送侧验证+rfc8460 §4 采集）──
	stsSender := transport.NewSTSSenderService()
	sender.SetSTSValidator(stsValidatorAdapter{inner: stsSender})
	tlsrptAgg := transport.NewTLSRPTAggregator()
	sender.SetTLSReporter(tlsrptRecorderAdapter{inner: tlsrptAgg})
	go runTLSRPTRoutine(rootCtx, tlsrptAgg, submissionPipeline, domain, logger)
	dsnBuilder := mail.NewDSNBuilderService(domain, msgSrc)
	worker := mail.NewQueueWorker(queueRepo, sender, dsnBuilder, signer, blobStore,
		func() config.DeliveryConf { return configWatcher.Current().Mail.Delivery }, domain)
	workerCtx, cancelWorker := context.WithCancel(rootCtx)
	defer cancelWorker()
	stopped := worker.Start(workerCtx) // 启动崩溃恢复（ReclaimStale 10min）+双 goroutine
	// 7.4.4 提交端点双端口（465 隐式 TLS 证书未配置跳过+告警，1.5⑫；587 明文 STARTTLS）
	// U23：协议 debug 收口（U21 登记项①）——独立 submitSession 补齐 debugFrame 埋点，
	// 快照注入与三协议同形态（每会话/每帧读热生效）。
	submissionServer := smtp.NewSubmissionServer(smtp.SubmissionConfig{
		Domain:         domain,
		MaxMessageSize: func() int64 { return configWatcher.Current().Mail.MaxMessageSizeBytes },
		TLSConfig:      func() *tls.Config { return tlsMgr.ServerTLSConfig(domain) },
		ProtocolDebug:  func() bool { return configWatcher.Current().Log.ProtocolDebug }, // U23 协议 debug 快照（proto=submission）
	}, submissionPipeline, credentialVerifierAdapter{inner: accounts.VerifyCredentials})
	go func() {
		cur := configWatcher.Current().Server
		subPort, tlsPort := cur.SubmissionPort, cur.SubmissionTLSPort
		if subPort <= 0 {
			subPort = 587
		}
		if tlsPort <= 0 {
			tlsPort = 465
		}
		if err := submissionServer.ListenAndServe(fmt.Sprintf(":%d", tlsPort), fmt.Sprintf(":%d", subPort)); err != nil {
			logger.Error("提交端点异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("SMTP 提交端点与投递 worker 已启动（U5：465 隐式/587 STARTTLS；worker 2 池按域串行）")

	// 7.5 U6 IMAP 编排（Q1-A 仅 993 隐式 TLS/Q2-A IDLE 事件驱动；架构第四章单向链：
	// protocol/imap → {account,storage}，transport TLS 注入）
	imapServer := imap.NewServer(imap.ServerConfig{
		Domain: domain,
		TLSConfig: func() *tls.Config {
			return tlsMgr.ServerTLSConfig(domain)
		},
		MaxAppendSize: func() int64 { return configWatcher.Current().Mail.MaxMessageSizeBytes },
		ProtocolDebug: func() bool { return configWatcher.Current().Log.ProtocolDebug }, // U21 协议 debug 快照（DebugWriter 条件输出）
	}, accounts, messageRepo, blobStore)
	// 落库观察者桥接（Q2-A：InboundPipeline → Notifier → IDLE 会话实时 EXISTS）
	pipeline.SetObserver(imapServer.NotifierAccessor())
	go func() {
		imapPort := configWatcher.Current().Server.IMAPPort
		if imapPort <= 0 {
			imapPort = 993 // 缺省档（Q1-A；监听器启动期绑定——重启生效）
		}
		if err := imapServer.ListenAndServeTLS(fmt.Sprintf(":%d", imapPort)); err != nil {
			if err == imap.ErrTLSNotReady {
				logger.Warn("IMAP 993 端点跳过（TLS 证书未配置——配置后重启生效）", "error", err)
				return
			}
			logger.Error("IMAP 服务异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("IMAP 993 端点已启动（U6：IMAP4rev2+IDLE+LITERAL+/UTF8=ACCEPT；仅隐式 TLS）")

	// 7.6 U7 POP3 编排（Q1-A QUIT=HardDelete/Q2-A 仅 AUTH PLAIN/Q3-A CAPA+UIDL+TOP+
	// PIPELINING/Q4-A 明文连接 AUTH 拒绝；架构第四章单向链：protocol/pop3 →
	// {account,storage}，transport TLS 注入；契约 v1.3.1 2.4 预登记形态）
	pop3Server := pop3.NewServer(pop3.ServerConfig{
		Domain: domain,
		TLSConfig: func() *tls.Config {
			return tlsMgr.ServerTLSConfig(domain)
		},
		ProtocolDebug: func() bool { return configWatcher.Current().Log.ProtocolDebug }, // U21 协议 debug 快照（命令响应面条件输出）
	}, accounts, messageRepo, folderRepo, blobStore)
	go func() {
		pop3Port := configWatcher.Current().Server.POP3Port
		if pop3Port <= 0 {
			pop3Port = 995 // 缺省档（U7 计划书步骤 1；监听器启动期绑定——重启生效）
		}
		if err := pop3Server.ListenAndServeTLS(fmt.Sprintf(":%d", pop3Port)); err != nil {
			if err == pop3.ErrTLSNotReady {
				logger.Warn("POP3 995 端点跳过（TLS 证书未配置——配置后重启生效）", "error", err)
				return
			}
			logger.Error("POP3 服务异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("POP3 995 端点已启动（U7：rfc1939 全命令集+AUTH PLAIN+UIDL/TOP/PIPELINING；仅隐式 TLS）")

	// 7.6.5 U12b ManageSieve 编排（4190 明文承载+STARTTLS 可选升级——契约 v1.8.0 2.4 注入
	// 形态七项；无条件挂载：无证书时 STARTTLS 不通告、SASL 能力空=只读不可认证态，与 25 端口
	// 明文收信同口径——U12b 计划书 1.5③⑦；AUTHENTICATE PLAIN 主体=mailbox active 经
	// accounts 防枚举复用；HAVESPACE 配额缺省档 10 脚本/64KB——U12 计划书 1.5⑦ G2 已批复）
	sieveManageServer := managesieve.NewServer(managesieve.ServerConfig{
		Port:     configWatcher.Current().Server.ManageSievePort,
		Accounts: accounts,
		Scripts:  sieveRepo,
		Validate: func(src string) error { _, err := sieve.Parse(src); return err }, // PUTSCRIPT/CHECKSCRIPT 编译期校验
		TLSConfig: func() *tls.Config {
			return tlsMgr.ServerTLSConfig(domain) // STARTTLS 快照（nil 返回=未就绪不通告）
		},
		ProtocolDebug: func() bool { return configWatcher.Current().Log.ProtocolDebug }, // U23 协议 debug 快照（命令响应面条件输出）
		Domain:        domain,
	})
	go func() {
		if err := sieveManageServer.ListenAndServe(); err != nil {
			logger.Error("ManageSieve 4190 端点异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("ManageSieve 4190 端点已启动（U12b：rfc5804 命令族+STARTTLS+AUTH PLAIN；明文承载）")

	// 7.7 U8+U9+U10 Web 编排（架构第四章单向链：protocol/web → {account,mail,storage}，
	// transport TLS 注入；契约 v1.6.0 2.4 形态——U8：SessionRepo/UserRepo/LoginAttemptRepo+
	// account 服务注入 Gin 中间件；U9：MessageRepo/FolderRepo/MailboxRepo/BlobStore/
	// SubmissionPipeline 注入业务路由——写信经 mail 域同链路复用，流程设计 3.1；
	// U10：config 读写/快照函数/ACME 挑战表注入（设置页+向导已完成态分流））
	acmeMgr := transport.NewACMEManager(domain,
		func() config.ACMEConf { return configWatcher.Current().ACME },
		func(certFile, keyFile string) error {
			return saveConfig(func(c *config.Config) {
				c.TLS.CertFile = certFile
				c.TLS.KeyFile = keyFile
			})
		})
	// U13 Q3-A：MTA-STS 启用时签发/续期清单含 mta-sts.<主域>（SAN 覆盖策略宿主——
	// rfc8461 §3.3；HTTP-01 双域名挑战经既有 80 路由承载；开关热加载——关闭后下次续期收窄）
	acmeMgr.SetStsEnabled(func() bool { return configWatcher.Current().MTASts.Enabled })
	if cur := configWatcher.Current().ACME; cur.Enabled {
		// Q6-A：首签/补签异步尝试（每日 tick 兜底重试；落盘后回写 config→TLSManager 热重载链）
		acmeCtx, cancelACME := context.WithCancel(rootCtx)
		defer cancelACME()
		go func() {
			if err := acmeMgr.EnsureIssued(acmeCtx); err != nil {
				logger.Warn("ACME 首签未完成（每日检查自动重试）", "error", err)
			}
		}()
		go acmeMgr.Run(acmeCtx) // 续期循环（ctx 取消即退——退出序联动）
	}
	webServer := web.NewServer(web.ServerConfig{
		Domain: domain,
		TLSConfig: func() *tls.Config {
			return tlsMgr.ServerTLSConfig(domain)
		},
		Messages:  messageRepo,
		Folders:   folderRepo,
		Mailboxes: mailboxRepo,
		Blobs:     blobStore,
		Submit:    submissionPipeline,
		// ── U10 增量注入（契约 v1.6.0 2.4）──
		SetupDone:       func() bool { return configWatcher.Current().SetupCompleted },
		CfgSnapshot:     func() *config.Config { return configWatcher.Current() },
		SaveConfig:      saveConfig,
		SessionSnapshot: func() config.SessionConf { return configWatcher.Current().Session },
		LimitSnapshot:   func() config.LoginLimitConf { return configWatcher.Current().LoginLimit },
		Challenge:       acmeMgr.Store(),
		// ── U12b 增量注入（契约 v1.8.0 2.4——/sieve 端点族 503 渐进态终结）──
		SieveScripts: sieveRepo,
		// ── U14 增量注入（契约 v1.10.0 2.4——Bearer 通道+/admin/tokens 端点族激活）──
		Tokens: tokenRepo,
		// ── U24 增量注入（契约 v1.20.0 2.4——/settings/2fa 端点族+登录二步+强制
		// 引导门卫激活；mailboxRepo 同源——FR-018 Webmail 双因素认证）──
		TwoFactor: account.NewTwoFactorService(mailboxRepo),
		// ── U23 增量注入（HTTP 请求摘要 debug 中间件——Q2-A 条件输出热生效）──
		ProtocolDebug: func() bool { return configWatcher.Current().Log.ProtocolDebug },
		// ── U13 增量注入（契约 v1.9.0 2.4——mta-sts 端点 Q2-A 443 路由级承载）──
		STSPolicy: func() (string, bool) {
			cur := configWatcher.Current() // 每请求快照热生效（判定③：关闭即停发——无重启链）
			return transport.STSPolicyText(cur.Server.Domain, cur.MTASts), cur.MTASts.Enabled
		},
	}, sessionRepo, userRepo, loginAttemptRepo, accounts) // U18：7.4.2h/i 变量化复用（语义等价改写）
	// U10 Q3-A：HTTP 端点双态（完成态=ACME 挑战直答+其余 301 https；向导已完成故不走向导
	// 分支）。HTTP端口参数化批次：监听端口经 httpPort 接线（-p 覆盖/缺省 80——0.6 段兜底后
	// 恒为有效值 1~65535）
	go func() {
		if err := webServer.ListenAndServeHTTP(fmt.Sprintf(":%d", httpPort)); err != nil {
			logger.Error("Web HTTP 端点异常退出", "error", err, "port", httpPort)
			os.Exit(1)
		}
	}()
	logger.Info("Web HTTP 端点已启动", "port", httpPort, "用途", "ACME 挑战直答+301 跳转 HTTPS")
	go func() {
		webPort := configWatcher.Current().Server.HTTPPort
		if webPort <= 0 {
			webPort = 443 // 缺省档（config HTTPPort 注释口径；监听器启动期绑定——重启生效）
		}
		if err := webServer.ListenAndServeTLS(fmt.Sprintf(":%d", webPort)); err != nil {
			if err == web.ErrTLSNotReady {
				logger.Warn("Web HTTPS 端点跳过（TLS 证书未配置——配置后重启生效；Setup 载体归 U10）", "error", err)
				return
			}
			logger.Error("Web 服务异常退出", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("Web HTTPS 端点已启动（U8：双端点登录+OWASP 会话基线；U9：Webmail 核心+admin 邮箱管理）")

	// 7. 信号处理：SIGINT/SIGTERM 优雅停止；SIGHUP 触发配置重载（Restart 语义）
	logger.Info("GRmail 启动完成", "version", version, "driver", cfg.Database.Driver)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			logger.Info("收到 SIGHUP：触发配置重载")
			_ = configWatcher.Reload()
			continue
		}
		logger.Info("收到停止信号，开始优雅退出", "signal", sig.String())
		break
	}

	// 8. 优雅退出（U8 退出序：Web 关（HTTP 优先停，新请求最先拒）→停提交监听→IMAP 关
	//	（IDLE 会话终结）→POP3 关（在途会话终结）→worker 停（drain in_flight）→25 收信关
	//	→TLS/配置/DB 关）
	webShutdownCtx, cancelWebShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWebShutdown()
	if err := webServer.Shutdown(webShutdownCtx); err != nil {
		logger.Error("Web 关闭异常", "error", err)
	}
	if err := submissionServer.Shutdown(); err != nil {
		logger.Error("提交端点关闭异常", "error", err)
	}
	if err := imapServer.Shutdown(); err != nil {
		logger.Error("IMAP 关闭异常", "error", err)
	}
	if err := pop3Server.Shutdown(); err != nil {
		logger.Error("POP3 关闭异常", "error", err)
	}
	if err := sieveManageServer.Shutdown(); err != nil { // U12b：协议端点链（POP3 后、worker 前——1.5④）
		logger.Error("ManageSieve 关闭异常", "error", err)
	}
	pluginHost.Shutdown() // U15：插件子进程停止（协议端点链后——计划书 1.5⑥）
	cancelWorker()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		logger.Warn("worker drain 超时，强制继续退出")
	}
	if err := smtpServer.Shutdown(); err != nil {
		logger.Error("SMTP 关闭异常", "error", err)
	}
	_ = tlsMgr.Close()
	if err := configWatcher.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		logger.Error("配置监听关闭异常", "error", err)
	}
	logger.Info("GRmail 已停止")
}

// runTokenPurgeLoop Token 过期清理循环（U14b——计划书 1.5①②③）：
// 首轮立即执行（清理存量过期行），此后每 period 一轮；单轮失败尽力 Warn（不 panic
// 不退出——后台维护任务非关键路径，下轮 tick 自愈）；ctx 取消即返回。
// 参数：ctx 生命周期（rootCtx 派生——信号退出联动）；tokens Token 仓储（PurgeExpired
// 既有接口——契约 v1.10.0 2.1，删除 expires_at 非空且≤now 的行）；period 清理周期
// （生产 24h 工程常量/测试注入短周期）；logger 日志器。
// 返回：无（goroutine 形态——经 ctx 取消终止）。
// SRS 条目：FR-013（3.8）Token 管理子项运维补强；TC-013 关联锚；CON-002 纯标准库。
func runTokenPurgeLoop(ctx context.Context, tokens storage.TokenRepo, period time.Duration, logger *slog.Logger) {
	purgeOnce := func() {
		n, err := tokens.PurgeExpired(ctx, time.Now().UTC())
		if err != nil {
			logger.Warn("Token 过期清理失败（下轮自动重试）", "error", err)
			return
		}
		if n > 0 {
			logger.Info("Token 过期清理完成", "purged", n)
		}
	}
	purgeOnce() // 首轮立即——清理存量过期行（U14 交付以来积压）
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purgeOnce()
		}
	}
}

// runBodyCacheBackfill 存量正文缓存回填循环（U16 Q3-A——计划书 1.5③⑨）：
// 批查 body_cache IS NULL 行→读 Blob→BodyCacheOf 截断提取→FillBodyCache 单行回填；
// 全量补齐后退出（新写入路径已即时填充——本任务仅收口存量）；单行失败跳过计数
// Warn（缓存可重建——下轮启动重跑自然收敛）；ctx 取消即返回。
// 参数：ctx 生命周期（rootCtx——信号退出联动）；messages 邮件仓储（批查+回填）；
// blobs 字节存储（读源）；logger 日志器。
// 返回：无（goroutine 形态——补齐即退）。
// SRS 条目：FR-013（3.8 正文检索子项——存量行搜索维度渐进覆盖）；契约 v1.12.0 2.1。
func runBodyCacheBackfill(ctx context.Context, messages storage.MessageRepo, blobs storage.BlobStore, logger *slog.Logger) {
	const batch = 500
	done, failed := 0, 0
	for {
		if ctx.Err() != nil {
			return
		}
		rows, err := messages.ListBodyCachePending(ctx, batch)
		if err != nil {
			logger.Warn("正文缓存回填批查失败（下轮启动重试）", "error", err)
			return
		}
		if len(rows) == 0 {
			if done > 0 {
				logger.Info("正文缓存回填完成", "filled", done, "skipped", failed)
			}
			return
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				return
			}
			raw, rerr := blobs.Read(ctx, row.BlobKey)
			if rerr != nil {
				failed++
				continue // Blob 缺失行跳过（对账任务另行标记——职责分离）
			}
			if err := messages.FillBodyCache(ctx, row.ID, mail.BodyCacheOf(raw)); err != nil {
				failed++
				continue
			}
			done++
		}
	}
}

// runAggregateBackfill 存量影子归档回填任务（U25——S3-W Q4 裁决：shadow 邮箱历史
// 归档信一次性补聚合副本至 postmaster Unregistered 文件夹，与 Q2 删除级联覆盖面
// 一致——新旧信统一可见统一可删）。收敛循环：批查（NOT EXISTS 幂等——已补行自然
// 消失）→逐条补写；单条失败跳过计数 Warn 尽力（失败行下轮批查仍命中——failed 超
// 熔断阈值终止防持续失败死循环，下次启动续跑）；ctx 取消即返回（剩余下次启动续跑）。
// 参数：ctx 生命周期（rootCtx——信号退出联动）；accounts 账号域（postmaster 邮箱
// 确保）；messages 邮件仓储（批查+补写）；domain 主域；logger 日志器。
// 返回：无（goroutine 形态）。
// SRS 条目：FR-003（3.1.3——存量覆盖面补全）；契约 v1.22.0 2.1 两新方法消费位。
func runAggregateBackfill(ctx context.Context, accounts *account.Service, messages storage.MessageRepo, domain string, logger *slog.Logger) {
	pm, err := accounts.EnsurePostmasterMailbox(ctx, domain)
	if err != nil {
		logger.Warn("聚合回填：postmaster 邮箱确保失败（任务终止）", "error", err)
		return
	}
	const batch = 500
	const failFast = 1000 // 失败熔断阈值（防持续失败行死循环——下次启动续跑）
	done, failed := 0, 0
	for {
		if ctx.Err() != nil {
			logger.Info("聚合回填：ctx 退出（剩余下次启动续跑）", "done", done)
			return
		}
		ids, err := messages.ListShadowBackfill(ctx, batch)
		if err != nil {
			logger.Warn("聚合回填批查失败（已处理部分保留，下次启动续跑）", "error", err, "done", done)
			return
		}
		if len(ids) == 0 {
			if done > 0 || failed > 0 {
				logger.Info("聚合回填完成", "copied", done, "failed", failed)
			}
			return
		}
		for _, mid := range ids {
			if ctx.Err() != nil {
				logger.Info("聚合回填：ctx 退出（剩余下次启动续跑）", "done", done)
				return
			}
			if cerr := messages.CopyToAggregateFolder(ctx, pm.ID, mid); cerr != nil {
				failed++
				logger.Warn("聚合回填：单条补写失败（跳过）", "message_id", mid, "error", cerr)
				continue
			}
			done++
		}
		if failed >= failFast {
			logger.Warn("聚合回填：失败熔断终止（下次启动续跑）", "done", done, "failed", failed)
			return
		}
	}
}

// runSessionPurgeLoop 会话过期清理循环（U18——U14b 登记项①收口，Q1-A 两独立循环裁决）：
// 首轮立即执行（清理历史累积过期会话——U8 交付以来积压），此后每 period 一轮；单轮失败
// 尽力 Warn（不 panic 不退出——后台维护任务非关键路径，下轮 tick 自愈）；ctx 取消即返回。
// 参数：ctx 生命周期（rootCtx 派生——信号退出联动）；sessions 会话仓储（PurgeExpired
// 既有接口——契约 v1.4.0 2.1，删除 absolute_expires_at≤now 的行）；period 清理周期
// （生产 24h 工程常量/测试注入短周期）；logger 日志器。
// 返回：无（goroutine 形态——经 ctx 取消终止）。
// SRS 条目：FR-001（3.1）会话承载运维关联；OWASP Session Expiration；TC-001 关联锚；CON-002 纯标准库。
func runSessionPurgeLoop(ctx context.Context, sessions storage.SessionRepo, period time.Duration, logger *slog.Logger) {
	purgeOnce := func() {
		n, err := sessions.PurgeExpired(ctx, time.Now().UTC())
		if err != nil {
			logger.Warn("会话过期清理失败（下轮自动重试）", "error", err)
			return
		}
		if n > 0 {
			logger.Info("会话过期清理完成", "purged", n)
		}
	}
	purgeOnce() // 首轮立即——清理存量过期会话（U8 交付以来积压）
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purgeOnce()
		}
	}
}

// runLoginAttemptPurgeLoop 登录尝试旧记录清理循环（U18——U14b 登记项①收口）：
// 每轮删除 attempted_at 早于 now-loginAttemptPurgeWindow 的行（30d 保留窗——窗口外
// 全清防膨胀，窗口内计数行不受影响）；其余语义同 runSessionPurgeLoop（首轮立即+
// 尽力 Warn+ctx 退出联动——沿 runTokenPurgeLoop 逐条样板）。
// 参数：ctx 生命周期（rootCtx 派生）；attempts 登录尝试仓储（PurgeOld 既有接口
// ——契约 v1.4.0 2.1）；period 清理周期（生产 24h 工程常量/测试注入短周期）；logger 日志器。
// 返回：无（goroutine 形态——经 ctx 取消终止）。
// SRS 条目：FR-001（3.1）登录限流运维关联（数据模型 v1.3.0 3.10「维护任务 PurgeOld
// 防膨胀」注记兑现）；TC-001 关联锚；CON-002 纯标准库。
func runLoginAttemptPurgeLoop(ctx context.Context, attempts storage.LoginAttemptRepo, period time.Duration, logger *slog.Logger) {
	purgeOnce := func() {
		n, err := attempts.PurgeOld(ctx, time.Now().UTC().Add(-loginAttemptPurgeWindow))
		if err != nil {
			logger.Warn("登录尝试记录清理失败（下轮自动重试）", "error", err)
			return
		}
		if n > 0 {
			logger.Info("登录尝试记录清理完成", "purged", n)
		}
	}
	purgeOnce() // 首轮立即——清理窗口外积压行
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purgeOnce()
		}
	}
}

// runTLSRPTRoutine TLS-RPT 每日报告周期任务（传输安全与日志增强批次 L-B——rfc8460
// §4.1 全天报告窗+§5.3 邮件投递；沿 runTokenPurgeLoop 周期样板：ctx 退出联动+尽力
// 失败语义。报告窗=本轮 tick 前一整天〔UTC 00:00-24:00 对齐〕；多部署实例因启动
// 时刻各异天然错峰〔§4.1 随机延迟建议的工程等价〕）。
// 参数：ctx 生命周期（rootCtx）；agg 内存聚合器；submit 提交管道（DKIM 签名+入队
// 既有链承载——rfc8460 §3 mailto 报告 MUST DKIM）；domain 本域（提交方身份）；logger。
func runTLSRPTRoutine(ctx context.Context, agg *transport.TLSRPTAggregator, submit mail.SubmissionPipeline, domain string, logger *slog.Logger) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		runTLSRPTReportRound(ctx, agg, submit, domain, logger)
	}
}

// runTLSRPTReportRound 单轮报告：统计快照读出清零→逐策略域发现 rua（_smtp._tls
// TXT）→构造 JSON（§4.4）+gzip（§5.2 SHOULD）+报告邮件（§5.3 multipart/report）
// →经 Submit 入队（信封 null path：authorizeSender 放行+DSN 同款防退信循环语义；
// 报告投递不因 TLS 失败永久拒发——既有队列 deferred 重试链承载 §5.3 MUST NOT）。
// 统计已读出清零：单域提交失败即损失本期该域报告（尽力语义——Warn 落日志，真发送
// 归 D7 部署域实录）；sending-mta-ip 首版空串（多网卡/NAT 环境不可静态判定——登记）。
func runTLSRPTReportRound(ctx context.Context, agg *transport.TLSRPTAggregator, submit mail.SubmissionPipeline, domain string, logger *slog.Logger) {
	stats := agg.SnapshotAndReset()
	if len(stats) == 0 {
		return // 本周期零流量零报告（§4.2.1 成功心跳语义不适用——零会话域不产生报告）
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-24 * time.Hour)
	for policyDomain, st := range stats {
		txts, err := net.DefaultResolver.LookupTXT(ctx, "_smtp._tls."+policyDomain)
		if err != nil {
			logger.Warn("TLS-RPT rua 发现失败（本期该域报告损失）", "domain", policyDomain, "error", err)
			continue
		}
		rua, ok := transport.DiscoverTLSRPTRua(txts)
		if !ok {
			continue // 对端未实现 TLSRPT（§3）——合法静默跳过
		}
		reportID := fmt.Sprintf("%s.%d.%d", policyDomain, start.Unix(), end.Unix())
		jsonBytes := transport.BuildTLSRPTReport(transport.TLSRPTReportInput{
			OrganizationName: domain,
			ContactEmail:     "tlsrpt@" + domain,
			ReportID:         reportID,
			WindowStart:      start,
			WindowEnd:        end,
			PolicyDomain:     policyDomain,
			PolicyType:       "no-policy-found", // 统计面未存策略快照——首版按 §4.4 无策略形态（登记：策略快照入报归后续增强）
			Stats:            st,
		})
		var gz bytes.Buffer
		gzw := gzip.NewWriter(&gz)
		_, _ = gzw.Write(jsonBytes)
		_ = gzw.Close()
		filename := transport.TLSRPTReportFilename(domain, policyDomain, start, end, observability.NewLogID()[:8])
		email := transport.BuildTLSRPTReportEmail(domain, policyDomain, rua, filename, reportID, gz.Bytes())
		if err = submit.Submit(ctx, &mail.Submission{
			Envelope:   auth.Envelope{MailFrom: "", Helo: domain}, // null path（授权放行+防循环）
			Recipients: []string{rua},
		}, email); err != nil {
			logger.Warn("TLS-RPT 报告提交失败（本期该域报告损失——次日重试新周期）", "domain", policyDomain, "error", err)
		}
	}
}
