// GRmail Web 服务端装配（U8 计划书步骤 6 + U9 计划书步骤 4 + U10 计划书步骤 6/7/8）：Gin 引擎、
// 中间件链（入口 LogID+no-store → recovery → 会话解析 → CSRF → Setup 分流）、双端点登录路由（U8）、
// Webmail 业务路由组（U9：列表/详情/批量/写信/搜索/附件/文件夹/admin 两端点/静态资源）、
// Setup 六步向导与 /admin/settings（U10：Q3-A 80 双态承载/Q4-A 引导态唯一入口/Q7-C 全量配置页）、
// HTTPS 监听（Q3-A 未就绪跳过+告警）+HTTP 80 监听（U10：向导态全站承载/完成态仅 ACME 挑战+301）。
// 依据：契约 v1.6.0 2.4（web：SessionRepo+account 服务注入+U9 增量五依赖+U10 增量 config 读写/
// 快照函数/挑战表接口/80 双态）与 3.1/3.2/3.3 端点表；架构总览 v1.0.1 第四章（web 单向依赖
// {account,mail,config}，不 import 其他 protocol/*——挑战表经中性接口注入，零 transport import）；
// 5.1 LogID HTTP 入口义务；NFR-006（TLS1.2 下限复用 transport.TLSManager 产物）。
// 修改历史：
//
//	2026-09-19 05:15:00 | 新建 | U8 Web 会话与登录
//	2026-09-19 10:26:00 | 扩展 | U9 Webmail 核心（计划书步骤 4，G2 批准 2026-09-19 10:00:41）：
//	  ServerConfig 增四依赖字段（Messages/Folders/Blobs/Submit）；业务路由挂载；homeGET
//	  改造为 Webmail 列表页（依赖未注入时回退 U8 占位形态——u8_test nil 依赖兼容）
//	2026-09-20 01:00:00 | 扩展 | U10 Setup 向导与 ACME（计划书步骤 6/7/8，G2 批准 2026-09-20 00:32:33）：
//	  ServerConfig 增六注入位（SetupDone/CfgSnapshot/SaveConfig/SessionSnapshot/LimitSnapshot/
//	  Challenge）；/setup 与 /admin/settings 路由挂载+setupGate 分流中间件；ListenAndServeHTTP 80 双态
//	2026-09-23 08:42:00 | 扩展 | U13 传输安全全量（计划书步骤 4，G2 批准 2026-09-23 08:19:32；契约
//	  v1.9.0 2.4/3.1）：ServerConfig 增 STSPolicy 注入位（transport 生成器桥接——零 transport
//	  import）；GET /.well-known/mta-sts.txt 路由挂载（Q2-A 443 路由级承载——Host 判定+开关停发）
//	2026-09-24 02:55:00 | 扩展 | U14 API Token 管理（计划书步骤 4，G2 批准 2026-09-24 02:30:51；
//	  契约 v1.10.0 2.4/3.3）：ServerConfig 增 Tokens 注入位（TokenRepo——nil=/admin/tokens
//	  端点族 503 渐进态+Bearer 通道关闭）；/admin/tokens 三路由挂载（Q3-B 独立端点族——
//	  列表/生成（三档+IP 绑定+一次性明文）/撤销（双条件））
//	2026-09-27 13:46:00 | 扩展 | U23 可观测性扩展（计划书步骤 6，G2 批准 2026-09-27 13:20:53；
//	  U21 登记项②收口——Q2-A 裁决）：ServerConfig 增 ProtocolDebug 注入位；
//	  httpDebugMiddleware 条件中间件插入 Use 链（entryMiddleware 后——请求摘要单行
//	  Debug 输出：method+path+status+cost_ms+logid，不含请求体/头——防刷屏防敏感泄露）
//	2026-10-01 17:05:00 | 扩展 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）：ServerConfig
//	  增 TwoFactor 注入位（account.TwoFactorService——nil=2FA 端点 503+登录判定跳过渐进态）；
//	  Server 增 twoFactor/pending2fa 两字段（pendingLoginStore——S4-W Q1-A 内存态凭据）；
//	  路由增登录二步两端点+/settings/2fa 四端点+auth 组挂 twoFactorGate（FR-018 判定④）
//	2026-10-05 00:22:00 | 修正 | Setup向导缺陷修复批次（缺陷①）：增 GET /setup 根路由 302
//	  /setup/1——消除无步号访问 gin 树不匹配 404（尾斜杠陷阱：/setup→301 /setup/→:step
//	  空段不匹配）；完成态由 setupGate 前置拦截（302 /），本路由不执行零冲突
//	  （依据：Setup向导缺陷修复计划书 v1.0.0 1.2 组1，G2 批准 2026-10-05 00:21:19；
//	  SRS FR-015 判定标准「向导完成部署」入口可达性收口）
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/mail"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// ChallengeLookup ACME HTTP-01 挑战中性查询接口（U10：transport.ChallengeStore 结构化满足；
// web 零 transport import——架构第四章依赖边界保持）。
type ChallengeLookup interface {
	// Lookup 挑战路由查询：按 token 取应答正文（不存在返回 false——调用方 404）。
	Lookup(token string) (string, bool)
}

// ErrTLSNotReady TLS 证书未就绪哨兵（调用方跳过启动+告警——Q3-A，U5 1.5⑫/U6/U7 同款语义）。
var ErrTLSNotReady = errors.New("web: TLS 证书未就绪")

// ServerConfig Web 服务配置（依赖注入闭包形态，U6/U7 ServerConfig 同款；U9 增四依赖字段；
// U10 增六注入位——nil 语义均回退旧形态，既有测试零适配）。
type ServerConfig struct {
	Domain    string                  // 主域名（证书 ServerName 语境与日志关联；admin 视图 postmaster@域名、写信 From 域）
	TLSConfig func() *tls.Config      // 服务端 TLS 配置供给（nil=未就绪；transport.TLSManager.ServerTLSConfig 注入）
	Messages  storage.MessageRepo     // 邮件仓储（U9：列表/详情/批量/搜索/草稿落库）
	Folders   storage.FolderRepo      // 文件夹仓储（U9：侧边栏+管理三端点）——account.Service 同源注入
	Mailboxes storage.MailboxRepo     // 邮箱仓储（U9：admin 三态列表+mailbox 主体发件地址反查）
	Blobs     storage.BlobStore       // CAS 字节存储（U9：详情/附件读取、草稿双写）
	Submit    mail.SubmissionPipeline // 提交管道（U9：写信发送入队——流程设计 3.1 同链路复用）

	// ── U10 增量注入位（Q2-A/Q3-A/Q7-C；nil=缺省行为）──
	SetupDone       func() bool                             // setupCompleted 快照（nil=恒 true——既有部署/测试形态，分流不生效）
	CfgSnapshot     func() *config.Config                   // 当前配置快照（设置页读；nil=/admin/settings 503）
	HTTPPort        int                                     // HTTP 明文端口呈现值（Setup向导新手可用性批次 P3——setupmode 装配的 -p 覆盖值/缺省 80；零值=按 80 口径呈现；仅向导端口警示消费）
	SaveConfig      func(modify func(*config.Config)) error // 配置原子读改写（向导每步+设置页；读 Current→modify→Save→Watcher 广播）
	SessionSnapshot func() config.SessionConf               // 会话双超时快照（nil=缺省档 30min/12h——Q7-C 快照热生效）
	LimitSnapshot   func() config.LoginLimitConf            // 登录限流快照（nil=缺省档 15min/5 次）
	Challenge       ChallengeLookup                         // ACME 挑战表（nil=挑战路由 404）

	// ── U12 增量注入位（v1.8.0；nil=/sieve 路由 503——渐进部署形态）──
	SieveScripts storage.SieveScriptRepo // Sieve 脚本仓储（FR-011 Web 编辑器）

	// ── U13 增量注入位（v1.9.0；nil=mta-sts 端点 404——渐进部署形态）──
	STSPolicy STSPolicyProvider // MTA-STS 策略供给（transport.STSPolicyText 桥接——每请求快照热生效）

	// ── U14 增量注入位（v1.10.0；nil=Bearer 通道关闭+/admin/tokens 端点族 503——渐进部署形态）──
	Tokens storage.TokenRepo // API Token 仓储（FR-013 Token 管理子项；Bearer 并列认证数据源——Q1-A）

	// ── U23 增量注入位（HTTP 请求摘要 debug——Q2-A 条件中间件；nil=零输出零开销）──
	ProtocolDebug func() bool // 协议 debug 快照（config Log.ProtocolDebug——每请求读热生效）

	// ── U24 增量注入位（v1.20.0；nil=/settings/2fa 端点族 503+登录二步判定跳过——渐进部署形态）──
	TwoFactor *account.TwoFactorService // 2FA 域服务（FR-018；account 包承载——web→account 单向合法）
}

// Server Web 服务端（Gin 引擎宿主）。
type Server struct {
	cfg          ServerConfig
	sess         *sessionService
	sessions     storage.SessionRepo
	users        storage.UserRepo
	attempts     storage.LoginAttemptRepo
	accounts     *account.Service
	messages     storage.MessageRepo       // U9 业务依赖（cfg.Messages 装配）
	folders      storage.FolderRepo        // U9
	mailboxes    storage.MailboxRepo       // U9
	blobs        storage.BlobStore         // U9
	submit       mail.SubmissionPipeline   // U9
	sieveScripts storage.SieveScriptRepo   // U12（v1.8.0——/sieve 端点族；nil=503 渐进态）
	stsPolicy    STSPolicyProvider         // U13（v1.9.0——mta-sts 端点；nil=404 停发态）
	tokens       storage.TokenRepo         // U14（v1.10.0——Bearer 通道+/admin/tokens；nil=渐进态）
	twoFactor    *account.TwoFactorService // U24（v1.20.0——/settings/2fa+登录二步；nil=渐进态）
	pending2fa   *pendingLoginStore        // U24：短时一次性登录凭据仓（S4-W Q1-A 内存态）
	engine       *gin.Engine
	httpSrv      *http.Server
	listeners    []net.Listener
}

// NewServer 构造 Web 服务端：引擎装配+中间件链+路由挂载。
// 参数：cfg 配置；sessions 会话仓储；users 管理员仓储；attempts 登录尝试仓储；
// accounts 账号域服务（邮箱账号端点凭据校验）。
// 返回：服务实例（未启动监听——Serve/ListenAndServeTLS 显式调用）。
func NewServer(cfg ServerConfig, sessions storage.SessionRepo, users storage.UserRepo,
	attempts storage.LoginAttemptRepo, accounts *account.Service) *Server {
	gin.SetMode(gin.ReleaseMode) // 服务形态固定（测试经 Serve 注入驱动，无需 TestMode 副作用）
	s := &Server{
		cfg:          cfg,
		sess:         newSessionService(sessions, cfg.SessionSnapshot),
		sessions:     sessions,
		users:        users,
		attempts:     attempts,
		accounts:     accounts,
		messages:     cfg.Messages,
		folders:      cfg.Folders,
		mailboxes:    cfg.Mailboxes,
		blobs:        cfg.Blobs,
		submit:       cfg.Submit,
		sieveScripts: cfg.SieveScripts,
		stsPolicy:    cfg.STSPolicy,
		tokens:       cfg.Tokens,
		twoFactor:    cfg.TwoFactor,
		pending2fa:   newPendingLoginStore(),
	}
	s.engine = gin.New()
	// U23：HTTP 请求摘要 debug 中间件（entryMiddleware 后——logid ctx 已建可取；Q2-A 摘要口径）
	s.engine.Use(s.entryMiddleware(), s.httpDebugMiddleware(), gin.Recovery(), s.sessionMiddleware(), csrfProtect(), s.setupGate())
	s.mountRoutes()
	s.httpSrv = &http.Server{
		Handler:           s.engine,
		ReadHeaderTimeout: 10 * time.Second, // 慢速头攻击防护基线
	}
	return s
}

// mountRoutes 路由挂载（契约 v1.5.0 3.1 登录族 + 3.2 Webmail 核心与文件夹管理 +
// 3.3 admin 两端点（Q3-C：/admin/settings 归 U10）+ 静态资源）。
func (s *Server) mountRoutes() {
	// 登录族（U8）
	s.engine.GET("/login", s.adminLoginGET)
	s.engine.POST("/login", s.adminLoginPOST)
	s.engine.GET("/webmail/login", s.mailboxLoginGET)
	s.engine.POST("/webmail/login", s.mailboxLoginPOST)
	// U24：登录二步（会话前——pending 凭据承载，无 requireAuth；FR-018 判定②）
	s.engine.GET("/webmail/login/2fa", s.login2FAGET)
	s.engine.POST("/webmail/login/2fa", s.login2FAPost)
	s.engine.POST("/logout", s.logoutPOST)
	s.engine.GET("/lang", s.langSetGET) // U16 Q2-A：语言切换（公开——偏好先于认证承载）

	// Setup 六步向导（U10：引导态匿名可达——Q3-A 80 承载/OWASP 无会话条款；
	// 完成态经 setupGate 禁入）
	s.engine.GET("/setup/:step", s.setupGET)
	s.engine.POST("/setup/:step", s.setupPOST)
	// 向导根入口（Setup向导缺陷修复批次·缺陷①）：/setup 无步号 302 首步——消除
	// gin 树不匹配 404；完成态 setupGate 先拦（302 /），本路由不执行零冲突
	s.engine.GET("/setup", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/setup/1")
	})

	// 静态资源（公开——无会话承载内容）
	s.engine.GET("/static/*filepath", s.staticHandler)

	// MTA-STS 策略发布（U13：rfc8461 §3.2——公开只读；Host 判定+开关停发在 handler；
	// 注册于中间件链之后（entryMiddleware LogID 承载——会话/CSRF 中间件对 GET 天然放行）
	s.engine.GET(stsPolicyPath, s.mtaStsGET)

	// Webmail 业务组（认证后；HTMX 片段与整页同 handler；U24 增 twoFactorGate——
	// 强制标记未绑定账号重定向绑定页，FR-018 判定④）
	auth := s.engine.Group("/", requireAuth(), s.twoFactorGate())
	auth.GET("/", s.homeGET)
	auth.GET("/mails", s.mailsFragmentGET)
	auth.GET("/mails/:id", s.mailDetailGET)
	auth.POST("/mails/batch", s.mailsBatchPOST) // POST 树独立——与 GET /mails/:id 无冲突
	auth.GET("/compose", s.composeGET)
	auth.POST("/compose", s.composePOST)
	auth.POST("/compose/csv-import", s.csvImportPOST) // U16 Q5-A：CSV 批量收件人解析
	auth.GET("/search", s.searchGET)
	auth.GET("/attachments/:id", s.attachmentGET)
	auth.POST("/folders", s.folderCreatePOST)
	auth.POST("/folders/:id/rename", s.folderRenamePOST)
	auth.POST("/folders/:id/delete", s.folderDeletePOST)

	// /sieve 端点族（v1.8.0/U12——FR-011 Web 编辑器；mailbox 自管/admin postmaster 视图；
	// Sieve编辑器缺口修复批次 #31 增 deactivate——契约 v1.24.0）
	auth.GET("/sieve", s.sieveListGET)
	auth.GET("/sieve/:name", s.sieveEditGET)
	auth.POST("/sieve/:name", s.sieveEditPOST)
	auth.POST("/sieve/:name/activate", s.sieveActivatePOST)
	auth.POST("/sieve/:name/deactivate", s.sieveDeactivatePOST)
	auth.POST("/sieve/:name/delete", s.sieveDeletePOST)

	// /settings/2fa 端点族（U24/v1.20.0——FR-018 绑定管理；mailbox 主体
	// （twoFactorGuard 内 403 admin）；TwoFactor nil=503 渐进态；Q2-A 独立最小页）
	auth.GET("/settings/2fa", s.twoFactorGET)
	auth.POST("/settings/2fa/setup", s.twoFactorSetupPOST)
	auth.POST("/settings/2fa/confirm", s.twoFactorConfirmPOST)
	auth.POST("/settings/2fa/disable", s.twoFactorDisablePOST)

	// admin（Q3-C 拆分：邮箱管理+聚合视图归 U9；/admin/settings 归 U10）
	s.engine.GET("/admin", requireAuth(), func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/admin/mailboxes")
	})
	s.engine.GET("/admin/mailboxes", requireAuth(), s.adminMailboxesGET)
	s.engine.POST("/admin/mailboxes", requireAuth(), s.adminMailboxesPOST)
	s.engine.GET("/admin/mailboxes/unregistered", requireAuth(), s.adminUnregisteredGET)

	// admin 设置页（U10：/admin/settings——Q3-C 归属+Q7-C 全量 config 可写项；
	// admin 门卫在 handler 内沿 U9 admin.go 同形态）
	s.engine.GET("/admin/settings", requireAuth(), s.adminSettingsGET)
	s.engine.POST("/admin/settings", requireAuth(), s.adminSettingsPOST)

	// API Token 管理端点族（U14：Q3-B 独立路由——/admin/tokens；admin 门卫沿 admin.go
	// 形态（requireAuth+handler 内 SubjectType==admin）；Tokens nil=503 渐进态）
	s.engine.GET("/admin/tokens", requireAuth(), s.tokensListGET)
	s.engine.POST("/admin/tokens", requireAuth(), s.tokensCreatePOST)
	s.engine.POST("/admin/tokens/:id/revoke", requireAuth(), s.tokensRevokePOST)
}

// entryMiddleware 入口中间件：每 HTTP 请求生成 LogID（架构 5.1：HTTP 入口义务）
// 并统一下发 no-store（OWASP：会话响应禁止缓存——流程设计第六章第 8 条）。
func (s *Server) entryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, logID := observability.ContextWithNewLogID(c.Request.Context(),
			observability.LoggerFromContext(c.Request.Context()))
		c.Request = c.Request.WithContext(ctx)
		c.Set(ctxKeyLogID, logID)
		c.Writer.Header().Set("Cache-Control", "no-store")
		c.Next()
	}
}

// httpDebugMiddleware HTTP 请求摘要 debug 条件中间件（U23——U21 登记项②收口，Q2-A 裁决）。
// 输出：Debug 级单行 http_debug——method+path+status+cost_ms+logid（logid 经 entryMiddleware
// 建立的 ctx 绑定 logger 携带，LoggerFromContext 显式取——slog-context 语义）；
// 不含请求体/请求头/响应头（摘要口径——防刷屏防敏感泄露，与协议 debug「DATA 体不输出」同语义）；
// 快照关闭时仅 time.Now+c.Next 开销（零行为变化）。
func (s *Server) httpDebugMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		if s.cfg.ProtocolDebug == nil || !s.cfg.ProtocolDebug() {
			return // nil 注入=禁用（缺省装配/测试直构防御）
		}
		observability.LoggerFromContext(c.Request.Context()).Debug("http_debug",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"cost_ms", float64(time.Since(start).Microseconds())/1000.0)
	}
}

// homeGET 认证后首页（U9：Webmail 列表页；U8 依赖未注入时回退占位形态——u8_test
// nil 依赖构造与部署引导期兼容）。
func (s *Server) homeGET(c *gin.Context) {
	sess, _ := currentSession(c)
	if s.messages == nil || s.folders == nil {
		// U8 占位形态（依赖缺位——测试/引导态）
		label := fmt.Sprintf("%s #%d", sess.SubjectType, sess.SubjectID)
		kindText := "管理员"
		if sess.SubjectType == storage.SubjectTypeMailbox {
			kindText = "邮箱账号"
		}
		renderPage(c, http.StatusOK, templates.HomeView(langOf(c), label, kindText, sess.CSRFToken))
		return
	}
	s.renderMailListPage(c)
}

// ListenAndServeTLS HTTPS 隐式 TLS 监听（NFR-006：TLS1.2 下限由注入的 TLSConfig 承载）。
// 参数：addr 监听地址（如 :443）。
// 返回：ErrTLSNotReady 证书未就绪（调用方跳过+告警——Q3-A）；监听/服务故障返回 error。
func (s *Server) ListenAndServeTLS(addr string) error {
	tlsCfg := s.cfg.TLSConfig()
	if tlsCfg == nil {
		return ErrTLSNotReady
	}
	s.httpSrv.TLSConfig = tlsCfg // ServeTLS 依赖 httpSrv.TLSConfig（证书与下限在此注入）
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web 监听: %w", err)
	}
	s.listeners = append(s.listeners, ln)
	return s.httpSrv.ServeTLS(ln, "", "")
}

// setupCompleted Setup 完成态快照（SetupDone 未注入=恒完成——旧装配/测试形态零分流）。
func (s *Server) setupCompleted() bool {
	if s.cfg.SetupDone == nil {
		return true
	}
	return s.cfg.SetupDone()
}

// ListenAndServeHTTP 明文 HTTP 80 监听（U10 Q3-A 双态：Setup 未完成=向导全站承载
// （engine 直驱——setupGate 放行 /setup 与静态资源，其余 302 /setup）；完成态=仅
// /.well-known/acme-challenge/{token} 直答（rfc8555 HTTP-01 资源语义，Challenge 表），
// 其余一律 301 → https（80→443 标准形态）。
// 参数：addr 监听地址（如 :80）。返回：监听/服务故障。
func (s *Server) ListenAndServeHTTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web 80 监听: %w", err)
	}
	s.listeners = append(s.listeners, ln)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", s.challengeHTTP)
	mux.HandleFunc("/", s.http80Root)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// http80Root 80 根分流：未完成态转 engine（向导/静态）；完成态 301 https。
func (s *Server) http80Root(w http.ResponseWriter, r *http.Request) {
	if !s.setupCompleted() {
		s.engine.ServeHTTP(w, r)
		return
	}
	u := *r.URL
	u.Scheme = "https"
	u.Host = r.Host
	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
}

// Serve 可测形态：直接驱动既有监听器（httptest 注入路径；NFR-015 全离线）。
// 参数：ln 已就绪监听器（明文或 TLS 包裹均可）。返回：服务期内错误。
func (s *Server) Serve(ln net.Listener) error {
	s.listeners = append(s.listeners, ln)
	if tc := s.cfg.TLSConfig(); tc != nil {
		s.httpSrv.TLSConfig = tc
		return s.httpSrv.Serve(tls.NewListener(ln, tc))
	}
	return s.httpSrv.Serve(ln)
}

// Addr 首监听器地址（未监听返回空串；多监听场景取主入口）。
func (s *Server) Addr() string {
	if len(s.listeners) == 0 {
		return ""
	}
	return s.listeners[0].Addr().String()
}

// Shutdown 优雅停止（排空在途请求；上下文超时由调用方掌控）。
// 参数：ctx 截止上下文。返回：停机故障（已断开监听视为完成）。
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.httpSrv.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
