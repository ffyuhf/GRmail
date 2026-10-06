// Package web 实现 Web 层会话与登录（U8）：Gin 中间件链、OWASP 会话全约束、
// 双端点登录（Q2-B）、会话绑定 CSRF（Q5-B）。
// 依据：SRS v1.0.1 FR-001（三入口之三 Webmail HTTPS）/NFR-006/015/016、CON-001/002；
// 模块接口契约 v1.4.0 2.4（web：SessionRepo+account 服务注入 Gin 中间件）/3.1/3.4；
// 关键流程设计 v1.0.0 第六章（会话生命周期八条强制约束）；
// OWASP 会话管理指南（Session ID Properties/Cookies/Life Cycle/Expiration/Detection 各章）；
// 系统架构总览 v1.0.1 第四章（web → {account,storage,config,observability} 单向，不触其他 protocol/*）。
// 修改历史：
//
//	2026-09-19 05:15:00 | 新建 | U8 Web 会话与登录（计划书步骤 4/5，G2 批准 2026-09-19 04:56:31）
//	2026-09-24 02:56:00 | 扩展 | U14 API Token 管理（计划书步骤 4，G2 批准 2026-09-24 02:30:51；
//	  契约 v1.10.0 2.4）：sessionMiddleware 匿名三分支后统一追加 Bearer 并列认证判定
//	  （Q1-A——Authorization: Bearer <64hex>→合成 admin 会话注入；无效/过期/IP 不符 401 Abort）
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/config"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
)

// ───────────────────────── OWASP 会话安全常量（流程设计第六章八条） ─────────────────────────

const (
	// sessionCookieName 会话 cookie 名：__Host- 前缀（浏览器强制 Secure+无 Domain+Path=/，
	// OWASP Cookies 章推荐；值无语义——CSPRNG 128bit hex 原文）
	sessionCookieName = "__Host-sid"
	// sessionIDBytes session ID 随机字节数：128bit 熵（OWASP：自建 ID 用 CSPRNG ≥128bit；
	// 高于 64bit 抗猜解下限）
	sessionIDBytes = 16
	// U10（Q7-C）：双超时由 config.SessionConf 承载（原 U8 代码常量迁移为缺省档
	// IdleMinutes=30/AbsoluteHours=12——config.Default 同值；快照每请求读取热生效）
)

// Gin 上下文键（组件内约定，禁止跨包引用）
const (
	ctxKeyLogID    = "web.log_id"
	ctxKeySession  = "web.session"
	csrfFormField  = "csrf_token" // 表单隐藏域名（契约 3.4）
	csrfTokenBytes = 16           // CSRF token 随机字节（128bit）
)

// sessionService 会话凭据服务：session ID/CSRF token 生成与派生哈希（纯函数族，可独立测试）。
type sessionService struct {
	sessions storage.SessionRepo
	salt     []byte                    // 进程级日志盐（CSPRNG）——日志只出现盐哈希，禁止原文（OWASP Logging 章）
	sessCfg  func() config.SessionConf // 双超时快照（U10 Q7-C；nil=缺省档 30min/12h）
}

// newSessionService 构造会话凭据服务。
// 参数：sessions 会话仓储；sessCfg 双超时快照函数（可 nil=缺省档）。返回：服务实例
// （盐生成失败属不可恢复系统级故障，panic 上抛）。
func newSessionService(sessions storage.SessionRepo, sessCfg func() config.SessionConf) *sessionService {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("会话日志盐生成失败（CSPRNG 不可用）: " + err.Error())
	}
	return &sessionService{sessions: sessions, salt: salt, sessCfg: sessCfg}
}

// sessionTimeouts 双超时取值（快照缺省兜底——注入位未配置时 30min/12h 沿 U8 缺省档）。
func (ss *sessionService) sessionTimeouts() (idle time.Duration, absolute time.Duration) {
	conf := config.SessionConf{IdleMinutes: 30, AbsoluteHours: 12}
	if ss.sessCfg != nil {
		if c := ss.sessCfg(); c.IdleMinutes > 0 && c.AbsoluteHours > 0 {
			conf = c // 快照合法值优先生效（热加载——每请求读取）
		}
	}
	return time.Duration(conf.IdleMinutes) * time.Minute, time.Duration(conf.AbsoluteHours) * time.Hour
}

// newSessionID 生成 session ID 原文（CSPRNG 128bit hex，32 字符）。
func (s *sessionService) newSessionID() string {
	buf := make([]byte, sessionIDBytes)
	if _, err := rand.Read(buf); err != nil {
		panic("session ID 生成失败（CSPRNG 不可用）: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// newCSRFToken 生成会话绑定 CSRF token（CSPRNG 128bit hex；Q5-B）。
func (s *sessionService) newCSRFToken() string {
	buf := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		panic("CSRF token 生成失败（CSPRNG 不可用）: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// idHashOf session ID 原文 → 库内主键哈希（hex(SHA-256)；数据模型 3.6：cookie 载原文、库存哈希）。
func (s *sessionService) idHashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// logHashOf session ID 原文 → 日志关联盐哈希（hex(HMAC-SHA256(进程盐, 原文)) 前 16 字符；
// OWASP Logging Sessions Life Cycle：日志可关联会话但禁止暴露 ID）。
func (s *sessionService) logHashOf(raw string) string {
	mac := hmac.New(sha256.New, s.salt)
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// issueSession 认证成功后签发新会话（含特权变化防 fixation 重建：旧会话先删除——
// 流程设计第六章第 4 条；CSRF token 随会话生成——Q5-B）。
// 参数：c Gin 上下文（取 ip/ua）；subjectType 主体类型；subjectID 主体 ID。
// 返回：签发的会话（csrf token 含于其内）；存储故障返回 error（调用方按 500 处理）。
func (s *sessionService) issueSession(c *gin.Context, subjectType storage.SubjectType, subjectID int64) (*storage.Session, error) {
	ctx := c.Request.Context()
	// 防 fixation：cookie 若携带旧会话一律先失效（匿名→认证为特权变化点）
	if raw, err := c.Cookie(sessionCookieName); err == nil && raw != "" {
		if oldHash := s.idHashOf(raw); oldHash != "" {
			_ = s.sessions.Delete(ctx, oldHash) // 旧会话不存在时删除为无害空操作
		}
	}
	now := time.Now().UTC()
	raw := s.newSessionID()
	_, absolute := s.sessionTimeouts()
	sess := &storage.Session{
		ID:                s.idHashOf(raw),
		SubjectType:       subjectType,
		SubjectID:         subjectID,
		IP:                c.ClientIP(),
		UserAgent:         c.Request.UserAgent(),
		CSRFToken:         s.newCSRFToken(),
		CreatedAt:         now,
		LastSeenAt:        now,
		AbsoluteExpiresAt: now.Add(absolute),
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}
	// cookie：__Host-sid；Secure+HttpOnly+SameSite=Strict+Path=/；无 Domain；非持久（无 Expires/Max-Age）
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    raw,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	logger := observability.LoggerFromContext(ctx)
	logger.Info("会话签发", "log_id", c.GetString(ctxKeyLogID), "session", s.logHashOf(raw),
		"subject_type", string(subjectType), "subject_id", subjectID)
	return sess, nil
}

// currentSession 从 Gin 上下文取会话中间件注入的有效会话。
// 参数：c Gin 上下文。返回：会话与存在性（匿名返回 false）。
func currentSession(c *gin.Context) (*storage.Session, bool) {
	v, ok := c.Get(ctxKeySession)
	if !ok {
		return nil, false
	}
	sess, ok := v.(*storage.Session)
	return sess, ok
}

// sessionMiddleware 会话解析中间件（每请求）：
// 仅 cookie 交换（URL/参数/header 一律不读——流程设计第六章第 3 条；Bearer 头为 U14
// 并列认证旁路非会话交换，见 tryBearerAuth）→ Find →
// 双超时服务端判定（过期即删转匿名——第 5 条）→ IP/UA 突变告警（第 6 条，不中断）→
// Touch 活跃痕迹 → 上下文注入主体。
// U14（Q1-A）：三个匿名返回点（无 cookie/Find 故障/超时失效）统一前置 Bearer 判定——
// 带有效 Bearer 头的程序化请求经合成 admin 会话认证（cookie 会话路径零变化）。
func (s *Server) sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		logger := observability.LoggerFromContext(ctx)
		raw, err := c.Cookie(sessionCookieName)
		if err != nil || raw == "" {
			s.tryBearerAuth(c) // U14：匿名态 Bearer 并列判定（注入或 401 Abort）
			c.Next()           // 匿名态（首访无 cookie）
			return
		}
		idHash := s.sess.idHashOf(raw)
		sess, findErr := s.sessions.Find(ctx, idHash)
		if findErr != nil {
			if !errors.Is(findErr, storage.ErrSessionNotFound) {
				logger.Error("会话查询故障", "error", findErr)
			}
			s.tryBearerAuth(c) // U14：同上（超时/无效 cookie 与 Bearer 独立——Token 有效即认证）
			c.Next()           // 无效/故障一律按匿名处理（禁止因故障放行已认证态）
			return
		}
		now := time.Now().UTC()
		// 双超时：绝对超时或空闲超时命中即服务端强制失效（过期主动动作：双侧失效；
		// U10 Q7-C：取值经快照热生效）
		idle, _ := s.sess.sessionTimeouts()
		if now.After(sess.AbsoluteExpiresAt) || now.Sub(sess.LastSeenAt) > idle {
			_ = s.sessions.Delete(ctx, idHash)
			logger.Info("会话超时失效", "session", s.sess.logHashOf(raw), "reason", "timeout")
			s.tryBearerAuth(c) // U14：cookie 会话超时后 Bearer 仍可认证（两通道独立）
			c.Next()
			return
		}
		// IP/UA 绑定检测：突变记告警（检测增强，不中断会话——1.5 口径）
		ip, ua := c.ClientIP(), c.Request.UserAgent()
		if sess.IP != "" && sess.IP != ip {
			logger.Warn("会话内 IP 突变（疑似劫持）", "session", s.sess.logHashOf(raw),
				"prev_ip", sess.IP, "cur_ip", ip)
		}
		if sess.UserAgent != "" && sess.UserAgent != ua {
			logger.Warn("会话内 User-Agent 突变（疑似劫持）", "session", s.sess.logHashOf(raw))
		}
		if err := s.sessions.Touch(ctx, idHash, ip, ua, now); err != nil {
			logger.Error("会话 Touch 失败（不中断请求）", "error", err)
		}
		c.Set(ctxKeySession, sess)
		c.Next()
	}
}

// requireAuth 认证门卫：无有效会话时 401+HX-Redirect（HTMX 请求）或 302（整页请求）——
// 契约 v1.4.0 3.4：默认重定向入口 /login（主体未知场景）。
// 管理员主体增强批次 G6（D15）：整页 302 前记录来源路径到临时 cookie（登录成功后
// 回跳——消除「被登出重登后回不到原页」；仅 GET 安全方法记录，站内校验归消费端
// safeRedirectPath；HTMX 片段请求无整页回跳语义不记录）。
func requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := currentSession(c); !ok {
			if c.GetHeader("HX-Request") == "true" {
				c.Header("HX-Redirect", "/login")
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			if c.Request.Method == http.MethodGet {
				c.SetCookie(loginRedirectCookie, c.Request.URL.Path, 300, "/", "",
					true, true) // 5min 窗口 HttpOnly+SameSite=Strict（站内回跳临时态）
			}
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

// loginRedirectCookie 登录回跳临时 cookie 名（G6——D15：会话超时 302 登录后回原页）。
const loginRedirectCookie = "grmail_login_redirect"

// safeRedirectPath 站内回跳路径校验（沿 /lang next 先例：绝对路径且非协议相对形态；
// 非法值回 /——防开放重定向）。
func safeRedirectPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "/"
	}
	return p
}

// redirectAfterLogin 登录成功回跳：读临时 cookie→站内校验→303 目标+清除；
// 无 cookie/非法值回既有 / 口径（集中一处——admin/mailbox 两通道共用）。
func redirectAfterLogin(c *gin.Context) string {
	if p, err := c.Cookie(loginRedirectCookie); err == nil && p != "" {
		c.SetCookie(loginRedirectCookie, "", -1, "/", "", true, true) // 清除（一次性）
		return safeRedirectPath(p)
	}
	return "/"
}

// csrfProtect CSRF 校验中间件（契约 3.4：SameSite=Strict 之外的纵深防御；Q5-B 会话绑定）。
// 语义：安全方法（GET/HEAD/OPTIONS）放行；匿名 POST（登录端点）放行——主防线为 SameSite=Strict
// 与限流；已认证会话的非安全请求必须携带表单 token 且与 session.CSRFToken 常数时间相等，
// 否则 403。
func csrfProtect() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		sess, ok := currentSession(c)
		if !ok || sess.CSRFToken == "" {
			c.Next() // 匿名/未绑定：登录路径（SameSite=Strict 主防线承载）
			return
		}
		token := c.PostForm(csrfFormField)
		if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) != 1 {
			logger := observability.LoggerFromContext(c.Request.Context())
			logger.Warn("CSRF 校验拒绝", "method", c.Request.Method, "path", c.Request.URL.Path)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// bearerPrefix Authorization 头 Bearer 方案前缀（RFC 6750 形态——Q1-A 裁决承载）。
const bearerPrefix = "Bearer "

// tryBearerAuth Bearer 并列认证判定（U14 Q1-A——sessionMiddleware 匿名三分支统一前置）：
// 无 Authorization 头/非 Bearer 前缀→纯匿名放行（零行为变化）；携带 Bearer <token> 时——
// 哈希点查（FindValidByHash——过期判定在 SQL）→IP 绑定行内比对→合成 admin 会话注入
// （CSRFToken 空——csrfProtect 未绑定放行分支承载程序化 POST；OWASP：Header 显式
// 认证无 CSRF 面）+TouchLastUsed 尽力刷新（Q2-B）；无效/过期/IP 不符/查询故障一律
// 401 Abort（程序化请求非浏览器——不做 HX-Redirect/302 登录跳转）。
// Tokens 注入 nil=通道关闭（零 Bearer 判定——U13 末态等价锚）。
func (s *Server) tryBearerAuth(c *gin.Context) {
	if s.tokens == nil {
		return // 通道关闭（渐进部署形态）
	}
	auth := c.GetHeader("Authorization")
	if len(auth) <= len(bearerPrefix) || auth[:len(bearerPrefix)] != bearerPrefix {
		return // 无 Bearer 头——纯匿名（浏览器路径零变化）
	}
	raw := auth[len(bearerPrefix):]
	ctx := c.Request.Context()
	logger := observability.LoggerFromContext(ctx)

	tok, err := s.tokens.FindValidByHash(ctx, bearerHashOf(raw), time.Now().UTC())
	if err != nil {
		logger.Info("Bearer 认证拒绝（无效/过期）", "token", raw[:min(8, len(raw))]+"…")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// IP 绑定判定（行内比对——拒绝原因可观测；C2 参照）
	if tok.ClientIP != "" && tok.ClientIP != c.ClientIP() {
		logger.Info("Bearer 认证拒绝（IP 不符）", "bound", tok.ClientIP, "cur", c.ClientIP())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// 合成 admin 会话（CSRFToken 空——csrfProtect 放行分支承载；IP/UA 留空——非会话通道）
	c.Set(ctxKeySession, &storage.Session{
		SubjectType: storage.SubjectTypeAdmin,
		SubjectID:   tok.UserID,
		CSRFToken:   "", // 程序化请求无表单 CSRF 承载（Header 认证无 CSRF 攻击面）
	})
	// last_used_at 尽力刷新（Q2-B——失败不中断请求）
	if err := s.tokens.TouchLastUsed(ctx, tok.ID, time.Now().UTC()); err != nil {
		logger.Error("Token 使用时刻刷新失败（不中断）", "error", err)
	}
	logger.Info("Bearer 认证通过", "user_id", tok.UserID)
}

// sessLogger 会话中间件族共用的日志器取用捷径（NFR-016：全链路 slog-context）。
func sessLogger(c *gin.Context) *slog.Logger {
	return observability.LoggerFromContext(c.Request.Context())
}

// sessLoggerCtx 无 Gin 上下文场景的日志器取用（recordFail 等）。
func sessLoggerCtx(ctx context.Context) *slog.Logger {
	return observability.LoggerFromContext(ctx)
}
