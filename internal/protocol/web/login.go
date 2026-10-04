// GRmail Web 登录双端点（U8 计划书步骤 5）。
// 裁决依据：Q2-B 双端点分离（2026-09-19 04:48:48）——/login 管理员（用户名不含 @，
// UserRepo.FindByName+account.VerifyPassword）与 /webmail/login 邮箱账号（地址含 @ 语义，
// account.Service.VerifyCredentials 防枚举统一拒绝复用——FR-001 三入口之三）；
// Q4-B 失败计数限流（DB 持久化，LoginAttemptRepo）。
// 修改历史：
//
//	2026-09-19 05:15:00 | 新建 | U8 Web 会话与登录
package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/config"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// ───────────────────────── 登录限流参数（U10 Q7-C：config.LoginLimitConf 承载，快照热生效） ─────────────────────────
// 原 U8 代码常量（15min 窗口/5 次阈值）迁移为 config.Default 缺省档；注入位未配置时兜底同值。

// 统一模糊错误文本（防枚举：不区分「用户不存在/密码错误/影子无凭据/禁用」——
// OWASP 登录失败统一口径，复用 U2 ErrInvalidCredentials 语义）。
// U18 双语化收口（U16 登记项③）：常量改经 templates.Tr 取值——键 login.errInvalid/
// login.errLocked（zh 文案与原常量逐字一致，缺省 zh 零回归锚）。

// adminLoginGET 管理员登录页（GET /login）。
func (s *Server) adminLoginGET(c *gin.Context) {
	renderPage(c, http.StatusOK, templates.AdminLoginView(langOf(c), ""))
}

// adminLoginPOST 管理员登录（POST /login）：
// 限流前置（subject_key=admin:用户名小写）→ FindByName+VerifyPassword →
// 失败记尝试+模糊文本重渲染 → 成功清零+签发会话（subject=admin）→ 303 /。
func (s *Server) adminLoginPOST(c *gin.Context) {
	ctx := c.Request.Context()
	username := strings.ToLower(strings.TrimSpace(c.PostForm("username")))
	password := c.PostForm("password")
	subjectKey := "admin:" + username // 命名空间前缀防与邮箱主体键碰撞

	locked, err := s.locked(ctx, subjectKey)
	if err != nil {
		sessLogger(c).Error("限流查询故障", "error", err)
		renderPage(c, http.StatusInternalServerError, templates.AdminLoginView(langOf(c), templates.Tr(langOf(c), "login.errInvalid")))
		return
	}
	if locked { // 423：限流锁定（Q4-B 判定锚）
		renderPage(c, http.StatusLocked, templates.AdminLoginView(langOf(c), templates.Tr(langOf(c), "login.errLocked")))
		return
	}

	valid, subjectID, verr := s.verifyAdmin(ctx, username, password)
	if verr != nil {
		sessLogger(c).Error("管理员查询故障", "error", verr)
		renderPage(c, http.StatusInternalServerError, templates.AdminLoginView(langOf(c), templates.Tr(langOf(c), "login.errInvalid")))
		return
	}
	if !valid {
		s.recordFail(ctx, subjectKey, c.ClientIP())
		sessLogger(c).Info("管理员登录失败（统一拒绝）", "ip", c.ClientIP())
		renderPage(c, http.StatusOK, templates.AdminLoginView(langOf(c), templates.Tr(langOf(c), "login.errInvalid")))
		return
	}

	if err := s.attempts.ClearSubject(ctx, subjectKey); err != nil { // 成功清零（尽力语义）
		sessLogger(c).Warn("登录成功清零失败", "error", err)
	}
	if _, err := s.sess.issueSession(c, storage.SubjectTypeAdmin, subjectID); err != nil {
		sessLogger(c).Error("会话签发失败", "error", err)
		renderPage(c, http.StatusInternalServerError, templates.AdminLoginView(langOf(c), templates.Tr(langOf(c), "login.errInvalid")))
		return
	}
	c.Redirect(http.StatusSeeOther, "/") // 303（契约 3.1 重定向形态）
}

// verifyAdmin 管理员凭据校验（三态：无效/有效/存储故障）。
// 参数：ctx 上下文；username 用户名（已小写）；password 明文。
// 返回：valid 判定；subjectID 管理员 ID（valid 为真时有效）；err 存储故障（非凭据问题）。
func (s *Server) verifyAdmin(ctx context.Context, username, password string) (valid bool, subjectID int64, err error) {
	if username == "" || password == "" {
		return false, 0, nil
	}
	user, err := s.users.FindByName(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return false, 0, nil // 不存在 → 统一拒绝（防枚举）
		}
		return false, 0, err
	}
	match, verr := account.VerifyPassword(password, user.PasswordHash)
	if verr != nil || !match {
		return false, 0, nil // 密码错误/PHC 异常 → 统一拒绝
	}
	return true, user.ID, nil
}

// mailboxLoginGET 邮箱账号登录页（GET /webmail/login）。
func (s *Server) mailboxLoginGET(c *gin.Context) {
	renderPage(c, http.StatusOK, templates.MailboxLoginView(langOf(c), ""))
}

// mailboxLoginPOST 邮箱账号登录（POST /webmail/login）：
// 限流前置（subject_key=mailbox:地址小写）→ account.VerifyCredentials（影子/禁用/不存在/错密
// 统一 ErrInvalidCredentials——FR-001 防枚举口径，U2 同源）→ 成功清零+签发会话 → 303 /。
func (s *Server) mailboxLoginPOST(c *gin.Context) {
	ctx := c.Request.Context()
	address := strings.ToLower(strings.TrimSpace(c.PostForm("address")))
	password := c.PostForm("password")
	subjectKey := "mailbox:" + address

	locked, err := s.locked(ctx, subjectKey)
	if err != nil {
		sessLogger(c).Error("限流查询故障", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	if locked {
		renderPage(c, http.StatusLocked, templates.MailboxLoginView(langOf(c), templates.Tr(langOf(c), "login.errLocked")))
		return
	}

	mailbox, err := s.accounts.VerifyCredentials(ctx, address, password)
	if err != nil {
		// 统一拒绝：不存在/影子无凭据/禁用/密码错误同文本（account 层已收敛为 ErrInvalidCredentials）
		s.recordFail(ctx, subjectKey, c.ClientIP())
		sessLogger(c).Info("邮箱账号登录失败（统一拒绝）", "ip", c.ClientIP())
		renderPage(c, http.StatusOK, templates.MailboxLoginView(langOf(c), templates.Tr(langOf(c), "login.errInvalid")))
		return
	}

	// U24（FR-018 判定②）：绑定完成账号密码通过后须第二因子方可建立会话——签发
	// pending 凭据转二步页（TC-027 判定②③锚）；未绑定/服务未注入走既有直通路径
	// （兼容锚——协议入口零触及由判定仅在 web 登录 handler 层注入保证）。
	if s.twoFactor != nil {
		st, stErr := s.twoFactor.State(ctx, mailbox.ID)
		if stErr != nil {
			sessLogger(c).Error("2FA 状态查询故障", "error", stErr)
			c.Status(http.StatusInternalServerError)
			return
		}
		if st.Bound() {
			tok := s.pending2fa.issue(mailbox.ID, mailbox.Address)
			renderPage(c, http.StatusOK, templates.Login2FAView(langOf(c), tok, ""))
			return
		}
	}

	if err := s.attempts.ClearSubject(ctx, subjectKey); err != nil {
		sessLogger(c).Warn("登录成功清零失败", "error", err)
	}
	if _, err := s.sess.issueSession(c, storage.SubjectTypeMailbox, mailbox.ID); err != nil {
		sessLogger(c).Error("会话签发失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	s.redirectPostLogin(c, mailbox.ID) // U24：强制标记未绑定→引导绑定页；否则 303 /
}

// limitConf 限流参数快照（ServerConfig.LimitSnapshot 未注入=缺省档 15min/5 次）。
func (s *Server) limitConf() (window time.Duration, threshold int64) {
	conf := config.LoginLimitConf{WindowMinutes: 15, Threshold: 5}
	if s.cfg.LimitSnapshot != nil {
		if c := s.cfg.LimitSnapshot(); c.WindowMinutes > 0 && c.Threshold > 0 {
			conf = c // 快照合法值优先生效（热加载）
		}
	}
	return time.Duration(conf.WindowMinutes) * time.Minute, conf.Threshold
}

// locked 主体是否处于限流锁定（窗口内失败 ≥ 阈值；Q4-B；U10 Q7-C 快照取值）。
// 参数：ctx 上下文；subjectKey 主体键（含命名空间前缀）。
// 返回：锁定判定；查询故障返回 error（调用方按 500 处理，禁止故障放行锁定判定）。
func (s *Server) locked(ctx context.Context, subjectKey string) (bool, error) {
	window, threshold := s.limitConf()
	fails, err := s.attempts.CountRecentFails(ctx, subjectKey, time.Now().UTC().Add(-window))
	if err != nil {
		return false, err
	}
	return fails >= threshold, nil
}

// recordFail 记录一次失败尝试（尽力语义：记录故障不改变拒绝应答）。
func (s *Server) recordFail(ctx context.Context, subjectKey, ip string) {
	if err := s.attempts.RecordAttempt(ctx, subjectKey, ip, false, time.Now().UTC()); err != nil {
		sessLoggerCtx(ctx).Error("登录尝试记录失败", "error", err)
	}
}

// renderPage 渲染 templ 页面组件（SSR——CON-002 templ 范式）。
// 参数：c Gin 上下文；code HTTP 状态码；component templ 组件。
func renderPage(c *gin.Context, code int, component templ.Component) {
	c.Status(code)
	if err := component.Render(c.Request.Context(), c.Writer); err != nil {
		sessLogger(c).Error("页面渲染失败", "error", err)
	}
}
