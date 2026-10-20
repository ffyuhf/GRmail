// GRmail Web 登录双端点（U8 计划书步骤 5）。
// 裁决依据：Q2-B 双端点分离（2026-09-19 04:48:48）——/login 管理员（用户名不含 @，
// UserRepo.FindByName+account.VerifyPassword）与 /webmail/login 邮箱账号（地址含 @ 语义，
// account.Service.VerifyCredentials 防枚举统一拒绝复用——FR-001 三入口之三）；
// Q4-B 失败计数限流（DB 持久化，LoginAttemptRepo）。
// 修改历史：
//
//	2026-09-19 05:15:00 | 新建 | U8 Web 会话与登录
//	2026-10-20 12:50:00 | 修正 | GRM代码侧批 E-2-A（GRM-009）：verifyAdmin 用户不存在
//	分支增 adminDummyVerify 等成本校验（sync.Once 惰性生成 argon2id dummy PHC——两路径
//	响应时序一致，管理员用户名枚举面收口；G2 批准 2026-10-20 12:06:32）
package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	if locked { // 423：限流锁定（Q4-B 判定锚；E10 批二：Retry-After 头=限流窗口）
		s.setRetryAfter(c)
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
	// 管理员主体增强批次（G2——D13：FR-018 admin 通道扩展；S3-W Q2-A）：绑定完成账号
	// 密码通过后须第二因子方可建立 admin 会话——签发 pending 凭据转二步页；未绑定/
	// 服务未注入走直通路径（兼容锚——TC-027 判定②语义同款；协议入口零触及保持）。
	if s.adminTwoFactor != nil {
		st, stErr := s.adminTwoFactor.State(ctx, subjectID)
		if stErr != nil {
			sessLogger(c).Error("admin 2FA 状态查询故障", "error", stErr)
			c.Status(http.StatusInternalServerError)
			return
		}
		if st.Bound() {
			tok := s.pending2fa.issue(subjectID, username)
			renderPage(c, http.StatusOK, templates.AdminLogin2FAView(langOf(c), tok, ""))
			return
		}
	}
	if _, err := s.sess.issueSession(c, storage.SubjectTypeAdmin, subjectID); err != nil {
		sessLogger(c).Error("会话签发失败", "error", err)
		renderPage(c, http.StatusInternalServerError, templates.AdminLoginView(langOf(c), templates.Tr(langOf(c), "login.errInvalid")))
		return
	}
	c.Redirect(http.StatusSeeOther, redirectAfterLogin(c)) // 303（G6——D15 登录后回跳原页）
}

// adminDummyHashOnce / adminDummyHash GRM-009（GRM代码侧批 E-2-A——G2 批准
// 2026-10-20 12:06:32）：管理员登录 dummy 哈希惰性生成（sync.Once——首次命中不存在
// 用户名时对固定哑口令生成 argon2id PHC，与真实校验同参数档同成本）；用户不存在路径
// 执行等成本校验使两路径响应时序一致——管理员用户名枚举面（响应计时区分存在性）收口。
var (
	adminDummyHashOnce sync.Once
	adminDummyHash     string
)

// adminDummyVerify 用户不存在路径的等成本校验（dummy 哈希——校验结果恒弃用仅取时序；
// 生成失败〔系统级 CSPRNG 故障〕时跳过——拒绝语义不受影响，仅时序对齐尽力）。
func adminDummyVerify(password string) {
	adminDummyHashOnce.Do(func() {
		if h, err := account.HashPassword("grmail-dummy-password"); err == nil {
			adminDummyHash = h
		}
	})
	if adminDummyHash != "" {
		_, _ = account.VerifyPassword(password, adminDummyHash)
	}
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
			adminDummyVerify(password) // GRM-009：不存在 → 等成本校验后统一拒绝（时序对齐防枚举）
			return false, 0, nil
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
		s.setRetryAfter(c) // E10 批二：Retry-After
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

// setRetryAfter 423 锁定响应的 Retry-After 头（E10 批二——三轮评审三轮#4 承载：
// 值=限流窗口秒数〔保守口径——最近失败时刻不可得，窗口全长为重试最短上界〕；
// 消费点=登录双端点/2FA 二步/改密双通道全部 423 分支）。
func (s *Server) setRetryAfter(c *gin.Context) {
	window, _ := s.limitConf()
	c.Header("Retry-After", strconv.FormatInt(int64(window/time.Second), 10))
}

// renderPage 渲染 templ 页面组件（SSR——CON-002 templ 范式）。
// E8（Webmail前端缺陷修复批批二）：渲染先入缓冲、成功后一次性写出——原实现先
// c.Status(code) 再流式渲染，渲染中途失败时状态码已提交、响应体半截（不可恢复
// 页面）；本版渲染失败降级纯 500 状态码（零字节体——客户端可重试），半截页根除。
// 参数：c Gin 上下文；code HTTP 状态码；component templ 组件。
func renderPage(c *gin.Context, code int, component templ.Component) {
	var buf bytes.Buffer
	if err := component.Render(c.Request.Context(), &buf); err != nil {
		sessLogger(c).Error("页面渲染失败（降级纯状态码）", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(code)
	_, _ = c.Writer.Write(buf.Bytes())
}
