// GRmail Web 管理员 2FA 端点族（管理员主体增强与Webmail职能补全批次 G2——D13 收口：
// admin 登录入口二步验证+/admin/2fa 绑定管理三端点）。
// 依据：SRS v1.1.0 FR-018 admin 通道扩展（S3-W Q2-A 裁决 2026-10-05 23:20:14——
// 「仅 Webmail HTTPS 登录入口」语义内承载：/login 即 Webmail 入口，IMAP/POP3/SMTP
// 协议入口零触及——判定⑤保持）；TC-027/028 admin 维度伴随锚；
// 计划书 v1.1.0 1.3 G2（G2 批准 2026-10-05 23:31:37）。
// 形态：平移 mailbox 版 twofactor.go 端点母版（twoFactorViewOf/three POST 母版）；
// pending 凭据仓复用（pendingEntry{mailboxID,address} 承载 {userID,username}——
// token 一次性随机串天然主体无关，消费端语义区分）。
// 修改历史：
//
//	2026-10-05 23:43:00 | 新建 | 管理员主体增强与Webmail职能补全批次（G2 批准 2026-10-05 23:31:37）
package web

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/goqrcode"

	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// ───────────────────────── /login/2fa 登录二步端点（admin 通道） ─────────────────────────

// adminLogin2FAGET 管理员二步验证页（GET /login/2fa?t=…——密码步通过后渲染；
// 直接访问无 t 参数渲染空凭据页——提交即过期拒绝）。
func (s *Server) adminLogin2FAGET(c *gin.Context) {
	renderPage(c, http.StatusOK, templates.AdminLogin2FAView(langOf(c), c.Query("t"), ""))
}

// adminLogin2FAPost 管理员二步验证提交（POST /login/2fa）：
// pending 凭据取出（一次性）→AdminTwoFactorService.VerifyLoginFactor（TOTP 优先/
// 恢复码兜底——双失败 recordFail 限流〔admin: 用户名主体键〕+重签凭据可重试）→
// 通过→清零限流+issueSession（admin 会话建立）→303 /。
func (s *Server) adminLogin2FAPost(c *gin.Context) {
	ctx := c.Request.Context()
	lang := langOf(c)
	entry, ok := s.pending2fa.take(c.PostForm("t"))
	if !ok {
		// 凭据过期/无效：回到密码步（会话不建立）
		renderPage(c, http.StatusOK, templates.AdminLogin2FAView(lang, "", templates.Tr(lang, "login2fa.errExpired")))
		return
	}
	if s.adminTwoFactor == nil {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	// F3④/B-S10④（提交端点对齐批）：admin 二步失败锁定判定（recordFail 既有计数
	// 的消费闭环——沿 login 限流母版；超限 423+空凭据回密码步）。
	if locked, lerr := s.locked(ctx, "admin:"+entry.address); lerr != nil {
		sessLogger(c).Error("admin 2FA 限流查询故障", "error", lerr)
		c.Status(http.StatusInternalServerError)
		return
	} else if locked {
		renderPage(c, http.StatusLocked, templates.AdminLogin2FAView(lang, "", templates.Tr(lang, "login.errLocked")))
		return
	}
	if err := s.adminTwoFactor.VerifyLoginFactor(ctx, entry.mailboxID, c.PostForm("code")); err != nil {
		subjectKey := "admin:" + entry.address
		s.recordFail(ctx, subjectKey, c.ClientIP())
		sessLogger(c).Info("管理员 2FA 二步验证失败", "ip", c.ClientIP())
		tok := s.pending2fa.issue(entry.mailboxID, entry.address) // 重签供重试（旧凭据已消耗）
		renderPage(c, http.StatusOK, templates.AdminLogin2FAView(lang, tok, templates.Tr(lang, "login2fa.errInvalid")))
		return
	}
	if err := s.attempts.ClearSubject(ctx, "admin:"+entry.address); err != nil {
		sessLogger(c).Warn("登录成功清零失败", "error", err)
	}
	if _, err := s.sess.issueSession(c, storage.SubjectTypeAdmin, entry.mailboxID); err != nil {
		sessLogger(c).Error("admin 会话签发失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Redirect(http.StatusSeeOther, redirectAfterLogin(c)) // 303（G6——D15 登录后回跳原页）
}

// ───────────────────────── /admin/2fa 端点族（绑定管理） ─────────────────────────

// admin2faGuard 端点门卫：AdminTwoFactor 注入 nil=503（渐进态）+主体限 admin。
func (s *Server) admin2faGuard(c *gin.Context) bool {
	if s.adminTwoFactor == nil {
		c.Status(http.StatusServiceUnavailable)
		return false
	}
	sess, ok := currentSession(c)
	if !ok || sess.SubjectType != storage.SubjectTypeAdmin {
		c.Status(http.StatusForbidden)
		return false
	}
	return true
}

// admin2faViewOf 会话主体状态快照→页面数据骨架（三 POST 响应复用；Label=admin
// 用户名呈现——admin 主体无邮箱反查语义，UsernameLabel 沿 Label 字段承载）。
func (s *Server) admin2faViewOf(c *gin.Context) (*templates.TwoFactorData, error) {
	sess, _ := currentSession(c)
	st, err := s.adminTwoFactor.State(c.Request.Context(), sess.SubjectID)
	if err != nil {
		return nil, err
	}
	return &templates.TwoFactorData{
		Lang:    langOf(c),
		Label:   templates.Tr(langOf(c), "home.adminKind"),
		CSRF:    sess.CSRFToken,
		Bound:   st.Bound(),
		Pending: st.TotpSecret != "" && !st.Bound(), // F4/C5 改名（原 PendingSecret）
		Nav:     s.sidebarDataFor(c),                // D3 B 形态——全站侧栏
	}, nil
}

// admin2faGET 管理员 2FA 管理页（GET /admin/2fa——状态三态渲染）。
func (s *Server) admin2faGET(c *gin.Context) {
	if !s.admin2faGuard(c) {
		return
	}
	d, err := s.admin2faViewOf(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	renderPage(c, http.StatusOK, templates.AdminTwoFactorView(*d))
}

// admin2faSetupPOST 发起绑定（POST /admin/2fa/setup——FR-018 判定①前半 admin 承载）：
// 生成密钥+otpauth URI→二维码 PNG base64→pending 态渲染（二维码+明文密钥双形态）。
// otpauth label=admin 用户名（FindByName 反查）。
func (s *Server) admin2faSetupPOST(c *gin.Context) {
	if !s.admin2faGuard(c) {
		return
	}
	lang := langOf(c)
	sess, _ := currentSession(c)
	ctx := c.Request.Context()
	// otpauth label=admin@主域（呈现形态——UserRepo 无 FindByID 反查，label 非安全语义）
	label := "admin@" + s.issuerDomain()
	mat, err := s.adminTwoFactor.InitiateBinding(ctx, sess.SubjectID, label, s.issuerDomain())
	if err != nil {
		d, derr := s.admin2faViewOf(c)
		if derr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		d.ErrText = twoFactorErrText(lang, err)
		renderPage(c, http.StatusOK, templates.AdminTwoFactorView(*d))
		return
	}
	// 二维码 PNG → data URI（256px/Medium——mailbox 版同档）
	png, err := goqrcode.Encode(mat.OtpauthURI, goqrcode.Medium, 256)
	qrURI := ""
	if err != nil {
		sessLogger(c).Error("二维码生成失败", "error", err) // 降级：密钥手动输入通道仍可用
	} else {
		qrURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	renderPage(c, http.StatusOK, templates.AdminTwoFactorView(templates.TwoFactorData{
		Lang:      lang,
		Label:     templates.Tr(lang, "home.adminKind"),
		CSRF:      sess.CSRFToken,
		Pending:   true,
		QRDataURI: qrURI,
		Secret:    mat.Secret,
		Nav:       s.sidebarDataFor(c),
	}))
}

// admin2faConfirmPOST 绑定确认（POST /admin/2fa/confirm）：TOTP 码验证通过→
// 恢复码一次性生成展示（本响应非空即唯一呈现点——TC-027 判定①语义同款）。
func (s *Server) admin2faConfirmPOST(c *gin.Context) {
	if !s.admin2faGuard(c) {
		return
	}
	lang := langOf(c)
	sess, _ := currentSession(c)
	codes, err := s.adminTwoFactor.ConfirmBinding(c.Request.Context(), sess.SubjectID, c.PostForm("code"))
	if err != nil {
		d, derr := s.admin2faViewOf(c)
		if derr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		d.ErrText = twoFactorErrText(lang, err)
		renderPage(c, http.StatusOK, templates.AdminTwoFactorView(*d))
		return
	}
	sessLogger(c).Info("管理员 2FA 绑定确认", "admin_id", sess.SubjectID)
	renderPage(c, http.StatusOK, templates.AdminTwoFactorView(templates.TwoFactorData{
		Lang:          lang,
		Label:         templates.Tr(lang, "home.adminKind"),
		CSRF:          sess.CSRFToken,
		Bound:         true,
		RecoveryCodes: codes, // 一次性展示锚
		Nav:           s.sidebarDataFor(c),
	}))
}

// admin2faDisablePOST 停用（POST /admin/2fa/disable——须一次第二因子验证）。
func (s *Server) admin2faDisablePOST(c *gin.Context) {
	if !s.admin2faGuard(c) {
		return
	}
	lang := langOf(c)
	sess, _ := currentSession(c)
	if err := s.adminTwoFactor.Disable(c.Request.Context(), sess.SubjectID, c.PostForm("code")); err != nil {
		d, derr := s.admin2faViewOf(c)
		if derr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		d.ErrText = twoFactorErrText(lang, err)
		renderPage(c, http.StatusOK, templates.AdminTwoFactorView(*d))
		return
	}
	sessLogger(c).Info("管理员 2FA 停用", "admin_id", sess.SubjectID)
	c.Redirect(http.StatusSeeOther, "/admin/2fa")
}
