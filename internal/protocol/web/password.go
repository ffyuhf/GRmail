// GRmail Web 密码管理双通道+个人设置枢纽（Webmail管理职能批次 G1/G2——D1/D6 缺陷收口）。
// G1 三通道之二（第三通道=admin.go setpassword 行内改密）：
//
//	/admin/password   管理员自身改密（username+旧密码 verifyAdmin 既有链复用+UpdatePassword）；
//	/settings/password 邮箱用户个人改密（FindMailboxByID 反查地址+VerifyCredentials 旧密码验证）。
//
// G2 个人设置枢纽 /settings（mailbox 主体四分区：账户/改密/2FA/规则；admin 主体 302 管理枢纽）。
// 安全语义（OWASP 会话管理指南第 4 条——Renew the Session ID）：改密成功后 issueSession
// 重建会话（其内置 cookie 旧会话删除+新 ID+新 CSRF——特权变化防 fixation 既有承载）。
// 依据：Webmail管理职能计划书 v1.0.0 1.2 G1/G2（G2 批准 2026-10-05 15:15:22）；
// SRS FR-002（管理员「编辑」语义）/FR-001（独立账号凭据）/FR-013（设置面板）。
// 修改历史：
//
//	2026-10-05 15:20:00 | 新建 | Webmail管理职能批次（计划书阶段 2/3，G2 批准 2026-10-05 15:15:22）
//	2026-10-14 20:45:00 | 修正 | Webmail前端可用性收口批 B7：审计点名四点空体收口入
//	errPage（passwordFormGET 401/passwordChangePOST 403+locked 500+SetMailboxPassword 500；
//	状态码语义保持——G2 批准 2026-10-14 20:37）
package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// passwordFormGET 邮箱用户改密表单页（GET /settings/password——mailbox 域恒定）。
// F9（Webmail前端缺陷修复批批二·D8-A）：/admin/password 改挂独立 admin 门卫
// handler（adminPasswordFormGET）后本表单恒 mailbox 形态；admin 主体直访本 URL
// 302 至 /admin/password（域隔离直达——原双主体共用+自适应呈现矛盾收口）。
func (s *Server) passwordFormGET(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok {
		s.errPage(c, http.StatusUnauthorized, "err.page401") // B7（α 批）：空体收口（err.page401 本批新增键）
		return
	}
	if sess.SubjectType == storage.SubjectTypeAdmin {
		c.Redirect(http.StatusFound, "/admin/password")
		return
	}
	renderPage(c, http.StatusOK, templates.PasswordView(&templates.PasswordData{
		Lang:      string(langOf(c)),
		CSRFToken: sess.CSRFToken,
		IsAdmin:   false,
		Action:    "/settings/password",
		Nav:       s.sidebarDataFor(c), // D3 B 形态——全站侧栏
	}))
}

// adminPasswordFormGET 管理员改密表单页（GET /admin/password——F9/D8-A：admin
// 门卫先行，mailbox 主体 403〔域隔离显隐一致——原双主体可达+写入域正确的呈现
// 矛盾收口，批一 G2 裁决 D8-A 归批二承载〕）。
func (s *Server) adminPasswordFormGET(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	sess, _ := currentSession(c)
	renderPage(c, http.StatusOK, templates.PasswordView(&templates.PasswordData{
		Lang:      string(langOf(c)),
		CSRFToken: sess.CSRFToken,
		IsAdmin:   true,
		Action:    "/admin/password",
		Nav:       s.sidebarDataFor(c),
	}))
}

// passwordChangePOST 邮箱用户个人改密（POST /settings/password——mailbox 主体）：
// 旧密码验证（FindMailboxByID 反查地址→VerifyCredentials 防枚举链复用+失败计数）→
// SetMailboxPassword 域方法→issueSession 重建（OWASP Renew ID）→303 枢纽 ?pwchanged=1。
func (s *Server) passwordChangePOST(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}
	if sess.SubjectType != storage.SubjectTypeMailbox {
		// B7（α 批）：空体收口（admin 主体请走 /admin/password——分域承载语义注释保持）。
		s.errPage(c, http.StatusForbidden, "err.page403")
		return
	}
	ctx := c.Request.Context()
	lang := langOf(c)
	fail := func(msg string) {
		renderPage(c, http.StatusOK, templates.PasswordView(&templates.PasswordData{
			Lang: string(lang), CSRFToken: sess.CSRFToken, IsAdmin: false,
			Action: "/settings/password", ErrText: msg, Nav: s.sidebarDataFor(c),
		}))
	}
	newPassword := c.PostForm("newPassword")
	if newPassword == "" {
		fail(templates.Tr(lang, "pw.errEmpty"))
		return
	}
	if newPassword != c.PostForm("confirmPassword") {
		fail(templates.Tr(lang, "pw.errMismatch"))
		return
	}
	m, err := s.mailboxes.FindMailboxByID(ctx, sess.SubjectID)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	// F3④/B-S10④（提交端点对齐批）：改密失败锁定判定——recordFail 既有计数的
	// 消费闭环（沿 login 限流母版 s.locked；阈值内零影响，超限 423 防爆破）。
	if locked, lerr := s.locked(ctx, "mailbox:"+m.Address); lerr != nil {
		sessLogger(c).Error("改密限流查询故障", "error", lerr)
		s.errPage(c, http.StatusInternalServerError, "err.page500") // B7（α 批）：空体收口
		return
	} else if locked {
		s.setRetryAfter(c) // E10 批二：Retry-After
		renderPage(c, http.StatusLocked, templates.PasswordView(&templates.PasswordData{
			Lang: string(lang), CSRFToken: sess.CSRFToken, IsAdmin: false,
			Action: "/settings/password", ErrText: templates.Tr(lang, "login.errLocked"), Nav: s.sidebarDataFor(c),
		}))
		return
	}
	// 旧密码验证：VerifyCredentials 统一拒绝语义复用（影子/禁用/错密同拒——防枚举口径）
	if _, verr := s.accounts.VerifyCredentials(ctx, m.Address, c.PostForm("oldPassword")); verr != nil {
		s.recordFail(ctx, "mailbox:"+m.Address, c.ClientIP()) // 失败计数（防爆破——Q4-B 链路）
		sessLogger(c).Info("邮箱用户改密旧密码验证失败", "mailbox_id", sess.SubjectID, "ip", c.ClientIP())
		fail(templates.Tr(lang, "pw.errWrongOld"))
		return
	}
	if err := s.accounts.SetMailboxPassword(ctx, m.Address, newPassword); err != nil {
		if errors.Is(err, account.ErrPasswordTooShort) {
			fail(templates.Tr(lang, "pw.errShort")) // D10 批二：下限统一（哨兵→用户可读）
			return
		}
		sessLogger(c).Error("邮箱用户改密失败", "mailbox_id", sess.SubjectID, "error", err)
		s.errPage(c, http.StatusInternalServerError, "err.page500") // B7（α 批）：空体收口
		return
	}
	// 会话重建（OWASP 第 4 条：特权变化 Renew the Session ID——内置旧会话删除）
	if _, err := s.sess.issueSession(c, storage.SubjectTypeMailbox, sess.SubjectID); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	sessLogger(c).Info("邮箱用户修改自身密码", "mailbox_id", sess.SubjectID)
	c.Redirect(http.StatusSeeOther, "/settings?pwchanged=1")
}

// adminPasswordChangePOST 管理员自身改密（POST /admin/password——admin 主体）：
// username+旧密码 verifyAdmin 既有链复用（失败计数防爆破）→ 主体一致性校验（表单用户名
// 必须匹配当前会话——防跨账户改密）→ UpdatePassword → issueSession 重建 →303 管理枢纽。
func (s *Server) adminPasswordChangePOST(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}
	if sess.SubjectType != storage.SubjectTypeAdmin {
		c.Status(http.StatusForbidden)
		return
	}
	ctx := c.Request.Context()
	lang := langOf(c)
	fail := func(msg string) {
		renderPage(c, http.StatusOK, templates.PasswordView(&templates.PasswordData{
			Lang: string(lang), CSRFToken: sess.CSRFToken, IsAdmin: true,
			Action: "/admin/password", ErrText: msg, Username: strings.TrimSpace(c.PostForm("username")),
			Nav: s.sidebarDataFor(c),
		}))
	}
	newPassword := c.PostForm("newPassword")
	if newPassword == "" {
		fail(templates.Tr(lang, "pw.errEmpty"))
		return
	}
	if newPassword != c.PostForm("confirmPassword") {
		fail(templates.Tr(lang, "pw.errMismatch"))
		return
	}
	username := strings.ToLower(strings.TrimSpace(c.PostForm("username")))
	// F3④/B-S10④（提交端点对齐批）：改密失败锁定判定（沿 login 限流母版——键与
	// 下方 recordFail 对称）。
	if locked, lerr := s.locked(ctx, "admin:"+username); lerr != nil {
		sessLogger(c).Error("管理员改密限流查询故障", "error", lerr)
		c.Status(http.StatusInternalServerError)
		return
	} else if locked {
		s.setRetryAfter(c) // E10 批二：Retry-After
		renderPage(c, http.StatusLocked, templates.PasswordView(&templates.PasswordData{
			Lang: string(lang), CSRFToken: sess.CSRFToken, IsAdmin: true,
			Action: "/admin/password", ErrText: templates.Tr(lang, "login.errLocked"), Nav: s.sidebarDataFor(c),
		}))
		return
	}
	valid, subjectID, verr := s.verifyAdmin(ctx, username, c.PostForm("oldPassword"))
	if verr != nil {
		sessLogger(c).Error("管理员改密查询故障", "error", verr)
		c.Status(http.StatusInternalServerError)
		return
	}
	if !valid {
		s.recordFail(ctx, "admin:"+username, c.ClientIP())
		sessLogger(c).Info("管理员改密旧密码验证失败", "ip", c.ClientIP())
		fail(templates.Tr(lang, "pw.errWrongOld"))
		return
	}
	if subjectID != sess.SubjectID {
		// 表单用户名与当前会话主体不一致——拒绝（防以会话身份为他账户改密）
		sessLogger(c).Warn("管理员改密主体不一致拒绝", "form_subject", subjectID, "sess_subject", sess.SubjectID)
		fail(templates.Tr(lang, "pw.errWrongOld"))
		return
	}
	hash, err := account.HashPassword(newPassword)
	if err != nil {
		if errors.Is(err, account.ErrPasswordTooShort) {
			fail(templates.Tr(lang, "pw.errShort")) // D10 批二：下限统一（哨兵→用户可读）
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}
	if err := s.users.UpdatePassword(ctx, subjectID, hash); err != nil {
		sessLogger(c).Error("管理员密码更新失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	if _, err := s.sess.issueSession(c, storage.SubjectTypeAdmin, subjectID); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	sessLogger(c).Info("管理员修改自身密码", "admin_id", subjectID)
	c.Redirect(http.StatusSeeOther, "/admin/settings?pwchanged=1")
}

// settingsHubGET 个人设置枢纽（GET /settings——G2/Q1-A 裁决：mailbox 主体四分区
// 账户/改密/2FA/规则；admin 主体 302 管理枢纽——单枢纽原则防入口歧义）。
func (s *Server) settingsHubGET(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}
	if sess.SubjectType == storage.SubjectTypeAdmin {
		c.Redirect(http.StatusFound, "/admin/settings")
		return
	}
	address := ""
	if m, err := s.mailboxes.FindMailboxByID(c.Request.Context(), sess.SubjectID); err == nil {
		address = m.Address
	}
	renderPage(c, http.StatusOK, templates.SettingsHubView(&templates.SettingsHubData{
		Lang:      string(langOf(c)),
		CSRFToken: sess.CSRFToken,
		Address:   address,
		PWChanged: c.Query("pwchanged") == "1",
		Nav:       s.sidebarDataFor(c),
	}))
}
