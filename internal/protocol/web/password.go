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
package web

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// passwordFormGET 改密表单页（GET /settings/password 与 /admin/password 共用——
// action 按当前主体类型分派；admin 呈现 username 字段，mailbox 免输）。
func (s *Server) passwordFormGET(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}
	isAdmin := sess.SubjectType == storage.SubjectTypeAdmin
	data := &templates.PasswordData{
		Lang:      string(langOf(c)),
		CSRFToken: sess.CSRFToken,
		IsAdmin:   isAdmin,
		Action:    "/settings/password",
		Nav:       s.sidebarDataFor(c), // D3 B 形态——全站侧栏
	}
	if isAdmin {
		data.Action = "/admin/password"
	}
	renderPage(c, http.StatusOK, templates.PasswordView(data))
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
		c.Status(http.StatusForbidden) // admin 主体请走 /admin/password（分域承载）
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
	// 旧密码验证：VerifyCredentials 统一拒绝语义复用（影子/禁用/错密同拒——防枚举口径）
	if _, verr := s.accounts.VerifyCredentials(ctx, m.Address, c.PostForm("oldPassword")); verr != nil {
		s.recordFail(ctx, "mailbox:"+m.Address, c.ClientIP()) // 失败计数（防爆破——Q4-B 链路）
		sessLogger(c).Info("邮箱用户改密旧密码验证失败", "mailbox_id", sess.SubjectID, "ip", c.ClientIP())
		fail(templates.Tr(lang, "pw.errWrongOld"))
		return
	}
	if err := s.accounts.SetMailboxPassword(ctx, m.Address, newPassword); err != nil {
		sessLogger(c).Error("邮箱用户改密失败", "mailbox_id", sess.SubjectID, "error", err)
		c.Status(http.StatusInternalServerError)
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
