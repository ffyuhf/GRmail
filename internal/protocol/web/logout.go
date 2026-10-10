// GRmail Web 登出（U8 计划书步骤 6）：双侧失效 + Clear-Site-Data（OWASP Web Content
// Caching and Clear-Site-Data 章 / 流程设计第六章第 8 条 / 契约 v1.4.0 3.1：303）。
// 修改历史：
//
//	2026-09-19 05:15:00 | 新建 | U8 Web 会话与登录
package web

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/storage"
)

// logoutPOST 登出（POST /logout；CSRF 已由全局中间件按会话 token 校验——Q5-B）：
// 服务端 Delete（会话即刻失效）+ 客户端 cookie 置空过期 + Clear-Site-Data 清缓存，
// 303 重定向至主体对应登录入口（契约 v1.4.0 3.4：admin→/login、mailbox→/webmail/login）。
func (s *Server) logoutPOST(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok { // 无有效会话：登出幂等，直接回登录入口
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	// F11（C22，2026-10-10 C级债务收尾批）：Bearer 合成会话（ID 空）短路——服务端
	// Delete("") 为空操作、cookie 置空与 Clear-Site-Data 对程序化客户端均无意义；
	// Token 生命周期管理归 /admin/tokens 撤销（语义完整）。应答 303 /login 不变。
	if sess.ID == "" {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	ctx := c.Request.Context()
	if err := s.sessions.Delete(ctx, sess.ID); err != nil {
		sessLogger(c).Error("登出会话删除失败", "error", err)
	}
	// 客户端失效：置空值 + 过期时间戳置于过去（OWASP Session Expiration：客户端清理动作）
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	// 缓存清理指令（登出场景全量三类：浏览器缓存/cookie/存储）
	c.Header("Clear-Site-Data", `"cache", "cookies", "storage"`)
	sessLogger(c).Info("会话登出（双侧失效）", "subject_type", string(sess.SubjectType))

	dest := "/login"
	if sess.SubjectType == storage.SubjectTypeMailbox {
		dest = "/webmail/login"
	}
	c.Redirect(http.StatusSeeOther, dest)
}
