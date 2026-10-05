// GRmail Web admin API Token 管理端点族（U14，Q3-B：/admin/tokens 独立路由）。
// 依据：契约 v1.10.0 3.3（GET /admin/tokens+POST /admin/tokens+POST /admin/tokens/{id}/revoke）
// 与 2.4（Tokens 注入位——nil=端点族 503 渐进态沿 U12 SieveScripts 先例）；
// SRS FR-013（3.8「设置面板含 Token 管理」子项）；G19 参照（三档有效期+一次性明文展示+撤销）；
// U14 计划书 1.5③⑥（Token=32 字节 crypto/rand 64hex；哈希 SHA-256——idHashOf 同形态）。
// 修改历史：
//
//	2026-09-24 02:54:00 | 新建 | U14 API Token 管理（计划书步骤 4，G2 批准 2026-09-24 02:30:51）
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// bearerTokenBytes Token 原文随机字节数（C2 参照：32 字节→64 字符 hex）。
const bearerTokenBytes = 32

// tokensReady Token 端点族就绪判定（Tokens 未注入=503 渐进态——装配渐进锚）。
func (s *Server) tokensReady() bool { return s.tokens != nil }

// newBearerToken 生成 Token 原文（CSPRNG 32 字节→64hex）。
func newBearerToken() (string, error) {
	buf := make([]byte, bearerTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// bearerHashOf Token 原文→库内哈希（hex(SHA-256)——sessionService.idHashOf 同形态）。
func bearerHashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// tokensListGET Token 列表页（GET /admin/tokens——admin 门卫沿 admin.go 形态）。
func (s *Server) tokensListGET(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	if !s.tokensReady() {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	sess, _ := currentSession(c)
	renderPage(c, http.StatusOK, templates.TokensView(langOf(c), s.tokenList(c, sess.SubjectID), "", "", sess.CSRFToken, s.sidebarDataFor(c)))
}

// tokensCreatePOST Token 生成（POST /admin/tokens——三档有效期+IP 绑定可选；
// 成功=列表页重渲染+一次性明文横幅——G19 判定形态，哈希存储语义仅此一次可见）。
func (s *Server) tokensCreatePOST(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	if !s.tokensReady() {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	sess, _ := currentSession(c)
	ctx := c.Request.Context()

	// 有效期三档（G19 参照；forever=零值→NULL 永久——数据模型 v1.2.0 3.11）
	now := time.Now().UTC()
	var expires time.Time
	switch c.PostForm("expires") {
	case "7d":
		expires = now.Add(7 * 24 * time.Hour)
	case "30d":
		expires = now.Add(30 * 24 * time.Hour)
	case "forever", "":
		// 零值=永久
	default:
		renderPage(c, http.StatusBadRequest, templates.TokensView(langOf(c), s.tokenList(c, sess.SubjectID), "", templates.Tr(langOf(c), "tokens.errTier"), sess.CSRFToken, s.sidebarDataFor(c)))
		return
	}

	raw, err := newBearerToken()
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if err := s.tokens.Create(ctx, &storage.ApiToken{
		UserID:    sess.SubjectID,
		TokenHash: bearerHashOf(raw),
		ExpiresAt: expires,
		ClientIP:  c.PostForm("client_ip"), // 空=不绑定（可选输入——C2 参照）
		CreatedAt: now,
	}); err != nil {
		sessLogger(c).Error("Token 生成失败", "error", err)
		renderPage(c, http.StatusInternalServerError, templates.TokensView(langOf(c), s.tokenList(c, sess.SubjectID), "", templates.Tr(langOf(c), "tokens.errGen"), sess.CSRFToken, s.sidebarDataFor(c)))
		return
	}
	sessLogger(c).Info("Token 已生成", "user_id", sess.SubjectID, "expires", c.PostForm("expires"))
	renderPage(c, http.StatusOK, templates.TokensView(langOf(c), s.tokenList(c, sess.SubjectID), raw, "", sess.CSRFToken, s.sidebarDataFor(c)))
}

// tokensRevokePOST Token 撤销（POST /admin/tokens/:id/revoke——CSRF+双条件 Delete）。
func (s *Server) tokensRevokePOST(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	if !s.tokensReady() {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	sess, _ := currentSession(c)
	ctx := c.Request.Context()

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	if err := s.tokens.Delete(ctx, id, sess.SubjectID); err != nil {
		sessLogger(c).Error("Token 撤销失败", "error", err, "id", id)
		renderPage(c, http.StatusInternalServerError, templates.TokensView(langOf(c), s.tokenList(c, sess.SubjectID), "", templates.Tr(langOf(c), "tokens.errRevoke"), sess.CSRFToken, s.sidebarDataFor(c)))
		return
	}
	sessLogger(c).Info("Token 已撤销", "user_id", sess.SubjectID, "id", id)
	renderPage(c, http.StatusOK, templates.TokensView(langOf(c), s.tokenList(c, sess.SubjectID), "", "", sess.CSRFToken, s.sidebarDataFor(c)))
}

// tokenList 列表查询辅助（查询失败返回空表——管理页可用性优先）。
func (s *Server) tokenList(c *gin.Context, userID int64) []*storage.ApiToken {
	list, err := s.tokens.ListByUser(c.Request.Context(), userID)
	if err != nil {
		sessLogger(c).Error("Token 列表查询失败", "error", err)
		return nil
	}
	return list
}
