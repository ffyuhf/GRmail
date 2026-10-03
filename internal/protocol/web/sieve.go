// web 层 /sieve 端点族（契约 v1.8.0 3.2——FR-011 Web 编辑器双入口之二，U12）。
// 主体隔离（计划书 1.5⑩）：mailbox 主体操作 subject_id 邮箱脚本；admin 沿 U9
// postmaster 视图先例（currentMailboxView 统一解析）；CSRF 表单沿 U8/U9 先例；
// 保存时 sieve.Parse 编译期校验拒绝（rfc5228 §2.10.6 编译期错误分类）。
// 修改历史：
//
//	2026-09-21 01:06:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 9）
package web

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"GRmail/internal/sieve"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// csrfOf 当前会话 CSRF token（U9 currentSession 形态复用——AppLayout 第 4 参）。
func (s *Server) csrfOf(c *gin.Context) string {
	sess, _ := currentSession(c)
	if sess == nil {
		return ""
	}
	return sess.CSRFToken
}

// sieveScriptsView 当前主体的脚本视图（mailbox 主体=subject_id；admin=postmaster
// 视图——U9 currentMailboxView 先例；未就绪返回 false）。
func (s *Server) sieveScriptsView(c *gin.Context) (storage.SieveScriptRepo, int64, bool) {
	view, err := s.currentMailboxView(c)
	if err != nil || view == nil {
		return nil, 0, false
	}
	return s.sieveScripts, view.MailboxID, true
}

// sieveListGET GET /sieve 列表页。
func (s *Server) sieveListGET(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, templates.Tr(langOf(c), "sieve.errDisabled"))
		return
	}
	data := &templates.SieveListData{Lang: langOf(c), CSRF: s.csrfOf(c), Scripts: []templates.SieveScriptRow{}}
	scripts, err := repo.ListScripts(c.Request.Context(), mboxID)
	if err != nil {
		data.Error = templates.Trf(langOf(c), "sieve.errList", err.Error())
	}
	for _, sc := range scripts {
		data.Scripts = append(data.Scripts, templates.SieveScriptRow{Name: sc.Name, Active: sc.IsActive})
	}
	renderPage(c, http.StatusOK, templates.SieveListView(data))
}

// sieveEditGET GET /sieve/:name 编辑页（new=新建空表单）。
func (s *Server) sieveEditGET(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, templates.Tr(langOf(c), "sieve.errDisabled"))
		return
	}
	name := c.Param("name")
	data := &templates.SieveEditData{Lang: langOf(c), CSRF: s.csrfOf(c), Name: name}
	if name != "new" {
		sc, err := repo.GetScript(c.Request.Context(), mboxID, name)
		if err != nil {
			if errors.Is(err, storage.ErrSieveScriptNotFound) {
				c.String(http.StatusNotFound, templates.Tr(langOf(c), "sieve.notFound"))
				return
			}
			data.Error = templates.Trf(langOf(c), "sieve.errGet", err.Error())
		} else {
			data.Content = sc.Content
		}
	}
	renderPage(c, http.StatusOK, templates.SieveEditView(data))
}

// sieveEditPOST POST /sieve/:name 保存（编译期校验拒绝重渲染）。
func (s *Server) sieveEditPOST(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, templates.Tr(langOf(c), "sieve.errDisabled"))
		return
	}
	name := c.Param("name")
	content := c.PostForm("content")
	data := &templates.SieveEditData{Lang: langOf(c), CSRF: s.csrfOf(c), Name: name, Content: content}
	if name == "new" || name == "" {
		data.Error = templates.Tr(langOf(c), "sieve.errName")
		renderPage(c, http.StatusBadRequest, templates.SieveEditView(data))
		return
	}
	if _, perr := sieve.Parse(content); perr != nil { // 编译期校验（PUTSCRIPT 同款）
		data.Error = templates.Trf(langOf(c), "sieve.errSyntax", perr.Error())
		renderPage(c, http.StatusBadRequest, templates.SieveEditView(data))
		return
	}
	if err := repo.PutScript(c.Request.Context(), &storage.SieveScript{
		MailboxID: mboxID, Name: name, Content: content,
	}); err != nil {
		data.Error = templates.Trf(langOf(c), "sieve.errSave", err.Error())
		renderPage(c, http.StatusInternalServerError, templates.SieveEditView(data))
		return
	}
	c.Redirect(http.StatusSeeOther, "/sieve")
}

// sieveActivatePOST POST /sieve/:name/activate 激活（互斥单激活）。
func (s *Server) sieveActivatePOST(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, "Sieve 未启用")
		return
	}
	if err := repo.SetActive(c.Request.Context(), mboxID, c.Param("name")); err != nil {
		c.String(http.StatusBadRequest, "激活失败："+err.Error())
		return
	}
	c.Redirect(http.StatusSeeOther, "/sieve")
}

// sieveDeletePOST POST /sieve/:name/delete 删除（激活脚本连带清激活）。
func (s *Server) sieveDeletePOST(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, "Sieve 未启用")
		return
	}
	if err := repo.DeleteScript(c.Request.Context(), mboxID, c.Param("name")); err != nil {
		c.String(http.StatusBadRequest, "删除失败："+err.Error())
		return
	}
	c.Redirect(http.StatusSeeOther, "/sieve")
}
