// web 层 /sieve 端点族（契约 v1.8.0 3.2——FR-011 Web 编辑器双入口之二，U12）。
// 主体隔离（计划书 1.5⑩）：mailbox 主体操作 subject_id 邮箱脚本；admin 沿 U9
// postmaster 视图先例（currentMailboxView 统一解析）；CSRF 表单沿 U8/U9 先例；
// 保存时 sieve.Parse 编译期校验拒绝（rfc5228 §2.10.6 编译期错误分类）。
// 修改历史：
//
//	2026-09-21 01:06:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 9）
//	2026-10-04 22:02:00 | 修正 | Sieve编辑器缺口修复批次：#30 新建死锁（POST 表单 name 优先于
//	URL 参数+validSieveScriptName 校验+new 态 NameEditable）+#31 取消激活
//	（sieveDeactivatePOST——GetActiveScript 名比对后 SetActive 哨兵清除，防误清
//	非目标脚本激活态；幂等语义：非激活目标直接 303）
//	（依据：Sieve编辑器缺口修复_计划 v1.0.0 步骤 1/2，G2 批准 2026-10-04 21:56:23）
package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/sieve"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// validSieveScriptName Web 侧脚本名校验（#30）。managesieve PUTSCRIPT 侧对名称无
// 字符级限制（unquote 后任意 UTF-8——rfc5804 仅约束语法载体）；Web 侧因名称经
// URL 路径参数承载（/sieve/:name）增最小防御：非空、非保留路由名 new、无路径
// 分隔与查询锚点字符（/?#&）、长度 ≤128（与模板 maxlength 同口径）。
func validSieveScriptName(name string) bool {
	if name == "" || name == "new" || len(name) > 128 {
		return false
	}
	return !strings.ContainsAny(name, "/?#&")
}

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
	data := &templates.SieveListData{Lang: langOf(c), CSRF: s.csrfOf(c), Scripts: []templates.SieveScriptRow{}, Nav: s.sidebarDataFor(c)}
	scripts, err := repo.ListScripts(c.Request.Context(), mboxID)
	if err != nil {
		data.Error = templates.Trf(langOf(c), "sieve.errList", err.Error())
	}
	for _, sc := range scripts {
		data.Scripts = append(data.Scripts, templates.SieveScriptRow{Name: sc.Name, Active: sc.IsActive})
	}
	renderPage(c, http.StatusOK, templates.SieveListView(data))
}

// sieveEditGET GET /sieve/:name 编辑页（new=新建空表单——#30：NameEditable 态承载名称输入框）。
func (s *Server) sieveEditGET(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, templates.Tr(langOf(c), "sieve.errDisabled"))
		return
	}
	name := c.Param("name")
	data := &templates.SieveEditData{Lang: langOf(c), CSRF: s.csrfOf(c), Name: name, NameEditable: name == "new", Nav: s.sidebarDataFor(c)}
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

// sieveEditPOST POST /sieve/:name 保存（编译期校验拒绝重渲染；#30：表单 name 字段
// 优先于 URL :name 参数——new 态名称经输入框承载，编辑态表单无 name 字段=URL 名直用）。
func (s *Server) sieveEditPOST(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, templates.Tr(langOf(c), "sieve.errDisabled"))
		return
	}
	isNewEntry := c.Param("name") == "new" // 原入口态（重渲染保持 NameEditable——名称输入框不消失）
	name := c.Param("name")
	if formName := c.PostForm("name"); formName != "" {
		name = formName
	}
	content := c.PostForm("content")
	data := &templates.SieveEditData{Lang: langOf(c), CSRF: s.csrfOf(c), Name: name, NameEditable: isNewEntry, Content: content, Nav: s.sidebarDataFor(c)}
	if !validSieveScriptName(name) {
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

// sieveDeactivatePOST POST /sieve/:name/deactivate 取消激活（#31——契约 v1.24.0）。
// 语义与协议侧 SETACTIVE ""（managesieve cmdSetActive 空名分支）对称；差异点：
// 本端点带目标名，须先比对当前激活脚本名——仅目标为当前激活时清除（防误清
// 其他脚本的激活态）；目标非激活=幂等成功 303；目标不存在=404。
func (s *Server) sieveDeactivatePOST(c *gin.Context) {
	repo, mboxID, ok := s.sieveScriptsView(c)
	if !ok {
		c.String(http.StatusServiceUnavailable, templates.Tr(langOf(c), "sieve.errDisabled"))
		return
	}
	name := c.Param("name")
	ctx := c.Request.Context()
	if _, err := repo.GetScript(ctx, mboxID, name); err != nil {
		if errors.Is(err, storage.ErrSieveScriptNotFound) {
			c.String(http.StatusNotFound, templates.Tr(langOf(c), "sieve.notFound"))
			return
		}
		c.String(http.StatusInternalServerError, templates.Trf(langOf(c), "sieve.errGet", err.Error()))
		return
	}
	if act, err := repo.GetActiveScript(ctx, mboxID); err == nil && act != nil && act.Name == name {
		// 取消激活哨兵（与 managesieve SETACTIVE "" 同款 "\x00none"——清空且不置新；
		// ErrSieveScriptNotFound 容忍同协议侧语义）
		if err := repo.SetActive(ctx, mboxID, "\x00none"); err != nil && !errors.Is(err, storage.ErrSieveScriptNotFound) {
			c.String(http.StatusBadRequest, templates.Trf(langOf(c), "sieve.errSave", err.Error()))
			return
		}
	}
	c.Redirect(http.StatusSeeOther, "/sieve")
}
