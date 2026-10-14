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
// 视图——U9 currentMailboxView 先例）。返回：repo/mailboxID/状态码（A4 批三：
// 0=就绪；1=SieveScripts 未注入〔真·未启用〕；2=主体视图缺位〔admin 主邮箱实体
// 未建立——原与未启用共用 errDisabled 误导文案，分键收口〕）。
func (s *Server) sieveScriptsView(c *gin.Context) (storage.SieveScriptRepo, int64, int) {
	view, err := s.currentMailboxView(c)
	if err != nil || view == nil {
		return nil, 0, 2
	}
	if s.sieveScripts == nil {
		return nil, 0, 1
	}
	return s.sieveScripts, view.MailboxID, 0
}

// sieveViewErrKey /sieve 族不可用态文案键（A4 批三——状态分键：视图缺位≠Sieve
// 未启用，errNoView 如实呈现「主邮箱未建立」语义，配合 E-2-A 启动确保双防线）。
func sieveViewErrKey(state int) string {
	if state == 2 {
		return "sieve.errNoView"
	}
	return "sieve.errDisabled"
}

// sieveListGET GET /sieve 列表页。
func (s *Server) sieveListGET(c *gin.Context) {
	repo, mboxID, st := s.sieveScriptsView(c)
	if st != 0 {
		s.errPage(c, http.StatusServiceUnavailable, sieveViewErrKey(st))
		return
	}
	// F7（批二）：主体标记填充（admin 直达管理枢纽返回链）。
	data := &templates.SieveListData{Lang: langOf(c), CSRF: s.csrfOf(c), IsAdmin: s.sessionIsAdmin(c), Scripts: []templates.SieveScriptRow{}, Nav: s.sidebarDataFor(c)}
	// B2/E-1-A（α 批）：操作成功反馈（noticed 303 回带——键映射后注入 Notice 呈现）。
	if k := sieveNoticedKey(c.Query("noted")); k != "" {
		data.Notice = templates.Tr(langOf(c), k)
	}
	scripts, err := repo.ListScripts(c.Request.Context(), mboxID)
	if err != nil {
		// E2 补齐（批二续接）：列表失败原文入日志、界面模糊文案（errList 改非格式串）。
		sessLogger(c).Error("脚本列举失败", "error", err)
		data.Error = templates.Tr(langOf(c), "sieve.errList")
	}
	for _, sc := range scripts {
		data.Scripts = append(data.Scripts, templates.SieveScriptRow{Name: sc.Name, Active: sc.IsActive})
	}
	renderPage(c, http.StatusOK, templates.SieveListView(data))
}

// sieveEditGET GET /sieve/:name 编辑页（new=新建空表单——#30：NameEditable 态承载名称输入框）。
func (s *Server) sieveEditGET(c *gin.Context) {
	repo, mboxID, st := s.sieveScriptsView(c)
	if st != 0 {
		s.errPage(c, http.StatusServiceUnavailable, sieveViewErrKey(st))
		return
	}
	name := c.Param("name")
	data := &templates.SieveEditData{Lang: langOf(c), CSRF: s.csrfOf(c), Name: name, NameEditable: name == "new", IsAdmin: s.sessionIsAdmin(c), Nav: s.sidebarDataFor(c)}
	if name != "new" {
		sc, err := repo.GetScript(c.Request.Context(), mboxID, name)
		if err != nil {
			if errors.Is(err, storage.ErrSieveScriptNotFound) {
				s.errPage(c, http.StatusNotFound, "sieve.notFound")
				return
			}
			sessLogger(c).Error("脚本读取失败", "error", err)
			data.Error = templates.Tr(langOf(c), "sieve.errSave")
		} else {
			data.Content = sc.Content
		}
	}
	renderPage(c, http.StatusOK, templates.SieveEditView(data))
}

// sieveNoticedKey 操作反馈查询参→文案键（B2/E-1-A——α 批；未知值返回空串零呈现）。
func sieveNoticedKey(noted string) string {
	switch noted {
	case "saved":
		return "sieve.noticedSaved"
	case "activated":
		return "sieve.noticedActivated"
	case "deactivated":
		return "sieve.noticedDeactivated"
	case "deleted":
		return "sieve.noticedDeleted"
	}
	return ""
}

// sieveEditPOST POST /sieve/:name 保存（编译期校验拒绝重渲染；#30：表单 name 字段
// 优先于 URL :name 参数——new 态名称经输入框承载，编辑态表单无 name 字段=URL 名直用）。
func (s *Server) sieveEditPOST(c *gin.Context) {
	repo, mboxID, st := s.sieveScriptsView(c)
	if st != 0 {
		// B7（α 批）：裸 c.String 收口入 errPage 双态（同族 listGET 形态一致化；
		// 状态码语义保持 503）。
		s.errPage(c, http.StatusServiceUnavailable, sieveViewErrKey(st))
		return
	}
	isNewEntry := c.Param("name") == "new" // 原入口态（重渲染保持 NameEditable——名称输入框不消失）
	name := c.Param("name")
	if formName := c.PostForm("name"); formName != "" {
		name = formName
	}
	content := c.PostForm("content")
	data := &templates.SieveEditData{Lang: langOf(c), CSRF: s.csrfOf(c), Name: name, NameEditable: isNewEntry, Content: content, IsAdmin: s.sessionIsAdmin(c), Nav: s.sidebarDataFor(c)}
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
		sessLogger(c).Error("脚本保存失败", "error", err)
		data.Error = templates.Tr(langOf(c), "sieve.errSave")
		renderPage(c, http.StatusInternalServerError, templates.SieveEditView(data))
		return
	}
	c.Redirect(http.StatusSeeOther, "/sieve?noted=saved") // B2/E-1-A（α 批）：成功反馈
}

// sieveActivatePOST POST /sieve/:name/activate 激活（互斥单激活）。
func (s *Server) sieveActivatePOST(c *gin.Context) {
	repo, mboxID, st := s.sieveScriptsView(c)
	if st != 0 {
		s.errPage(c, http.StatusServiceUnavailable, sieveViewErrKey(st))
		return
	}
	if err := repo.SetActive(c.Request.Context(), mboxID, c.Param("name")); err != nil {
		// E2（批二）：内部错误模糊化（原文入日志——sieve.errActivate 键承载）。
		sessLogger(c).Error("脚本激活失败", "error", err)
		s.errPage(c, http.StatusBadRequest, "sieve.errActivate")
		return
	}
	c.Redirect(http.StatusSeeOther, "/sieve?noted=activated") // B2/E-1-A（α 批）：成功反馈
}

// sieveDeletePOST POST /sieve/:name/delete 删除（激活脚本连带清激活）。
func (s *Server) sieveDeletePOST(c *gin.Context) {
	repo, mboxID, st := s.sieveScriptsView(c)
	if st != 0 {
		s.errPage(c, http.StatusServiceUnavailable, sieveViewErrKey(st))
		return
	}
	if err := repo.DeleteScript(c.Request.Context(), mboxID, c.Param("name")); err != nil {
		sessLogger(c).Error("脚本删除失败", "error", err)
		s.errPage(c, http.StatusBadRequest, "sieve.errDelete")
		return
	}
	c.Redirect(http.StatusSeeOther, "/sieve?noted=deleted") // B2/E-1-A（α 批）：成功反馈
}

// sieveDeactivatePOST POST /sieve/:name/deactivate 取消激活（#31——契约 v1.24.0）。
// 语义与协议侧 SETACTIVE ""（managesieve cmdSetActive 空名分支）对称；差异点：
// 本端点带目标名，须先比对当前激活脚本名——仅目标为当前激活时清除（防误清
// 其他脚本的激活态）；目标非激活=幂等成功 303；目标不存在=404。
// sessionIsAdmin 当前会话主体是否 admin（F7 批二——Sieve 视图标记填充辅助）。
func (s *Server) sessionIsAdmin(c *gin.Context) bool {
	sess, ok := currentSession(c)
	return ok && sess.SubjectType == storage.SubjectTypeAdmin
}

func (s *Server) sieveDeactivatePOST(c *gin.Context) {
	repo, mboxID, st := s.sieveScriptsView(c)
	if st != 0 {
		s.errPage(c, http.StatusServiceUnavailable, sieveViewErrKey(st))
		return
	}
	name := c.Param("name")
	ctx := c.Request.Context()
	if _, err := repo.GetScript(ctx, mboxID, name); err != nil {
		if errors.Is(err, storage.ErrSieveScriptNotFound) {
			s.errPage(c, http.StatusNotFound, "sieve.notFound")
			return
		}
		sessLogger(c).Error("脚本读取失败", "error", err)
		s.errPage(c, http.StatusInternalServerError, "sieve.errSave")
		return
	}
	if act, err := repo.GetActiveScript(ctx, mboxID); err == nil && act != nil && act.Name == name {
		// 取消激活哨兵（与 managesieve SETACTIVE "" 同款 "\x00none"——清空且不置新；
		// ErrSieveScriptNotFound 容忍同协议侧语义）
		if err := repo.SetActive(ctx, mboxID, "\x00none"); err != nil && !errors.Is(err, storage.ErrSieveScriptNotFound) {
			sessLogger(c).Error("取消激活失败", "error", err)
			s.errPage(c, http.StatusBadRequest, "sieve.errSave")
			return
		}
	}
	c.Redirect(http.StatusSeeOther, "/sieve?noted=deactivated") // B2/E-1-A（α 批）：成功反馈
}
