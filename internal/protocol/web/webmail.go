// GRmail Webmail 列表与侧边栏（U9 计划书步骤 5）：首页整页装配与 HTMX 列表片段。
// 依据：契约 v1.5.0 3.2（GET / 列表页、GET /mails 列表片段——hx-get 翻页/过滤）；
// SRS FR-013 核心子集+FR-012（侧边栏平铺+未读计数——REQ-021）；NFR-001（列表主路径）。
// 修改历史：
//
//	2026-09-19 10:30:00 | 新建 | U9 Webmail 核心（计划书步骤 5，G2 批准 2026-09-19 10:00:41）
package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// 分页工程常量（计划书 1.5，G2 批复生效——G12 档位作为查询参数）。
const (
	defaultPageSize = 25
	minPageSize     = 15
	maxPageSize     = 100
)

// mailListData 已收敛至 templates 包（MailListData/FolderEntry/MailRow——跨包拍平结构，
// web↔templates 零循环引用）；本文件仅装配。

// listParams 列表请求参数解析（folder/page/pagesize/unread/flagged——宽容缺省）。
type listParams struct {
	FolderID    int64
	Page        int
	Pagesize    int
	UnreadOnly  bool
	FlaggedOnly bool
}

// parseListParams 从查询串解析（缺省 folder=收件箱、page=1、pagesize=25）。
// 返回解析值与收件箱回填（folder 缺省时经 folders 定位 inbox——loadMailList 内处理）。
func parseListParams(c *gin.Context) listParams {
	p := listParams{Page: 1, Pagesize: defaultPageSize}
	if v, err := strconv.ParseInt(c.Query("folder"), 10, 64); err == nil && v > 0 {
		p.FolderID = v
	}
	if v, err := strconv.Atoi(c.Query("page")); err == nil && v > 0 {
		p.Page = v
	}
	if v, err := strconv.Atoi(c.Query("pagesize")); err == nil && v >= minPageSize && v <= maxPageSize {
		p.Pagesize = v
	}
	p.UnreadOnly = c.Query("unread") == "1"
	p.FlaggedOnly = c.Query("flagged") == "1"
	return p
}

// renderMailListPage 首页整页（U9 homeGET 业务形态）：主体视图→侧边栏+首屏列表。
func (s *Server) renderMailListPage(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	sess, _ := currentSession(c)
	data := s.loadMailListData(c, view, parseListParams(c), "", false, sess.CSRFToken)
	if data == nil {
		return
	}
	renderPage(c, http.StatusOK, templates.MailPageView(data))
}

// mailsFragmentGET 列表片段（GET /mails——HTMX 局部更新：翻页/过滤/文件夹切换）。
func (s *Server) mailsFragmentGET(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	sess, _ := currentSession(c)
	data := s.loadMailListData(c, view, parseListParams(c), "", false, sess.CSRFToken)
	if data == nil {
		return
	}
	renderFragment(c, http.StatusOK, templates.MailListFragment(data))
}

// loadMailListData 列表数据装配（folder 缺省定位收件箱；PageList Webmail 过滤路径；
// storage 原生行 → templates 拍平结构转换）。
// 参数：c 上下文；view 主体视图；p 参数；keyword 搜索关键词（非空走 Search）；
// isSearch 搜索形态标记；csrf 会话 token。返回：视图模型（失败已写响应，返回 nil）。
func (s *Server) loadMailListData(c *gin.Context, view *mailboxView, p listParams, keyword string, isSearch bool, csrf string) *templates.MailListData {
	ctx := c.Request.Context()
	folders, err := s.folders.List(ctx, view.MailboxID)
	if err != nil {
		sessLogger(c).Error("侧边栏文件夹查询失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return nil
	}
	unread, err := s.folders.UnreadCounts(ctx, view.MailboxID)
	if err != nil {
		sessLogger(c).Warn("未读计数查询失败（降级空计数）", "error", err)
		unread = map[int64]int64{}
	}

	data := &templates.MailListData{
		Lang: string(langOf(c)), Label: view.Label, IsAdmin: view.IsAdmin, CSRF: csrf, // U16 Q2-A：双语渲染
		ActiveFolder: p.FolderID, Page: p.Page, Pagesize: p.Pagesize,
		UnreadOnly: p.UnreadOnly, FlaggedOnly: p.FlaggedOnly,
		Keyword: keyword, IsSearch: isSearch,
		Folders: make([]templates.FolderEntry, 0, len(folders)),
		Items:   make([]templates.MailRow, 0, p.Pagesize),
	}
	for _, f := range folders {
		data.Folders = append(data.Folders, templates.FolderEntry{
			ID: f.ID, Name: f.Name, Kind: string(f.Kind), Unread: unread[f.ID],
		})
	}

	appendItems := func(items []*storage.ListItem, total int64) {
		data.Total = total
		for _, it := range items {
			sentAt := ""
			if !it.SentAt.IsZero() {
				sentAt = it.SentAt.Local().Format("2006-01-02 15:04")
			}
			data.Items = append(data.Items, templates.MailRow{
				ID: it.ID, Subject: it.Subject, FromAddr: it.FromAddr,
				SentAt: sentAt, IsRead: it.IsRead, IsFlagged: it.IsFlagged,
			})
		}
	}

	if isSearch {
		items, total, serr := s.messages.Search(ctx, storage.SearchQuery{
			MailboxID: view.MailboxID, Keyword: keyword,
			Limit: int32(p.Pagesize), Offset: int32((p.Page - 1) * p.Pagesize),
		})
		if serr != nil {
			sessLogger(c).Error("搜索失败", "error", serr)
			c.Status(http.StatusInternalServerError)
			return nil
		}
		appendItems(items, total)
	} else {
		folderID, ferr := s.resolveFolderID(c, folders, p.FolderID)
		if ferr != nil {
			return nil
		}
		data.ActiveFolder = folderID
		for i := range data.Folders {
			data.Folders[i].Active = data.Folders[i].ID == folderID
		}
		items, total, lerr := s.messages.PageList(ctx, storage.ListQuery{
			MailboxID: view.MailboxID, FolderID: folderID,
			Limit: int32(p.Pagesize), Offset: int32((p.Page - 1) * p.Pagesize),
			UnreadOnly: p.UnreadOnly, FlaggedOnly: p.FlaggedOnly, ExcludeDeleted: true,
		})
		if lerr != nil {
			sessLogger(c).Error("列表查询失败", "error", lerr)
			c.Status(http.StatusInternalServerError)
			return nil
		}
		appendItems(items, total)
	}

	data.PageCount = (int(data.Total) + data.Pagesize - 1) / data.Pagesize
	if data.PageCount < 1 {
		data.PageCount = 1
	}
	return data
}

// resolveFolderID 文件夹定位（0/非法→收件箱；跨账号 folder 防线：须属当前邮箱）。
func (s *Server) resolveFolderID(c *gin.Context, folders []*storage.Folder, want int64) (int64, error) {
	for _, f := range folders {
		if want > 0 && f.ID == want {
			return f.ID, nil // 属当前邮箱——合法
		}
	}
	// 缺省/非本邮箱 folder：回退收件箱（隔离防线——不暴露存在性）
	for _, f := range folders {
		if f.Kind == storage.FolderKindInbox {
			return f.ID, nil
		}
	}
	sessLogger(c).Error("收件箱文件夹缺失（数据异常）")
	c.Status(http.StatusInternalServerError)
	return 0, errFolderResolve
}

// errFolderResolve 文件夹定位失败哨兵（收件箱缺失——数据异常态）。
var errFolderResolve = errors.New("web: 文件夹定位失败")

// renderNoMailboxView 主体无邮箱视图引导页（部署引导期 admin 或异常态）。
// F23：硬编码中文双语文案 Tr 化（home.noMailbox/home.hintKind——Webmail界面精修批次 2026-10-03）。
func (s *Server) renderNoMailboxView(c *gin.Context) {
	sess, _ := currentSession(c)
	csrf := ""
	if sess != nil {
		csrf = sess.CSRFToken
	}
	lang := langOf(c)
	renderPage(c, http.StatusOK, templates.HomeView(lang,
		templates.Tr(lang, "home.noMailbox"), templates.Tr(lang, "home.hintKind"), csrf))
}

// renderFragment 渲染 HTMX 片段组件（与 renderPage 同源——片段无整页骨架）。
func renderFragment(c *gin.Context, code int, component templ.Component) {
	renderPage(c, code, component)
}

// sidebarDataFor 全站侧栏数据装配（D3 B 形态——侧栏交互缺陷修复批次：设置族页
// AppFrame 统一承载侧栏，folders+unread 查询链复用 renderMailListPage 既有形态；
// S3-W Q1=B 裁决 2026-10-05 18:28:52）。降级语义：无邮箱视图（admin 异常态）返回
// nil（AppFrame 退化为无侧栏直出）；folders/未读查询失败降级空列表不阻断页面渲染
// （Warn 记录）。pagesize 取 defaultPageSize（文件夹切换链接的一致分页基数）。
// 参数：c 请求上下文（会话/语言/邮箱视图三源）。返回：侧栏数据（nil=降级）。
func (s *Server) sidebarDataFor(c *gin.Context) *templates.MailListData {
	if s.folders == nil {
		return nil // Folders 未注入渐进态（ServerConfig nil 惯例——测试环境/降级装配；AppFrame 降级直出）
	}
	view, err := s.currentMailboxView(c)
	if err != nil {
		return nil // 无邮箱异常态——AppFrame 降级直出（既有各页行为保持）
	}
	ctx := c.Request.Context()
	folders, err := s.folders.List(ctx, view.MailboxID)
	if err != nil {
		sessLogger(c).Warn("侧栏文件夹查询失败（降级空侧栏）", "error", err)
		folders = nil
	}
	unread := map[int64]int64{}
	if u, uerr := s.folders.UnreadCounts(ctx, view.MailboxID); uerr == nil {
		unread = u
	} else {
		sessLogger(c).Warn("侧栏未读计数查询失败（降级空计数）", "error", uerr)
	}
	csrf := ""
	if sess, ok := currentSession(c); ok {
		csrf = sess.CSRFToken
	}
	nav := &templates.MailListData{
		Lang: string(langOf(c)), CSRF: csrf, Pagesize: defaultPageSize,
		Folders: make([]templates.FolderEntry, 0, len(folders)),
	}
	for _, f := range folders {
		nav.Folders = append(nav.Folders, templates.FolderEntry{
			ID: f.ID, Name: f.Name, Kind: string(f.Kind), Unread: unread[f.ID],
		})
	}
	return nav
}
