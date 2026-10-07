// GRmail Webmail 批量操作与文件夹管理（U9 计划书步骤 7）。
// 批量依据：契约 v1.5.0 3.2（POST /mails/batch 读/删/移）+ G10 批量套件语义；
// 两段式删除（计划书 1.5，G14 二次删除语义推导）：非 Trash 邮件 delete=Move 至 Trash、
// Trash 内 delete=HardDelete；标志位动作经 FlagPatch 三值补丁。
// 文件夹依据：契约 v1.5.0 3.2 新增三端点（Q4-A——FR-012 Webmail 侧验收载体）；
// account.Service 复用（系统文件夹保护/单层约束在 storage 层，U2）。
// 修改历史：
//
//	2026-09-19 10:36:00 | 新建 | U9 Webmail 核心（计划书步骤 7，G2 批准 2026-09-19 10:00:41）
package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/storage"
)

// 批量动作集（G10 核心子集——计划书 1.5 口径）。
const (
	batchMarkRead   = "mark-read"
	batchMarkUnread = "mark-unread"
	batchMarkFlag   = "mark-flag"
	batchUnmarkFlag = "unmark-flag"
	batchMove       = "move"
	batchDelete     = "delete"
)

// mailsBatchPOST 批量操作（POST /mails/batch）：ids[]+action（+folder 移动目标）→
// 响应刷新后的列表片段（HTMX 目标区原地更新）。
func (s *Server) mailsBatchPOST(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	action := c.PostForm("action")
	idsRaw := c.PostFormArray("ids")
	ids := parseIDList(idsRaw)
	if len(ids) == 0 || action == "" {
		c.Status(http.StatusBadRequest)
		return
	}
	ctx := c.Request.Context()

	switch action {
	case batchMarkRead, batchMarkUnread, batchMarkFlag, batchUnmarkFlag:
		patch := storage.FlagPatch{}
		v := action == batchMarkRead || action == batchMarkFlag
		switch action {
		case batchMarkRead, batchMarkUnread:
			patch.IsRead = &v
		case batchMarkFlag, batchUnmarkFlag:
			patch.IsFlagged = &v
		}
		for _, id := range ids {
			// 安全原子性批 F7（2026-10-06）：逐 id 归属预检（GetDetail 双限定——
			// 对齐 batchDelete 同文件防线）；跨邮箱 id 跳过并告警（FR-001 隔离）。
			if _, derr := s.messages.GetDetail(ctx, view.MailboxID, id); derr != nil {
				sessLogger(c).Warn("批量标志跳过（无权或不存在）", "id", id, "error", derr)
				continue
			}
			if err = s.messages.SetFlags(ctx, id, patch); err != nil {
				sessLogger(c).Warn("批量标志位失败（逐项尽力）", "id", id, "error", err)
			}
		}
	case batchMove:
		folderID, ferr := strconv.ParseInt(c.PostForm("folder"), 10, 64)
		if ferr != nil || folderID <= 0 {
			c.Status(http.StatusBadRequest)
			return
		}
		if !s.ownsFolder(c, view, folderID) {
			c.Status(http.StatusForbidden) // 跨账号 folder 防线
			return
		}
		for _, id := range ids {
			// 安全原子性批 F7：归属预检同上（跨邮箱搬移防线补齐）。
			if _, derr := s.messages.GetDetail(ctx, view.MailboxID, id); derr != nil {
				sessLogger(c).Warn("批量移动跳过（无权或不存在）", "id", id, "error", derr)
				continue
			}
			if err = s.messages.Move(ctx, id, folderID); err != nil {
				sessLogger(c).Warn("批量移动失败（逐项尽力）", "id", id, "error", err)
			}
		}
	case batchDelete:
		if serr := s.batchDelete(c, view, ids); serr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
	default:
		c.Status(http.StatusBadRequest)
		return
	}

	sessLogger(c).Info("批量操作", "action", action, "count", len(ids), "log_id", c.GetString(ctxKeyLogID))
	// 操作后刷新列表片段（当前上下文参数回放）
	s.mailsFragmentGET(c)
}

// batchDelete 两段式删除：非 Trash → Move 至 Trash（可恢复）；Trash 内 → HardDelete
// （G14 二次删除）。逐项按其当前 folder 判定（跨文件夹混合选择安全）。
// U25：聚合文件夹（Unregistered）内删除 → HardDelete+级联（S3-W Q2 附加指示
// 「删除聚合文件夹内邮件→真实邮件一并删除」——不经垃圾箱中转，级联在 storage 层）。
func (s *Server) batchDelete(c *gin.Context, view *mailboxView, ids []int64) error {
	ctx := c.Request.Context()
	folders, err := s.folders.List(ctx, view.MailboxID)
	if err != nil {
		return err
	}
	var trashID, aggregateID int64
	for _, f := range folders {
		switch f.Kind {
		case storage.FolderKindTrash:
			trashID = f.ID
		case storage.FolderKindUnregistered:
			aggregateID = f.ID
		}
	}
	for _, id := range ids {
		msg, merr := s.messages.GetDetail(ctx, view.MailboxID, id)
		if merr != nil {
			continue // 已不存在——幂等跳过
		}
		if aggregateID != 0 && msg.FolderID == aggregateID {
			if merr = s.messages.HardDelete(ctx, []int64{id}); merr != nil {
				sessLogger(c).Warn("聚合邮件级联删除失败", "id", id, "error", merr)
			}
			continue
		}
		if msg.FolderID != trashID {
			if merr = s.messages.Move(ctx, id, trashID); merr != nil {
				sessLogger(c).Warn("移入垃圾箱失败", "id", id, "error", merr)
			}
			continue
		}
		if merr = s.messages.HardDelete(ctx, []int64{id}); merr != nil {
			sessLogger(c).Warn("垃圾箱彻底删除失败", "id", id, "error", merr)
		}
	}
	return nil
}

// ownsFolder folder 归属判定（当前邮箱——跨账号防线）。
func (s *Server) ownsFolder(c *gin.Context, view *mailboxView, folderID int64) bool {
	folders, err := s.folders.List(c.Request.Context(), view.MailboxID)
	if err != nil {
		return false
	}
	for _, f := range folders {
		if f.ID == folderID {
			return true
		}
	}
	return false
}

// parseIDList 字符串 id 列表 → int64（非法项跳过）。
func parseIDList(raw []string) []int64 {
	out := make([]int64, 0, len(raw))
	for _, r := range raw {
		if v, err := strconv.ParseInt(strings.TrimSpace(r), 10, 64); err == nil && v > 0 {
			out = append(out, v)
		}
	}
	return out
}

// folderCreatePOST 创建自定义文件夹（POST /folders——契约 v1.5.0 3.2，Q4-A）。
func (s *Server) folderCreatePOST(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	name := strings.TrimSpace(c.PostForm("name"))
	if name == "" {
		c.Status(http.StatusBadRequest)
		return
	}
	if err = s.accounts.CreateFolder(c.Request.Context(), view.MailboxID, name); err != nil {
		s.folderErrResponse(c, err)
		return
	}
	sessLogger(c).Info("文件夹创建", "name", name)
	// 管理员主体增强批次 G3（D9）：整页 303 重定向——侧栏+列表+管理区全刷新+
	// noticed 反馈（原 hx 片段响应侧栏不在 #mail-list 内不刷新致重复提交误操作）
	c.Redirect(http.StatusSeeOther, "/?noted=created")
}

// folderRenamePOST 重命名自定义文件夹（POST /folders/{id}/rename）。
func (s *Server) folderRenamePOST(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	if !s.ownsFolder(c, view, id) {
		c.Status(http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(c.PostForm("name"))
	if name == "" {
		c.Status(http.StatusBadRequest)
		return
	}
	if err = s.accounts.RenameFolder(c.Request.Context(), id, name); err != nil {
		s.folderErrResponse(c, err)
		return
	}
	sessLogger(c).Info("文件夹重命名", "id", id, "name", name)
	c.Redirect(http.StatusSeeOther, "/?noted=renamed") // G3——D9 整页刷新+反馈
}

// folderDeletePOST 删除自定义文件夹（POST /folders/{id}/delete；系统文件夹保护在
// storage 层——RenameCustom/DeleteCustom 仅 kind=custom；非空删除 FK 拒绝）。
func (s *Server) folderDeletePOST(c *gin.Context) {
	view, err := s.currentMailboxView(c)
	if err != nil {
		s.renderNoMailboxView(c)
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.Status(http.StatusBadRequest)
		return
	}
	if !s.ownsFolder(c, view, id) {
		c.Status(http.StatusForbidden)
		return
	}
	if err = s.accounts.DeleteFolder(c.Request.Context(), id); err != nil {
		s.folderErrResponse(c, err)
		return
	}
	sessLogger(c).Info("文件夹删除", "id", id)
	c.Redirect(http.StatusSeeOther, "/?noted=deleted") // G3——D9 整页刷新+反馈
}

// folderErrResponse 文件夹操作错误 → 用户可读提示（FK 约束/重名/系统文件夹保护）。
func (s *Server) folderErrResponse(c *gin.Context, err error) {
	msg := "操作失败"
	switch {
	case strings.Contains(err.Error(), "UNIQUE"):
		msg = "同名文件夹已存在"
	case strings.Contains(err.Error(), "FOREIGN KEY"):
		msg = "文件夹非空，请先清空邮件"
	case strings.Contains(err.Error(), "kind"):
		msg = "系统文件夹不可操作"
	}
	c.Header("HX-Retarget", "#folder-hint")
	c.Header("HX-Reswap", "innerHTML")
	c.String(http.StatusOK, msg)
}
