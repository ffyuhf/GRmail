// GRmail Web admin 邮箱管理（U9 计划书步骤 10，Q3-C 裁决归属：/admin/mailboxes 与
// /admin/mailboxes/unregistered 归 U9；/admin/settings 归 U10）。
// 依据：契约 v1.5.0 3.3（归属注记）；SRS FR-002（管理员全权——创建/激活设密/禁用/
// 启用 Web 呈现）+FR-003（catch-all 聚合视图——shadow 邮箱巡览，未注册来信归档载体）；
// 数据源：MailboxRepo.ListByStatus 三态合并（计划书 1.5——契约五方法内路径零增量）+
// account.Service 复用（CreateMailbox/ActivateMailbox/SetMailboxStatus，U2）。
// 修改历史：
//
//	2026-09-19 10:44:00 | 新建 | U9 Webmail 核心（计划书步骤 10，G2 批准 2026-09-19 10:00:41）
package web

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// adminGuard admin 端点门卫（403 非 admin 主体——FR-002 权限锚）。
func (s *Server) adminGuard(c *gin.Context) bool {
	sess, ok := currentSession(c)
	if !ok || sess.SubjectType != storage.SubjectTypeAdmin {
		c.Status(http.StatusForbidden)
		return false
	}
	return true
}

// adminMailboxesGET 邮箱全量列表（GET /admin/mailboxes——三态合并：active/shadow/disabled；
// G4 增强行装配——2FA 态/创建时间列）。
func (s *Server) adminMailboxesGET(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	rows, err := s.adminMailboxRows(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	sess, _ := currentSession(c)
	renderPage(c, http.StatusOK, templates.AdminMailboxesView(langOf(c), rows, "", sess.CSRFToken, s.sidebarDataFor(c)))
}

// adminMailboxesPOST 邮箱管理操作（POST /admin/mailboxes——action 五态）：
// create（地址+密码）/ activate（影子激活设密——FR-004 原地继承）/ disable / enable /
// setpassword（Webmail管理职能批次 G1——FR-002「编辑」：管理员对任一邮箱改密）。
func (s *Server) adminMailboxesPOST(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	ctx := c.Request.Context()
	action := c.PostForm("action")
	addr := c.PostForm("address")
	password := c.PostForm("password")
	var opErr error
	switch action {
	case "create":
		if _, opErr = s.accounts.CreateMailbox(ctx, addr, password); opErr == nil {
			sessLogger(c).Info("admin 创建邮箱", "addr", addr)
		}
	case "activate":
		if opErr = s.accounts.ActivateMailbox(ctx, addr, password); opErr == nil {
			sessLogger(c).Info("admin 激活影子邮箱（原地继承）", "addr", addr)
		}
	case "disable":
		if opErr = s.accounts.SetMailboxStatus(ctx, addr, storage.MailboxStatusDisabled); opErr == nil {
			sessLogger(c).Info("admin 禁用邮箱", "addr", addr)
		}
	case "enable":
		if opErr = s.accounts.SetMailboxStatus(ctx, addr, storage.MailboxStatusActive); opErr == nil {
			sessLogger(c).Info("admin 启用邮箱", "addr", addr)
		}
	case "setpassword": // G1（FR-002）：管理员对任一 active/disabled 邮箱改密（影子拒绝——归激活流程）
		if opErr = s.accounts.SetMailboxPassword(ctx, addr, password); opErr == nil {
			sessLogger(c).Info("admin 修改邮箱密码", "addr", addr)
		}
	case "require2fa": // U24（FR-018 判定④）：管理员强制 2FA 标记（TC-028 判定⑤锚）
		if opErr = s.adminSetTwoFactorRequired(ctx, addr, true); opErr == nil {
			sessLogger(c).Info("admin 设置 2FA 强制标记", "addr", addr)
		}
	case "unrequire2fa":
		if opErr = s.adminSetTwoFactorRequired(ctx, addr, false); opErr == nil {
			sessLogger(c).Info("admin 取消 2FA 强制标记", "addr", addr)
		}
	default:
		c.Status(http.StatusBadRequest)
		return
	}

	errText := ""
	if opErr != nil {
		errText = adminErrText(langOf(c), opErr)
	}
	rows, err := s.adminMailboxRows(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	sess, _ := currentSession(c)
	renderPage(c, http.StatusOK, templates.AdminMailboxesView(langOf(c), rows, errText, sess.CSRFToken, s.sidebarDataFor(c)))
}

// adminMailboxRows 管理列表增强行装配（G4——D4：2FA 绑定/强制态+创建时间列；
// TwoFactor 未注入或单点查询故障时该行 2FA 态呈现未知——尽力语义，列表主数据不受阻）。
// 参数：c Gin 上下文。返回：增强行集；三态合并查询故障返回 error。
func (s *Server) adminMailboxRows(c *gin.Context) ([]*templates.AdminMailboxRow, error) {
	ctx := c.Request.Context()
	all, err := s.listAllMailboxes(c)
	if err != nil {
		return nil, err
	}
	rows := make([]*templates.AdminMailboxRow, 0, len(all))
	for _, m := range all {
		row := &templates.AdminMailboxRow{
			Address:   m.Address,
			Status:    string(m.Status),
			CreatedAt: m.CreatedAt.Format("2006-01-02"),
			MailboxID: m.ID,
		}
		if s.twoFactor != nil {
			if st, stErr := s.twoFactor.State(ctx, m.ID); stErr == nil {
				row.TwoFABound = st.Bound()
				row.TwoFARequired = st.Required
				row.TwoFAKnown = true
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// adminSetTwoFactorRequired 管理员强制 2FA 标记操作（U24——FR-018 判定④）：
// TwoFactor 未注入返回不可用哨兵（操作侧可读错误）；地址反查→SetRequired 落库。
// 参数：ctx 上下文；addr 邮箱地址；required 标记目标态。返回：操作错误。
func (s *Server) adminSetTwoFactorRequired(ctx context.Context, addr string, required bool) error {
	if s.twoFactor == nil {
		return errTwoFactorUnavailable
	}
	m, err := s.accounts.GetMailbox(ctx, addr)
	if err != nil {
		return err
	}
	return s.twoFactor.SetRequired(ctx, m.ID, required)
}

// adminUnregisteredGET catch-all 聚合视图（GET /admin/mailboxes/unregistered——
// FR-003：shadow 邮箱列表巡览，未注册来信按址归档载体；G4 增强行形态承载）。
func (s *Server) adminUnregisteredGET(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	rows, err := s.adminMailboxRows(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	shadows := make([]*templates.AdminMailboxRow, 0, len(rows))
	for _, r := range rows {
		if r.Status == string(storage.MailboxStatusShadow) {
			shadows = append(shadows, r)
		}
	}
	sess, _ := currentSession(c)
	renderPage(c, http.StatusOK, templates.AdminUnregisteredView(langOf(c), shadows, sess.CSRFToken, s.sidebarDataFor(c)))
}

// listAllMailboxes 三态合并全量列表（active/shadow/disabled；单管理员规模 REQ-001——
// 三查询成本可忽略，契约 MailboxRepo 零增量推导）。
func (s *Server) listAllMailboxes(c *gin.Context) ([]*storage.Mailbox, error) {
	ctx := c.Request.Context()
	var all []*storage.Mailbox
	for _, st := range []storage.MailboxStatus{
		storage.MailboxStatusActive, storage.MailboxStatusShadow, storage.MailboxStatusDisabled,
	} {
		list, err := s.mailboxes.ListByStatus(ctx, st)
		if err != nil {
			return nil, err
		}
		all = append(all, list...)
	}
	return all, nil
}

// adminErrText 管理操作错误 → 用户可读提示（哨兵映射；U18 双语化——lang 注入 Tr 取值）。
func adminErrText(lang templates.Lang, err error) string {
	switch {
	case err == account.ErrInvalidAddress:
		return templates.Tr(lang, "admin.errAddr")
	case err == account.ErrEmptyPassword:
		return templates.Tr(lang, "admin.errEmptyPass")
	case err == account.ErrInvalidStatus:
		return templates.Tr(lang, "admin.errStatus")
	case err == storage.ErrMailboxExists:
		return templates.Tr(lang, "admin.errExists")
	case err == storage.ErrMailboxNotFound:
		return templates.Tr(lang, "admin.errMissing")
	}
	return templates.Trf(lang, "admin.errOpFmt", err.Error())
}
