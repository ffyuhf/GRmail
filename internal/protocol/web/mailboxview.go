// GRmail Web 主体→邮箱视图解析（U9 计划书步骤 4）。
// 口径（计划书 1.5，从文档原文唯一推导）：mailbox 会话主体 → subject_id 即 mailboxID；
// admin 会话主体无邮箱实体（users/mailboxes 分离建模 REQ-001），其 Webmail 邮件视图
// 映射 postmaster@主域 邮箱——U4 影子通知投递目标（NoticeMeta 注释）且管道先行确保
// 存在，亦为 FR-003 管理员特殊文件夹聚合语义的载体。
// 主体显示名：mailbox 主体通用文案「我的邮箱」（MailboxRepo 无按 ID 反查地址方法——
// 契约 2.1 签名固定，零增量推导）；admin 主体显示 postmaster 地址。
// 修改历史：
//
//	2026-09-19 10:22:00 | 新建 | U9 Webmail 核心（计划书步骤 4，G2 批准 2026-09-19 10:00:41）
package web

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"

	"GRmail/internal/storage"
)

// ErrNoMailboxView 当前主体无可用的邮箱视图（admin 且 postmaster 邮箱不存在——部署
// 引导期场景；提示引导而非 500）。
var ErrNoMailboxView = errors.New("web: 主体无邮箱视图")

// mailboxLabelMailbox mailbox 主体的通用显示文案（地址反查无契约方法，通用文案零歧义）。
const mailboxLabelMailbox = "我的邮箱"

// mailboxView 主体解析产物（业务 handler 的统一数据定位输入）。
type mailboxView struct {
	MailboxID int64  // 数据定位键（FR-001 隔离锚——全部 Repo 查询必经）
	Label     string // 页面呈现主体名
	IsAdmin   bool   // admin 主体标记（写信 From 自由度/管理入口显隐）
}

// currentMailboxView 会话主体 → 邮箱视图。
// 参数：c Gin 上下文（须已过 requireAuth）。返回：视图；无可用视图返回 ErrNoMailboxView。
func (s *Server) currentMailboxView(c *gin.Context) (*mailboxView, error) {
	sess, _ := currentSession(c)
	ctx := c.Request.Context()
	switch sess.SubjectType {
	case storage.SubjectTypeMailbox:
		return &mailboxView{MailboxID: sess.SubjectID, Label: mailboxLabelMailbox, IsAdmin: false}, nil
	case storage.SubjectTypeAdmin:
		if s.accounts == nil {
			return nil, ErrNoMailboxView
		}
		// 管理员主体增强批次 G1（D4——S3-W Q1-A）：admin 视图优先随管理员主邮箱
		// （向导步 2 前缀@主域）；未配置回退 postmaster@主域（存量部署兼容锚——
		// postmaster 地址与 U25 聚合目标语义不变，收信管道零涉及）。
		addr := strings.TrimSpace(s.cfg.AdminMailbox)
		if addr == "" {
			addr = "postmaster@" + s.cfg.Domain
		}
		mb, err := s.accounts.GetMailbox(ctx, addr)
		if err != nil {
			sessLogger(c).Warn("admin 邮箱视图缺位（主邮箱/postmaster 未建立——收信管道建影子后可用）",
				"domain", s.cfg.Domain, "addr", addr)
			return nil, ErrNoMailboxView
		}
		return &mailboxView{MailboxID: mb.ID, Label: mb.Address, IsAdmin: true}, nil
	default:
		return nil, ErrNoMailboxView
	}
}
