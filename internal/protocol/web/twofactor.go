// GRmail Web 2FA 端点组（U24——FR-018 Web 层全量承载）。
// 范围：①登录二步（密码步后 pending 凭据承载——S4-W Q1-A 短时一次性内存凭据，
// OWASP「认证完成前不建立会话」严格对齐）②/settings/2fa 绑定管理端点族（G1-W Q2-A
// 独立最小页裁决——顶栏入口直达）③管理员强制引导门卫（twoFactorGate——TC-028 判定③④）。
// 依据：SRS v1.1.0 FR-018（判定①~⑤）/IR-009；契约 v1.20.0 2.4 web 注入形态+3.1/3.2 端点；
// 流程 v1.2.0 第六章（登录二步状态机）；rfc6238 §4/§5.2（重放拒绝经 account 层承载）。
// 入口隔离（建模 7.3 第 7 条）：本组仅作用于 Webmail HTTPS 入口——IMAP/POP3/SMTP
// 协议认证路径零触及（TC-027 判定⑤回归锚）。
// 修改历史：
//
//	2026-10-01 17:05:00 | 新增 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）
package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
	"GRmail/web/templates"

	"github.com/pschlump/goqrcode"
)

// errTwoFactorUnavailable 2FA 服务未注入哨兵（TwoFactor nil 渐进态——admin 标记
// 操作呈现可读错误；沿 Tokens 503 语义的操作侧形态）。
var errTwoFactorUnavailable = errors.New("web: 2FA 服务不可用（未注入）")

// ───────────────────────── 短时一次性登录凭据（S4-W Q1-A） ─────────────────────────

// pending2faTTL 凭据有效期 5 分钟（密码步→因子步的宽松人工窗口；重启丢失=用户重登）。
const pending2faTTL = 5 * time.Minute

// pendingEntry 单条凭据（密码步已通过的邮箱上下文——因子通过方换取正式会话）。
type pendingEntry struct {
	mailboxID int64
	address   string
	expiresAt time.Time
}

// pendingLoginStore 内存态凭据仓（互斥锁保护；惰性 GC——issue/take 顺带清扫过期项）。
type pendingLoginStore struct {
	mu      sync.Mutex
	entries map[string]pendingEntry
}

// newPendingLoginStore 构造凭据仓。返回：实例（零值 map 初始化）。
func newPendingLoginStore() *pendingLoginStore {
	return &pendingLoginStore{entries: make(map[string]pendingEntry)}
}

// issue 签发凭据（CSPRNG 32B hex——一次性：take 即删）。
// 参数：mailboxID 邮箱 ID；address 邮箱地址（限流主体键复用）。返回：凭据串。
func (p *pendingLoginStore) issue(mailboxID int64, address string) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("pending 凭据生成失败（CSPRNG 不可用）: " + err.Error())
	}
	tok := hex.EncodeToString(buf)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	p.entries[tok] = pendingEntry{mailboxID: mailboxID, address: address, expiresAt: time.Now().Add(pending2faTTL)}
	return tok
}

// take 取出并删除凭据（一次性语义——取出即失效，无论因子成败不复活）。
// 参数：tok 凭据串。返回：条目与有效性（未命中/过期=false）。
func (p *pendingLoginStore) take(tok string) (pendingEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[tok]
	if !ok {
		return pendingEntry{}, false
	}
	delete(p.entries, tok)
	if time.Now().After(e.expiresAt) {
		return pendingEntry{}, false
	}
	return e, true
}

// gcLocked 清扫过期项（调用方持锁）。
func (p *pendingLoginStore) gcLocked() {
	now := time.Now()
	for k, e := range p.entries {
		if now.After(e.expiresAt) {
			delete(p.entries, k)
		}
	}
}

// ───────────────────────── 登录二步端点（FR-018 判定②③） ─────────────────────────

// login2FAGET 二步验证页（GET /webmail/login/2fa?t=…——密码步通过后 302 目标；
// 直接访问无 t 参数渲染空凭据页——提交即过期拒绝）。
func (s *Server) login2FAGET(c *gin.Context) {
	renderPage(c, http.StatusOK, templates.Login2FAView(langOf(c), c.Query("t"), ""))
}

// login2FAPost 二步验证提交（POST /webmail/login/2fa）：
// pending 凭据取出（一次性）→account.VerifyLoginFactor（TOTP 优先/恢复码兜底——
// 双失败 recordFail 限流计数〔沿 mailbox: 地址主体键〕+重签凭据可重试）→
// 通过→清零限流+issueSession（会话方建立——DFD-P4「二步验证通过后会话建立」）→303 /。
// 强制引导：Required 且未绑定分支不在此（登录一步直通时处理）。
func (s *Server) login2FAPost(c *gin.Context) {
	ctx := c.Request.Context()
	lang := langOf(c)
	entry, ok := s.pending2fa.take(c.PostForm("t"))
	if !ok {
		// 凭据过期/无效：回到密码步（TC-027 判定③关联——会话不建立）
		renderPage(c, http.StatusOK, templates.Login2FAView(lang, "", templates.Tr(lang, "login2fa.errExpired")))
		return
	}
	if s.twoFactor == nil {
		c.Status(http.StatusServiceUnavailable)
		return
	}
	if err := s.twoFactor.VerifyLoginFactor(ctx, entry.mailboxID, c.PostForm("code")); err != nil {
		subjectKey := "mailbox:" + entry.address
		s.recordFail(ctx, subjectKey, c.ClientIP())
		sessLogger(c).Info("2FA 二步验证失败", "ip", c.ClientIP())
		tok := s.pending2fa.issue(entry.mailboxID, entry.address) // 重签供重试（旧凭据已消耗）
		renderPage(c, http.StatusOK, templates.Login2FAView(lang, tok, templates.Tr(lang, "login2fa.errInvalid")))
		return
	}
	if err := s.attempts.ClearSubject(ctx, "mailbox:"+entry.address); err != nil {
		sessLogger(c).Warn("登录成功清零失败", "error", err)
	}
	if _, err := s.sess.issueSession(c, storage.SubjectTypeMailbox, entry.mailboxID); err != nil {
		sessLogger(c).Error("会话签发失败", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	s.redirectPostLogin(c, entry.mailboxID)
}

// redirectPostLogin 登录成功重定向（U24：强制标记且未绑定→引导绑定页 TC-028 判定③；
// 否则既有 303 /——兼容口径集中一处）。
func (s *Server) redirectPostLogin(c *gin.Context, mailboxID int64) {
	if s.twoFactor != nil {
		if st, err := s.twoFactor.State(c.Request.Context(), mailboxID); err == nil && st.Required && !st.Bound() {
			c.Redirect(http.StatusSeeOther, "/settings/2fa?forced=1")
			return
		}
	}
	c.Redirect(http.StatusSeeOther, "/")
}

// ───────────────────────── /settings/2fa 端点族（FR-018 判定①/停用） ─────────────────────────

// twoFactorViewOf 主体邮箱反查+状态快照→页面数据骨架（三 POST 响应复用）。
// 参数：c Gin 上下文。返回：数据与错误（错误时调用方 500——主体已认证，库故障语义）。
func (s *Server) twoFactorViewOf(c *gin.Context) (*templates.TwoFactorData, error) {
	sess, _ := currentSession(c)
	ctx := c.Request.Context()
	m, err := s.mailboxes.FindMailboxByID(ctx, sess.SubjectID)
	if err != nil {
		return nil, err
	}
	st, err := s.twoFactor.State(ctx, sess.SubjectID)
	if err != nil {
		return nil, err
	}
	return &templates.TwoFactorData{
		Lang:    langOf(c),
		Label:   m.Address,
		CSRF:    sess.CSRFToken,
		Bound:   st.Bound(),
		Pending: st.PendingSecret != "" && !st.Bound(),
		Forced:  c.Query("forced") == "1",
	}, nil
}

// twoFactorErrText account 哨兵 → 双语提示（沿 adminErrText 先例）。
func twoFactorErrText(lang templates.Lang, err error) string {
	switch {
	case err == account.ErrTwoFactorBound:
		return templates.Tr(lang, "2fa.errBound")
	case err == account.ErrTwoFactorNotBound:
		return templates.Tr(lang, "2fa.errNotBound")
	case err == account.ErrTwoFactorCode:
		return templates.Tr(lang, "2fa.errCode")
	case err == account.ErrTwoFactorFormat:
		return templates.Tr(lang, "2fa.errFormat")
	}
	return templates.Trf(lang, "admin.errOpFmt", err.Error())
}

// twoFactorGET 2FA 管理页（GET /settings/2fa——状态三态渲染；mailbox 主体）。
func (s *Server) twoFactorGET(c *gin.Context) {
	if !s.twoFactorGuard(c) {
		return
	}
	d, err := s.twoFactorViewOf(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	renderPage(c, http.StatusOK, templates.TwoFactorView(*d))
}

// twoFactorSetupPOST 发起绑定（POST /settings/2fa/setup——FR-018 判定①前半）：
// 生成密钥+otpauth URI→二维码 PNG base64（pschlump/goqrcode——建模 7.2 既定形态）→
// pending 态渲染（二维码+明文密钥双形态）。
func (s *Server) twoFactorSetupPOST(c *gin.Context) {
	if !s.twoFactorGuard(c) {
		return
	}
	lang := langOf(c)
	sess, _ := currentSession(c)
	ctx := c.Request.Context()
	m, err := s.mailboxes.FindMailboxByID(ctx, sess.SubjectID)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	mat, err := s.twoFactor.InitiateBinding(ctx, sess.SubjectID, m.Address, s.issuerDomain())
	if err != nil {
		d, derr := s.twoFactorViewOf(c)
		if derr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		d.ErrText = twoFactorErrText(lang, err)
		renderPage(c, http.StatusOK, templates.TwoFactorView(*d))
		return
	}
	// 二维码 PNG → data URI（256px/Medium 纠错——屏幕扫描均衡档）
	png, err := goqrcode.Encode(mat.OtpauthURI, goqrcode.Medium, 256)
	qrURI := ""
	if err != nil {
		sessLogger(c).Error("二维码生成失败", "error", err) // 降级：密钥手动输入通道仍可用
	} else {
		qrURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	renderPage(c, http.StatusOK, templates.TwoFactorView(templates.TwoFactorData{
		Lang:      lang,
		Label:     m.Address,
		CSRF:      sess.CSRFToken,
		Pending:   true,
		QRDataURI: qrURI,
		Secret:    mat.Secret,
	}))
}

// twoFactorConfirmPOST 绑定确认（POST /settings/2fa/confirm——FR-018 判定①后半）：
// TOTP 码验证通过→恢复码一次性生成展示（TC-027 判定①——本响应非空即唯一呈现点）。
func (s *Server) twoFactorConfirmPOST(c *gin.Context) {
	if !s.twoFactorGuard(c) {
		return
	}
	lang := langOf(c)
	sess, _ := currentSession(c)
	ctx := c.Request.Context()
	m, err := s.mailboxes.FindMailboxByID(ctx, sess.SubjectID)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	codes, err := s.twoFactor.ConfirmBinding(ctx, sess.SubjectID, c.PostForm("code"))
	if err != nil {
		d, derr := s.twoFactorViewOf(c)
		if derr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		d.ErrText = twoFactorErrText(lang, err)
		renderPage(c, http.StatusOK, templates.TwoFactorView(*d))
		return
	}
	sessLogger(c).Info("2FA 绑定确认", "mailbox", m.Address)
	renderPage(c, http.StatusOK, templates.TwoFactorView(templates.TwoFactorData{
		Lang:          lang,
		Label:         m.Address,
		CSRF:          sess.CSRFToken,
		Bound:         true,
		RecoveryCodes: codes, // 一次性展示——TC-027 判定①锚（后续渲染恒空）
	}))
}

// twoFactorDisablePOST 停用（POST /settings/2fa/disable——FR-018 停用语段：
// 须一次第二因子验证；TC-028 判定②锚）。
func (s *Server) twoFactorDisablePOST(c *gin.Context) {
	if !s.twoFactorGuard(c) {
		return
	}
	lang := langOf(c)
	sess, _ := currentSession(c)
	ctx := c.Request.Context()
	if err := s.twoFactor.Disable(ctx, sess.SubjectID, c.PostForm("code")); err != nil {
		d, derr := s.twoFactorViewOf(c)
		if derr != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		d.ErrText = twoFactorErrText(lang, err)
		renderPage(c, http.StatusOK, templates.TwoFactorView(*d))
		return
	}
	sessLogger(c).Info("2FA 停用", "subject_id", sess.SubjectID)
	c.Redirect(http.StatusSeeOther, "/settings/2fa")
}

// twoFactorGuard 2FA 端点门卫：TwoFactor 注入 nil=503（渐进态沿 Tokens 先例）+
// 主体限 mailbox（admin User 不在 FR-018 范围——403）。
func (s *Server) twoFactorGuard(c *gin.Context) bool {
	if s.twoFactor == nil {
		c.Status(http.StatusServiceUnavailable)
		return false
	}
	sess, ok := currentSession(c)
	if !ok || sess.SubjectType != storage.SubjectTypeMailbox {
		c.Status(http.StatusForbidden)
		return false
	}
	return true
}

// issuerDomain otpauth issuer（主域名——authenticator App 内条目区分；空域兜底 GRmail）。
func (s *Server) issuerDomain() string {
	if d := strings.TrimSpace(s.cfg.Domain); d != "" {
		return d
	}
	return "GRmail"
}

// ───────────────────────── 强制引导门卫（FR-018 判定④——TC-028 判定③④） ─────────────────────────

// twoFactorGate 认证域条件中间件：mailbox 主体+管理员强制标记+未绑定 →
// 除 2FA 设置页/登出/语言/静态资源外一律重定向绑定页（「方可继续使用」语义）；
// 状态查询故障放行（防故障锁死——检测增强语义沿 IP/UA 突变告警不中断先例）；
// TwoFactor 未注入（nil）零判定（既有部署形态——渐进态）。
func (s *Server) twoFactorGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.twoFactor == nil {
			c.Next()
			return
		}
		sess, ok := currentSession(c)
		if !ok || sess.SubjectType != storage.SubjectTypeMailbox {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		if path == "/settings/2fa" || strings.HasPrefix(path, "/settings/2fa/") ||
			path == "/logout" || path == "/lang" || strings.HasPrefix(path, "/static/") {
			c.Next()
			return
		}
		st, err := s.twoFactor.State(c.Request.Context(), sess.SubjectID)
		if err != nil {
			observability.LoggerFromContext(c.Request.Context()).Error("2FA 门卫状态查询故障（放行）", "error", err)
			c.Next()
			return
		}
		if st.Required && !st.Bound() {
			c.Redirect(http.StatusFound, "/settings/2fa?forced=1")
			c.Abort()
			return
		}
		c.Next()
	}
}
