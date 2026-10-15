// /admin/settings 全量配置页（U10：Q3-C 归属承载+Q7-C 范围——认证栈四开关+DKIM 细节+
// catchAll 开关+邮件限值+会话双超时+登录限流；U8 登记项②「常量 config 化」兑现；
// U13 增传输安全节——MTA-STS/TLS-RPT 两开关+Mode/MaxAge/rua 参数+DNS 建议值只读区）。
// 保存链=流程设计第五章（FR-009/TC-009 判定链）：校验→SaveConfig 原子读改写→fsnotify
// →去抖 →订阅者回调→全程无重启（FR-010 判定③：关闭 MTA-STS 即端点停发——无重启链）。
// admin 门卫沿 U9 admin.go 同形态（内联主体判定 403）；CSRF 经 U8 csrfProtect
// （认证会话非安全方法强制表单 token——settings 页表单埋 csrf_token 隐藏域）。
// 修改历史：
//
//	2026-09-20 01:15:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 7）
//	2026-09-23 08:44:00 | 扩展 | U13 传输安全全量：传输安全节（计划书步骤 4/1.5①⑩；
//	  契约 v1.9.0 3.3——FR-010「二者默认启用、Web 可关闭」）
//	2026-10-15 01:35:00 | 重构 | Webmail前端可选交互增强批 γ B5/E-1-A：adminSettingsPOST
//	  改分区提交——section 隐藏域分派四节（auth/delivery/session/tls），每节仅校验+保存
//	  本节字段（既有校验规则逐字迁移零增减；未提交节保留现值）；「一次保存全部五节」
//	  批量交互移除（计划书 1.3 已披露获批）
//	  （依据：γ批计划书 v1.0.0 1.2 B5，G2 批准 2026-10-15 01:22 候选 E-1-A）
package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/config"
	"GRmail/web/templates"
)

// dkimAlgorithms DKIM 签名算法合法枚举（config.DKIMConf.Algorithm 值域——U3 Q1-A；
// 空串=未配置态合法）。
var dkimAlgorithms = map[string]bool{"rsa-sha256": true, "ed25519-sha256": true}

// adminSettingsGET 设置页（GET /admin/settings：四节当前值呈现）。
func (s *Server) adminSettingsGET(c *gin.Context) {
	if !s.adminGuard(c) { // B9（批四）：内联 403 空体收口——adminGuard 复用（批二 E1 错误整页）
		return
	}
	cfg := s.cfg.CfgSnapshot
	if cfg == nil {
		sessLogger(c).Error("CfgSnapshot 未注入：设置页不可用")
		s.errPage(c, http.StatusServiceUnavailable, "err.page503") // B9（批四）：空体改错误整页（沿批二 E1/err.page* 键族先例）
		return
	}
	// F01：保存成功反馈（303 回带 ?saved=1——成功态 notice 分型；Webmail界面精修批次 2026-10-03）
	data := s.buildSettingsData(c, cfg(), "")
	if c.Query("saved") == "1" {
		data.Notice = templates.Tr(langOf(c), "settings.saved")
	}
	// Webmail管理职能批次 G1：管理员改密成功反馈（/admin/password 303 回带 ?pwchanged=1）
	if c.Query("pwchanged") == "1" {
		data.PWChanged = true
	}
	renderPage(c, http.StatusOK, templates.SettingsView(data))
}

// buildSettingsData 装配设置页数据（当前配置快照+CSRF token；U18 增 Lang 深级双语承载）。
func (s *Server) buildSettingsData(c *gin.Context, cfg *config.Config, msg string) templates.SettingsData {
	sess, _ := currentSession(c)
	data := templates.SettingsData{
		Lang:               string(langOf(c)),
		CSRFToken:          sess.CSRFToken,
		Nav:                s.sidebarDataFor(c), // D3 B 形态——全站侧栏（覆盖全部 SettingsView 渲染点）
		Message:            msg,
		SPFEnabled:         cfg.Auth.SPFEnabled,
		DKIMEnabled:        cfg.Auth.DKIMEnabled,
		DMARCEnabled:       cfg.Auth.DMARCEnabled,
		ARCEnabled:         cfg.Auth.ARCEnabled,
		DKIMSelector:       cfg.Auth.DKIM.Selector,
		DKIMKeyPath:        cfg.Auth.DKIM.KeyPath,
		DKIMAlgo:           cfg.Auth.DKIM.Algorithm,
		CatchAll:           cfg.CatchAll,
		MaxMessageSizeMB:   cfg.Mail.MaxMessageSizeBytes / (1024 * 1024),
		RetryBaseSeconds:   cfg.Mail.Delivery.RetryBaseSeconds,
		RetryFactor:        cfg.Mail.Delivery.RetryFactor,
		RetryCapSeconds:    cfg.Mail.Delivery.RetryCapSeconds,
		MaxAttempts:        cfg.Mail.Delivery.MaxAttempts,
		IdleMinutes:        cfg.Session.IdleMinutes,
		AbsoluteHours:      cfg.Session.AbsoluteHours,
		LimitWindowMinutes: cfg.LoginLimit.WindowMinutes,
		LimitThreshold:     cfg.LoginLimit.Threshold,
	}
	// U13 传输安全节（FR-010：当前值回填+DNS 建议值只读区——判定①部署对照物）
	data.MTAStsEnabled = cfg.MTASts.Enabled
	data.MTAStsMode = cfg.MTASts.Mode
	data.MTAStsMaxAgeSeconds = cfg.MTASts.MaxAgeSeconds
	data.TLSRPTEnabled = cfg.MTASts.ReportEnabled
	data.TLSRPTRuaAddress = cfg.MTASts.RuaAddress
	data.StsPolicyURL = "https://mta-sts." + cfg.Server.Domain + stsPolicyPath
	// E9（批二）：真实主域注入（记录名渲染）；E6：停发提示改空串+模板键承载。
	data.Domain = cfg.Server.Domain
	data.StsTXTRecord = stsTXTSuggestion(cfg)
	data.TLSRPTRecord = tlsrptTXTSuggestion(cfg)
	if data.MaxMessageSizeMB <= 0 {
		data.MaxMessageSizeMB = 35 // 缺省档呈现（零值兜底语义）
	}
	return data
}

// stsTXTSuggestion _mta-sts TXT 记录建议值（rfc8461 §3.1——web 侧呈现形态；
// 生成逻辑与 transport.STSTXTRecordValue 同源语义，id 取呈现时刻——部署者复制时
// 即最新实例标识）。参数：cfg 配置快照。返回：记录值（MTA-STS 关闭时空串——
// 停发提示由模板键承载〔E6 批二：Go 侧中文串收口〕）。
func stsTXTSuggestion(cfg *config.Config) string {
	if !cfg.MTASts.Enabled {
		return ""
	}
	return "v=STSv1; id=" + time.Now().UTC().Format("20060102150405Z") + ";"
}

// tlsrptTXTSuggestion _smtp._tls TXT 记录建议值（rfc8460 §3——web 侧呈现形态；
// rua 缺省 postmaster@<主域> 兜底同 transport.TLSRPTTXTRecordValue）。
// 参数：cfg 配置快照。返回：记录值（TLS-RPT 关闭时空串——停显提示模板键承载）。
func tlsrptTXTSuggestion(cfg *config.Config) string {
	if !cfg.MTASts.ReportEnabled {
		return ""
	}
	rua := cfg.MTASts.RuaAddress
	if rua == "" {
		rua = "postmaster@" + cfg.Server.Domain
	}
	return "v=TLSRPTv1; rua=mailto:" + rua
}

// adminSettingsPOST 设置保存（POST /admin/settings）。B5/E-1-A（γ批 2026-10-15）：
// 分区提交——section 隐藏域分派四可编辑节（auth/delivery/session/tls），每节独立
// 校验+原子读改写（仅本节字段；未提交节保留现值——SaveConfig 读 Current 快照基底）；
// 校验规则沿 U10/U13 既有十二判定点逐字迁移零增减；非法/缺失 section → 400 错误整页。
func (s *Server) adminSettingsPOST(c *gin.Context) {
	if !s.adminGuard(c) { // B9（批四）：内联 403 空体收口——adminGuard 复用（批二 E1 错误整页）
		return
	}
	if s.cfg.CfgSnapshot == nil || s.cfg.SaveConfig == nil {
		sessLogger(c).Error("配置读写未注入：设置保存不可用")
		s.errPage(c, http.StatusServiceUnavailable, "err.page503") // B9（批四）：空体改错误整页
		return
	}
	switch c.PostForm("section") {
	case "auth":
		s.settingsSaveAuth(c)
	case "delivery":
		s.settingsSaveDelivery(c)
	case "session":
		s.settingsSaveSession(c)
	case "tls":
		s.settingsSaveTLS(c)
	default:
		s.errPage(c, http.StatusBadRequest, "err.page400") // B5：旧全量提交形态（无节标识）不再受支持
	}
}

// settingsSaveAuth 认证栈节保存（B5：dkimAlgo 枚举校验——规则零增减；未列字段保留现值）。
func (s *Server) settingsSaveAuth(c *gin.Context) {
	dkimAlgo := strings.TrimSpace(c.PostForm("dkimAlgorithm"))
	if dkimAlgo != "" && !dkimAlgorithms[dkimAlgo] {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errAlgo"))
		return
	}
	if err := s.cfg.SaveConfig(func(cfg *config.Config) {
		cfg.Auth.SPFEnabled = c.PostForm("spfEnabled") == "on"
		cfg.Auth.DKIMEnabled = c.PostForm("dkimEnabled") == "on"
		cfg.Auth.DMARCEnabled = c.PostForm("dmarcEnabled") == "on"
		cfg.Auth.ARCEnabled = c.PostForm("arcEnabled") == "on"
		cfg.Auth.DKIM = config.DKIMConf{
			Selector:  strings.TrimSpace(c.PostForm("dkimSelector")),
			KeyPath:   strings.TrimSpace(c.PostForm("dkimKeyPath")),
			Algorithm: dkimAlgo,
		}
	}); err != nil {
		s.settingsSaveFailed(c, "认证栈节", err)
		return
	}
	sessLogger(c).Info("设置已保存（认证栈节，热加载生效）", "log_id", c.GetString(ctxKeyLogID))
	c.Redirect(http.StatusSeeOther, "/admin/settings?saved=1") // F01：成功反馈经 ?saved=1 回显
}

// settingsSaveDelivery 投递聚合节保存（B5：五项正整数校验；未列字段保留现值）。
func (s *Server) settingsSaveDelivery(c *gin.Context) {
	maxSizeMB, err := parsePositiveForm(c, "maxMessageSizeMB")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errMaxSize"))
		return
	}
	retryBase, err := parsePositiveForm(c, "retryBaseSeconds")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errRetryBase"))
		return
	}
	retryFactor, err := parsePositiveForm(c, "retryFactor")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errRetryFactor"))
		return
	}
	retryCap, err := parsePositiveForm(c, "retryCapSeconds")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errRetryCap"))
		return
	}
	maxAttempts, err := parsePositiveForm(c, "maxAttempts")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errMaxAttempts"))
		return
	}
	if err := s.cfg.SaveConfig(func(cfg *config.Config) {
		cfg.CatchAll = c.PostForm("catchAll") == "on"
		cfg.Mail.MaxMessageSizeBytes = maxSizeMB * 1024 * 1024
		cfg.Mail.Delivery = config.DeliveryConf{
			RetryBaseSeconds: int(retryBase),
			RetryFactor:      int(retryFactor),
			RetryCapSeconds:  int(retryCap),
			MaxAttempts:      int(maxAttempts),
		}
	}); err != nil {
		s.settingsSaveFailed(c, "投递聚合节", err)
		return
	}
	sessLogger(c).Info("设置已保存（投递聚合节，热加载生效）", "log_id", c.GetString(ctxKeyLogID))
	c.Redirect(http.StatusSeeOther, "/admin/settings?saved=1")
}

// settingsSaveSession 会话限流节保存（B5：四项正整数校验；未列字段保留现值）。
func (s *Server) settingsSaveSession(c *gin.Context) {
	idleMinutes, err := parsePositiveForm(c, "idleMinutes")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errIdle"))
		return
	}
	absoluteHours, err := parsePositiveForm(c, "absoluteHours")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errAbsolute"))
		return
	}
	limitWindow, err := parsePositiveForm(c, "limitWindowMinutes")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errLimitWin"))
		return
	}
	limitThreshold, err := parsePositiveForm(c, "limitThreshold")
	if err != nil {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errLimitThr"))
		return
	}
	if err := s.cfg.SaveConfig(func(cfg *config.Config) {
		cfg.Session = config.SessionConf{IdleMinutes: int(idleMinutes), AbsoluteHours: int(absoluteHours)}
		cfg.LoginLimit = config.LoginLimitConf{WindowMinutes: int(limitWindow), Threshold: limitThreshold}
	}); err != nil {
		s.settingsSaveFailed(c, "会话限流节", err)
		return
	}
	sessLogger(c).Info("设置已保存（会话限流节，热加载生效）", "log_id", c.GetString(ctxKeyLogID))
	c.Redirect(http.StatusSeeOther, "/admin/settings?saved=1")
}

// settingsSaveTLS 传输安全节保存（B5：mode 枚举+max_age 值域校验〔rfc8461 §3.2——
// 写坏配置防御，U13 既有规则〕；开关热加载生效——判定③保存即端点停发/建议值停显）。
func (s *Server) settingsSaveTLS(c *gin.Context) {
	stsMode := strings.TrimSpace(c.PostForm("mtaStsMode"))
	if stsMode != "enforce" && stsMode != "testing" {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errStsMode"))
		return
	}
	stsMaxAge, err := parsePositiveForm(c, "mtaStsMaxAgeSeconds")
	if err != nil || stsMaxAge > 31557600 {
		s.settingsReject(c, templates.Tr(langOf(c), "settings.errStsAge"))
		return
	}
	if err := s.cfg.SaveConfig(func(cfg *config.Config) {
		cfg.MTASts = config.MTAStsConf{
			Enabled:       c.PostForm("mtaStsEnabled") == "on",
			Mode:          stsMode,
			MaxAgeSeconds: int(stsMaxAge),
			ReportEnabled: c.PostForm("tlsrptEnabled") == "on",
			RuaAddress:    strings.TrimSpace(c.PostForm("tlsrptRuaAddress")),
		}
	}); err != nil {
		s.settingsSaveFailed(c, "传输安全节", err)
		return
	}
	sessLogger(c).Info("设置已保存（传输安全节，热加载生效）", "log_id", c.GetString(ctxKeyLogID))
	c.Redirect(http.StatusSeeOther, "/admin/settings?saved=1")
}

// settingsSaveFailed 节保存失败统一出口（500 重渲染——B5 分派形态，语义与原全量保存失败一致）。
// 参数：c 上下文；section 节名（日志定位用）；err 保存错误（日志关联）。
func (s *Server) settingsSaveFailed(c *gin.Context, section string, err error) {
	sessLogger(c).Error("设置保存失败", "section", section, "error", err)
	renderPage(c, http.StatusInternalServerError, templates.SettingsView(
		s.buildSettingsData(c, s.cfg.CfgSnapshot(), templates.Tr(langOf(c), "settings.errSave"))))
}

// settingsReject 校验拒绝统一出口（重渲染+消息）。
func (s *Server) settingsReject(c *gin.Context, msg string) {
	renderPage(c, http.StatusOK, templates.SettingsView(s.buildSettingsData(c, s.cfg.CfgSnapshot(), msg)))
}

// parsePositiveForm 表单正整数字段解析（strconv；≤0/非数字=错误）。
// 参数：c 上下文；field 表单字段名。返回：解析值；失败返回 error。
func parsePositiveForm(c *gin.Context, field string) (int64, error) {
	raw := strings.TrimSpace(c.PostForm(field))
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, errBadFormValue
	}
	return v, nil
}

// errBadFormValue 表单数值字段非法哨兵。
var errBadFormValue = &errSetupStep{msg: "数值字段非法"}
