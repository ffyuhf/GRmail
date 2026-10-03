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
package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/config"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// dkimAlgorithms DKIM 签名算法合法枚举（config.DKIMConf.Algorithm 值域——U3 Q1-A；
// 空串=未配置态合法）。
var dkimAlgorithms = map[string]bool{"rsa-sha256": true, "ed25519-sha256": true}

// adminSettingsGET 设置页（GET /admin/settings：四节当前值呈现）。
func (s *Server) adminSettingsGET(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok || sess.SubjectType != storage.SubjectTypeAdmin {
		c.Status(http.StatusForbidden)
		return
	}
	cfg := s.cfg.CfgSnapshot
	if cfg == nil {
		sessLogger(c).Error("CfgSnapshot 未注入：设置页不可用")
		c.Status(http.StatusServiceUnavailable)
		return
	}
	// F01：保存成功反馈（303 回带 ?saved=1——成功态 notice 分型；Webmail界面精修批次 2026-10-03）
	data := s.buildSettingsData(c, cfg(), "")
	if c.Query("saved") == "1" {
		data.Notice = templates.Tr(langOf(c), "settings.saved")
	}
	renderPage(c, http.StatusOK, templates.SettingsView(data))
}

// buildSettingsData 装配设置页数据（当前配置快照+CSRF token；U18 增 Lang 深级双语承载）。
func (s *Server) buildSettingsData(c *gin.Context, cfg *config.Config, msg string) templates.SettingsData {
	sess, _ := currentSession(c)
	data := templates.SettingsData{
		Lang:               string(langOf(c)),
		CSRFToken:          sess.CSRFToken,
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
	data.StsTXTRecord = stsTXTSuggestion(cfg)
	data.TLSRPTRecord = tlsrptTXTSuggestion(cfg)
	if data.MaxMessageSizeMB <= 0 {
		data.MaxMessageSizeMB = 35 // 缺省档呈现（零值兜底语义）
	}
	return data
}

// stsTXTSuggestion _mta-sts TXT 记录建议值（rfc8461 §3.1——web 侧呈现形态；
// 生成逻辑与 transport.STSTXTRecordValue 同源语义，id 取呈现时刻——部署者复制时
// 即最新实例标识）。参数：cfg 配置快照。返回：记录值（MTA-STS 关闭时返回停发提示）。
func stsTXTSuggestion(cfg *config.Config) string {
	if !cfg.MTASts.Enabled {
		return "（MTA-STS 已关闭——无需发布本记录；重新启用后此处呈现建议值）"
	}
	return "v=STSv1; id=" + time.Now().UTC().Format("20060102150405Z") + ";"
}

// tlsrptTXTSuggestion _smtp._tls TXT 记录建议值（rfc8460 §3——web 侧呈现形态；
// rua 缺省 postmaster@<主域> 兜底同 transport.TLSRPTTXTRecordValue）。
// 参数：cfg 配置快照。返回：记录值（TLS-RPT 关闭时返回停显提示）。
func tlsrptTXTSuggestion(cfg *config.Config) string {
	if !cfg.MTASts.ReportEnabled {
		return "（TLS-RPT 已关闭——建议移除已发布的 _smtp._tls 记录）"
	}
	rua := cfg.MTASts.RuaAddress
	if rua == "" {
		rua = "postmaster@" + cfg.Server.Domain
	}
	return "v=TLSRPTv1; rua=mailto:" + rua
}

// adminSettingsPOST 设置保存（POST /admin/settings）：整体校验→原子读改写→303 回显。
func (s *Server) adminSettingsPOST(c *gin.Context) {
	sess, ok := currentSession(c)
	if !ok || sess.SubjectType != storage.SubjectTypeAdmin {
		c.Status(http.StatusForbidden)
		return
	}
	if s.cfg.CfgSnapshot == nil || s.cfg.SaveConfig == nil {
		sessLogger(c).Error("配置读写未注入：设置保存不可用")
		c.Status(http.StatusServiceUnavailable)
		return
	}

	// ── 表单解析与校验（1.5⑨：零值/非法值拒绝——禁止把配置写坏）──
	dkimAlgo := strings.TrimSpace(c.PostForm("dkimAlgorithm"))
	if dkimAlgo != "" && !dkimAlgorithms[dkimAlgo] {
		renderPage(c, http.StatusOK, templates.SettingsView(s.buildSettingsData(c, s.cfg.CfgSnapshot(),
			templates.Tr(langOf(c), "settings.errAlgo"))))
		return
	}
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
	// U13 传输安全节：mode 枚举+max_age 值域校验（rfc8461 §3.2——写坏配置防御）
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

	// ── 原子读改写（全量节合并；未列字段保留现值——SaveConfig 读 Current 快照基底）──
	err = s.cfg.SaveConfig(func(cfg *config.Config) {
		cfg.Auth.SPFEnabled = c.PostForm("spfEnabled") == "on"
		cfg.Auth.DKIMEnabled = c.PostForm("dkimEnabled") == "on"
		cfg.Auth.DMARCEnabled = c.PostForm("dmarcEnabled") == "on"
		cfg.Auth.ARCEnabled = c.PostForm("arcEnabled") == "on"
		cfg.Auth.DKIM = config.DKIMConf{
			Selector:  strings.TrimSpace(c.PostForm("dkimSelector")),
			KeyPath:   strings.TrimSpace(c.PostForm("dkimKeyPath")),
			Algorithm: dkimAlgo,
		}
		cfg.CatchAll = c.PostForm("catchAll") == "on"
		cfg.Mail.MaxMessageSizeBytes = maxSizeMB * 1024 * 1024
		cfg.Mail.Delivery = config.DeliveryConf{
			RetryBaseSeconds: int(retryBase),
			RetryFactor:      int(retryFactor),
			RetryCapSeconds:  int(retryCap),
			MaxAttempts:      int(maxAttempts),
		}
		cfg.Session = config.SessionConf{IdleMinutes: int(idleMinutes), AbsoluteHours: int(absoluteHours)}
		cfg.LoginLimit = config.LoginLimitConf{WindowMinutes: int(limitWindow), Threshold: limitThreshold}
		cfg.MTASts = config.MTAStsConf{ // U13：开关热加载生效（判定③——保存即端点停发/建议值停显）
			Enabled:       c.PostForm("mtaStsEnabled") == "on",
			Mode:          stsMode,
			MaxAgeSeconds: int(stsMaxAge),
			ReportEnabled: c.PostForm("tlsrptEnabled") == "on",
			RuaAddress:    strings.TrimSpace(c.PostForm("tlsrptRuaAddress")),
		}
	})
	if err != nil {
		sessLogger(c).Error("设置保存失败", "error", err)
		renderPage(c, http.StatusInternalServerError, templates.SettingsView(
			s.buildSettingsData(c, s.cfg.CfgSnapshot(), templates.Tr(langOf(c), "settings.errSave"))))
		return
	}
	sessLogger(c).Info("设置已保存（热加载生效）", "log_id", c.GetString(ctxKeyLogID))
	// F01：成功反馈经 ?saved=1 回显 notice（GET 分支渲染）
	c.Redirect(http.StatusSeeOther, "/admin/settings?saved=1")
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
