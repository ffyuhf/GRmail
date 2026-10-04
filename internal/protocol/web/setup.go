// Setup 六步向导（U10：FR-015/NFR-010——Q1-A 范围/Q2-A setupCompleted 判定/Q3-A 80 承载/
// Q5-A 双模式 SSL 步/Q6-A ACME 落盘回写链消费侧）。
// 步骤序沿手册第 1 章：①数据库（SQLite 默认/MySQL/PG——连接探活）→②管理员密码
// （EnsureAdmin+argon2id，数据模型 3.1「Setup 向导创建唯一管理员」；旧部署跳过路径
// 计划书 1.5⑩）→③域名+DKIM 密钥生成→④DNS 建议（真实值呈现）→⑤SSL 模式（ACME/
// 手动导入）→⑥完成（setupCompleted=true+重启提示——Q4-A 完成后重启全量拉起）。
// 安全边界（计划书 1.5③）：向导期不签发会话 cookie（OWASP 跨协议会话条款——80 明文
// 承载禁携认证态）；每步 POST 即 Save（部分完成态可恢复——重启后从首个未完成步继续）；
// 步 2 复用 LoginAttemptRepo 限流（subject_key=setup:admin 防向导期爆破）。
// 修改历史：
//
//	2026-09-20 01:10:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 6）
//	2026-10-04 15:06:00 | 修正 | 向导占位符与布局修复批次：①步 3 增 DKIM 密钥生成区
//	（强度四档裁决三a——auth.GenerateDKIMKeyPair 消费；私钥落盘 data/dkim.pem 四a+
//	config 回写 selector=grmail 二a；FR-015「无需手工编辑任何配置文件」收口）②步 4
//	DNS 建议真实值化：A 记录=UDP 拨号探测出口 IP（五a——零外呼；NAT 私网回退留空+
//	说明引导）、DKIM 行=既有/新生成密钥的真实公钥 TXT（六a SPKI 形态；未配置不显示
//	——占位文本全清除）③畸形 DKIM 主机名随 selector 正常化消除
//	（依据：向导占位符与布局修复计划书 v1.0.0 1.2-DKIM/IP 组，G2 批准 2026-10-04
//	15:03:25；干系人核心裁决 12:19+实现方向六项 15:01；SRS FR-015/FR-008/NFR-012）
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"GRmail/internal/account"
	"GRmail/internal/auth"
	"GRmail/internal/config"
	"GRmail/internal/observability"
	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// setupSteps 六步定义（slug↔序号；手册第 1 章步骤序——契约 3.1 /setup/{step}）。
var setupSteps = []struct {
	Slug  string
	Title string
}{
	{"database", "数据库"},
	{"admin", "管理员"},
	{"domain", "域名"},
	{"dns", "DNS 记录建议"},
	{"ssl", "证书模式"},
	{"done", "完成"},
}

// setupStepIndex step 参数→序号（0 基）；双形态解析：slug（表单 action/复现友好的
// /setup/database）与序号（gate 重定向的 /setup/1）；未知名返回 -1。
func setupStepIndex(step string) int {
	for i, s := range setupSteps {
		if s.Slug == step {
			return i
		}
	}
	if n, err := strconv.Atoi(step); err == nil && n >= 1 && n <= len(setupSteps) {
		return n - 1
	}
	return -1
}

// errSetupStep 向导步骤校验失败哨兵（携带用户可读消息——重渲染当前步呈现）。
type errSetupStep struct{ msg string }

func (e *errSetupStep) Error() string { return e.msg }

// setupFail 向导步骤失败统一出口：重渲染当前步骤页（含错误消息）；存储故障 500。
// 参数：c 上下文；idx 当前步序号；err 失败（errSetupStep=表单错误；其余=系统故障）。
func (s *Server) setupFail(c *gin.Context, idx int, err error) {
	if _, ok := err.(*errSetupStep); ok {
		renderPage(c, http.StatusOK, templates.SetupView(s.buildSetupData(c, idx, err.Error())))
		return
	}
	sessLogger(c).Error("Setup 步骤处理故障", "error", err, "step", setupSteps[idx].Slug)
	renderPage(c, http.StatusInternalServerError, templates.SetupView(s.buildSetupData(c, idx, templates.Tr(langOf(c), "setup.errSystem"))))
}

// setupGET 向导步骤页（GET /setup/{step}）：已存配置回填呈现（部分完成态恢复）。
func (s *Server) setupGET(c *gin.Context) {
	idx := setupStepIndex(c.Param("step"))
	if idx < 0 {
		c.Redirect(http.StatusFound, "/setup/1")
		return
	}
	renderPage(c, http.StatusOK, templates.SetupView(s.buildSetupData(c, idx, "")))
}

// buildSetupData 装配向导页数据（当前配置快照回填）。
// 参数：c 上下文；idx 步序号；errMsg 错误消息（空=无）。
func (s *Server) buildSetupData(c *gin.Context, idx int, errMsg string) templates.SetupData {
	cfg := s.currentConfig(c)
	data := templates.SetupData{
		Lang:  string(langOf(c)), // U18：深级双语承载（向导无会话仍可读 cookie lang）
		Step:  idx + 1,
		Total: len(setupSteps),
		Title: setupSteps[idx].Title,
		Error: errMsg,
		Next:  setupSteps[min(idx+1, len(setupSteps)-1)].Slug,
	}
	if cfg == nil {
		return data
	}
	data.Driver = cfg.Database.Driver
	data.DSN = cfg.Database.DSN
	data.Domain = cfg.Server.Domain
	data.Username = "admin" // 缺省建议名（步 2 表单预填）
	data.SSLMode = "acme"
	data.ACMEMail = cfg.ACME.Email
	data.ACMEStaging = cfg.ACME.Staging
	data.ACMEChallenge = "http" // D8#12：缺省 HTTP-01（既有口径）；cloudflare 配置态回填 dns
	if cfg.ACME.DNSProvider == "cloudflare" {
		data.ACMEChallenge = "dns"
	}
	data.CertFile = cfg.TLS.CertFile
	data.KeyFile = cfg.TLS.KeyFile
	// 步 3 DKIM 区回填（向导占位符与布局修复批次）：强度选择框按算法映射回显
	// （生成档位选择——非现状位数呈现；rsa 档统称 rsa-2048 缺省位）；KeyPath 非空
	// 即提示已生成（沿用优先，勾选重新生成方覆盖——1.3-4 设置页既有键零破坏）。
	data.DKIMStrength = auth.DefaultDKIMStrength
	if cfg.Auth.DKIM.Algorithm == "ed25519-sha256" {
		data.DKIMStrength = "ed25519"
	}
	data.DKIMGenerated = cfg.Auth.DKIM.KeyPath != "" && cfg.Auth.DKIM.Selector != ""
	if idx == 3 { // DNS 建议步：按当前域名计算呈现（计划书 1.5⑤；真实值化——IP 探测/DKIM 公钥）
		data.DNSRecords = buildDNSRecords(cfg)
	}
	if idx == 5 {
		data.DomainFinal = cfg.Server.Domain
	}
	return data
}

// buildDNSRecords DNS 建议值清单（只读呈现——全部记录值直接可复制发布；NFR-012 对照输入；
// U13 增 _mta-sts/_smtp._tls 两行——FR-010 发布侧记录，按开关条件呈现）。
// 真实值化（向导占位符与布局修复批次——干系人裁决 12:19）：A 记录=UDP 拨号探测的
// 本机出口公网 IP（探测失败/NAT 私网→值留空+说明列引导，不虚构）；DKIM 行=config
// 现键的真实公钥 TXT（SPKI 形态六a；未配置/不可读→该行不呈现，零占位文本）。
func buildDNSRecords(cfg *config.Config) []templates.DNSRecordView {
	d := cfg.Server.Domain
	if d == "" || d == "localhost" {
		d = "你的域名"
	}
	spf := "v=spf1 mx -all"
	dmarc := "v=DMARC1; p=none; rua=mailto:postmaster@" + d
	// A 记录值：探测本机公网出口 IP（裁决五a——UDP 拨号零外呼；私网/失败回退留空引导）
	pubIP := detectPublicIP()
	aValue, aNote := pubIP, "主机记录解析"
	if aValue == "" {
		aNote = "填你的服务器公网 IP（自动探测不可用——本机处于内网/NAT 环境）"
	}
	records := []templates.DNSRecordView{
		{Type: "A", Name: d, Value: aValue, Note: aNote},
		{Type: "MX", Name: d, Value: "10 " + d, Note: "邮件交换（优先级 10）"},
		{Type: "TXT", Name: d, Value: spf, Note: "SPF 发信授权（rfc7208）"},
		{Type: "TXT", Name: "_dmarc." + d, Value: dmarc, Note: "DMARC 策略（rfc9989）"},
	}
	// DKIM 行：仅当私钥可用时呈现真实公钥记录（裁决六a——v=DKIM1; k=…; p=Base64(SPKI)）；
	// 未配置/不可读不呈现该行（零占位——畸形主机名随 selector 正常条件一并消除）。
	if selector := cfg.Auth.DKIM.Selector; selector != "" && cfg.Auth.DKIM.KeyPath != "" {
		if txt, err := auth.DKIMPublicKeyDNSValue(cfg.Auth.DKIM.KeyPath); err == nil && txt != "" {
			records = append(records, templates.DNSRecordView{
				Type: "TXT", Name: selector + "._domainkey." + d,
				Value: txt, Note: "DKIM 签名验证（rfc6376）",
			})
		}
	}
	// U13：MTA-STS/TLS-RPT 发布记录（FR-010 默认启用——关闭开关时该行不呈现）；
	// id 取向导呈现时刻（部署者复制即最新实例标识——rfc8461 §3.1）
	if cfg.MTASts.Enabled {
		records = append(records, templates.DNSRecordView{
			Type: "TXT", Name: "_mta-sts." + d,
			Value: "v=STSv1; id=" + stsSuggestionID() + ";",
			Note:  "MTA-STS 策略发现（rfc8461——需同时发布 mta-sts 子域 A 记录）",
		})
		records = append(records, templates.DNSRecordView{
			Type: "A", Name: "mta-sts." + d,
			Value: aValue,
			Note:  "MTA-STS 策略宿主（rfc8461 §3.2——与主域同机，策略端点 443 承载）",
		})
	}
	if cfg.MTASts.ReportEnabled {
		records = append(records, templates.DNSRecordView{
			Type: "TXT", Name: "_smtp._tls." + d,
			Value: tlsrptTXTSuggestion(cfg),
			Note:  "TLS-RPT 聚合报告接收（rfc8460）",
		})
	}
	return records
}

// detectPublicIP 探测本机公网出口 IP（裁决五a——UDP 拨号：对公网地址 connect 仅做
// 本地路由决策，不发送任何数据包，零第三方服务依赖）。NAT 内网（RFC1918/环回/链路
// 本地）或拨号失败返回空串——调用方按裁决留空引导（不虚构值）。
func detectPublicIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	ip := udpAddr.IP
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// stsSuggestionID 建议值 id（呈现时刻 UTC 紧凑格式——与 adminsettings 呈现同源）。
func stsSuggestionID() string { return time.Now().UTC().Format("20060102150405Z") }

// currentConfig 当前配置快照（CfgSnapshot 未注入=Default 兜底——测试/降级形态）。
func (s *Server) currentConfig(c *gin.Context) *config.Config {
	if s.cfg.CfgSnapshot != nil {
		return s.cfg.CfgSnapshot()
	}
	def := config.Default()
	return def
}

// saveStep 步骤保存：注入的原子读改写闭包（未注入=内存直改——测试形态）。
func (s *Server) saveStep(c *gin.Context, modify func(*config.Config)) error {
	if s.cfg.SaveConfig == nil {
		sessLogger(c).Warn("SaveConfig 未注入（测试形态）：配置未持久化")
		return nil
	}
	return s.cfg.SaveConfig(modify)
}

// setupPOST 向导步骤提交（POST /setup/{step}）：校验→保存→303 下一 slug。
func (s *Server) setupPOST(c *gin.Context) {
	idx := setupStepIndex(c.Param("step"))
	if idx < 0 {
		c.Redirect(http.StatusFound, "/setup/1")
		return
	}
	var err error
	switch setupSteps[idx].Slug {
	case "database":
		err = s.setupPostDatabase(c)
	case "admin":
		err = s.setupPostAdmin(c)
	case "domain":
		err = s.setupPostDomain(c)
	case "dns":
		// 只读确认步：无保存（DNS 记录由部署者在域名服务商处发布）
	case "ssl":
		err = s.setupPostSSL(c)
	case "done":
		err = s.setupPostDone(c)
	}
	if err != nil {
		s.setupFail(c, idx, err)
		return
	}
	if setupSteps[idx].Slug == "done" {
		return // 完成步在内部渲染终态页（SetupCompleted 已置位——setupGate 对后续请求禁入）
	}
	next := setupSteps[min(idx+1, len(setupSteps)-1)]
	c.Redirect(http.StatusSeeOther, "/setup/"+next.Slug)
}

// setupPostDatabase 步 1：数据库选择与连接探活（FR-014；重启生效口径注记随页呈现）。
func (s *Server) setupPostDatabase(c *gin.Context) error {
	driver := strings.ToLower(strings.TrimSpace(c.PostForm("driver")))
	dsn := strings.TrimSpace(c.PostForm("dsn"))
	switch driver {
	case "sqlite", "mysql", "postgres":
	default:
		return &errSetupStep{msg: "数据库类型必须为 sqlite / mysql / postgres"}
	}
	if driver != "sqlite" && dsn == "" {
		return &errSetupStep{msg: "MySQL/PostgreSQL 必须填写连接串（DSN）"}
	}
	// 连接探活（fail-fast——storage.Open 语义：sqlite 建文件+探活，mysql/pg 真连）
	if driver != "sqlite" || dsn != "" {
		probeCtx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		db, err := storage.Open(probeCtx, config.DatabaseConf{Driver: driver, DSN: dsn})
		if err != nil {
			return &errSetupStep{msg: "数据库连接失败：" + err.Error() + "（请检查地址/凭据）"}
		}
		_ = db.Close()
	}
	if err := s.saveStep(c, func(cfg *config.Config) {
		if driver == "sqlite" && dsn == "" {
			dsn = "data/grmail.db" // 缺省档
		}
		cfg.Database = config.DatabaseConf{Driver: driver, DSN: dsn}
	}); err != nil {
		return err
	}
	sessLogger(c).Info("Setup 步骤 1 完成：数据库选定", "driver", driver)
	return nil
}

// setupPostAdmin 步 2：管理员创建（数据模型 3.1 初始化；argon2id 哈希零明文持久化）+
// 旧部署跳过路径（action=skip——计划书 1.5⑩）+向导限流（subject_key=setup:admin）。
func (s *Server) setupPostAdmin(c *gin.Context) error {
	ctx := c.Request.Context()
	// 限流前置（1.5③：防向导期爆破——复用 U8 LoginAttemptRepo 设施）
	if s.attempts != nil {
		subjectKey := "setup:admin"
		fails, err := s.attempts.CountRecentFails(ctx, subjectKey, time.Now().UTC().Add(-15*time.Minute))
		if err == nil && fails >= 5 {
			return &errSetupStep{msg: "尝试次数过多，请稍后再试"}
		}
	}
	if c.PostForm("action") == "skip" {
		// 旧部署跳过：管理员已存在（EnsureAdmin 幂等语义下重设会静默失效——FindByName
		// 判重路径防御），直接进入下一步；全新部署误跳过可回本步补设
		if s.attempts != nil {
			_ = s.attempts.ClearSubject(ctx, "setup:admin")
		}
		sessLogger(c).Info("Setup 步骤 2 跳过（既有部署补记路径）")
		return nil
	}
	username := strings.ToLower(strings.TrimSpace(c.PostForm("username")))
	password := c.PostForm("password")
	confirm := c.PostForm("confirm")
	if username == "" || password == "" {
		return &errSetupStep{msg: "用户名与密码不能为空"}
	}
	if password != confirm {
		return &errSetupStep{msg: "两次输入的密码不一致"}
	}
	if _, err := s.users.FindByName(ctx, username); err == nil {
		return &errSetupStep{msg: "用户名已存在（既有部署请使用下方跳过按钮）"}
	} else if !errors.Is(err, storage.ErrUserNotFound) {
		return err
	}
	hash, err := account.HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.users.EnsureAdmin(ctx, &storage.User{
		Username:     username,
		PasswordHash: hash,
		IsAdmin:      true,
	}); err != nil {
		return err
	}
	if s.attempts != nil {
		_ = s.attempts.ClearSubject(ctx, "setup:admin")
	}
	sessLogger(c).Info("Setup 步骤 2 完成：管理员已创建", "username", username)
	return nil
}

// setupPostDomain 步 3：主域名（发信身份/收信判定/证书 CN——后续步骤依赖）
// +DKIM 密钥生成（向导占位符与布局修复批次——裁决一a：生成本步承载；FR-015
// 「无需手工编辑任何配置文件」收口：密钥原需管理员 openssl 手工生成放置）。
// 表单：domain（既有）+dkimStrength（四档三a，缺省 rsa-2048）+dkimRegen（重新生成
// 勾选——不勾选且已有键则沿用，设置页既有键零覆盖）。
// 生成链：GenerateDKIMKeyPair→私钥 PKCS#8 落盘 data/dkim.pem（四a，0600）→
// config 原子回写 selector=grmail（二a）/keyPath/algorithm（saveStep 既有链）。
func (s *Server) setupPostDomain(c *gin.Context) error {
	domain := strings.ToLower(strings.TrimSpace(c.PostForm("domain")))
	if domain == "" || len(domain) > 255 || strings.ContainsAny(domain, " \t/@") {
		return &errSetupStep{msg: "域名格式非法（非空、≤255 字符、不含空格与 @）"}
	}
	strength := strings.TrimSpace(c.PostForm("dkimStrength"))
	if strength == "" {
		strength = auth.DefaultDKIMStrength
	}
	regen := c.PostForm("dkimRegen") == "on"
	cur := s.currentConfig(c)
	needKey := regen || cur.Auth.DKIM.KeyPath == "" || cur.Auth.DKIM.Selector == ""
	var newDKIM config.DKIMConf
	if needKey {
		privPEM, _, algorithm, err := auth.GenerateDKIMKeyPair(strength)
		if err != nil {
			return &errSetupStep{msg: "DKIM 密钥生成失败：" + err.Error()}
		}
		keyPath := "data/dkim.pem" // 裁决四a：固定落盘路径（设置页可改）
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return &errSetupStep{msg: "DKIM 私钥目录创建失败：" + err.Error()}
		}
		if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
			return &errSetupStep{msg: "DKIM 私钥写入失败：" + err.Error()}
		}
		newDKIM = config.DKIMConf{Selector: "grmail", KeyPath: keyPath, Algorithm: algorithm}
	}
	if err := s.saveStep(c, func(cfg *config.Config) {
		cfg.Server.Domain = domain
		if needKey {
			cfg.Auth.DKIM = newDKIM
		}
	}); err != nil {
		return err
	}
	if needKey {
		sessLogger(c).Info("Setup 步骤 3 完成：域名选定+DKIM 密钥已生成",
			"domain", domain, "strength", strength, "keyPath", newDKIM.KeyPath)
		return nil
	}
	sessLogger(c).Info("Setup 步骤 3 完成：域名选定（DKIM 沿用既有键）", "domain", domain)
	return nil
}

// setupPostSSL 步 5：证书模式（Q5-A 双模式：ACME HTTP-01 自动/手动导入）。
// ACME 模式：Email+Staging 落 config（签发由 ACMEManager 第六步后异步承载——Q6-A）；
// 手动模式：证书路径即时校验（LoadX509KeyPair 配对解析）落 TLS 字段。
func (s *Server) setupPostSSL(c *gin.Context) error {
	mode := c.PostForm("mode")
	switch mode {
	case "acme":
		email := strings.TrimSpace(c.PostForm("acmeEmail"))
		if email == "" || !strings.Contains(email, "@") {
			return &errSetupStep{msg: "ACME 联系人邮箱不能为空（证书到期通知用）"}
		}
		staging := c.PostForm("acmeStaging") == "on"
		// D8#12：挑战方式单选（http=HTTP-01 既有缺省〔80 挑战路由〕/dns=Cloudflare
		// DNS-01〔API Token 凭证——FR-015 判定标准双模式兑现；S4-W Q1-A 裁决〕）
		challenge := c.PostForm("acmeChallenge")
		if challenge == "" {
			challenge = "http"
		}
		if challenge != "http" && challenge != "dns" {
			return &errSetupStep{msg: "ACME 挑战方式仅支持 HTTP-01 / DNS-01（Cloudflare）"}
		}
		dnsToken := strings.TrimSpace(c.PostForm("acmeDnsToken"))
		if challenge == "dns" && dnsToken == "" {
			return &errSetupStep{msg: "DNS-01（Cloudflare）需要 API Token（Zone:DNS:Edit 权限）"}
		}
		if err := s.saveStep(c, func(cfg *config.Config) {
			cfg.ACME.Enabled = true
			cfg.ACME.Email = email
			cfg.ACME.Staging = staging
			if challenge == "dns" {
				cfg.ACME.DNSProvider = "cloudflare"
				cfg.ACME.DNSApiToken = dnsToken
			} else {
				cfg.ACME.DNSProvider = ""
				cfg.ACME.DNSApiToken = ""
			}
			if staging {
				cfg.ACME.CADirURL = config.ACMEDirectoryStaging
			} else if cfg.ACME.CADirURL == "" || cfg.ACME.CADirURL == config.ACMEDirectoryStaging {
				cfg.ACME.CADirURL = config.ACMEDirectoryProduction
			}
		}); err != nil {
			return err
		}
		sessLogger(c).Info("Setup 步骤 5 完成：ACME 模式选定（后台签发于完成步后）", "email", email, "staging", staging)
		return nil
	case "manual":
		certFile := strings.TrimSpace(c.PostForm("certFile"))
		keyFile := strings.TrimSpace(c.PostForm("keyFile"))
		if certFile == "" || keyFile == "" {
			return &errSetupStep{msg: "手动模式必须填写证书与私钥文件路径"}
		}
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return &errSetupStep{msg: "证书对校验失败：" + err.Error()}
		}
		if err := s.saveStep(c, func(cfg *config.Config) {
			cfg.TLS = config.TLSConf{CertFile: certFile, KeyFile: keyFile}
			cfg.ACME.Enabled = false
		}); err != nil {
			return err
		}
		sessLogger(c).Info("Setup 步骤 5 完成：手动证书已校验", "cert", certFile)
		return nil
	default:
		return &errSetupStep{msg: "请选择证书模式（ACME 自动 / 手动导入）"}
	}
}

// setupPostDone 步 6：完成（setupCompleted=true 落盘——Q2-A；Q4-A 重启全量拉起提示；
// ACME 模式下签发由 main 装配的后台 goroutine 承载——本 handler 仅落标志并渲染终态页）。
func (s *Server) setupPostDone(c *gin.Context) error {
	if err := s.saveStep(c, func(cfg *config.Config) {
		cfg.SetupCompleted = true
	}); err != nil {
		return err
	}
	logger := observability.LoggerFromContext(c.Request.Context())
	logger.Info("Setup 完成：setupCompleted 已落盘（重启后全量端点拉起）")
	renderPage(c, http.StatusOK, templates.SetupView(s.buildSetupData(c, 5, "")))
	return nil
}
