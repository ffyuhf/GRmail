// config 模块单测（NFR-015：独立驱动）。
// 修改历史：
//
//	2026-09-16 04:45:00 | 新建 | U1 工程骨架
//	2026-09-17 02:46:00 | 扩展 | U3 auth 基础：DKIMConf 往返与旧格式兼容用例（Q1-A）
//	2026-09-17 03:20:00 | 扩展 | U4 SMTP 收信：SMTPPort/MailConf 往返与旧格式零值兼容用例（Q2-A）
//	2026-09-20 00:44:00 | 扩展 | U10 Setup 向导与 ACME：四节增量往返/旧格式兜底/缺省防漂移用例
//	（Q2-A/Q5-A/Q7-C——计划书步骤 3）
//	2026-09-23 12:50:00 | 扩展 | U12b 装配收口：ManageSievePort 往返+缺省防漂移+旧格式兜底用例
//	（U12b 计划书 v1.0.0 步骤 1/1.5①，G2 批准 2026-09-23 12:49:06；SRS FR-011/IR-004）
//	2026-09-23 08:25:00 | 扩展 | U13 传输安全全量：MTASts 节往返+缺省防漂移+旧 JSON 缺节兜底+
//	显式关闭保持用例（U13 计划书 v1.0.0 步骤 2/1.5①，G2 批准 2026-09-23 08:19:32；SRS FR-010）
package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfigSaveLoadRoundtrip 保存→加载往返一致（原子写正确性）
func TestConfigSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Default()
	want.Server.Domain = "grmail.example"
	want.Auth.ARCEnabled = false
	if err := Save(path, want); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got.Server.Domain != want.Server.Domain || got.Auth.ARCEnabled != false {
		t.Fatalf("往返不一致: %+v", got)
	}
	// 临时文件不应残留（原子写清理）
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("临时文件残留")
	}
}

// TestConfigLoadMissingFileReturnsDefault 文件缺失回退默认（首启 Setup 引导语义）
func TestConfigLoadMissingFileReturnsDefault(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatalf("缺失文件应回退默认: %v", err)
	}
	if got.Database.Driver != "sqlite" || !got.Auth.DKIMEnabled {
		t.Fatalf("默认值不符: %+v", got)
	}
}

// TestConfigWatchReload 热加载链路：写文件→去抖→Current 更新（TC-009 语义的单元级验证）
func TestConfigWatchReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	initial := Default()
	if err := Save(path, initial); err != nil {
		t.Fatalf("初始保存: %v", err)
	}
	w, err := Watch(context.Background(), path, initial)
	if err != nil {
		t.Fatalf("启动监听: %v", err)
	}
	defer w.Close()

	fresh := Default()
	fresh.Auth.SPFEnabled = false
	if err := Save(path, fresh); err != nil {
		t.Fatalf("触发保存: %v", err)
	}
	// 去抖 300ms + fsnotify 传播，留足余量
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !w.Current().Auth.SPFEnabled {
			return // 热加载生效
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("热加载超时：Current 未更新")
}

// TestConfigDKIMConfRoundtrip DKIM 子配置 JSON 往返（Q1-A 裁决落地的序列化正确性）
func TestConfigDKIMConfRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Default()
	want.Auth.DKIM = DKIMConf{Selector: "s1024", KeyPath: "data/dkim.pem", Algorithm: "rsa-sha256"}
	if err := Save(path, want); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got.Auth.DKIM != want.Auth.DKIM {
		t.Fatalf("DKIMConf 往返不一致: got=%+v want=%+v", got.Auth.DKIM, want.Auth.DKIM)
	}
}

// TestConfigLegacyJSONNoDKIMSection 旧格式 JSON（无 dkim 节）加载零值兼容
// （Q1-A：扩展向后兼容，缺省零值=未配置态，不影响既有四开关解析）
func TestConfigLegacyJSONNoDKIMSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"server":{"domain":"legacy.example"},"auth":{"spfEnabled":true,"dkimEnabled":false}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("写入旧格式: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载失败: %v", err)
	}
	if got.Auth.DKIM != (DKIMConf{}) {
		t.Fatalf("旧格式 DKIM 应为零值: %+v", got.Auth.DKIM)
	}
	if !got.Auth.SPFEnabled || got.Auth.DKIMEnabled {
		t.Fatalf("旧格式四开关解析被破坏: %+v", got.Auth)
	}
}

// TestConfigSMTPPortAndMailConfRoundtrip SMTP 端口与邮件限值 JSON 往返
// （Q2-A 裁决落地的序列化正确性：ServerConf.SMTPPort + MailConf.MaxMessageSizeBytes）
func TestConfigSMTPPortAndMailConfRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Default()
	want.Server.SMTPPort = 2525
	want.Mail.MaxMessageSizeBytes = 10485760 // 10MiB
	if err := Save(path, want); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got.Server.SMTPPort != 2525 || got.Mail.MaxMessageSizeBytes != 10485760 {
		t.Fatalf("SMTPPort/MailConf 往返不一致: got server=%+v mail=%+v", got.Server, got.Mail)
	}
}

// TestConfigDefaultSMTPAndMailValues 缺省值防漂移（Q2-A 档位：25 端口 + 35MiB SIZE 通告值）
func TestConfigDefaultSMTPAndMailValues(t *testing.T) {
	d := Default()
	if d.Server.SMTPPort != 25 {
		t.Fatalf("SMTPPort 缺省应为 25: %d", d.Server.SMTPPort)
	}
	if d.Mail.MaxMessageSizeBytes != 36700160 {
		t.Fatalf("MaxMessageSizeBytes 缺省应为 36700160(35MiB): %d", d.Mail.MaxMessageSizeBytes)
	}
}

// TestConfigLegacyJSONNoMailSection 旧格式 JSON（无 smtpPort/mail 节）加载兜底为缺省档
// （Q2-A：扩展向后兼容；Load 既有语义=Default 基底+JSON 覆盖——旧配置自动获得
// 安全缺省值 SMTPPort=25/MaxMessageSizeBytes=35MiB，与 U1 缺省行为一致）
func TestConfigLegacyJSONNoMailSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"server":{"domain":"legacy.example","httpPort":8443},"catchAll":false}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("写入旧格式: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载失败: %v", err)
	}
	if got.Server.SMTPPort != 25 || got.Mail.MaxMessageSizeBytes != 36700160 {
		t.Fatalf("旧格式 SMTPPort/Mail 应兜底缺省档: server=%+v mail=%+v", got.Server, got.Mail)
	}
	if got.Server.Domain != "legacy.example" || got.Server.HTTPPort != 8443 || got.CatchAll {
		t.Fatalf("旧格式既有节解析被破坏: %+v", got)
	}
}

// TestConfigU5FieldsRoundtrip U5 子配置 JSON 往返
// （Q2-A/Q5-C 裁决落地的序列化正确性：提交双端口 + TLS 段 + DeliveryConf）
func TestConfigU5FieldsRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	in := Default()
	in.Server.SubmissionPort = 2587
	in.Server.SubmissionTLSPort = 2465
	in.TLS = TLSConf{CertFile: "/etc/cert.pem", KeyFile: "/etc/key.pem"}
	in.Mail.Delivery = DeliveryConf{RetryBaseSeconds: 120, RetryFactor: 3, RetryCapSeconds: 7200, MaxAttempts: 5}
	if err := Save(path, in); err != nil {
		t.Fatalf("保存: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if got.Server.SubmissionPort != 2587 || got.Server.SubmissionTLSPort != 2465 {
		t.Fatalf("提交端口往返不一致: %+v", got.Server)
	}
	if got.TLS.CertFile != "/etc/cert.pem" || got.TLS.KeyFile != "/etc/key.pem" {
		t.Fatalf("TLS 段往返不一致: %+v", got.TLS)
	}
	if got.Mail.Delivery != (DeliveryConf{RetryBaseSeconds: 120, RetryFactor: 3, RetryCapSeconds: 7200, MaxAttempts: 5}) {
		t.Fatalf("DeliveryConf 往返不一致: %+v", got.Mail.Delivery)
	}
}

// TestConfigU5DefaultsAndLegacy U5 缺省值防漂移与旧格式兜底
// （Q2-A 档位：587/465 端口；Q5-C 档位：60s/×2/3600s/8 次；旧 JSON 零值兜底缺省）
// TestConfigU6IMAPPortRoundtrip IMAP 端口往返+缺省防漂移+旧格式兜底
// （Q1-A 裁决 2026-09-18 00:00:04：仅 993 隐式 TLS）。
func TestConfigU6IMAPPortRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	in := Default()
	if in.Server.IMAPPort != 993 {
		t.Fatalf("IMAP 缺省端口期望 993: %d", in.Server.IMAPPort)
	}
	in.Server.IMAPPort = 9930
	if err := Save(path, in); err != nil {
		t.Fatalf("保存: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if got.Server.IMAPPort != 9930 {
		t.Fatalf("IMAP 端口往返期望 9930: %d", got.Server.IMAPPort)
	}
	// 旧格式（无 imapPort 字段）零值兜底——监听器缺省档路径
	if err = os.WriteFile(path, []byte(`{"server":{"domain":"x.io"}}`), 0o600); err != nil {
		t.Fatalf("写旧格式: %v", err)
	}
	legacy, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载: %v", err)
	}
	if legacy.Server.IMAPPort != 993 {
		t.Fatalf("旧格式 IMAP 端口兜底期望 993: %d", legacy.Server.IMAPPort)
	}
}

// TestConfigU7POP3PortRoundtrip POP3 端口往返+缺省防漂移+旧格式兜底
// （U7 计划书 v1.0.0 步骤 1，G2 批准 2026-09-19 04:09:01：仅 995 隐式 TLS，
// SRS FR-007/IR-003 rfc1939/5034）。
func TestConfigU7POP3PortRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	in := Default()
	if in.Server.POP3Port != 995 {
		t.Fatalf("POP3 缺省端口期望 995: %d", in.Server.POP3Port)
	}
	in.Server.POP3Port = 9950
	if err := Save(path, in); err != nil {
		t.Fatalf("保存: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if got.Server.POP3Port != 9950 {
		t.Fatalf("POP3 端口往返期望 9950: %d", got.Server.POP3Port)
	}
	// 旧格式（无 pop3Port 字段）零值兜底——监听器缺省档路径
	if err = os.WriteFile(path, []byte(`{"server":{"domain":"x.io"}}`), 0o600); err != nil {
		t.Fatalf("写旧格式: %v", err)
	}
	legacy, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载: %v", err)
	}
	if legacy.Server.POP3Port != 995 {
		t.Fatalf("旧格式 POP3 端口兜底期望 995: %d", legacy.Server.POP3Port)
	}
}

func TestConfigU5DefaultsAndLegacy(t *testing.T) {
	d := Default()
	if d.Server.SubmissionPort != 587 || d.Server.SubmissionTLSPort != 465 {
		t.Fatalf("提交端口缺省应为 587/465: %+v", d.Server)
	}
	if d.Mail.Delivery != (DeliveryConf{RetryBaseSeconds: 60, RetryFactor: 2, RetryCapSeconds: 3600, MaxAttempts: 8}) {
		t.Fatalf("DeliveryConf 缺省档防漂移: %+v", d.Mail.Delivery)
	}
	if d.TLS != (TLSConf{}) {
		t.Fatalf("TLS 缺省应为零值未配置态: %+v", d.TLS)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"server":{"domain":"u5.example","smtpPort":25}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("写入旧格式: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载失败: %v", err)
	}
	if got.Server.SubmissionPort != 587 || got.Server.SubmissionTLSPort != 465 {
		t.Fatalf("旧格式提交端口应兜底缺省档: %+v", got.Server)
	}
	if got.Mail.Delivery.MaxAttempts != 8 || got.Mail.Delivery.RetryBaseSeconds != 60 {
		t.Fatalf("旧格式 Delivery 应兜底缺省档: %+v", got.Mail.Delivery)
	}
	if got.TLS.CertFile != "" {
		t.Fatalf("旧格式 TLS 应为未配置态: %+v", got.TLS)
	}
}

// TestConfigU10FieldsRoundtrip U10 四节增量 JSON 往返
// （Q2-A setupCompleted/Q5-A ACME 节/Q7-C 会话与限流节——计划书步骤 3）
func TestConfigU10FieldsRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	in := Default()
	in.SetupCompleted = true
	in.Session = SessionConf{IdleMinutes: 45, AbsoluteHours: 24}
	in.LoginLimit = LoginLimitConf{WindowMinutes: 30, Threshold: 3}
	in.ACME = ACMEConf{Enabled: true, Email: "admin@grmail.example", Staging: true}
	if err := Save(path, in); err != nil {
		t.Fatalf("保存: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if !got.SetupCompleted {
		t.Fatal("SetupCompleted 往返丢失")
	}
	if got.Session != (SessionConf{IdleMinutes: 45, AbsoluteHours: 24}) {
		t.Fatalf("Session 往返不一致: %+v", got.Session)
	}
	if got.LoginLimit != (LoginLimitConf{WindowMinutes: 30, Threshold: 3}) {
		t.Fatalf("LoginLimit 往返不一致: %+v", got.LoginLimit)
	}
	if !got.ACME.Enabled || got.ACME.Email != "admin@grmail.example" || !got.ACME.Staging {
		t.Fatalf("ACME 往返不一致: %+v", got.ACME)
	}
}

// TestConfigU12bManageSievePortRoundtrip ManageSieve 端口往返+缺省防漂移+旧格式兜底
// （U12b 计划书 1.5①：缺省 4190——rfc5804 §1.8；监听器启动期绑定重启生效口径沿端口先例）
func TestConfigU12bManageSievePortRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	in := Default()
	if in.Server.ManageSievePort != 4190 {
		t.Fatalf("ManageSieve 缺省端口期望 4190: %d", in.Server.ManageSievePort)
	}
	in.Server.ManageSievePort = 14190
	if err := Save(path, in); err != nil {
		t.Fatalf("保存: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if got.Server.ManageSievePort != 14190 {
		t.Fatalf("ManageSieve 端口往返期望 14190: %d", got.Server.ManageSievePort)
	}
	// 旧格式（无 manageSievePort 字段）零值兜底——监听器缺省档路径
	if err = os.WriteFile(path, []byte(`{"server":{"domain":"x.io"}}`), 0o600); err != nil {
		t.Fatalf("写旧格式: %v", err)
	}
	legacy, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载: %v", err)
	}
	if legacy.Server.ManageSievePort != 4190 {
		t.Fatalf("旧格式 ManageSieve 端口兜底期望 4190: %d", legacy.Server.ManageSievePort)
	}
}

// TestConfigU10DefaultsAndLegacy U10 缺省防漂移与旧格式兜底
// （旧 JSON 无 setupCompleted/session/loginLimit/acme 节：零值 false+缺省档——已部署
// 实例经向导跳过路径补记，计划书 1.5⑩）
func TestConfigU10DefaultsAndLegacy(t *testing.T) {
	d := Default()
	if d.SetupCompleted {
		t.Fatal("缺省应为引导态（false）")
	}
	if d.Session != (SessionConf{IdleMinutes: 30, AbsoluteHours: 12}) {
		t.Fatalf("Session 缺省档防漂移: %+v", d.Session)
	}
	if d.LoginLimit != (LoginLimitConf{WindowMinutes: 15, Threshold: 5}) {
		t.Fatalf("LoginLimit 缺省档防漂移: %+v", d.LoginLimit)
	}
	if d.ACME.Enabled || d.ACME.CADirURL != ACMEDirectoryProduction || d.ACME.CertsDir != "data/certs" {
		t.Fatalf("ACME 缺省档防漂移（手动模式+production 端点）: %+v", d.ACME)
	}

	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"server":{"domain":"u10.example"},"setupCompleted":true}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("写入旧格式: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载失败: %v", err)
	}
	if !got.SetupCompleted {
		t.Fatal("显式 setupCompleted=true 应被解析")
	}
	if got.Session.IdleMinutes != 30 || got.LoginLimit.Threshold != 5 {
		t.Fatalf("旧格式会话/限流应兜底缺省档: session=%+v limit=%+v", got.Session, got.LoginLimit)
	}
	if got.ACME.CADirURL != ACMEDirectoryProduction {
		t.Fatalf("旧格式 ACME 端点应兜底缺省档: %+v", got.ACME)
	}
}

// TestConfigU13MTAStsRoundtripAndLegacy U13 MTASts 节：往返+缺省防漂移+旧 JSON 缺节
// 兜底（FR-010 默认启用锚——bool 零值与「关闭」语义经节存在性区分）+显式关闭保持
// （判定③：Web 关闭后端点停发的配置载体）。
func TestConfigU13MTAStsRoundtripAndLegacy(t *testing.T) {
	// 1. 缺省防漂移：默认启用+enforce+1 周+报告启用（FR-010「二者默认启用」）
	d := Default()
	if !d.MTASts.Enabled || d.MTASts.Mode != "enforce" || d.MTASts.MaxAgeSeconds != 604800 || !d.MTASts.ReportEnabled {
		t.Fatalf("MTASts 缺省档防漂移: %+v", d.MTASts)
	}

	// 2. 往返：显式关闭+testing 模式+自定义 max_age+rua
	path := filepath.Join(t.TempDir(), "config.json")
	want := Default()
	want.MTASts = MTAStsConf{Enabled: false, Mode: "testing", MaxAgeSeconds: 1296000, ReportEnabled: false, RuaAddress: "tlsrpt@x.io"}
	if err := Save(path, want); err != nil {
		t.Fatalf("保存: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if got.MTASts != want.MTASts {
		t.Fatalf("MTASts 往返不一致: got=%+v want=%+v", got.MTASts, want.MTASts)
	}

	// 3. 旧 JSON 缺节兜底：无 "mtaSts" 键→恢复默认启用档（U12b 之前部署形态）
	if err := os.WriteFile(path, []byte(`{"server":{"domain":"x.io"}}`), 0o600); err != nil {
		t.Fatalf("写旧格式: %v", err)
	}
	legacy, err := Load(path)
	if err != nil {
		t.Fatalf("旧格式加载: %v", err)
	}
	if !legacy.MTASts.Enabled || legacy.MTASts.Mode != "enforce" || legacy.MTASts.MaxAgeSeconds != 604800 || !legacy.MTASts.ReportEnabled {
		t.Fatalf("旧格式 MTASts 缺节应兜底默认启用档: %+v", legacy.MTASts)
	}

	// 4. 越界/非法值兜底：mode 与 max_age 归位缺省（写坏配置防御——设置页校验外二道防线）
	if err := os.WriteFile(path, []byte(`{"server":{"domain":"x.io"},"mtaSts":{"enabled":true,"mode":"bogus","maxAgeSeconds":999999999}}`), 0o600); err != nil {
		t.Fatalf("写越界格式: %v", err)
	}
	bad, err := Load(path)
	if err != nil {
		t.Fatalf("越界加载: %v", err)
	}
	if bad.MTASts.Mode != "enforce" || bad.MTASts.MaxAgeSeconds != 604800 {
		t.Fatalf("越界 mode/maxAge 应兜底缺省档: %+v", bad.MTASts)
	}
}
