// DKIM Webmail 管理功能测试（DKIM管理缺陷修复批——E-1-A 重新生成/E-2-A selector 自定义/E-3-A 公钥呈现）。
// 覆盖：isValidDKIMSelector 语法锚（rfc6376 §3.6.1+rfc5321bis sub-domain）/重新生成端点
// （服务端强制二次确认+强度值域+生成链端到端：私钥落盘→config 回写→303 反馈）/向导
// selector 即时落盘（乙形态——已生成态改值生效/缺省 grmail/非法拒绝）/设置页公钥
// TXT 呈现（正常三元+不可读态错误提示）。
// SRS 条目：FR-008（3.4.1）/FR-009（3.4.2）/FR-015（3.9.2）/NFR-012（4.3）；
// TC-008/TC-009/TC-015/TC-025 判定原文零触碰（离线半场锚）。
// 依据：DKIM管理缺陷修复批计划书 v1.0.0 第三章（G2 批准 2026-10-22 23:02:54 三段闭合链）。
// 修改历史：
//
//	2026-10-22 23:20:00 | 新建 | DKIM管理缺陷修复批（计划书步骤 1~3 用例承载）
package web

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"GRmail/internal/auth"
	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// ───────────────────────── 用例组 1：isValidDKIMSelector 纯函数（E-2-A） ─────────────────────────

// TestIsValidDKIMSelector selector 语法锚（rfc6376 §3.6.1 L581「selector =
// sub-domain *( "." sub-domain )」+rfc5321bis L2460「sub-domain = Let-dig [Ldh-str]」）。
func TestIsValidDKIMSelector(t *testing.T) {
	valid := []string{
		"grmail", "default", "s1024", "x",
		"march2005.reykjavik", // rfc6376 §3.6.1 点分隔组件先例原文（"march2005.reykjavik"）
		"a-b-c", "a1-b2.c3",
	}
	for _, s := range valid {
		if !isValidDKIMSelector(s) {
			t.Fatalf("合法 selector 被拒: %q", s)
		}
	}
	invalid := []string{
		"",                // 空
		"Grmail",          // 大写（Let-dig 小写值域外）
		"-lead", "trail-", // 首尾连字符（Ldh-str 首尾必须 Let-dig）
		"under_score", "a b", // 下划线/空格
		".lead", "trail.", // 空段（点分隔首尾）
		"double..dot",           // 连续点空段
		strings.Repeat("a", 64), // 单标签 >63（DNS 单标签上限）
	}
	for _, s := range invalid {
		if isValidDKIMSelector(s) {
			t.Fatalf("非法 selector 通过: %q", s)
		}
	}
}

// ───────────────────────── 环境构造（完成态+已生成键） ─────────────────────────

// newDKIMManageEnv 完成态环境＋已生成 DKIM 键（ed25519 预置——生成快；selector=grmail）。
// 私钥真实落盘 tempdir（公钥呈现/重新生成覆盖链全真）。
func newDKIMManageEnv(t *testing.T) *u10Env {
	t.Helper()
	cfg := config.Default()
	cfg.SetupCompleted = true
	env := newU10Env(t, cfg)
	privPEM, _, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatalf("预置私钥生成: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatalf("预置私钥落盘: %v", err)
	}
	env.mu.Lock()
	env.cfg.Auth.DKIM = config.DKIMConf{Selector: "grmail", KeyPath: keyPath, Algorithm: "ed25519-sha256"}
	env.mu.Unlock()
	return env
}

// dkimGetBody 带 admin 会话 GET 并读全文（历批 io.ReadAll 形态——get 辅助关闭 Body 不复用）。
func dkimGetBody(t *testing.T, env *u10Env, path string, cookie *http.Cookie) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.ts.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("执行请求: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// dkimCfgLocked 加锁读当前配置快照字段（DKIMConf 拷贝）。
func dkimCfgLocked(env *u10Env) config.DKIMConf {
	env.mu.Lock()
	defer env.mu.Unlock()
	return env.cfg.Auth.DKIM
}

// ───────────────────────── 用例组 2：重新生成端点（E-1-A——二次确认强制+生成链） ─────────────────────────

// TestDKIMRegenRequiresConfirm 二次确认强制（服务端防线——未勾选拒绝+零副作用）与强度值域。
func TestDKIMRegenRequiresConfirm(t *testing.T) {
	env := newDKIMManageEnv(t)
	cookie := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-dk")
	// 未勾选确认：200 重渲染拒绝（配置与私钥文件零变化）
	form := url.Values{"csrf_token": {"csrf-dk"}, "dkimStrength": {"rsa-2048"}}
	if resp := postForm(t, env.ts, "/admin/settings/dkim/regen", form, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("未勾选确认应 200 拒绝，得 %d", resp.StatusCode)
	}
	dkim := dkimCfgLocked(env)
	if dkim.Algorithm != "ed25519-sha256" {
		t.Fatalf("未确认不应改配置，得 %s", dkim.Algorithm)
	}
	if _, err := os.Stat(dkim.KeyPath); err != nil {
		t.Fatalf("预置私钥应在位: %v", err)
	}
	// 勾选但强度非法：拒绝
	form2 := url.Values{"csrf_token": {"csrf-dk"}, "dkimConfirm": {"on"}, "dkimStrength": {"rsa-512"}}
	if resp := postForm(t, env.ts, "/admin/settings/dkim/regen", form2, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("非法强度应 200 拒绝，得 %d", resp.StatusCode)
	}
}

// TestDKIMRegenGeneratesAndSwaps 生成链端到端：勾选+合法强度→303 ?regen=1+私钥覆盖落盘
// +config.Algorithm 回写（selector/keyPath 保持现值——E-1-A 语义锚）。
func TestDKIMRegenGeneratesAndSwaps(t *testing.T) {
	env := newDKIMManageEnv(t)
	cookie := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-dk")
	before := dkimCfgLocked(env)
	form := url.Values{"csrf_token": {"csrf-dk"}, "dkimConfirm": {"on"}, "dkimStrength": {"rsa-2048"}}
	resp := postForm(t, env.ts, "/admin/settings/dkim/regen", form, cookie)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin/settings?regen=1" {
		t.Fatalf("重新生成应 303 ?regen=1，得 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	after := dkimCfgLocked(env)
	if after.Algorithm != "rsa-sha256" {
		t.Fatalf("algorithm 应回写 rsa-sha256，得 %s", after.Algorithm)
	}
	if after.Selector != before.Selector || after.KeyPath != before.KeyPath {
		t.Fatalf("selector/keyPath 应保持现值: %+v vs %+v", after, before)
	}
	// 私钥文件被新 RSA 键覆盖（PEM 可读——新算法与文件内容一致）
	data, err := os.ReadFile(after.KeyPath)
	if err != nil || !strings.Contains(string(data), "PRIVATE KEY") {
		t.Fatalf("新私钥应覆盖落盘: err=%v", err)
	}
}

// ───────────────────────── 用例组 3：向导 selector（E-2-A 乙·即时落盘） ─────────────────────────

// TestSetupDomainSelectorPersists 已生成态不勾重新生成时 selector 提交即落盘（乙形态锚）
// +缺省 grmail 零变化+非法值拒绝。
func TestSetupDomainSelectorPersists(t *testing.T) {
	cfg := config.Default()
	cfg.SetupCompleted = false // 引导态（向导可达）
	env := newU10Env(t, cfg)
	privPEM, _, _, err := auth.GenerateDKIMKeyPair("ed25519")
	if err != nil {
		t.Fatalf("预置私钥生成: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatalf("预置私钥落盘: %v", err)
	}
	env.mu.Lock()
	env.cfg.Auth.DKIM = config.DKIMConf{Selector: "grmail", KeyPath: keyPath, Algorithm: "ed25519-sha256"}
	env.mu.Unlock()

	// ①已生成态改 selector（不勾 regen）→即时落盘；keyPath/algorithm 沿用
	form := url.Values{"domain": {"mail.example.org"}, "dkimSelector": {"default"}}
	if resp := postForm(t, env.ts, "/setup/domain", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("步 3 应 303，得 %d", resp.StatusCode)
	}
	env.mu.Lock()
	dkim := env.cfg.Auth.DKIM
	env.mu.Unlock()
	if dkim.Selector != "default" {
		t.Fatalf("乙形态即时落盘锚：selector 应 default，得 %s", dkim.Selector)
	}
	if dkim.KeyPath != keyPath || dkim.Algorithm != "ed25519-sha256" {
		t.Fatalf("沿用既有键应不变: %+v", dkim)
	}

	// ②缺省：不填 → grmail（零变化锚——向导占位符批裁决二a 缺省形态保持）
	form2 := url.Values{"domain": {"mail.example.org"}}
	if resp := postForm(t, env.ts, "/setup/domain", form2); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("缺省提交应 303，得 %d", resp.StatusCode)
	}
	if dkim := dkimCfgLocked(env); dkim.Selector != "grmail" {
		t.Fatalf("缺省应 grmail，得 %s", dkim.Selector)
	}

	// ③非法值：拒绝重渲染（不落盘）
	form3 := url.Values{"domain": {"mail.example.org"}, "dkimSelector": {"-bad"}}
	if resp := postForm(t, env.ts, "/setup/domain", form3); resp.StatusCode != http.StatusOK {
		t.Fatalf("非法 selector 应 200 拒绝，得 %d", resp.StatusCode)
	}
	if dkim := dkimCfgLocked(env); dkim.Selector != "grmail" {
		t.Fatalf("非法值不应落盘，得 %s", dkim.Selector)
	}
}

// ───────────────────────── 用例组 4：设置页公钥呈现（E-3-A） ─────────────────────────

// TestSettingsDKIMPublicKeyShown 公钥 TXT 三元呈现（记录名+TXT 值——完成态再查看）
// 与不可读态错误提示行（原静默态暴露锚）。
func TestSettingsDKIMPublicKeyShown(t *testing.T) {
	env := newDKIMManageEnv(t)
	cookie := env.u10Session(t, storage.SubjectTypeAdmin, 1, "csrf-dk")

	// ①正常态：DKIM TXT 行呈现（记录名 grmail._domainkey.<主域> + v=DKIM1 前缀值）
	code, body := dkimGetBody(t, env, "/admin/settings", cookie)
	if code != http.StatusOK {
		t.Fatalf("设置页应 200，得 %d", code)
	}
	domain := func() string { env.mu.Lock(); defer env.mu.Unlock(); return env.cfg.Server.Domain }()
	wantName := "grmail._domainkey." + domain
	if !strings.Contains(body, wantName) {
		t.Fatalf("呈现应含 DKIM 记录名 %q", wantName)
	}
	if !strings.Contains(body, "v=DKIM1; k=ed25519; p=") {
		t.Fatalf("呈现应含 DKIM TXT 值前缀（v=DKIM1; k=ed25519; p=…）")
	}

	// ②不可读态：keyPath 指向丢失文件→错误提示行（原静默——配置缺陷当场暴露）
	env.mu.Lock()
	env.cfg.Auth.DKIM.KeyPath = filepath.Join(t.TempDir(), "missing.pem")
	env.mu.Unlock()
	code2, body2 := dkimGetBody(t, env, "/admin/settings", cookie)
	if code2 != http.StatusOK {
		t.Fatalf("不可读态设置页应 200，得 %d", code2)
	}
	if !strings.Contains(body2, "DKIM 私钥文件不可读") {
		t.Fatalf("不可读态应呈现错误提示行（zh 键）")
	}
}
