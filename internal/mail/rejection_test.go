// 两项变更实施批测试（SRS v1.2.0 FR-008 判定③/FR-009/TC-029 拒收档位矩阵——
// G2 批准 2026-10-17 03:37「E-1 A / E-2 B / E-3 A」；S5-REV-20261017-001）。
// 覆盖锚点：TC-029 拒收档位矩阵（SPF fail/softfail/none×软硬+DKIM 失败/无签名×软硬+
// temperror/permerror/空路径/开关关闭豁免格+档位热生效时序格）；FR-004 判定①承载
// （聚合可见/零通知——断言意图锚随 TC-004 v1.2.0 判定更新）。
// 修改历史：
//
//	2026-10-17 03:55:00 | 新建 | 两项变更实施批（计划书步骤 6）
package mail

import (
	"context"
	"testing"

	"GRmail/internal/auth"
	"GRmail/internal/config"
)

// ───────────────────────── TC-029 拒收档位矩阵（纯函数逐格） ─────────────────────────

// rejectionTestCase 拒收矩阵单格输入（纯函数形态——零网络端点 NFR-015）。
type rejectionTestCase struct {
	name        string
	spf         string // 验证结论（""=未启用项不判定）
	dkim        string
	spfEnabled  bool
	dkimEnabled bool
	spfPolicy   string // soft|hard
	dkimPolicy  string
	mailFrom    string // 空=空路径豁免
	wantReject  bool   // 期望拒收
	wantReason  string // 期望原因子串（拒收时）
}

func TestRejectionPolicyMatrix(t *testing.T) {
	// 档位矩阵逐格（TC-029 判定方法——拒收=5xx+零落库；照收=250+A-R 标注）
	cases := []rejectionTestCase{
		// ── SPF 软档（fail 拒收；softfail/none/permerror/temperror 照收）──
		{name: "SPF软档-fail-拒收", spf: "fail", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: true, wantReason: "SPF fail 拒收（档位=soft）"},
		{name: "SPF软档-softfail-照收", spf: "softfail", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "SPF软档-none-照收", spf: "none", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "SPF软档-permerror-照收（G1 Q1 裁决）", spf: "permerror", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "SPF软档-temperror-照收", spf: "temperror", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		// ── SPF 硬档（fail+softfail 拒收；none/permerror/temperror 照收）──
		{name: "SPF硬档-fail-拒收", spf: "fail", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: true, wantReason: "SPF fail 拒收（档位=hard）"},
		{name: "SPF硬档-softfail-拒收", spf: "softfail", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: true, wantReason: "SPF softfail 拒收（档位=硬）"},
		{name: "SPF硬档-none-照收", spf: "none", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "SPF硬档-permerror-照收（G1 Q1 裁决）", spf: "permerror", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "SPF硬档-temperror-照收", spf: "temperror", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		// ── DKIM 软档（有签名验证失败拒收；无签名照收）──
		{name: "DKIM软档-fail-拒收", spf: "pass", dkim: "fail", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: true, wantReason: "DKIM 验证失败拒收（档位=soft）"},
		{name: "DKIM软档-none-照收", spf: "pass", dkim: "none", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "DKIM软档-temperror-照收", spf: "pass", dkim: "temperror", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		// ── DKIM 硬档（无签名亦拒收）──
		{name: "DKIM硬档-fail-拒收", spf: "pass", dkim: "fail", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "hard", mailFrom: "a@b.io", wantReject: true, wantReason: "DKIM 验证失败拒收（档位=hard）"},
		{name: "DKIM硬档-none-拒收", spf: "pass", dkim: "none", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "hard", mailFrom: "a@b.io", wantReject: true, wantReason: "DKIM 无签名拒收（档位=硬）"},
		{name: "DKIM硬档-temperror-照收", spf: "pass", dkim: "temperror", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "hard", mailFrom: "a@b.io", wantReject: false},
		// ── 开关关闭豁免（未启用项不判定）──
		{name: "SPF关闭-fail-照收（未启用项不判定）", spf: "fail", dkim: "pass", spfEnabled: false, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		{name: "DKIM关闭-fail-照收（未启用项不判定）", spf: "pass", dkim: "fail", spfEnabled: true, dkimEnabled: false, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
		// ── 空路径豁免（退信防丢——澄清答复 02:05）──
		{name: "空路径-SPF-fail-照收（退信豁免）", spf: "fail", dkim: "pass", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "hard", mailFrom: "", wantReject: false},
		{name: "空路径-DKIM-fail-照收（退信豁免）", spf: "pass", dkim: "fail", spfEnabled: true, dkimEnabled: true, spfPolicy: "hard", dkimPolicy: "hard", mailFrom: "", wantReject: false},
		// ── 未注入=现状等价（E-1-A 渐进部署锚）──
		{name: "未注入-全fail-照收（现状等价）", spf: "fail", dkim: "fail", spfEnabled: true, dkimEnabled: true, spfPolicy: "soft", dkimPolicy: "soft", mailFrom: "a@b.io", wantReject: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, _ := newTestPipeline()
			if tc.name != "未注入-全fail-照收（现状等价）" {
				svc.SetRejectionPolicy(func() config.AuthStack {
					return config.AuthStack{
						SPFEnabled: tc.spfEnabled, DKIMEnabled: tc.dkimEnabled,
						SPFPolicy: tc.spfPolicy, DKIMPolicy: tc.dkimPolicy,
					}
				})
			}
			res := &auth.VerifyResults{SPF: tc.spf, DKIM: tc.dkim, DMARC: "none", ARC: "none"}
			in := testDelivery("x@test.example")
			in.Envelope.MailFrom = tc.mailFrom
			// DMARC处置实施批适配：checkRejectionPolicy 增 raw 参数（私有签名机械适配——
			// 断言语义零变化；矩阵用例 DMARCDisposition 零值=不分派，TC-029 格行为零影响）
			err := svc.checkRejectionPolicy(context.Background(), in, res, sampleRaw())
			if tc.wantReject {
				if err == nil {
					t.Fatalf("应拒收: %+v", tc)
				}
				rej, ok := err.(*RejectPolicyError)
				if !ok {
					t.Fatalf("应返回 RejectPolicyError: %T %v", err, err)
				}
				if rej.Code != 550 {
					t.Fatalf("应答码应 550: %d", rej.Code)
				}
				if tc.wantReason != "" && !contains(rej.Reason, tc.wantReason) {
					t.Fatalf("原因子串不符: got %q want %q", rej.Reason, tc.wantReason)
				}
			} else {
				if err != nil {
					t.Fatalf("应照收: %v", err)
				}
			}
		})
	}
}

// contains 子串包含判定（strings.Contains 简化——测试辅助）。
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// ───────────────────────── 档位热生效时序格（TC-029） ─────────────────────────

// TestRejectionPolicyHotReload 档位切换后下一封来信行为即时变化（TC-029 热生效格——
// 切换→立即投递→行为变化；快照函数每调用读取=config 热加载语义锚）。
func TestRejectionPolicyHotReload(t *testing.T) {
	svc, _, _, _ := newTestPipeline()
	policy := "soft"
	svc.SetRejectionPolicy(func() config.AuthStack {
		return config.AuthStack{SPFEnabled: true, DKIMEnabled: true, SPFPolicy: policy, DKIMPolicy: "soft"}
	})
	res := &auth.VerifyResults{SPF: "softfail", DKIM: "pass", DMARC: "none", ARC: "none"}
	in := testDelivery("x@test.example")

	// 软档：softfail 照收（raw 参数为 DMARC处置实施批签名适配——机械传递）
	if err := svc.checkRejectionPolicy(context.Background(), in, res, sampleRaw()); err != nil {
		t.Fatalf("软档 softfail 应照收: %v", err)
	}
	// 切换硬档→立即生效（无重启）
	policy = "hard"
	err := svc.checkRejectionPolicy(context.Background(), in, res, sampleRaw())
	if err == nil {
		t.Fatal("硬档 softfail 应拒收（热生效——切换后下一封行为变化）")
	}
	rej, ok := err.(*RejectPolicyError)
	if !ok || rej.Code != 550 {
		t.Fatalf("应 550 拒收: %T %v", err, err)
	}
	// 切回软档→恢复照收
	policy = "soft"
	if err := svc.checkRejectionPolicy(context.Background(), in, res, sampleRaw()); err != nil {
		t.Fatalf("切回软档应恢复照收: %v", err)
	}
}

// ───────────────────────── FR-004 判定①承载（TC-004 v1.2.0） ─────────────────────────

// TestDeliverNoShadowNoticeAggregateOnly 影子建立零通知+聚合副本承载（TC-004 v1.2.0
// 判定①：postmaster 收件箱无「新影子邮箱」通知行；聚合文件夹含该邮件副本行——
// 通知链删除后语义锚：Notice 字段已删除〔编译期〕，聚合副本 target 为唯一感知面）。
func TestDeliverNoShadowNoticeAggregateOnly(t *testing.T) {
	svc, _, accounts, store := newTestPipeline()

	if err := svc.Deliver(context.Background(), testDelivery("newguy@test.example"), sampleRaw()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	meta := store.saved[0]
	// 零通知邮件（Notice 字段已删除——编译期锚）；聚合副本 target 在位
	var aggCount int
	for _, r := range meta.Recipients {
		if r.Aggregate {
			aggCount++
		}
	}
	if aggCount != 1 {
		t.Fatalf("聚合副本目标应恰 1（TC-004 v1.2.0 判定①聚合可见承载）: %+v", meta.Recipients)
	}
	// 影子建立保持（FR-004 判定②——自动建立/归档/注册激活继承）
	if len(accounts.Created) != 2 || accounts.Created[0] != "newguy@test.example" || accounts.Created[1] != "postmaster@test.example" {
		t.Fatalf("影子建立序列错（newguy+postmaster 聚合承载）: %v", accounts.Created)
	}
}
