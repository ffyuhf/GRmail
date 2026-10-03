// dmarc 自研包测试（NFR-015：stub DNS 离线驱动；rfc9989 4.10/4.10.1/4.10.2 语义锚定）。
// 修改历史：
//
//	2026-09-17 02:54:00 | 新建 | U3 auth 基础（计划书步骤 8）
package dmarc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// txtStub DMARC TXT 解析 stub（错误分类：temp 域→ErrTemporary；miss→ErrNoRecord 由
// 包内错误映射约定——LookupTXT 返回非 ErrTemporary 错误即视为无记录）。
type txtStub struct {
	mu      sync.Mutex
	txts    map[string][]string
	temp    map[string]bool
	queries []string
}

func newTxtStub() *txtStub {
	return &txtStub{txts: map[string][]string{}, temp: map[string]bool{}}
}

func (s *txtStub) with(name string, records ...string) *txtStub {
	s.txts[name] = records
	return s
}

func (s *txtStub) withTemp(name string) *txtStub {
	s.temp[name] = true
	return s
}

func (s *txtStub) queryLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// LookupTXT name 已含 _dmarc 前缀（Discover/OrganizationalDomain 拼名后调用）。
func (s *txtStub) LookupTXT(_ context.Context, name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, name)
	if s.temp[name] {
		return nil, ErrTemporary
	}
	recs, ok := s.txts[name]
	if !ok {
		return nil, fmt.Errorf("nxdomain: %s", name) // 非 ErrTemporary → 按「无记录」处理
	}
	return recs, nil
}

// ───────────────────────── ParseRecord ─────────────────────────

// TestParseRecordFull 合法全标签解析（含 DMARCbis 新标签 np/psd；未知标签忽略）
func TestParseRecordFull(t *testing.T) {
	rec, err := ParseRecord("v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=r; pct=25; rua=mailto:agg@example.com; psd=n; unknown-tag=xyz")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if rec.Policy != "reject" || rec.SubPolicy != "quarantine" || rec.NoPolicy != "none" {
		t.Fatalf("策略标签不符: %+v", rec)
	}
	if rec.ADKIM != "s" || rec.ASPF != "r" || rec.PSD != "n" || rec.Pct == nil || *rec.Pct != 25 {
		t.Fatalf("对齐/psd/pct 不符: %+v", rec)
	}
}

// TestParseRecordDefaults 缺省对齐模式 r（rfc9989 4.7：adkim/aspf OPTIONAL default r）
func TestParseRecordDefaults(t *testing.T) {
	rec, err := ParseRecord("v=DMARC1; p=none")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if rec.ADKIM != "r" || rec.ASPF != "r" || rec.PSD != "u" {
		t.Fatalf("缺省值不符: %+v", rec)
	}
}

// TestParseRecordErrors 非 DMARC 前缀/缺 p/坏标签/坏 pct
func TestParseRecordErrors(t *testing.T) {
	if _, err := ParseRecord("v=spf1 -all"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("非 DMARC 前缀应 ErrNoRecord: %v", err)
	}
	if _, err := ParseRecord("v=DMARC1"); err == nil {
		t.Fatal("缺 p= 应报错")
	}
	if _, err := ParseRecord("v=DMARC1; p=none; broken"); err == nil {
		t.Fatal("坏标签应报错")
	}
	if _, err := ParseRecord("v=DMARC1; p=none; pct=abc"); err == nil {
		t.Fatal("坏 pct 应报错")
	}
}

// ───────────────────────── Discover（4.10.1） ─────────────────────────

// TestDiscoverFirstHit 首查命中（Author Domain 自身记录即适用记录）
func TestDiscoverFirstHit(t *testing.T) {
	stub := newTxtStub().with("_dmarc.example.com", "v=DMARC1; p=none")
	disc, err := Discover(context.Background(), stub, "example.com")
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if disc.RecordDomain != "example.com" || disc.Record.Policy != "none" {
		t.Fatalf("发现产物不符: %+v", disc)
	}
}

// TestDiscoverWalkUp 子域未命中→上探父域命中（rfc9989 4.10 步骤 5-7）
func TestDiscoverWalkUp(t *testing.T) {
	stub := newTxtStub().with("_dmarc.example.com", "v=DMARC1; p=quarantine")
	disc, err := Discover(context.Background(), stub, "mail.example.com")
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if disc.RecordDomain != "example.com" {
		t.Fatalf("应上探命中 example.com: %+v", disc)
	}
}

// TestDiscoverNoRecord 全程无记录 → ErrNoRecord（4.10.1：不适用 DMARC）
func TestDiscoverNoRecord(t *testing.T) {
	stub := newTxtStub()
	if _, err := Discover(context.Background(), stub, "mail.example.com"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("应 ErrNoRecord: %v", err)
	}
}

// TestDiscoverMultipleRecordsDiscarded 同名多条 DMARC 记录全部丢弃后上探（4.10 步骤 2）
func TestDiscoverMultipleRecordsDiscarded(t *testing.T) {
	stub := newTxtStub().
		with("_dmarc.mail.example.com", "v=DMARC1; p=none", "v=DMARC1; p=reject"). // 两条→丢弃
		with("_dmarc.example.com", "v=DMARC1; p=quarantine")
	disc, err := Discover(context.Background(), stub, "mail.example.com")
	if err != nil {
		t.Fatalf("发现失败: %v", err)
	}
	if disc.RecordDomain != "example.com" || disc.Record.Policy != "quarantine" {
		t.Fatalf("多条丢弃后应上探父域: %+v", disc)
	}
}

// TestTreeWalkQueryCap 13 标签 Author Domain 的 Tree Walk 查询序列与 8 次上限
// （rfc9989 4.10 例：a.b.c.d.e.f.g.h.i.j.mail.example.com 全程恰 8 查询）
func TestTreeWalkQueryCap(t *testing.T) {
	stub := newTxtStub()
	if _, err := Discover(context.Background(), stub, "a.b.c.d.e.f.g.h.i.j.mail.example.com"); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("应 ErrNoRecord: %v", err)
	}
	want := []string{
		"_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com", // 首查（全名）
		"_dmarc.g.h.i.j.mail.example.com",             // 削至 7 标签（4.10 步骤 4）
		"_dmarc.h.i.j.mail.example.com",
		"_dmarc.i.j.mail.example.com",
		"_dmarc.j.mail.example.com",
		"_dmarc.mail.example.com",
		"_dmarc.example.com",
		"_dmarc.com",
	}
	got := stub.queryLog()
	if len(got) != 8 {
		t.Fatalf("查询数应恰 8（rfc9989 4.10 例证）: %d %v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("查询序列第 %d 项不符: got=%s want=%s", i, got[i], want[i])
		}
	}
}

// TestDiscoverTemporary 瞬时故障 → ErrTemporary（temperror 结论来源）
func TestDiscoverTemporary(t *testing.T) {
	stub := newTxtStub().withTemp("_dmarc.example.com")
	if _, err := Discover(context.Background(), stub, "example.com"); !errors.Is(err, ErrTemporary) {
		t.Fatalf("应 ErrTemporary: %v", err)
	}
}

// ───────────────────────── 组织域选择（4.10.2） ─────────────────────────

// TestOrgDomainPSDN psd=n 命中即组织域（规则①；例证：mail.example.com psd=n）
func TestOrgDomainPSDN(t *testing.T) {
	stub := newTxtStub().with("_dmarc.mail.example.com", "v=DMARC1; p=none; psd=n")
	org, err := OrganizationalDomain(context.Background(), stub, "a.mail.example.com")
	if err != nil {
		t.Fatalf("求组织域失败: %v", err)
	}
	if org != "mail.example.com" {
		t.Fatalf("psd=n 应即组织域: %s", org)
	}
}

// TestOrgDomainPSDY psd=y（非起点）→ PSD 上一标签域（规则②；rfc9989 4.10.2 例3：
// 起点 a.mail.example.com 命中 _dmarc.com psd=y → org=example.com）
func TestOrgDomainPSDY(t *testing.T) {
	stub := newTxtStub().with("_dmarc.com", "v=DMARC1; p=none; psd=y")
	org, err := OrganizationalDomain(context.Background(), stub, "a.mail.example.com")
	if err != nil {
		t.Fatalf("求组织域失败: %v", err)
	}
	if org != "example.com" {
		t.Fatalf("psd=y 规则②应得 example.com: %s", org)
	}
}

// TestOrgDomainPSDYClosest 规则②近距例（4.10.2 正文：起点 mail.example.com
// 命中 _dmarc.example.com psd=y → org=mail.example.com）
func TestOrgDomainPSDYClosest(t *testing.T) {
	stub := newTxtStub().with("_dmarc.example.com", "v=DMARC1; p=none; psd=y")
	org, err := OrganizationalDomain(context.Background(), stub, "mail.example.com")
	if err != nil {
		t.Fatalf("求组织域失败: %v", err)
	}
	if org != "mail.example.com" {
		t.Fatalf("psd=y 近距例应得 mail.example.com: %s", org)
	}
}

// TestOrgDomainFewestLabels 无 psd 命中→标签数最少者（规则③）
func TestOrgDomainFewestLabels(t *testing.T) {
	stub := newTxtStub().
		with("_dmarc.b.example.com", "v=DMARC1; p=none").
		with("_dmarc.example.com", "v=DMARC1; p=none")
	org, err := OrganizationalDomain(context.Background(), stub, "a.b.example.com")
	if err != nil {
		t.Fatalf("求组织域失败: %v", err)
	}
	if org != "example.com" {
		t.Fatalf("规则③应取标签最少的 example.com: %s", org)
	}
}

// TestOrgDomainNoHits 无任何命中→起点域自身（规则④）
func TestOrgDomainNoHits(t *testing.T) {
	stub := newTxtStub()
	org, err := OrganizationalDomain(context.Background(), stub, "mail.example.com")
	if err != nil {
		t.Fatalf("求组织域失败: %v", err)
	}
	if org != "mail.example.com" {
		t.Fatalf("规则④应回起点域: %s", org)
	}
}

// ───────────────────────── Evaluate ─────────────────────────

// TestEvaluateMatrix 判定矩阵：dkim 对齐 pass / spf 对齐 pass / 不对齐 fail / 无记录 none / 瞬时 temperror
func TestEvaluateMatrix(t *testing.T) {
	ctx := context.Background()
	base := func() *txtStub {
		return newTxtStub().with("_dmarc.example.com", "v=DMARC1; p=none")
	}
	cases := []struct {
		name    string
		stub    *txtStub
		sigs    []SigResult
		spfPass bool
		spfDom  string
		want    Result
	}{
		{"dkim 对齐 pass（relaxed 子域）", base(),
			[]SigResult{{Domain: "mail.example.com", Pass: true}}, false, "", ResultPass},
		{"spf 对齐 pass", base(),
			nil, true, "mail.example.com", ResultPass},
		{"dkim pass 但不对齐 → fail", base(),
			[]SigResult{{Domain: "other.example.net", Pass: true}}, false, "", ResultFail},
		{"无对齐通过项 → fail", base(),
			[]SigResult{{Domain: "mail.example.com", Pass: false}}, true, "other.net", ResultFail},
		{"无 DMARC 记录 → none", newTxtStub(),
			[]SigResult{{Domain: "example.com", Pass: true}}, true, "example.com", ResultNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, _ := Evaluate(ctx, c.stub, "example.com", c.sigs, c.spfPass, c.spfDom)
			if got != c.want {
				t.Fatalf("判定不符: got=%s want=%s", got, c.want)
			}
		})
	}
}

// TestEvaluateStrictAlignment adkim=s 严格对齐：子域签名 pass 但不精确相等 → fail
func TestEvaluateStrictAlignment(t *testing.T) {
	stub := newTxtStub().with("_dmarc.example.com", "v=DMARC1; p=none; adkim=s")
	got, _, _ := Evaluate(context.Background(), stub, "example.com",
		[]SigResult{{Domain: "mail.example.com", Pass: true}}, false, "")
	if got != ResultFail {
		t.Fatalf("strict 模式子域签名应 fail: %s", got)
	}
}

// TestEvaluateTemporary 策略发现瞬时故障 → temperror（rfc9989 4.10.1 尾段定档）
func TestEvaluateTemporary(t *testing.T) {
	stub := newTxtStub().withTemp("_dmarc.example.com")
	got, _, _ := Evaluate(context.Background(), stub, "example.com", nil, false, "")
	if got != ResultTemperror {
		t.Fatalf("应 temperror: %s", got)
	}
}
