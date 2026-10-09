// B-S安全域批 F12 新用例（计划书 v2.0.0 步骤 4 检查点承载）——DMARC 值域校验。
// 依据：rfc9989 4.7 tag-value 语法（非法值按语法坏丢弃——queryLevel :149 既有路径；
// 原静默按缺省 r 用为 fail-open）。
// 修改历史：
//
//	2026-10-09 16:56:00 | 新增 | B-S安全域批（G2 批准 2026-10-09 13:37:42）
package dmarc

import "testing"

// TestBSF12AlignmentValueDomain adkim/aspf 值域 s|r（越界按解析错误→记录语法坏丢弃）。
func TestBSF12AlignmentValueDomain(t *testing.T) {
	for _, bad := range []string{
		"v=DMARC1; p=none; adkim=x",
		"v=DMARC1; p=none; aspf=q",
		"v=DMARC1; p=none; adkim=",
	} {
		if _, err := ParseRecord(bad); err == nil {
			t.Fatalf("非法对齐模式应按语法坏拒绝: %q", bad)
		}
	}
	for _, ok := range []string{
		"v=DMARC1; p=none; adkim=s; aspf=r",
		"v=DMARC1; p=none; adkim=S", // 值大小写归一（ToLower 后域内判定）
	} {
		if _, err := ParseRecord(ok); err != nil {
			t.Fatalf("合法对齐模式不应拒绝: %q err=%v", ok, err)
		}
	}
}

// TestBSF12PctValueDomain pct 值域 0-100（负数/>100 按解析错误）。
func TestBSF12PctValueDomain(t *testing.T) {
	for _, bad := range []string{
		"v=DMARC1; p=none; pct=101",
		"v=DMARC1; p=none; pct=200",
		"v=DMARC1; p=none; pct=-1",
	} {
		if _, err := ParseRecord(bad); err == nil {
			t.Fatalf("pct 越界应按语法坏拒绝: %q", bad)
		}
	}
	for _, ok := range []string{"v=DMARC1; p=none; pct=0", "v=DMARC1; p=none; pct=100"} {
		if _, err := ParseRecord(ok); err != nil {
			t.Fatalf("pct 边界值不应拒绝: %q err=%v", ok, err)
		}
	}
}
