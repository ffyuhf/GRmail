// U22 富文本高级特性构造侧回归测试（NFR-015 全离线——纯函数直驱）。
// 覆盖：htmlToPlain 对 U22 新增控件标签的派生矩阵——行内标签（span 色彩/字号/字体
// class 与 style 形态、u/s）、块级样式属性（p 带 text-align/ql-indent 类）经既有
// 剥离路径产出可读纯文本零适配（构造层 compose_build.go 零触碰锚——计划书 1.5④）。
// 依据：U22 计划书 v1.0.0 步骤 4/1.5④（Quill 2.0.3 控件产出标签形态：color/
// background/size/font→span（class ql-* 或 style）；align/indent→p（style/class）；
// underline→u；strike→s——源码 Attributor 形态推导）。
// 修改历史：
//
//	2026-09-27 11:06:00 | 新建 | U22 富文本高级特性（计划书步骤 4，G2 批准 2026-09-27 10:38:20）
package mail

import (
	"strings"
	"testing"
)

// TestU22HtmlToPlainInlineTags 新控件标签矩阵：span/u/s 行内剥离+p 样式/类块级换行
// ——无标签残留、无 style/class 泄漏、可读纯文本产出。
func TestU22HtmlToPlainInlineTags(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"色彩 span 剥离", `<p>彩色<span style="color:#dc2626">红字</span>续文</p>`, "彩色红字续文"},
		{"背景 span 剥离", `<p><span style="background-color:#ffff00">高亮</span>段</p>`, "高亮段"},
		{"字号类 span", `<p><span class="ql-size-large">大字</span>普通</p>`, "大字普通"},
		{"字体类 span", `<p><span class="ql-font-serif">衬线</span>正文</p>`, "衬线正文"},
		{"行内 u/s 标签", `<p><u>下划线</u>与<s>删除线</s></p>`, "下划线与删除线"},
		{"对齐样式 p", `<p style="text-align:center">居中段</p><p>后续段</p>`, "居中段\n\n后续段"},
		{"缩进类 p", `<p class="ql-indent-2">缩进段</p>`, "缩进段"},
		{"对齐类 p（Quill blot 实际产出 class 形态）", `<p class="ql-align-center">居中段</p><p>左段</p>`, "居中段\n\n左段"},
		{"组合形态", `<p class="ql-align-center"><span class="ql-size-huge" style="color:#2563eb">标题字</span></p><p><br></p><p>正文</p>`, "标题字\n\n正文"},
	}
	for _, c := range cases {
		got := htmlToPlain(c.in)
		if got != c.want {
			t.Fatalf("%s: htmlToPlain(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		// 零残留锚：产出不得含尖括号（标签/style/class 泄漏）
		if strings.ContainsAny(got, "<>") {
			t.Fatalf("%s: 产出含标签残留: %q", c.name, got)
		}
	}
	// 病态属性值含尖括号（属性值内 > 早于真闭合）——至首个 > 截断（尽力语义：
	// 属性残段容错产出可读主体，与剥离循环同口径——独立断言不适用零残留锚）
	if got := htmlToPlain(`<p class="a>b">容错段</p>`); got != `b">容错段` {
		t.Fatalf("病态属性截断: got %q", got)
	}
}

// TestU22BuildOutgoingRichControlsAlternative 新控件富文本经构造层：alternative
// 双 part 递增序保持（构造层零触碰回归锚——plain part 为新标签剥离派生）。
func TestU22BuildOutgoingRichControlsAlternative(t *testing.T) {
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "控件主题", "",
		`<p class="ql-align-center"><span style="color:#dc2626" class="ql-size-large">居中大字</span></p>`, nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s := string(raw)
	plainIdx := strings.Index(s, "Content-Type: text/plain; charset=utf-8")
	htmlIdx := strings.Index(s, "Content-Type: text/html; charset=utf-8")
	if plainIdx < 0 || htmlIdx < 0 || plainIdx > htmlIdx {
		t.Fatalf("alternative 递增序破坏（plain=%d html=%d）", plainIdx, htmlIdx)
	}
	if !strings.Contains(s, "居中大字") {
		t.Fatalf("派生纯文本缺失（新标签剥离产出）")
	}
	if !strings.Contains(s, `style="color:#dc2626"`) {
		t.Fatalf("html 原文 part 应保留控件样式原文")
	}
}
