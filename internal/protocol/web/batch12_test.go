// 快赢清单批 web 侧测试（计划书 v1.0.1 第三章步骤 2~6 验收锚）。
// K-1 时间列等宽数字（tabular-nums）/K-2 双曲线差异化（emphasized 进入+exit
// 出向——报告 5.5 违例③+5.10 M7）/K-3 徽标前景加深（4.53:1 零余量收口）/
// K-5 sidebar 全站 sticky（干系人指令替换原限宽项——差异裁决 A）。
// 静态结构锚（CSS 源文件断言——沿 batch11 先例；浏览器渲染行为属干系人实机域）。
// 依据：快赢清单批_计划_20261016_17-16-00_v1.0.0.md 6.1（G2 批准 2026-10-16
// 17:36——K-1 A/K-2 A/K-3 A/K-4 B 登记〔零代码无锚〕/K-5 全站 sticky）。
package web

import (
	"os"
	"strings"
	"testing"
)

// TestBatch12StaticAnchors 快赢四项静态锚（K-1/K-2/K-3/K-5——源文件断言）。
func TestBatch12StaticAnchors(t *testing.T) {
	b, err := os.ReadFile("../../../web/static/app.css")
	if err != nil {
		t.Fatalf("读 app.css: %v", err)
	}
	css := string(b)

	// K-1（裁决 A 仅时间列）：td.time-cell 等宽数字。
	if !strings.Contains(css, "td.time-cell { white-space: nowrap; font-size: var(--text-caption); color: var(--fg-secondary); font-variant-numeric: tabular-nums; }") {
		t.Fatal("K-1 时间列 tabular-nums 缺失")
	}
	// K-2（裁决 A 双曲线差异化）：两新令牌在位。
	if !strings.Contains(css, "--ease-emphasized: cubic-bezier(0.2, 0, 0, 1);") {
		t.Fatal("K-2 --ease-emphasized 令牌缺失")
	}
	if !strings.Contains(css, "--ease-exit: cubic-bezier(0.4, 0, 1, 1);") {
		t.Fatal("K-2 --ease-exit 令牌缺失")
	}
	// K-2：进入消费点分派 emphasized（六处——卡片 grow/菜单/提示条 slide-up×2/
	// 详情 grow/compose grow；抽屉进入在移动档媒体查询内）。
	enterCount := strings.Count(css, "var(--ease-emphasized)")
	if enterCount < 7 {
		t.Fatalf("K-2 emphasized 消费点不足（实际 %d 处，期望 ≥7——六进入+抽屉进入）", enterCount)
	}
	// K-2：出向消费点改绑 exit（抽屉收起 margin/width 两属性行）。
	if !strings.Contains(css, "transition: margin-left var(--dur-drawer-out) var(--ease-exit)") {
		t.Fatal("K-2 抽屉收得出向 exit 曲线缺失")
	}
	// K-2：--ease-out 定义保留（零消费登记——死类登记池先例）。
	if !strings.Contains(css, "--ease-out: cubic-bezier(0, 0, 0.2, 1);") {
		t.Fatal("K-2 --ease-out 定义应保留（零消费登记口径）")
	}
	// K-3（裁决 A 点名单点）：亮档 warn 前景 #8d6e00→#7a6000（≥5:1 有余量）。
	if !strings.Contains(css, "--badge-warn-bg: var(--warning-soft); --badge-warn-fg: #7a6000;") {
		t.Fatal("K-3 warn 徽标前景 #7a6000 加深缺失")
	}
	if strings.Contains(css, "--badge-warn-fg: #8d6e00") {
		t.Fatal("K-3 旧值 #8d6e00 应已替换（零残留）")
	}
	// K-3：暗档 #ffe082 零触碰。
	if !strings.Contains(css, "--badge-warn-bg: #3d3340; --badge-warn-fg: #ffe082;") {
		t.Fatal("K-3 暗档 warn 前景 #ffe082 应保持零触碰")
	}
	// K-5（差异裁决 A 全站 sticky）：sticky 声明组四要素。
	if !strings.Contains(css, "position: sticky;") {
		t.Fatal("K-5 sidebar position:sticky 缺失")
	}
	if !strings.Contains(css, "top: var(--topbar-h);") {
		t.Fatal("K-5 sidebar top=应用栏下沿缺失")
	}
	if !strings.Contains(css, "height: calc(100vh - var(--topbar-h));") {
		t.Fatal("K-5 sidebar 视口高缺失")
	}
	if !strings.Contains(css, "align-self: flex-start;") {
		t.Fatal("K-5 sidebar align-self:flex-start（sticky 生效前提）缺失")
	}
	// K-5：移动档浮层抽屉 fixed 覆盖在位（<768 媒体查询内）。
	if !strings.Contains(css, "\tposition: fixed;\n\t\ttop: var(--topbar-h);") {
		t.Fatal("K-5 移动档 fixed 覆盖应保持（浮层抽屉形态零变化）")
	}
	// K-5 伴随锚：A-5 border-box 保持（batch11 锚不破坏）。
	if !strings.Contains(css, "box-sizing: border-box;") {
		t.Fatal("K-5 A-5 border-box 伴同声明应保持")
	}
}
