// GRmail Web 插件管理只读状态页（Webmail管理职能批次 G6——D7 缺陷收口；S3-W Q3-A 裁决：
// 只读呈现，零进程管理扩展——启停控制超出 FR-016 判定面）。
// 数据链：plugin.Supervisor.StatusSnapshot()（plugin 包自有结构）→ main 装配桥接适配器
// 转换 web.PluginStatus（中性接口——web 零 plugin import，沿 ChallengeLookup/STSPolicy 先例）。
// 依据：Webmail管理职能计划书 v1.0.0 1.2 G6（G2 批准 2026-10-05 15:15:22）；SRS FR-016。
// 修改历史：
//
//	2026-10-05 15:20:00 | 新建 | Webmail管理职能批次（计划书阶段 6，G2 批准 2026-10-05 15:15:22）
package web

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"GRmail/web/templates"
)

// PluginStatus 单插件状态呈现行（中性结构——main 装配桥接 plugin.StatusRow 转换；
// web 域不 import plugin 包，架构第四章依赖方向保持）。
type PluginStatus struct {
	Name    string   // GetInfo 插件名
	Version string   // GetInfo 版本声明
	Caps    []string // 能力声明（inbound_hook/submit_hook/protocol）
	Alive   bool     // 运行态（false=崩溃摘除——重启主程序恢复）
}

// PluginStatusSource 插件状态只读供给（G6——/admin/plugins 数据源；
// nil 注入=端点 503 渐进态，沿 TwoFactor/Tokens nil 语义先例）。
type PluginStatusSource interface {
	// PluginStatuses 返回全部托管插件状态快照（零插件=空切片）。
	PluginStatuses() []PluginStatus
}

// adminPluginsGET 插件状态页（GET /admin/plugins——admin 门卫沿 admin.go 形态；
// 呈现：名称/版本/能力/运行状态；空态引导文案——放置插件二进制后重启生效）。
func (s *Server) adminPluginsGET(c *gin.Context) {
	if !s.adminGuard(c) {
		return
	}
	if s.plugins == nil {
		c.Status(http.StatusServiceUnavailable) // 渐进态（未注入——测试/裁剪部署形态）
		return
	}
	// 桥接转换：web 中性结构 → templates 视图模型（单向依赖 web→templates）
	statuses := s.plugins.PluginStatuses()
	rows := make([]templates.PluginRow, 0, len(statuses))
	for _, p := range statuses {
		rows = append(rows, templates.PluginRow{Name: p.Name, Version: p.Version, Caps: p.Caps, Alive: p.Alive})
	}
	renderPage(c, http.StatusOK, templates.PluginsView(templates.PluginsData{
		Lang:    string(langOf(c)),
		Nav:     s.sidebarDataFor(c),
		Plugins: rows,
	}))
}
