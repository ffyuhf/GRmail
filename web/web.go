// Package web 静态资源内嵌载体（U9：web/static/ 位于本包目录——embed 仅可嵌包内路径）。
// 依据：CON-001（Web 资源全部 embed 单二进制——Q7）；Q2-B 裁决 2026-09-19 01:52:04
// （静态资源 embed 通道启用，HTMX.js vendor 内嵌）。
// 修改历史：
//
//	2026-09-19 10:24:00 | 新建 | U9 Webmail 核心（计划书步骤 4，G2 批准 2026-09-19 10:00:41）
package web

import "embed"

// StaticFS 静态资源树（htmx.min.js 等 vendor 产物；protocol/web 经 fs.Sub 消费）。
//
//go:embed all:static
var StaticFS embed.FS
