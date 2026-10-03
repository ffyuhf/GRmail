// GRmail Web 静态资源服务（U9 计划书步骤 4）：embed 内嵌（CON-001 单二进制——
// Q2-B 裁决 2026-09-19 01:52:04 启用静态资源 embed 通道，HTMX.js vendor 内嵌；
// embed 声明位于 GRmail/web 包——embed 仅可嵌包内路径，本包经 fs.Sub 消费）。
// 缓存策略（计划书 1.5）：静态 JS 无会话数据，允许私有缓存 max-age=86400（handler
// 覆写 entry 中间件的 no-store——OWASP Web Content Caching 章限定会话承载内容禁缓存）。
// 修改历史：
//
//	2026-09-19 10:22:00 | 新建 | U9 Webmail 核心（计划书步骤 4，G2 批准 2026-09-19 10:00:41）
package web

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"

	webassets "GRmail/web"
)

// staticFiles 内嵌静态子树（/static 前缀剥离后的内容寻址）。
var staticFiles = staticSubtree()

// staticSubtree 子树裁剪（失败属构建期不可恢复——embed 声明与目录不一致）。
func staticSubtree() fs.FS {
	sub, err := fs.Sub(webassets.StaticFS, "static")
	if err != nil {
		panic("静态资源子树不可用: " + err.Error())
	}
	return sub
}

// staticHandler 静态资源端点（GET /static/*filepath）：
// embed 读取 + 扩展名 MIME + 私有缓存头（覆写入口中间件的 no-store）。
// 目录穿越防线：拒绝空名与.. 段（embed.FS 本身也拒绝越界）。
func (s *Server) staticHandler(c *gin.Context) {
	name := strings.TrimPrefix(c.Param("filepath"), "/")
	if name == "" || strings.Contains(name, "..") {
		c.Status(http.StatusNotFound)
		return
	}
	data, err := fs.ReadFile(staticFiles, path.Clean(name))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", "private, max-age=86400") // 覆写 no-store（静态非会话承载）
	c.Data(http.StatusOK, mimeByExt(name), data)
}

// mimeByExt 常见前端资源 MIME（不足者 application/octet-stream 兜底）。
func mimeByExt(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// htmxScriptSrc 页面引用的 HTMX 脚本地址（AppLayout 统一消费——vendor 版本更新单一事实来源）。
const htmxScriptSrc = "/static/htmx.min.js"
