// Setup 分流中间件（U10：Q2-A setupCompleted 判定/Q4-A 引导态唯一入口/契约 3.4
// 「Setup 未完成：302 → /setup」的 web 层承载）。
// 语义：未完成态=仅放行 /setup 族与 /static（向导资源），其余 302 /setup/1（首步）；
// 完成态=/setup 族禁入（302 首页——温和形态，防旧标签页回访重放）；挑战略由 80 监听
// mux 前置直答（不进 engine——见 server.go ListenAndServeHTTP）。
// 修改历史：
//
//	2026-09-20 01:05:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 6）
package web

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// setupGate Setup 完成态分流（挂载于 CSRF 之后——向导匿名 POST 经 csrfProtect 匿名
// 放行分支到达此处）。
func (s *Server) setupGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if !s.setupCompleted() {
			// 引导态（Q4-A）：向导族+静态资源放行，其余一律 302 向导首步
			if strings.HasPrefix(path, "/setup") || strings.HasPrefix(path, "/static/") {
				c.Next()
				return
			}
			c.Redirect(http.StatusFound, "/setup/1")
			c.Abort()
			return
		}
		// 完成态：向导禁入（重放防线——向导表单在完成后无副作用但呈现误导）
		if strings.HasPrefix(path, "/setup") {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}
		c.Next()
	}
}
