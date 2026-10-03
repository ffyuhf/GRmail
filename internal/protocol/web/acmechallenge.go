// ACME HTTP-01 挑战路由（U10：Q5-A HTTP-01/Q3-A 完成态 80 仅留挑战+301）。
// 语义：GET /.well-known/acme-challenge/{token} → ChallengeLookup 命中直答 keyAuth
// （text/plain；rfc8555 HTTP-01 资源语义经 lego challenge.Presenter 回调链承载——
// Present 存表/路由直答/CleanUp 清除）；未命中或表未注入→404。
// 本路由挂 80 监听 mux（engine 外——挑战无会话语义，绕过中间件链零开销）。
// 修改历史：
//
//	2026-09-20 01:06:00 | 新建 | U10 Setup 向导与 ACME（计划书步骤 6）
package web

import (
	"net/http"
	"strings"
)

// acmeChallengePrefix 挑战路径前缀（rfc8555 §8.3 HTTP-01 资源约定 /.well-known/acme-challenge/）。
const acmeChallengePrefix = "/.well-known/acme-challenge/"

// challengeHTTP 挑战直答（http.ServeMux HandleFunc 形态——非 gin）。
// 参数：w/r 标准 HTTP 对（token 取自路径剥前缀段）。
func (s *Server) challengeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Challenge == nil {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, acmeChallengePrefix)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	keyAuth, ok := s.cfg.Challenge.Lookup(token)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(keyAuth))
}
