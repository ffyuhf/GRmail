// Package web U10 域 Setup 向导新手可用性批次新增用例（P3/P11——纯函数单测：
// DSN 分字段拼装双库形态与端口缺省归一；Setup向导新手可用性计划书 v1.0.0 阶段 6）。
// 修改历史：
//
//	2026-10-05 05:06:00 | 新增 | Setup向导新手可用性批次（G2 批准 2026-10-05 01:27:29）
package web

import "testing"

// TestBuildDSNFromFields P11 分字段拼装（mysql/postgres 双库形态+缺字段空串拒绝）。
func TestBuildDSNFromFields(t *testing.T) {
	cases := []struct {
		name, driver, host, port, user, pass, db, want string
	}{
		{
			name: "mysql 全参", driver: "mysql", host: "db.local", port: "3307",
			user: "u", pass: "p", db: "mail",
			want: "u:p@tcp(db.local:3307)/mail?parseTime=true",
		},
		{
			name: "mysql 缺省端口", driver: "mysql", host: "h", user: "u", pass: "p", db: "m",
			want: "u:p@tcp(h:3306)/m?parseTime=true",
		},
		{
			name: "postgres 全参", driver: "postgres", host: "pg.local", port: "5433",
			user: "u", pass: "p", db: "mail",
			want: "postgres://u:p@pg.local:5433/mail?sslmode=disable",
		},
		{
			name: "postgres 缺省端口", driver: "postgres", host: "h", user: "u", pass: "p", db: "m",
			want: "postgres://u:p@h:5432/m?sslmode=disable",
		},
	}
	for _, tc := range cases {
		if got := buildDSNFromFields(tc.driver, tc.host, tc.port, tc.user, tc.pass, tc.db); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
	// 必填缺失（host/user/dbname 任一）→ 空串（调用方按连接信息缺失拒绝）
	for _, miss := range []struct{ host, user, db string }{
		{"", "u", "m"}, {"h", "", "m"}, {"h", "u", ""},
	} {
		if got := buildDSNFromFields("mysql", miss.host, "", miss.user, "p", miss.db); got != "" {
			t.Fatalf("缺必填应空串: host=%q user=%q db=%q got %q", miss.host, miss.user, miss.db, got)
		}
	}
	// sqlite 不经本函数（独立 sqlitePath 通道）——非 mysql/pg 返回空串
	if got := buildDSNFromFields("sqlite", "h", "", "u", "p", "m"); got != "" {
		t.Fatalf("sqlite 应空串: %q", got)
	}
}

// TestHTTPPortZeroAsDefault P3 端口缺省归一（零值=80 呈现口径——警示判定输入）。
func TestHTTPPortZeroAsDefault(t *testing.T) {
	if got := HTTPPortZeroAsDefault(0); got != 80 {
		t.Fatalf("零值应归一 80: %d", got)
	}
	if got := HTTPPortZeroAsDefault(-1); got != 80 {
		t.Fatalf("负值应归一 80: %d", got)
	}
	if got := HTTPPortZeroAsDefault(8899); got != 8899 {
		t.Fatalf("正值应原样: %d", got)
	}
}
