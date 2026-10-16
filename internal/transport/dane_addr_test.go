// daneServerAddr 单测（B——生产缺陷修复批，G2 批准 2026-10-17 02:30「批准，乙 C」）。
// IPv6 裸地址经 net.JoinHostPort 加方括号（生产根因形态复现：resolv.conf
// nameserver fdae:6a60:38ca::1 环境拨号串「too many colons」修复锚）；IPv4 与
// 原手工拼接逐字节等价（回归零变化锚）；空端口防御形态（ClientConfigFromFile
// 恒填 53——防御断言）。
package transport

import "testing"

func TestDaneServerAddr(t *testing.T) {
	cases := []struct{ server, port, want string }{
		{"fdae:6a60:38ca::1", "53", "[fdae:6a60:38ca::1]:53"},
		{"2001:db8::1", "53", "[2001:db8::1]:53"},
		{"1.1.1.1", "53", "1.1.1.1:53"},
		{"8.8.8.8", "", "8.8.8.8:"},
	}
	for _, c := range cases {
		if got := daneServerAddr(c.server, c.port); got != c.want {
			t.Fatalf("daneServerAddr(%q,%q)=%q, want %q", c.server, c.port, got, c.want)
		}
	}
}
