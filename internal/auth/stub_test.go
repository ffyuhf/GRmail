// auth 包测试公共件：离线 DNS stub（NFR-015：认证验证脱离网络端点独立驱动）。
// 修改历史：
//
//	2026-09-17 02:48:00 | 新建 | U3 auth 基础（计划书步骤 8）
package auth

import (
	"context"
	"fmt"
	"net"
	"sync"

	ravendns "github.com/synqronlabs/raven/dns"
)

// stubResolver 内存记录表解析器（实现 Resolver 五方法；错误分类映射 ravendns 哨兵：
// 注入域→ErrDNSTimeout（temperror 路径）；未登记域→ErrDNSNotFound（none 路径））。
type stubResolver struct {
	mu      sync.Mutex
	txts    map[string][]string
	ips     map[string][]net.IP
	temp    map[string]bool
	queries []string // 查询审计（Tree Walk 次数与序列断言）
}

// newStubResolver 构造空 stub。
func newStubResolver() *stubResolver {
	return &stubResolver{
		txts: map[string][]string{},
		ips:  map[string][]net.IP{},
		temp: map[string]bool{},
	}
}

// withTXT 登记域名 TXT 记录（链式）。
func (s *stubResolver) withTXT(domain string, records ...string) *stubResolver {
	s.txts[domain] = records
	return s
}

// withIP 登记域名 A/AAAA 记录（链式）。
func (s *stubResolver) withIP(domain string, ips ...net.IP) *stubResolver {
	s.ips[domain] = ips
	return s
}

// withTemp 注入瞬时故障域（链式）。
func (s *stubResolver) withTemp(domain string) *stubResolver {
	s.temp[domain] = true
	return s
}

// queryLog 返回查询审计副本（域名序列）。
func (s *stubResolver) queryLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// LookupTXT TXT 查询（错误分类：temp→ErrDNSTimeout；miss→ErrDNSNotFound）。
func (s *stubResolver) LookupTXT(_ context.Context, domain string) (ravendns.Result[string], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, domain)
	if s.temp[domain] {
		return ravendns.Result[string]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSTimeout, domain)
	}
	recs, ok := s.txts[domain]
	if !ok {
		return ravendns.Result[string]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSNotFound, domain)
	}
	return ravendns.Result[string]{Records: recs}, nil
}

// LookupCNAME CNAME 查询（验证测试无 CNAME 链场景，恒 NotFound）。
func (s *stubResolver) LookupCNAME(_ context.Context, domain string) (ravendns.Result[string], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, domain)
	return ravendns.Result[string]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSNotFound, domain)
}

// LookupIP A/AAAA 查询（SPF a/mx 机制路径）。
func (s *stubResolver) LookupIP(_ context.Context, domain string) (ravendns.Result[net.IP], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, domain)
	if s.temp[domain] {
		return ravendns.Result[net.IP]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSTimeout, domain)
	}
	ips, ok := s.ips[domain]
	if !ok {
		return ravendns.Result[net.IP]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSNotFound, domain)
	}
	return ravendns.Result[net.IP]{Records: ips}, nil
}

// LookupMX MX 查询（SPF mx 机制路径，测试未用 mx 机制，恒 NotFound）。
func (s *stubResolver) LookupMX(_ context.Context, domain string) (ravendns.Result[*net.MX], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, domain)
	return ravendns.Result[*net.MX]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSNotFound, domain)
}

// LookupAddr 反向解析（测试未用 ptr 机制，恒 NotFound）。
func (s *stubResolver) LookupAddr(_ context.Context, ip net.IP) (ravendns.Result[string], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, ip.String())
	return ravendns.Result[string]{}, fmt.Errorf("%w: %s", ravendns.ErrDNSNotFound, ip.String())
}

// 编译期断言：stub 满足生产 Resolver 接口（测试与生产同接口，NFR-015）
var _ Resolver = (*stubResolver)(nil)
