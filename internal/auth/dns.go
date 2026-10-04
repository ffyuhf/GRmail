// auth DNS 查询封装（Q10 裁决：统一复用 miekg/dns——raven 内部即以 miekg/dns 实现，
// 本文件经 raven dns 包间接满足 Q10，auth 不直接 import miekg/dns）。
// 依据：SRS NFR-015（认证验证脱离网络端点独立驱动测试→Resolver 接口化+stub 注入）；
// 架构总览 v1.0.0 第三章 auth 模块职责「DNS 查询封装」；
// U3 计划书 1.5 口径④（仅常规查询，DNSSEC 验证归阶段二 transport 域）。
// 修改历史：
//
//	2026-09-17 02:22:00 | 新建 | U3 auth 基础（计划书步骤 3，G2 批准 2026-09-17 02:13:45）
package auth

import (
	"context"
	"net"
	"strings"

	ravendns "github.com/synqronlabs/raven/dns"
	ravenspf "github.com/synqronlabs/raven/spf"
)

// Resolver 认证验证所需 DNS 查询接口（方法集与 ravendns.Resolver 一致，
// dkim.Verify 与 arc.Verifier 直接消费；DMARC 自研包经 txtResolver 适配消费）。
// 生产实现 NewResolver（miekg/dns），测试实现 stubResolver（内存记录表，NFR-015）。
type Resolver interface {
	// LookupTXT 返回域名的 TXT 记录集合
	LookupTXT(ctx context.Context, domain string) (ravendns.Result[string], error)
	// LookupCNAME 返回显式 CNAME 记录
	LookupCNAME(ctx context.Context, domain string) (ravendns.Result[string], error)
	// LookupIP 返回 A/AAAA 记录（单结果集合并返回）
	LookupIP(ctx context.Context, domain string) (ravendns.Result[net.IP], error)
	// LookupMX 返回按优先级排序的 MX 记录
	LookupMX(ctx context.Context, domain string) (ravendns.Result[*net.MX], error)
	// LookupAddr 对 IP 执行反向解析
	LookupAddr(ctx context.Context, ip net.IP) (ravendns.Result[string], error)
}

// NewResolver 生产 DNS 解析器（ravendns 实现，内部 miekg/dns；系统 resolv.conf 名单，
// 超时/重试取库默认档 5s/2 次）。返回：Resolver 接口实例。
func NewResolver() Resolver {
	return ravendns.NewResolver(ravendns.ResolverConfig{})
}

// 编译期断言：生产实现满足本包 Resolver 接口（dkim/arc 消费口径）
var _ Resolver = ravendns.NewResolver(ravendns.ResolverConfig{})

// ───────────────────────── SPF 适配器 ─────────────────────────

// spfResolver 将 Resolver 适配为 raven spf.Resolver 接口。
// 存在原因（实测落档）：spf.Resolver 与 dns.Resolver 方法集同名不同签名
// （扁平式 []string,spf.Result,error vs 泛型 dns.Result[T]），单一类型无法同时实现，
// raven 自身亦以包装结构提供 spf.DNSResolver——本适配器为测试 stub 的统一注入路径。
type spfResolver struct{ r Resolver }

// asSPFResolver 包装为 spf.Resolver。
func asSPFResolver(r Resolver) ravenspf.Resolver { return spfResolver{r: r} }

// fqdnTrim 规范化查询名（实测修正 2026-09-17 02:48：raven SPF 内部以 FQDN 尾点形式
// 查询——"example.com."；统一去尾点，使生产与 stub 的键匹配语义一致，生产 DNS 无影响）。
func fqdnTrim(name string) string { return strings.TrimSuffix(name, ".") }

// LookupTXT 转换泛型结果为扁平签名（查询名尾点规范化）。
func (s spfResolver) LookupTXT(ctx context.Context, name string) ([]string, ravenspf.Result, error) {
	res, err := s.r.LookupTXT(ctx, fqdnTrim(name))
	if err != nil {
		return nil, ravenspf.Result{}, err
	}
	return res.Records, ravenspf.Result{Authentic: res.Authentic}, nil
}

// LookupIP 按 network 过滤 IP 族（"ip"全部 / "ip4"仅 IPv4 / "ip6"仅 IPv6；尾点规范化）。
func (s spfResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, ravenspf.Result, error) {
	res, err := s.r.LookupIP(ctx, fqdnTrim(host))
	if err != nil {
		return nil, ravenspf.Result{}, err
	}
	var ips []net.IP
	for _, ip := range res.Records {
		switch network {
		case "ip4":
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		case "ip6":
			if ip.To4() == nil {
				ips = append(ips, ip)
			}
		default: // "ip" 或其他：全量
			ips = append(ips, ip)
		}
	}
	return ips, ravenspf.Result{Authentic: res.Authentic}, nil
}

// LookupMX 转换 MX 记录（尾点规范化）。
func (s spfResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, ravenspf.Result, error) {
	res, err := s.r.LookupMX(ctx, fqdnTrim(name))
	if err != nil {
		return nil, ravenspf.Result{}, err
	}
	return res.Records, ravenspf.Result{Authentic: res.Authentic}, nil
}

// LookupAddr 反向解析（addr 为 IP 字符串，转 net.IP 后转发）。
func (s spfResolver) LookupAddr(ctx context.Context, addr string) ([]string, ravenspf.Result, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, ravenspf.Result{}, &net.DNSError{Err: "invalid ip", Name: addr}
	}
	res, err := s.r.LookupAddr(ctx, ip)
	if err != nil {
		return nil, ravenspf.Result{}, err
	}
	return res.Records, ravenspf.Result{Authentic: res.Authentic}, nil
}
