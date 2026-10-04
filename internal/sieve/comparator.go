// sieve 比较器与匹配（rfc5228 §2.7——R1-A 自研）。
// 规范锚点：§2.7.1 三匹配（:is 绝等/:contains 子串/:matches glob——'*' 零或多、
// '?' 恰一字符，'\\*'/'\\?' 转义匹配自身 L768-772）；§2.7.2 跨字符集比较（按八位组，
// US-ASCII/ISO-8859-1/UTF-8 转换能力 MUST——工程实现按 UTF-8 字节直比+i;ascii-casemap
// US-ASCII 折叠，符合「comparator 定义字符为单八位组」的 i;octet/i;ascii-casemap 语义
// L763-765）；§2.7.3 双比较器 MUST（默认 i;ascii-casemap；未知 comparator 错误——
// 非 comparator- 前缀 require 场景）；§2.7.4 ADDRESS-PART（:all/:localpart/:domain——
// 解析归 eval 侧地址提取）。
// 修改历史：
//
//	2026-09-21 00:52:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 6）
package sieve

import "strings"

// comparatorID 比较器标识（§2.7.3：MUST 支持两值；默认 i;ascii-casemap）。
const (
	comparatorOctet     = "i;octet"         // 字节等值比较
	comparatorASCIICase = "i;ascii-casemap" // US-ASCII 大小写折叠（默认）
)

// resolveComparator 归一比较器名（空→默认；未知→错误）。
func resolveComparator(name string) (string, bool) {
	if name == "" {
		return comparatorASCIICase, true
	}
	if name == comparatorOctet || name == comparatorASCIICase {
		return name, true
	}
	return "", false // 非 MUST 集——require 声明扩展比较器未支持（错误语义 §2.7.3）
}

// foldComparator 按比较器折叠字符串（匹配前置变换：octet 原样/casemap US-ASCII 折叠）。
func foldComparator(comparator, s string) string {
	if comparator == comparatorASCIICase {
		var b strings.Builder
		b.Grow(len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b.WriteByte(c)
		}
		return b.String()
	}
	return s
}

// matchIs :is 绝等匹配（§2.7.1：折叠后全等；空键仅配空值）。
func matchIs(comparator, value, key string) bool {
	return foldComparator(comparator, value) == foldComparator(comparator, key)
}

// matchContains :contains 子串匹配（§2.7.1：值包含键为子串；空键含于一切值）。
func matchContains(comparator, value, key string) bool {
	return strings.Contains(foldComparator(comparator, value), foldComparator(comparator, key))
}

// matchMatches :matches glob 匹配（§2.7.1：'*' 零或多、'?' 恰一字符（i;octet/casemap
// 字符=单八位组）；'\\*','\\?' 转义；全值匹配——实现为双指针贪心回溯）。
func matchMatches(comparator, value, key string) bool {
	v := foldComparator(comparator, value)
	k := foldComparator(comparator, key)
	// 预解转义：key 分解为 literal 段与通配符序列（'*'=任意、'?'=单字符）
	var seq []matchPart
	var lit strings.Builder
	for i := 0; i < len(k); i++ {
		switch {
		case k[i] == '\\' && i+1 < len(k) && (k[i+1] == '*' || k[i+1] == '?' || k[i+1] == '\\'):
			lit.WriteByte(k[i+1])
			i++
		case k[i] == '*':
			if lit.Len() > 0 {
				seq = append(seq, matchPart{literal: lit.String()})
				lit.Reset()
			}
			seq = append(seq, matchPart{star: true})
		case k[i] == '?':
			if lit.Len() > 0 {
				seq = append(seq, matchPart{literal: lit.String()})
				lit.Reset()
			}
			seq = append(seq, matchPart{question: true})
		default:
			lit.WriteByte(k[i])
		}
	}
	if lit.Len() > 0 {
		seq = append(seq, matchPart{literal: lit.String()})
	}
	// 贪心+回溯匹配
	vi, si := 0, 0
	starVI, starSI := -1, -1
	for vi < len(v) {
		if si < len(seq) {
			p := seq[si]
			switch {
			case p.star:
				starVI, starSI = vi, si
				si++ // '*' 先匹配空，失败回溯吞一字符
				continue
			case p.question:
				vi++
				si++
				continue
			case strings.HasPrefix(v[vi:], p.literal):
				vi += len(p.literal)
				si++
				continue
			}
		}
		if starVI >= 0 && starSI+1 <= len(seq) {
			starVI++
			vi = starVI
			si = starSI + 1
			continue
		}
		return false
	}
	for si < len(seq) && seq[si].star {
		si++
	}
	return si == len(seq)
}

// matchPart glob 分解段（literal 固定段/star 任意段/question 单字符段）。
type matchPart struct {
	literal  string
	star     bool
	question bool
}

// matchAny 组合匹配（列表语义 §2.4.2.1：任一组合命中即真——值×键双循环）。
func matchAny(comparator, matchType string, values, keys []string) bool {
	for _, v := range values {
		for _, k := range keys {
			var hit bool
			switch matchType {
			case "contains":
				hit = matchContains(comparator, v, k)
			case "matches":
				hit = matchMatches(comparator, v, k)
			default: // "is"（缺省 §2.7.1）
				hit = matchIs(comparator, v, k)
			}
			if hit {
				return true
			}
		}
	}
	return false
}

// tagsOf 从标签集提取单值标签（matchType/comparator/addressPart/over/under——
// 返回空串=未指定；标签合法性由 parser 保证）。
func tagsOf(tags []TagArg) (matchType, comparator, addressPart, sizeDir string, flagsTag []string) {
	for _, t := range tags {
		switch t.Tag {
		case "is", "contains", "matches":
			matchType = t.Tag
		case "comparator":
			comparator = t.Value
		case "all", "localpart", "domain":
			addressPart = t.Tag
		case "over", "under":
			sizeDir = t.Tag
		case "flags":
			// fileinto :flags <list>（rfc5232 §3——值列表经位置参数承载，标签本身无值；
			// 此处仅记录出现性，列表解析在动作执行侧）
			flagsTag = append(flagsTag, t.Tag)
		}
	}
	return
}
