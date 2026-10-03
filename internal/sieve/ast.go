// Package sieve Sieve 脚本引擎（rfc5228 基础语言+rfc5232 imap4flags 扩展）——
// R1-A 全自研裁决（Q1-R1 2026-09-21 00:30:59）：词法器+递归下降语法器+求值器三层，
// 纯标准库零新增依赖（CON-002）。
// 依据：rfc5228（§2 词法封闭集/§3 控制命令/§4 四动作/§5 九测试+envelope/§8.2 文法）、
// rfc5232（imap4flags：setflag/addflag/removeflag/hasflag/:flags）；
// 契约 v1.8.0 2.3 SieveEvaluator（mail 域接口——本包实现，依赖方向 sieve→mail 合法，
// 架构总览第四章单向链）；SRS FR-011（3.6）/IR-005；NFR-015（求值器纯函数零 IO）。
// 修改历史：
//
//	2026-09-21 00:46:00 | 新建 | U12 Sieve 过滤与 ManageSieve（计划书步骤 4/5，G2 批准 2026-09-21 00:36:18）
package sieve

// ───────────────────────── AST（rfc5228 §8.2 文法的树化） ─────────────────────────

// CommandNode 命令节点（控制/动作/require 三类统一承载——§2.9）。
// Name 大小写不敏感（词法器已归一小写）；Test/Block 仅控制命令（if/elsif/else）使用；
// Tags 为标签参数（fileinto 的 :flags）；Strings 为位置字符串参数（require 列表/
// fileinto 邮箱名/redirect 地址/imap4flags 标志列表——单串等价单元素列表 §2.4.2.1）。
type CommandNode struct {
	Name    string        // if|elsif|else|require|stop|keep|fileinto|redirect|discard|setflag|addflag|removeflag
	Tags    []TagArg      // 标签参数（fileinto :flags <list>）
	Strings []string      // 位置字符串参数（字符串与字符串列表统一）
	Test    *TestNode     // if/elsif 的测试
	Block   []CommandNode // if/elsif/else 的命令块
	Line    int           // 源行号（错误定位）
}

// TestNode 测试节点（§5；not/allof/anyof 经 Tests 承载子测试——§2.5.1 test-list）。
// Tags 承载 :is/:contains/:matches（MATCH-TYPE）、:comparator <name>、:over/:under（size）、
// :all/:localpart/:domain（ADDRESS-PART）、:flags（无——hasflag 用 MATCH-TYPE/COMPARATOR）。
type TestNode struct {
	Name    string // address|allof|anyof|envelope|exists|false|header|not|size|true|hasflag
	Tags    []TagArg
	Strings []string    // 单列表测试专用（exists 头名列表/hasflag 标志列表——统一列表）
	Names   []string    // header/address/envelope 第一列表（header-names/envelope-parts——双列表边界承载，RF-F/F-S1）
	Keys    []string    // header/address/envelope 第二列表（key-list——同上）
	Number  *int64      // size 的 limit（K/M/G 已展开——§2.4.1）
	Tests   []*TestNode // not=单元素；allof/anyof=列表
	Line    int
}

// TagArg 标签参数（§2.6.2：tag 可携带值——仅 :comparator <string>；其余无值）。
type TagArg struct {
	Tag   string // 归一小写（is/contains/matches/comparator/over/under/all/localpart/domain/flags）
	Value string // comparator 名（其余空）
}

// Script 解析产物（顶层命令序列；requires 为 require 声明的能力集——§3.2 前置）。
type Script struct {
	Commands []CommandNode
	Requires map[string]bool // require 声明的能力串集合（大小写敏感——§6 能力串区分大小写，此处保留原样）
}
