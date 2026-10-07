// Package storage IMAP SEARCH 动态查询构建（Bob 承载，架构总览选型 #8 定位：
// 「Bob（动态查询构建：IMAP SEARCH/列表过滤）」；Q3-A 裁决 2026-09-18 00:06:55）。
// 中性条件结构 SearchFilter 由 protocol/imap 翻译自 imap.SearchCriteria（rfc9051 6.4.4
// 键子集），本文件仅做条件→SQL 映射——storage 零协议类型依赖（架构第三章分层规则）。
// 覆盖条目：FR-006（IMAP 命令集之 SEARCH）。
// 修改历史：
//
//	2026-09-18 00:23:00 | 新建 | U6 IMAP 集成（计划书步骤 3，G2 批准 2026-09-18 00:09:22）
//	2026-09-30 23:53:00 | 扩展 | D8登记项处置批次 K-A：KEYWORD/UNKEYWORD 真实承载
//	  （SearchFilter.Keywords/NotKeywords——每键 EXISTS/NOT EXISTS 子查询；废止
//	  v1.16.0「恒空集/恒真」承载；rfc9051 §6.4.4 L3908-3909/L3980-3981；依据：
//	  D8登记项处置_计划_20260930_23-45-00_v1.0.0 1.2#1，G2 批准 23:40:58）
package storage

import (
	"context"
	"strings"

	"github.com/stephenafamo/bob"
	sqlite "github.com/stephenafamo/bob/dialect/sqlite"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	"github.com/stephenafamo/bob/expr"
)

// likeEscape 转义 LIKE 通配符（% _ \）——契约 2.1「Bob LIKE 安全转义」：
// 用户输入经本函数转义后 % 匹配字面百分号，配合 ESCAPE '\' 子句生效。
// 参数：kw 原始关键词。返回：转义后关键词。
func likeEscape(kw string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(kw)
}

// likeExpr 构造「"table"."col" LIKE '%kw%' ESCAPE '\'」表达式（子串匹配统一形态；
// 列名经本函数白名单式拼接——仅本文件内固定列，用户输入只进参数不进 SQL 文本）。
// 参数：table 列所属表别名；col 列名；kw 关键词（自动转义）。返回：组合表达式。
func likeExpr(table, col, kw string) bob.Expression {
	return sqlite.Raw(`"`+table+`"."`+col+`" LIKE ? ESCAPE ?`, "%"+likeEscape(kw)+"%", `\`)
}

// filterConds SearchFilter → SQL 条件表达式切片（AND 组内条件；Not/Or 一层嵌套）。
// 语义对齐 rfc9051 6.4.4：多字段交集（spec 文档「intersection (and) of all fields」）。
// 参数：f 中性条件。返回：条件表达式列表。
func filterConds(f SearchFilter) []bob.Expression {
	conds := make([]bob.Expression, 0, 12)
	if len(f.UIDs) > 0 {
		conds = append(conds, expr.OP("IN", expr.Quote("mm", "uid"), expr.ArgGroup(toAnySlice(f.UIDs)...)))
	}
	if f.Since != nil {
		conds = append(conds, expr.OP(">=", expr.Quote("mm", "created_at"), expr.Arg(formatTimestamp(*f.Since))))
	}
	if f.Before != nil {
		conds = append(conds, expr.OP("<", expr.Quote("mm", "created_at"), expr.Arg(formatTimestamp(*f.Before))))
	}
	if f.SentSince != nil {
		conds = append(conds, expr.OP(">=", expr.Quote("m", "sent_at"), expr.Arg(formatTimestamp(*f.SentSince))))
	}
	if f.SentBefore != nil {
		conds = append(conds, expr.OP("<", expr.Quote("m", "sent_at"), expr.Arg(formatTimestamp(*f.SentBefore))))
	}
	if f.From != "" {
		conds = append(conds, likeExpr("m", "from_addr", f.From))
	}
	if f.To != "" {
		conds = append(conds, likeExpr("m", "to_addrs", f.To))
	}
	if f.Subject != "" {
		conds = append(conds, likeExpr("m", "subject", f.Subject))
	}
	// BODY/TEXT：正文无缓存列（元数据模型，数据模型 1.1）——退化为元数据维度匹配
	// （SUBJECT+FROM 联合子串）；全正文检索归 U9 数据模型演进裁决项（计划书 1.2 不改清单）
	if f.Body != "" || f.Text != "" {
		kw := f.Body
		if kw == "" {
			kw = f.Text
		}
		conds = append(conds, sqlite.Or(
			likeExpr("m", "subject", kw),
			likeExpr("m", "from_addr", kw),
		))
	}
	if f.Larger > 0 {
		conds = append(conds, expr.OP(">", expr.Quote("m", "raw_size"), expr.Arg(f.Larger)))
	}
	if f.Smaller > 0 {
		conds = append(conds, expr.OP("<", expr.Quote("m", "raw_size"), expr.Arg(f.Smaller)))
	}
	if f.FlagSeen != nil {
		conds = append(conds, expr.OP("=", expr.Quote("mm", "is_read"), boolLiteral(*f.FlagSeen)))
	}
	if f.FlagFlagged != nil {
		conds = append(conds, expr.OP("=", expr.Quote("mm", "is_flagged"), boolLiteral(*f.FlagFlagged)))
	}
	if f.FlagAnswered != nil {
		// RF-J/F-I10：ANSWERED/UNANSWERED 键承载（rfc9051 §6.4.4——is_answered 列 F-I16）
		conds = append(conds, expr.OP("=", expr.Quote("mm", "is_answered"), boolLiteral(*f.FlagAnswered)))
	}
	if f.FlagDraft != nil {
		// RF-J/F-I10：DRAFT/UNDRAFT 键承载（is_draft 列 F-I16）
		conds = append(conds, expr.OP("=", expr.Quote("mm", "is_draft"), boolLiteral(*f.FlagDraft)))
	}
	if f.FlagDeleted != nil {
		want := "normal"
		if *f.FlagDeleted {
			want = "deleted"
		}
		conds = append(conds, expr.OP("=", expr.Quote("mm", "status"), expr.Arg(want)))
	}
	// D8#1：KEYWORD <flag-keyword> 键（rfc9051 §6.4.4 L3908-3909「Messages with
	// the specified keyword flag set」）——每键一条 EXISTS 子查询，多键 AND 交集；
	// mailbox_keywords 独立表（迁移 00008）；占位符经方言 Build 转换（三库共用本函数）
	for _, kw := range f.Keywords {
		conds = append(conds, sqlite.Raw(
			`EXISTS (SELECT 1 FROM mailbox_keywords mk WHERE mk.mailbox_message_id = "mm"."id" AND mk.keyword = ?)`, kw))
	}
	// D8#1：UNKEYWORD <flag-keyword> 键（L3980-3981「Messages that do not have the
	// specified keyword flag set」）——逐键 NOT EXISTS（NOT k1 AND NOT k2 交集语义）
	for _, kw := range f.NotKeywords {
		conds = append(conds, sqlite.Raw(
			`NOT EXISTS (SELECT 1 FROM mailbox_keywords mk WHERE mk.mailbox_message_id = "mm"."id" AND mk.keyword = ?)`, kw))
	}
	if f.Not != nil {
		if inner := filterConds(*f.Not); len(inner) > 0 {
			conds = append(conds, sqlite.Not(sqlite.And(inner...)))
		}
	}
	for _, pair := range f.Or {
		left, right := filterConds(pair[0]), filterConds(pair[1])
		if len(left) > 0 && len(right) > 0 {
			conds = append(conds, sqlite.Or(sqlite.And(left...), sqlite.And(right...)))
		}
	}
	return conds
}

// buildIMAPSearchSQL 构造 IMAP SEARCH 查询（SELECT 列对齐 IMAPSearch 扫描顺序：
// id/uid/sent_at/subject/from_addr/is_read/is_flagged/raw_size/blob_key——尾部两列
// 为配置并发批 F10〔M3〕新增：POP3 loadMaildrop 单查询直取 size/blobKey，登录期
// 逐条 GetDetail N+1 消除）。
// 参数：ctx 构建上下文；q 查询输入。返回：SQL 文本、参数列表。
func buildIMAPSearchSQL(ctx context.Context, q IMAPSearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "folder_id"), expr.Arg(q.FolderID)),
	}
	conds = append(conds, filterConds(q.Filter)...)
	query := sqlite.Select(
		sm.Columns(
			expr.Quote("mm", "id"), expr.Quote("mm", "uid"), expr.Quote("m", "sent_at"),
			expr.Quote("m", "subject"), expr.Quote("m", "from_addr"),
			expr.Quote("mm", "is_read"), expr.Quote("mm", "is_flagged"),
			expr.Quote("m", "raw_size"), expr.Quote("m", "blob_key"),
		),
		sm.From("mailbox_messages AS mm"),
		sm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		sm.Where(sqlite.And(conds...)),
		sm.OrderBy("mm.uid ASC"),
	)
	return query.Build(ctx)
}

// toAnySlice []int64 → []any（ArgGroup 参数形态适配）。
func toAnySlice(ids []int64) []any {
	out := make([]any, len(ids))
	for i, v := range ids {
		out[i] = v
	}
	return out
}

// boolLiteral bool → 布尔字面量表达式（U11 三库通用：PG BOOLEAN 拒绝整数参数编码——
// 固定 true/false 关键字三库均认；非用户输入无注入面）。
func boolLiteral(b bool) bob.Expression {
	if b {
		return expr.Raw("true")
	}
	return expr.Raw("false")
}
