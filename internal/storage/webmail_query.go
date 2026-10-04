// Package storage Webmail 列表/搜索动态查询构建（U9，Bob 承载——契约 v1.5.0 2.1
// MessageRepo 头注释「列表查询经 Bob 动态构建」的 Webmail 过滤路径落地）。
// 依据：SRS v1.0.1 FR-013 核心子集（列表过滤/关键词搜索）+ NFR-001（十万封 P95——
// 条件可组合经参数化构建，命中既有索引 idx_mm_list）；Q6-A 裁决（2026-09-19 01:56:06，
// 搜索仅元数据缓存列 subject/from_addr/to_addrs LIKE，零数据模型演进——正文检索登记
// 阶段二演进项）；Q3-C/Q4-A 裁决随 G2 批准 2026-09-19 10:00:41。
// 复用：likeEscape/likeExpr（imap_search.go U6 既有——LIKE 安全转义统一形态，INV-06）。
// 覆盖条目：FR-013（Webmail 列表/搜索）、NFR-001（主查询路径）。
// U16 增量（Q3-A 裁决 2026-09-24 11:47:58，G2 批准 2026-09-24 11:51:57）：搜索 OR 集
// 增第四列 body_cache LIKE（数据模型 v1.3.0 3.4——U9 登记项②正文检索收口；NULL 行
// 不命中——存量回填任务渐进覆盖）。
// 修改历史：
//
//	2026-09-19 10:08:00 | 新建 | U9 Webmail 核心（计划书步骤 2，G2 批准 2026-09-19 10:00:41）
//	2026-09-24 16:36:00 | 扩展 | U16 Webmail 体验收尾（计划书步骤 3，G2 批准 2026-09-24 11:51:57）：
//	  搜索分页/计数两查询 OR 集增 body_cache 第四列（Q3-A——契约 v1.12.0 3.2 /search 注记）
package storage

import (
	"context"

	"github.com/stephenafamo/bob"
	sqlite "github.com/stephenafamo/bob/dialect/sqlite"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	"github.com/stephenafamo/bob/expr"
)

// webmailListColumns Webmail 列表 SELECT 列（对齐扫描顺序：id/uid/sent_at/subject/
// from_addr/is_read/is_flagged/status——status 供 ListItem.Deleted）。
// 形态：[]any——sm.Columns 变参签名（bob v0.50.0 实测 go doc）。
func webmailListColumns() []any {
	return []any{
		expr.Quote("mm", "id"), expr.Quote("mm", "uid"), expr.Quote("m", "sent_at"),
		expr.Quote("m", "subject"), expr.Quote("m", "from_addr"),
		expr.Quote("mm", "is_read"), expr.Quote("mm", "is_flagged"), expr.Quote("mm", "status"),
	}
}

// webmailListConds Webmail 列表固定条件（mailbox 隔离 FR-001 + Webmail 侧语义）：
// mailbox_id 限定 + folder_id 限定 + status='normal'（\Deleted 行对用户隐藏——
// 计划书 1.5 口径）+ 可选未读/星标过滤（状态可视化入口，G11 核心语义）。
// 参数：q 列表查询输入。返回：条件表达式列表。
func webmailListConds(q ListQuery) []bob.Expression {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "folder_id"), expr.Arg(q.FolderID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
	}
	if q.UnreadOnly {
		// U11：布尔字面量（三库通用——PG BOOLEAN 拒绝整数参数编码 OID16，SQLite/MySQL 认 false 关键字）
		conds = append(conds, expr.OP("=", expr.Quote("mm", "is_read"), expr.Raw("false")))
	}
	if q.FlaggedOnly {
		conds = append(conds, expr.OP("=", expr.Quote("mm", "is_flagged"), expr.Raw("true")))
	}
	return conds
}

// buildWebmailListPageSQL Webmail 列表分页查询（UID 降序——最新在前，与 PageList 同序）。
// 参数：ctx 构建上下文；q 查询输入。返回：SQL 文本与参数列表。
func buildWebmailListPageSQL(ctx context.Context, q ListQuery) (string, []any, error) {
	query := sqlite.Select(
		sm.Columns(webmailListColumns()...),
		sm.From("mailbox_messages AS mm"),
		sm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		sm.Where(sqlite.And(webmailListConds(q)...)),
		sm.OrderBy("mm.uid DESC"),
		sm.Limit(int64(q.Limit)), sm.Offset(int64(q.Offset)),
	)
	return query.Build(ctx)
}

// buildWebmailListCountSQL Webmail 列表总数查询（分页控件数据源；与分页查询同条件）。
func buildWebmailListCountSQL(ctx context.Context, q ListQuery) (string, []any, error) {
	query := sqlite.Select(
		sm.Columns(expr.Raw("COUNT(*)")),
		sm.From("mailbox_messages AS mm"),
		sm.Where(sqlite.And(webmailListConds(q)...)),
	)
	return query.Build(ctx)
}

// webmailSearchOrConds 搜索 OR 条件集（U16：四缓存列——subject/from_addr/to_addrs/body_cache；
// NULL body_cache 行不命中——SQL NULL LIKE 语义自然成立）。
func webmailSearchOrConds(q SearchQuery) []bob.Expression {
	return []bob.Expression{
		likeExpr("m", "subject", q.Keyword),
		likeExpr("m", "from_addr", q.Keyword),
		likeExpr("m", "to_addrs", q.Keyword),
		likeExpr("m", "body_cache", q.Keyword),
	}
}

// buildWebmailSearchPageSQL Webmail 关键词搜索分页查询（Q6-A 三列+U16 Q3-A 第四列
// body_cache LIKE；跨文件夹全局搜索——契约 3.2 /search 无 folder 维度，
// G17 全局关键词语义；mailbox 限定隔离 FR-001；normal 行可见语义同列表）。
// 参数：ctx 构建上下文；q 搜索输入。返回：SQL 文本与参数列表。
func buildWebmailSearchPageSQL(ctx context.Context, q SearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
		sqlite.Or(webmailSearchOrConds(q)...),
	}
	query := sqlite.Select(
		sm.Columns(webmailListColumns()...),
		sm.From("mailbox_messages AS mm"),
		sm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		sm.Where(sqlite.And(conds...)),
		sm.OrderBy("mm.uid DESC"),
		sm.Limit(int64(q.Limit)), sm.Offset(int64(q.Offset)),
	)
	return query.Build(ctx)
}

// buildWebmailSearchCountSQL Webmail 搜索命中总数查询（与分页查询同条件——U16 四列 OR）。
func buildWebmailSearchCountSQL(ctx context.Context, q SearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
		sqlite.Or(webmailSearchOrConds(q)...),
	}
	query := sqlite.Select(
		sm.Columns(expr.Raw("COUNT(*)")),
		sm.From("mailbox_messages AS mm"),
		sm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		sm.Where(sqlite.And(conds...)),
	)
	return query.Build(ctx)
}
