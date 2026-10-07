// Package storage 动态查询方言分派层（U11 1.5⑩）：Webmail 列表/搜索与 IMAP SEARCH
// 的外层 Select 构造按 driver 分派（bob/dialect/{sqlite,mysql,psql} 三方言 starter），
// 条件表达式层三库通用——bob expr.Clause.WriteSQL 经 convertQuestionMarks 按最终
// Build 的 Dialect 转换占位符（bob v0.50.0 expr/raw.go:41 源码实测，U11 计划书 1.5⑮），
// 故 webmailListConds/filterConds/likeExpr 等既有条件构造零改动复用。
// 依据：数据库表结构 v1.1.0 第五章「Bob 动态查询运行时按方言生成 LIMIT/OFFSET 等」；
// 架构总览选型 #8（Bob 定位）。
// 覆盖条目：FR-014（TC-014 动态查询路径 MySQL/PG 格）。
// 修改历史：
//
//	2026-09-20 05:32:00 | 新增 | U11 三库验收（计划书步骤 5，G2 批准 2026-09-20 05:07:20）
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/stephenafamo/bob"

	mysqldialect "github.com/stephenafamo/bob/dialect/mysql"
	msm "github.com/stephenafamo/bob/dialect/mysql/sm"
	psqldialect "github.com/stephenafamo/bob/dialect/psql"
	psm "github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/expr"
)

// ───────────────────────── MySQL/PG 外层构造（与 SQLite 形态同构，仅方言包不同） ─────────────────────────

// buildWebmailListPageSQLMySQL Webmail 列表分页（MySQL 方言；条件层复用 webmailListConds）。
func buildWebmailListPageSQLMySQL(ctx context.Context, q ListQuery) (string, []any, error) {
	query := mysqldialect.Select(
		msm.Columns(webmailListColumns()...),
		msm.From("mailbox_messages AS mm"),
		msm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		msm.Where(mysqldialect.And(webmailListConds(q)...)),
		msm.OrderBy("mm.uid DESC"),
		msm.Limit(int64(q.Limit)), msm.Offset(int64(q.Offset)),
	)
	return query.Build(ctx)
}

// buildWebmailListCountSQLMySQL Webmail 列表计数（MySQL 方言）。
func buildWebmailListCountSQLMySQL(ctx context.Context, q ListQuery) (string, []any, error) {
	query := mysqldialect.Select(
		msm.Columns(expr.Raw("COUNT(*)")),
		msm.From("mailbox_messages AS mm"),
		msm.Where(mysqldialect.And(webmailListConds(q)...)),
	)
	return query.Build(ctx)
}

// buildWebmailSearchPageSQLMySQL 关键词搜索分页（MySQL 方言；安全原子性批 F1
// 2026-10-06：OR 集补第四列 body_cache——三库四列一致，消除 MySQL/PG 正文检索
// 静默失效分叉〔SQLite webmail_query 四列口径为准绳〕）。
func buildWebmailSearchPageSQLMySQL(ctx context.Context, q SearchQuery) (string, []any, error) {
	kw := likeExpr("m", "subject", q.Keyword)
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
		mysqldialect.Or(kw, likeExpr("m", "from_addr", q.Keyword), likeExpr("m", "to_addrs", q.Keyword),
			likeExpr("m", "body_cache", q.Keyword)),
	}
	query := mysqldialect.Select(
		msm.Columns(webmailListColumns()...),
		msm.From("mailbox_messages AS mm"),
		msm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		msm.Where(mysqldialect.And(conds...)),
		msm.OrderBy("mm.uid DESC"),
		msm.Limit(int64(q.Limit)), msm.Offset(int64(q.Offset)),
	)
	return query.Build(ctx)
}

// buildWebmailSearchCountSQLMySQL 关键词搜索计数（MySQL 方言；F1 四列一致）。
func buildWebmailSearchCountSQLMySQL(ctx context.Context, q SearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
		mysqldialect.Or(
			likeExpr("m", "subject", q.Keyword),
			likeExpr("m", "from_addr", q.Keyword),
			likeExpr("m", "to_addrs", q.Keyword),
			likeExpr("m", "body_cache", q.Keyword),
		),
	}
	query := mysqldialect.Select(
		msm.Columns(expr.Raw("COUNT(*)")),
		msm.From("mailbox_messages AS mm"),
		msm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		msm.Where(mysqldialect.And(conds...)),
	)
	return query.Build(ctx)
}

// buildIMAPSearchSQLMySQL IMAP SEARCH（MySQL 方言；条件矩阵复用 filterConds）。
func buildIMAPSearchSQLMySQL(ctx context.Context, q IMAPSearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "folder_id"), expr.Arg(q.FolderID)),
	}
	conds = append(conds, filterConds(q.Filter)...)
	query := mysqldialect.Select(
		msm.Columns(
			expr.Quote("mm", "id"), expr.Quote("mm", "uid"), expr.Quote("m", "sent_at"),
			expr.Quote("m", "subject"), expr.Quote("m", "from_addr"),
			expr.Quote("mm", "is_read"), expr.Quote("mm", "is_flagged"),
		),
		msm.From("mailbox_messages AS mm"),
		msm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		msm.Where(mysqldialect.And(conds...)),
		msm.OrderBy("mm.uid ASC"),
	)
	return query.Build(ctx)
}

// buildWebmailListPageSQLPG Webmail 列表分页（PostgreSQL 方言）。
func buildWebmailListPageSQLPG(ctx context.Context, q ListQuery) (string, []any, error) {
	query := psqldialect.Select(
		psm.Columns(webmailListColumns()...),
		psm.From("mailbox_messages AS mm"),
		psm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		psm.Where(psqldialect.And(webmailListConds(q)...)),
		psm.OrderBy("mm.uid DESC"),
		psm.Limit(int64(q.Limit)), psm.Offset(int64(q.Offset)),
	)
	return query.Build(ctx)
}

// buildWebmailListCountSQLPG Webmail 列表计数（PostgreSQL 方言）。
func buildWebmailListCountSQLPG(ctx context.Context, q ListQuery) (string, []any, error) {
	query := psqldialect.Select(
		psm.Columns(expr.Raw("COUNT(*)")),
		psm.From("mailbox_messages AS mm"),
		psm.Where(psqldialect.And(webmailListConds(q)...)),
	)
	return query.Build(ctx)
}

// buildWebmailSearchPageSQLPG 关键词搜索分页（PostgreSQL 方言；F1 四列一致——
// body_cache 第四列补齐）。
func buildWebmailSearchPageSQLPG(ctx context.Context, q SearchQuery) (string, []any, error) {
	kw := likeExpr("m", "subject", q.Keyword)
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
		psqldialect.Or(kw, likeExpr("m", "from_addr", q.Keyword), likeExpr("m", "to_addrs", q.Keyword),
			likeExpr("m", "body_cache", q.Keyword)),
	}
	query := psqldialect.Select(
		psm.Columns(webmailListColumns()...),
		psm.From("mailbox_messages AS mm"),
		psm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		psm.Where(psqldialect.And(conds...)),
		psm.OrderBy("mm.uid DESC"),
		psm.Limit(int64(q.Limit)), psm.Offset(int64(q.Offset)),
	)
	return query.Build(ctx)
}

// buildWebmailSearchCountSQLPG 关键词搜索计数（PostgreSQL 方言；F1 四列一致）。
func buildWebmailSearchCountSQLPG(ctx context.Context, q SearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "status"), expr.Arg("normal")),
		psqldialect.Or(
			likeExpr("m", "subject", q.Keyword),
			likeExpr("m", "from_addr", q.Keyword),
			likeExpr("m", "to_addrs", q.Keyword),
			likeExpr("m", "body_cache", q.Keyword),
		),
	}
	query := psqldialect.Select(
		psm.Columns(expr.Raw("COUNT(*)")),
		psm.From("mailbox_messages AS mm"),
		psm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		psm.Where(psqldialect.And(conds...)),
	)
	return query.Build(ctx)
}

// buildIMAPSearchSQLPG IMAP SEARCH（PostgreSQL 方言）。
func buildIMAPSearchSQLPG(ctx context.Context, q IMAPSearchQuery) (string, []any, error) {
	conds := []bob.Expression{
		expr.OP("=", expr.Quote("mm", "mailbox_id"), expr.Arg(q.MailboxID)),
		expr.OP("=", expr.Quote("mm", "folder_id"), expr.Arg(q.FolderID)),
	}
	conds = append(conds, filterConds(q.Filter)...)
	query := psqldialect.Select(
		psm.Columns(
			expr.Quote("mm", "id"), expr.Quote("mm", "uid"), expr.Quote("m", "sent_at"),
			expr.Quote("m", "subject"), expr.Quote("m", "from_addr"),
			expr.Quote("mm", "is_read"), expr.Quote("mm", "is_flagged"),
		),
		psm.From("mailbox_messages AS mm"),
		psm.InnerJoin("messages AS m ON m.id = mm.message_id"),
		psm.Where(psqldialect.And(conds...)),
		psm.OrderBy("mm.uid ASC"),
	)
	return query.Build(ctx)
}

// ───────────────────────── 构建分派与共享执行器（MySQL/PG） ─────────────────────────

// dynQueryRunner MySQL/PG 动态查询执行器（扫描形态：可空时间 sql.NullTime——驱动
// parseTime/timestamptz 映射；与 SQLite 实现的 NullString+RFC3339 解析路径分离）。
type dynQueryRunner struct {
	driver string
	db     *sql.DB
}

// newDynQueryRunner 构造执行器（driver 决定外层 Select 方言）。
func newDynQueryRunner(driver string, db *sql.DB) dynQueryRunner {
	return dynQueryRunner{driver: driver, db: db}
}

// listPageSQL/countSQL 按 driver 分派外层构造（SQLite 回退既有函数——守护形态）。
func (r dynQueryRunner) listPageSQL(ctx context.Context, q ListQuery) (string, []any, error) {
	if r.driver == DriverMySQL {
		return buildWebmailListPageSQLMySQL(ctx, q)
	}
	return buildWebmailListPageSQLPG(ctx, q)
}

func (r dynQueryRunner) listCountSQL(ctx context.Context, q ListQuery) (string, []any, error) {
	if r.driver == DriverMySQL {
		return buildWebmailListCountSQLMySQL(ctx, q)
	}
	return buildWebmailListCountSQLPG(ctx, q)
}

func (r dynQueryRunner) searchPageSQL(ctx context.Context, q SearchQuery) (string, []any, error) {
	if r.driver == DriverMySQL {
		return buildWebmailSearchPageSQLMySQL(ctx, q)
	}
	return buildWebmailSearchPageSQLPG(ctx, q)
}

func (r dynQueryRunner) searchCountSQL(ctx context.Context, q SearchQuery) (string, []any, error) {
	if r.driver == DriverMySQL {
		return buildWebmailSearchCountSQLMySQL(ctx, q)
	}
	return buildWebmailSearchCountSQLPG(ctx, q)
}

func (r dynQueryRunner) imapSearchSQL(ctx context.Context, q IMAPSearchQuery) (string, []any, error) {
	if r.driver == DriverMySQL {
		return buildIMAPSearchSQLMySQL(ctx, q)
	}
	return buildIMAPSearchSQLPG(ctx, q)
}

// webmailList Webmail 列表路径（计数+分页+扫描，normal 基线语义与 SQLite 实现一致）。
func (r dynQueryRunner) webmailList(ctx context.Context, q ListQuery) ([]*ListItem, int64, error) {
	countSQL, countArgs, err := r.listCountSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建 Webmail 计数: %w", err)
	}
	var total int64
	if err = r.db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 Webmail 列表: %w", err)
	}
	pageSQL, pageArgs, err := r.listPageSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建 Webmail 分页: %w", err)
	}
	items, err := r.webmailItems(ctx, pageSQL, pageArgs)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// webmailSearch 关键词搜索路径。
func (r dynQueryRunner) webmailSearch(ctx context.Context, q SearchQuery) ([]*ListItem, int64, error) {
	countSQL, countArgs, err := r.searchCountSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建搜索计数: %w", err)
	}
	var total int64
	if err = r.db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计搜索命中: %w", err)
	}
	pageSQL, pageArgs, err := r.searchPageSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建搜索分页: %w", err)
	}
	items, err := r.webmailItems(ctx, pageSQL, pageArgs)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// webmailItems 执行列表形态查询并扫描（8 列对齐 webmailListColumns；NULL 防御）。
func (r dynQueryRunner) webmailItems(ctx context.Context, query string, args []any) ([]*ListItem, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("执行 Webmail 查询: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]*ListItem, 0, 32)
	for rows.Next() {
		var it ListItem
		var sentAt sql.NullTime
		var subject, fromAddr, status sql.NullString
		if err = rows.Scan(&it.ID, &it.UID, &sentAt, &subject, &fromAddr, &it.IsRead, &it.IsFlagged, &status); err != nil {
			return nil, fmt.Errorf("扫描 Webmail 行: %w", err)
		}
		it.SentAt = zeroTimeIfInvalid(sentAt)
		it.Subject, it.FromAddr = subject.String, fromAddr.String
		it.Deleted = status.Valid && status.String == "deleted"
		items = append(items, &it)
	}
	return items, rows.Err()
}

// imapSearch IMAP SEARCH 执行+扫描（7 列对齐；UID 升序）。
func (r dynQueryRunner) imapSearch(ctx context.Context, q IMAPSearchQuery) ([]*ListItem, error) {
	query, args, err := r.imapSearchSQL(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("构建 IMAP 搜索 SQL: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("执行 IMAP 搜索: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]*ListItem, 0, 32)
	for rows.Next() {
		var it ListItem
		var sentAt sql.NullTime
		var subject, fromAddr sql.NullString
		if err = rows.Scan(&it.ID, &it.UID, &sentAt, &subject, &fromAddr, &it.IsRead, &it.IsFlagged); err != nil {
			return nil, fmt.Errorf("扫描搜索行: %w", err)
		}
		it.SentAt = zeroTimeIfInvalid(sentAt)
		it.Subject, it.FromAddr = subject.String, fromAddr.String
		items = append(items, &it)
	}
	return items, rows.Err()
}

// ───────────────────────── MySQL/PG 共享辅助 ─────────────────────────

// nullZeroTime 零值时间 → NULL（Date 头缺失场景；MySQL TIMESTAMP(6)/PG TIMESTAMPTZ 参数形态）。
func nullZeroTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

// zeroTimeIfInvalid 可空时间列 → time.Time（NULL/零值容错——对齐 SQLite 路径
// parseTimestampOrZero 语义：Date 头缺失与异常数据兜底，IMAP INTERNALDATE 零值语义）。
func zeroTimeIfInvalid(t sql.NullTime) time.Time {
	if !t.Valid || t.Time.IsZero() {
		return time.Time{}
	}
	return t.Time
}
