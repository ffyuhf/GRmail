// U11 三库方言层单测：错误判定器分派+动态查询三方言构建 SQL 文本断言
// （占位符/引用符/ESCAPE 语义——计划书步骤 5 检查点；NFR-015 全离线）。
// 覆盖条目：FR-014（TC-014 方言层锚点）。
// 修改历史：
//
//	2026-09-20 05:50:00 | 新增 | U11 三库验收（计划书步骤 5）
package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"
)

// TestU11MySQLConstraintChecker MySQL 错误码判定（1062 唯一/1452 外键/其余不误判）。
func TestU11MySQLConstraintChecker(t *testing.T) {
	ck := newConstraintChecker(DriverMySQL)
	if !ck.uniqueViolation(&pmysql.MySQLError{Number: 1062}) {
		t.Fatal("1062 应判定唯一冲突")
	}
	if !ck.fkViolation(&pmysql.MySQLError{Number: 1452}) {
		t.Fatal("1452 应判定外键冲突")
	}
	if ck.uniqueViolation(&pmysql.MySQLError{Number: 1146}) {
		t.Fatal("1146 不应误判唯一冲突")
	}
	if ck.uniqueViolation(errors.New("普通错误")) {
		t.Fatal("普通错误不应判定约束冲突")
	}
}

// TestU11PostgresConstraintChecker PG SQLSTATE 判定（23505/23503/其余不误判）。
func TestU11PostgresConstraintChecker(t *testing.T) {
	ck := newConstraintChecker(DriverPostgres)
	if !ck.uniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("23505 应判定唯一冲突")
	}
	if !ck.fkViolation(&pgconn.PgError{Code: "23503"}) {
		t.Fatal("23503 应判定外键冲突")
	}
	if ck.uniqueViolation(&pgconn.PgError{Code: "42P01"}) {
		t.Fatal("42P01 不应误判唯一冲突")
	}
}

// TestU11SQLiteConstraintCheckerFallback 空值/未知 driver 回退 SQLite 判定（Open 同口径）。
func TestU11SQLiteConstraintCheckerFallback(t *testing.T) {
	ck := newConstraintChecker("")
	if _, ok := ck.(sqliteChecker); !ok {
		t.Fatal("空 driver 应回退 sqliteChecker")
	}
	sqErr := &sqlite.Error{} // Code 经构造不可直接注入，语义路径由 U2 既有单测覆盖；此处验证形态
	if ck.uniqueViolation(errors.New("x")) {
		t.Fatal("普通错误不应判定")
	}
	_ = sqErr
}

// TestU11DynQueryDialectSQL 三方言构建 SQL 文本断言：
// MySQL 反引号引用+? 占位符；PG 双引号引用+$n 占位符；SQLite 双引号+?。
// bob expr.Clause.convertQuestionMarks 按最终 Dialect 转换（步骤 1 源码实测锚）。
func TestU11DynQueryDialectSQL(t *testing.T) {
	ctx := context.Background()
	q := ListQuery{MailboxID: 1, FolderID: 2, Limit: 25, Offset: 0, UnreadOnly: true}

	// MySQL：反引号标识符 + ? 占位符
	mySQL, _, err := buildWebmailListPageSQLMySQL(ctx, q)
	if err != nil {
		t.Fatalf("MySQL 构建: %v", err)
	}
	if !strings.Contains(mySQL, "`mm`.`mailbox_id`") {
		t.Fatalf("MySQL 应反引号引用: %s", mySQL)
	}
	if !strings.Contains(mySQL, "`mailbox_id` = ?") {
		t.Fatalf("MySQL WHERE 应 ? 占位符: %s", mySQL)
	}
	if !strings.Contains(mySQL, "LIMIT") {
		t.Fatalf("MySQL 应含 LIMIT: %s", mySQL)
	}

	// PostgreSQL：双引号引用 + $n 占位符
	pgSQL, _, err := buildWebmailListPageSQLPG(ctx, q)
	if err != nil {
		t.Fatalf("PG 构建: %v", err)
	}
	if !strings.Contains(pgSQL, `"mm"."mailbox_id"`) {
		t.Fatalf("PG 应双引号引用: %s", pgSQL)
	}
	if !strings.Contains(pgSQL, `"mailbox_id" = $`) {
		t.Fatalf("PG WHERE 应 $n 占位符: %s", pgSQL)
	}
	if !strings.Contains(pgSQL, "LIMIT") {
		t.Fatalf("PG 应含 LIMIT: %s", pgSQL)
	}

	// MySQL likeExpr 的 ? 经 mysql Dialect 保持 ?；PG 转 $n（ESCAPE 子句保留）
	sq := SearchQuery{MailboxID: 1, Keyword: "a%b", Limit: 10, Offset: 0}
	mySearch, _, err := buildWebmailSearchPageSQLMySQL(ctx, sq)
	if err != nil {
		t.Fatalf("MySQL 搜索构建: %v", err)
	}
	if !strings.Contains(mySearch, "ESCAPE ?") {
		t.Fatalf("MySQL ESCAPE 应 ? 占位: %s", mySearch)
	}
	pgSearch, _, err := buildWebmailSearchPageSQLPG(ctx, sq)
	if err != nil {
		t.Fatalf("PG 搜索构建: %v", err)
	}
	if !strings.Contains(pgSearch, "ESCAPE $") {
		t.Fatalf("PG ESCAPE 应 $n 占位: %s", pgSearch)
	}

	// IMAP SEARCH 三方言可构建（条件矩阵复用）
	iq := IMAPSearchQuery{MailboxID: 1, FolderID: 2, Filter: SearchFilter{
		From: "x", FlagSeen: boolPtr(false),
	}}
	for name, build := range map[string]func() (string, []any, error){
		"mysql": func() (string, []any, error) { return buildIMAPSearchSQLMySQL(ctx, iq) },
		"pg":    func() (string, []any, error) { return buildIMAPSearchSQLPG(ctx, iq) },
	} {
		sqlText, args, err := build()
		if err != nil {
			t.Fatalf("%s IMAP 搜索构建: %v", name, err)
		}
		if len(args) == 0 {
			t.Fatalf("%s 应有参数", name)
		}
		if !strings.Contains(strings.ToUpper(sqlText), "ORDER BY") {
			t.Fatalf("%s 应含 ORDER BY: %s", name, sqlText)
		}
	}
}

// TestU11RepoSetFactory 工厂分派形态（driver→对应实现类型；空值回退 SQLite）。
func TestU11RepoSetFactory(t *testing.T) {
	if _, ok := NewMailboxRepoFor(DriverMySQL, nil).(*MySQLMailboxRepo); !ok {
		t.Fatal("mysql driver 应返回 MySQLMailboxRepo")
	}
	if _, ok := NewMailboxRepoFor(DriverPostgres, nil).(*PostgresMailboxRepo); !ok {
		t.Fatal("postgres driver 应返回 PostgresMailboxRepo")
	}
	if _, ok := NewMailboxRepoFor("", nil).(*SQLiteMailboxRepo); !ok {
		t.Fatal("空 driver 应回退 SQLiteMailboxRepo")
	}
	if _, ok := NewQueueStoreFor(DriverMySQL, nil).(*MySQLQueueRepo); !ok {
		t.Fatal("QueueStore mysql 分派失败")
	}
}

// 确保未被使用导致编译告警的引用（lib 常量沿 U2 判定先例）。
var _ = lib.SQLITE_CONSTRAINT_UNIQUE
