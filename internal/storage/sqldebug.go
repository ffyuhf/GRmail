// SQL 观测装饰器（U21 可观测性增强——Q2-A 裁决 2026-09-27 06:09：driver 装饰器层；
// 传输安全与日志增强批次 L-C〔D8#7〕：SQL 注释注入 log_id 开关——直连 query/exec
// 路径前缀 "/*logid:<id>*/ "，使 MySQL/pg 服务端慢查询日志可与应用日志按 log_id 关联
// 〔SQLite 文件态无服务端慢日志——注记不适用〕；注入改变语句文本致 database/sql
// prepare 缓存失效——缺省关闭，仅排障开启〔config.Log.sqlCommentId〕）。
// 机制：以包装名注册 database/sql/driver 装饰驱动（base 驱动实例经具名 import 构造），
// 透明拦截全部 Query/Exec/事务语句——计时后按快照输出：耗时 ≥ sqlSlowMs 输出 Warn 级
// 慢查询日志（H3 语义等价：PMail 经 xorm WithContext 注释注入 LogID，本项目无 ORM 层，
// 经日志行 log_id 属性承载关联——ctx 由 observability.LoggerFromContext 取 logger）；
// sqlDebug=true 输出 Debug 级全量语句（H4 ShowSQL 等价）。
// 接口保真：装饰层恒实现 ConnBeginTx/ConnPrepareContext/QueryerContext/ExecerContext/
// Pinger/Validator/SessionResetter 全部可选接口——base 未实现的加速路径返回 driver.ErrSkip
// 交还 database/sql 既有 fallback（Prepare 路径），base 能力集合与调用路径零漂移。
// 依赖方向：storage→observability（架构第四章允许集合内，非业务依赖）。
// 修改历史：
//
//	2026-09-27 06:16:00 | 新建 | U21 可观测性增强（计划书步骤 3，G2 批准 2026-09-27 06:13:36）
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"sync/atomic"
	"time"

	"GRmail/internal/observability"
)

// SQLLogConf SQL 观测配置快照（Q3-A：config.Log 三键的运行态投影；L-C 增第四键）。
// main 装配经 SetSQLLogConf 注入并随热加载订阅刷新；零值=全关（装饰器仅计时零输出）。
type SQLLogConf struct {
	SlowMs    int  // 慢查询阈值毫秒（0=禁用）
	Debug     bool // SQL 全量 Debug 输出
	CommentID bool // SQL 注释注入 log_id（L-C——直连路径前缀注释；缺省 false）
}

// sqlLogConfPtr 当前配置快照（atomic 无锁读——每查询读取热生效）。
var sqlLogConfPtr atomic.Pointer[SQLLogConf]

// SetSQLLogConf 更新 SQL 观测配置快照（main 装配初始注入+热加载订阅刷新双入口）。
func SetSQLLogConf(c SQLLogConf) { sqlLogConfPtr.Store(&c) }

// currentSQLLogConf 读取快照（零值安全）。
func currentSQLLogConf() SQLLogConf {
	if p := sqlLogConfPtr.Load(); p != nil {
		return *p
	}
	return SQLLogConf{}
}

// sqlLogSummaryMax SQL 语句摘要截断上限（防日志膨胀——全量 debug 与慢查询同口径）。
const sqlLogSummaryMax = 256

// logSQL 单条语句观测输出（装饰器统一出口）。
// 参数：ctx 调用链上下文（携带 log_id 的 logger——NFR-016 关联锚）；op 操作类型
// （query/exec/begin/commit/rollback）；query 语句原文（截断）；d 耗时；err 执行错误（可空）。
func logSQL(ctx context.Context, op, query string, d time.Duration, err error) {
	conf := currentSQLLogConf()
	slowThreshold := time.Duration(conf.SlowMs) * time.Millisecond
	isSlow := conf.SlowMs > 0 && d >= slowThreshold
	if !conf.Debug && !isSlow {
		return // 缺省态零输出（仅计时开销——time.Since 纳秒级）
	}
	logger := observability.LoggerFromContext(ctx)
	summary := query
	if len(summary) > sqlLogSummaryMax {
		summary = summary[:sqlLogSummaryMax] + "…(截断)"
	}
	attrs := []any{"op", op, "sql", summary, "cost_ms", float64(d.Nanoseconds()) / 1e6}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	if conf.Debug {
		logger.Debug("SQL 执行", attrs...) // H4 ShowSQL 等价（全量，排障时开启）
	}
	if isSlow {
		logger.Warn("SQL 慢查询", attrs...) // 慢查询告警（阈值 sqlSlowMs）
	}
}

// ───────────────────────── 装饰驱动注册 ─────────────────────────

var (
	instrumentedMu    sync.Mutex
	instrumentedNames = map[string]string{} // base 驱动名 → 包装名（幂等注册）
)

// registerInstrumentedDriver 以包装名注册观测装饰驱动（幂等）。
// 参数：name base 驱动短名（sqlite/mysql/pgx——仅用于包装名拼接与幂等键）；base 底层驱动实例
// （db.go 三 case 具名 import 构造）。返回：包装驱动名（GRmail-<name>）。
func registerInstrumentedDriver(name string, base driver.Driver) (string, error) {
	instrumentedMu.Lock()
	defer instrumentedMu.Unlock()
	if wrapped, ok := instrumentedNames[name]; ok {
		return wrapped, nil // 幂等：重复 Open（测试多库）复用既有注册
	}
	wrapped := "GRmail-" + name
	sql.Register(wrapped, &instrumentedDriver{base: base})
	instrumentedNames[name] = wrapped
	return wrapped, nil
}

// instrumentedDriver 装饰驱动（Open 包装连接）。
type instrumentedDriver struct {
	base driver.Driver
}

// Open 打开底层连接并包装（连接级装饰入口）。
func (d *instrumentedDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return &instrumentedConn{base: conn}, nil
}

// ───────────────────────── 连接装饰 ─────────────────────────

// instrumentedConn 装饰连接（driver.Conn 必需三方法+全部可选接口动态分派）。
type instrumentedConn struct {
	base driver.Conn
}

// Prepare 必需路径（database/sql 无 ConnPrepareContext 时的 fallback）——委托+包装语句。
func (c *instrumentedConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.base.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &instrumentedStmt{base: stmt, query: query}, nil
}

// Close 关闭底层连接。
func (c *instrumentedConn) Close() error { return c.base.Close() }

// Begin 必需路径事务开始（无 ctx——database/sql 未走 BeginTx 时的直连调用）。
func (c *instrumentedConn) Begin() (driver.Tx, error) {
	tx, err := c.base.Begin()
	if err != nil {
		return nil, err
	}
	return &instrumentedTx{base: tx}, nil
}

// PrepareContext 上下文 Prepare（base 实现 ConnPrepareContext 则委托，否则走必需 Prepare）。
func (c *instrumentedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	pc, ok := c.base.(driver.ConnPrepareContext)
	if !ok {
		return c.Prepare(query)
	}
	start := time.Now()
	stmt, err := pc.PrepareContext(ctx, query)
	logSQL(ctx, "prepare", query, time.Since(start), err)
	if err != nil {
		return nil, err
	}
	return &instrumentedStmt{base: stmt, query: query}, nil
}

// QueryContext 加速路径查询拦截（base 未实现 QueryerContext 时返回 ErrSkip 交还
// database/sql 走 Prepare fallback——调用路径与未装饰时一致）。
func (c *instrumentedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := c.base.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	rows, err := q.QueryContext(ctx, queryWithLogIDComment(ctx, query), args) // L-C：注释注入（开关开启时）
	logSQL(ctx, "query", query, time.Since(start), err)
	return rows, err
}

// ExecContext 加速路径执行拦截（同 QueryContext 的 ErrSkip 语义）。
func (c *instrumentedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	e, ok := c.base.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	res, err := e.ExecContext(ctx, queryWithLogIDComment(ctx, query), args) // L-C：注释注入（开关开启时）
	logSQL(ctx, "exec", query, time.Since(start), err)
	return res, err
}

// queryWithLogIDComment SQL 文本 log_id 注释前缀（L-C——D8#7：开启 sqlCommentId 且 ctx
// 携带 LogID 时返回 "/*logid:<id>*/ <原语句>"；关闭/缺 ID 返回原文。三库均支持块注释
// 语法透传；Prepare 路径不注入〔预编译语句文本固定——注入破坏参数化缓存〕）。
func queryWithLogIDComment(ctx context.Context, query string) string {
	if !currentSQLLogConf().CommentID {
		return query
	}
	id := observability.LogIDFromContext(ctx)
	if id == "" {
		return query
	}
	return "/*logid:" + id + "*/ " + query
}

// BeginTx 上下文事务开始（装饰层恒实现——database/sql 优先选择本路径；base 无
// ConnBeginTx 能力时退调必需 Begin，能力集合与计时双保真）。
func (c *instrumentedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	bt, ok := c.base.(driver.ConnBeginTx)
	start := time.Now()
	var (
		tx  driver.Tx
		err error
	)
	if ok {
		tx, err = bt.BeginTx(ctx, opts)
	} else {
		tx, err = c.base.Begin()
	}
	logSQL(ctx, "exec", "BEGIN", time.Since(start), err)
	if err != nil {
		return nil, err
	}
	return &instrumentedTx{base: tx}, nil
}

// Ping 连通性探活透传（base 实现 Pinger 时；未实现返回 ErrSkip 交还 database/sql
// 用自身探活语义——保真）。
func (c *instrumentedConn) Ping(ctx context.Context) error {
	p, ok := c.base.(driver.Pinger)
	if !ok {
		return driver.ErrSkip
	}
	return p.Ping(ctx)
}

// IsValid 连接有效性判定透传（连接池健康检查；base 未实现返回 true 保真——
// database/sql 对未实现者视为有效）。
func (c *instrumentedConn) IsValid() bool {
	if v, ok := c.base.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

// ResetSession 会话重置透传（连接池复用；base 未实现返回 nil——database/sql 同语义）。
func (c *instrumentedConn) ResetSession(ctx context.Context) error {
	if s, ok := c.base.(driver.SessionResetter); ok {
		return s.ResetSession(ctx)
	}
	return nil
}

// ───────────────────────── 语句装饰 ─────────────────────────

// instrumentedStmt 装饰预编译语句（Prepare 路径的执行拦截；query 为 Prepare 时绑定的
// 语句原文——StmtExecContext/StmtQueryContext 接口签名不含 query，经本字段承载日志源）。
type instrumentedStmt struct {
	base  driver.Stmt
	query string
}

// Close 关闭底层语句。
func (s *instrumentedStmt) Close() error { return s.base.Close() }

// NumInput 参数占位数（-1=驱动不自知）。
func (s *instrumentedStmt) NumInput() int { return s.base.NumInput() }

// Exec 必需路径执行（无 ctx 版本）。
func (s *instrumentedStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.base.Exec(args)
}

// Query 必需路径查询（无 ctx 版本）。
func (s *instrumentedStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.base.Query(args)
}

// ExecContext 上下文执行拦截（实现 driver.StmtExecContext——签名无 query 参数，语句
// 原文经结构字段承载；base 未实现时返回 ErrSkip 交还 database/sql 走必需 Exec 路径）。
func (s *instrumentedStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	se, ok := s.base.(driver.StmtExecContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	res, err := se.ExecContext(ctx, args)
	logSQL(ctx, "exec", s.query, time.Since(start), err)
	return res, err
}

// QueryContext 上下文查询拦截（实现 driver.StmtQueryContext；ErrSkip 语义同上）。
func (s *instrumentedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	sq, ok := s.base.(driver.StmtQueryContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	rows, err := sq.QueryContext(ctx, args)
	logSQL(ctx, "query", s.query, time.Since(start), err)
	return rows, err
}

// ───────────────────────── 事务装饰 ─────────────────────────

// instrumentedTx 装饰事务（Commit/Rollback 计时输出）。
type instrumentedTx struct {
	base driver.Tx
	ctx  context.Context // Begin 时携带（事务操作无 ctx 入参——沿用事务起点关联）
}

// Commit 提交事务（计时）。
func (t *instrumentedTx) Commit() error {
	start := time.Now()
	err := t.base.Commit()
	logSQL(t.ctx, "exec", "COMMIT", time.Since(start), err)
	return err
}

// Rollback 回滚事务（计时）。
func (t *instrumentedTx) Rollback() error {
	start := time.Now()
	err := t.base.Rollback()
	logSQL(t.ctx, "exec", "ROLLBACK", time.Since(start), err)
	return err
}

// ensureInterfaceCoverage 编译期断言：装饰层实现全部可选接口（database/sql 能力
// 探测面完整——漏实现任一将使 base 能力静默丢失，调用路径漂移）。
var (
	_ driver.ConnBeginTx        = (*instrumentedConn)(nil)
	_ driver.ConnPrepareContext = (*instrumentedConn)(nil)
	_ driver.QueryerContext     = (*instrumentedConn)(nil)
	_ driver.ExecerContext      = (*instrumentedConn)(nil)
	_ driver.Pinger             = (*instrumentedConn)(nil)
	_ driver.Validator          = (*instrumentedConn)(nil)
	_ driver.SessionResetter    = (*instrumentedConn)(nil)
	_ driver.StmtExecContext    = (*instrumentedStmt)(nil)
	_ driver.StmtQueryContext   = (*instrumentedStmt)(nil)
	_ driver.Driver             = (*instrumentedDriver)(nil)
)
