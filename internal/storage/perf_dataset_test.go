//go:build perf

// 性能基准验证批次 P-A：十万封级测试数据集直写构造器（S3-W Q1-A 裁决——storage
// 层直写：Blob CAS 批量写+messages/mailbox_messages 批量落库，绕过 SMTP 投递管道；
// 基准对象为查询/列表路径〔NFR-001 主路径——契约 v1.22.0 2.1 PageList/Search〕非
// 投递路径）。
// 覆盖锚点：SRS NFR-001/NFR-002（4.1 必须具备）前置——TC-017/TC-018 验收条件
// 「预置 100,000 封测试邮件库」（确认测试计划 v1.1.0）。
// 隔离锚点：//go:build perf tag——常规 `go test ./...`（17 包回归）零触发（计划书
// 1.3-6 边界：30 分钟用例不进常规链）。
// 数据分布（可复现锚——固定 seed，分布参数落 CHANGE5 第四章）：
//   - 文件夹：inbox 85% / sent 5% / drafts 5% / junk 3% / trash 2%
//   - 已读 70%；主题变长 10~64 字符（词池组合）；正文 1~8KB 变长；Date 头跨度 365 天
//   - 10% 行主题植入采样命中词（TC-017 命中路径锚）
//
// 修改历史：
//
//	2026-10-03 11:55:00 | 新建 | 性能基准验证批次 P-A（G2 批准 2026-10-03 11:51:26）
package storage_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"GRmail/internal/config"
	"GRmail/internal/storage"
)

// perfMigrateMu goose 迁移并发防线（t.Parallel 库级并行下 embed provider 全局态
// 竞争——迁移段串行化；迁移后业务操作仍并行）。
var perfMigrateMu sync.Mutex

// perfDatasetScale 数据集规模常量（TC-017/018 验收条件口径——十万封级）。
const perfDatasetScale = 100_000

// perfHitKeyword TC-017 命中采样词（构造期植入 10% 行主题）。
const perfHitKeyword = "基准采样锚点"

// perfMissKeyword TC-017 未命中采样词（构造数据不可能包含——词池之外构造）。
const perfMissKeyword = "ZZQ不存在的词QQZ"

// 三库实测 DSN（沿 u11_integration_test.go 1.5⑧ 收敛口径——compose 13306/15432）。
const (
	// compose 预建库 grmail（deploy/docker-compose.yml MYSQL_DATABASE/POSTGRES_DB）——
	// 沿 u11 DSN 口径零环境改动；重复跑经 perfOpenEnv 清表重建幂等
	perfMySQLDSN = "root:grmail@tcp(127.0.0.1:13306)/grmail?parseTime=true&loc=UTC&charset=utf8mb4&collation=utf8mb4_bin&sql_mode=ANSI_QUOTES"
	perfPGDSN    = "postgres://postgres:grmail@127.0.0.1:15432/grmail?sslmode=disable"
)

// perfEnv 单库基准环境（构造器与两 TC 采样共享）。
type perfEnv struct {
	t         *testing.T
	driver    string
	db        *sql.DB
	repos     *storage.RepoSet
	blobs     *storage.FileSystemBlobStore
	mailboxID int64
	folders   map[string]int64 // kind 名 → folder id（inbox/sent/drafts/junk/trash）
	buildCost time.Duration    // 构造耗时（落档锚）
}

// perfPlaceholder 按方言生成 n 参占位符串（sqlite/mysql=?、postgres=$1..$n）。
func perfPlaceholder(driver string, n int) string {
	if driver == "postgres" {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("$%d", i+1)
		}
		return strings.Join(parts, ",")
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// perfOpenEnv 打开目标库并完成迁移与邮箱/文件夹初始化（重复跑先清库重建——幂等）。
func perfOpenEnv(t *testing.T, driver, dsn string) *perfEnv {
	t.Helper()
	ctx := context.Background()

	var root string
	if driver == "sqlite" {
		root = t.TempDir()
		dsn = filepath.Join(root, "perf.db")
	} else {
		root = t.TempDir()
	}
	conf := config.DatabaseConf{Driver: driver, DSN: dsn}
	db, err := storage.Open(ctx, conf)
	if err != nil {
		t.Fatalf("[%s] 连接基准库: %v", driver, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// 幂等重建：真库重复跑先整删全部业务表+goose 版本表（DROP——goose 行为特性：
	// 版本表存在但行空时报「no next version found」而非全量重迁；整表删除后 goose
	// 重建版本表+初始行+从零跑全部迁移；DROP 兼清自增序列残留态）。表序按 FK 依赖
	// 逆序（子表先删——MySQL 外键检查下父表先 DROP 会 3730）。
	if driver != "sqlite" {
		for _, tbl := range []string{
			"mailbox_keywords", "mailbox_messages", "delivery_queue", "sieve_scripts",
			"api_tokens", "login_attempts", "sessions", "messages", "folders", "mailboxes", "users",
		} {
			if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", tbl)); err != nil {
				t.Fatalf("[%s] 删表 %s: %v", driver, tbl, err)
			}
		}
		if _, err := db.Exec(`DROP TABLE IF EXISTS goose_db_version`); err != nil {
			t.Fatalf("[%s] 删版本表: %v", driver, err)
		}
	}
	perfMigrateMu.Lock()
	err = storage.MigrateUp(ctx, db, driver)
	perfMigrateMu.Unlock()
	if err != nil {
		t.Fatalf("[%s] 迁移基准库: %v", driver, err)
	}
	repos, err := storage.NewRepoSet(conf, db)
	if err != nil {
		t.Fatalf("[%s] 装配 RepoSet: %v", driver, err)
	}

	env := &perfEnv{
		t: t, driver: driver, db: db, repos: repos,
		blobs: storage.NewFileSystemBlobStore(filepath.Join(root, "blobs")),
	}
	env.initMailbox(ctx)
	return env
}

// initMailbox 建立 active 测试邮箱并收集五系统文件夹 id（文件夹分布落库依据）。
func (e *perfEnv) initMailbox(ctx context.Context) {
	e.t.Helper()
	mb := &storage.Mailbox{
		LocalPart: "perf", Domain: "bench.test",
		Address: "perf@bench.test", Status: storage.MailboxStatusActive,
	}
	if err := e.repos.Mailboxes.Create(ctx, mb); err != nil {
		e.t.Fatalf("[%s] 建基准邮箱: %v", e.driver, err)
	}
	e.mailboxID = mb.ID
	folders, err := e.repos.Folders.List(ctx, mb.ID)
	if err != nil || len(folders) < 5 {
		e.t.Fatalf("[%s] 列系统文件夹: n=%d err=%v", e.driver, len(folders), err)
	}
	e.folders = make(map[string]int64, len(folders))
	for _, f := range folders {
		e.folders[string(f.Kind)] = f.ID
	}
}

// perfSubjectPool 主题词池（变长组合源——中文/英文/数字混合形态）。
var perfSubjectPool = []string{
	"周报", "会议纪要", "订单确认", "账单通知", "系统告警", "验证码", "邀请函",
	"invoice", "weekly report", "deployment notice", "security alert", "newsletter",
	"项目进展同步", "评审安排", "假期审批", "服务器巡检", "备份完成", "更新公告",
}

// perfSenderPool 发件人地址池（from_addr 分布源）。
var perfSenderPool = []string{
	"alice@corp.example", "bob@corp.example", "carol@mail.example", "dave@svc.example",
	"noreply@shop.example", "alert@mon.example", "hr@corp.example", "bot@ci.example",
	"support@saas.example", "news@press.example",
}

// perfBodyFor 生成第 i 封的变长原始字节（1~8KB——长度按 i 摊派保证可复现）。
func perfBodyFor(i int) []byte {
	size := 1024 + (i*7)%7168 // 1KB~8KB 确定性摊派
	body := make([]byte, size)
	fill := []byte("0123456789abcdefghijklmnopqrstuvwxyz基准正文样本")
	for p := 0; p < size; p += len(fill) {
		copy(body[p:], fill)
	}
	// 每封唯一化后缀（防内容碰撞导致 blob_key 集中）
	tag := fmt.Sprintf("#msg-%d@", i)
	copy(body[len(body)-len(tag):], tag)
	return body
}

// perfBuildDataset 批量直写十万封（S3-W Q1-A）：blob 先行批量 CAS 写（事务外文件
// 系统），随后 messages+mailbox_messages 单事务分批落库（5000/批——防单事务锁库）。
// 字段分布见文件头注释；耗时落 e.buildCost（CHANGE5 第四章锚）。
func (e *perfEnv) perfBuildDataset(ctx context.Context) {
	e.t.Helper()
	start := time.Now()
	rng := mathrand.New(mathrand.NewSource(20261003)) // 固定 seed——可复现锚

	// 1. blob 批量写（CAS 幂等；十万文件×fsync——耗时如实计入构造总时长；
	//    写入字节与 key 同源——sha256(body) 内容寻址语义保持，Read 回读一致）
	keys := make([]string, perfDatasetScale)
	for i := 0; i < perfDatasetScale; i++ {
		body := perfBodyFor(i)
		sum := sha256.Sum256(body)
		keys[i] = hex.EncodeToString(sum[:])
		if err := e.blobs.Write(ctx, keys[i], body); err != nil {
			e.t.Fatalf("[%s] blob 写 %d: %v", e.driver, i, err)
		}
	}

	// 2. 元数据分批事务落库（直写——批量 INSERT 单事务 5000/批）
	const batch = 5000
	folderPlan := e.folderPlan(rng)
	now := time.Now().UTC()
	phMsg := perfPlaceholder(e.driver, 13)
	phMM := perfPlaceholder(e.driver, 8)
	uid := int64(0)
	for base := 0; base < perfDatasetScale; base += batch {
		end := base + batch
		if end > perfDatasetScale {
			end = perfDatasetScale
		}
		tx, err := e.db.BeginTx(ctx, nil)
		if err != nil {
			e.t.Fatalf("[%s] 开事务 @%d: %v", e.driver, base, err)
		}
		// PG 驱动（pgx）不支持 LastInsertId——RETURNING id 形态；sqlite/mysql 走自增回取
		returningSuffix := ""
		if e.driver == "postgres" {
			returningSuffix = " RETURNING id"
		}
		stmtMsg, err := tx.PrepareContext(ctx, fmt.Sprintf(
			`INSERT INTO messages (blob_key,raw_size,subject,from_addr,to_addrs,body_cache,sent_at,
			 spf_result,dkim_result,dmarc_result,arc_result,auth_results_header,created_at)
			 VALUES (%s)%s`, phMsg, returningSuffix))
		if err != nil {
			e.t.Fatalf("[%s] 预编译 messages: %v", e.driver, err)
		}
		stmtMM, err := tx.PrepareContext(ctx, fmt.Sprintf(
			`INSERT INTO mailbox_messages (mailbox_id,folder_id,message_id,uid,is_read,is_flagged,status,created_at)
			 VALUES (%s)`, phMM))
		if err != nil {
			e.t.Fatalf("[%s] 预编译 mailbox_messages: %v", e.driver, err)
		}
		for i := base; i < end; i++ {
			subject := perfSubjectOf(rng, i)
			body := perfBodyFor(i)
			sentAt := now.Add(-time.Duration(rng.Intn(365*24)) * time.Hour)
			msgArgs := []any{
				keys[i], len(body), subject,
				perfSenderPool[rng.Intn(len(perfSenderPool))],
				`["perf@bench.test"]`, perfBodyCacheOf(body),
				sentAt,
				"pass", "pass", "pass", "none", "Authentication-Results: mx.test; spf=pass",
				sentAt, // created_at NOT NULL（落库时刻语义——构造直写与 sent_at 同源分布）
			}
			var msgID int64
			if e.driver == "postgres" {
				if err = stmtMsg.QueryRowContext(ctx, msgArgs...).Scan(&msgID); err != nil {
					e.t.Fatalf("[%s] 插 messages %d（RETURNING）: %v", e.driver, i, err)
				}
			} else {
				res, ierr := stmtMsg.ExecContext(ctx, msgArgs...)
				if ierr != nil {
					e.t.Fatalf("[%s] 插 messages %d: %v", e.driver, i, ierr)
				}
				if msgID, err = res.LastInsertId(); err != nil {
					e.t.Fatalf("[%s] 取 messages id %d: %v", e.driver, i, err)
				}
			}
			uid++
			isRead := rng.Intn(100) < 70
			if _, err = stmtMM.ExecContext(ctx,
				e.mailboxID, folderPlan[i], msgID, uid, isRead, false, "normal",
				now.Add(-time.Duration(rng.Intn(365*24))*time.Hour),
			); err != nil {
				e.t.Fatalf("[%s] 插 mailbox_messages %d: %v", e.driver, i, err)
			}
		}
		_ = stmtMsg.Close()
		_ = stmtMM.Close()
		if err = tx.Commit(); err != nil {
			e.t.Fatalf("[%s] 提交事务 @%d: %v", e.driver, base, err)
		}
	}
	e.buildCost = time.Since(start)

	// 3. 行数断言（验收条件：十万封全量落库）
	var n int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM mailbox_messages WHERE mailbox_id = $1`,
		e.mailboxID).Scan(&n); err != nil {
		// PG 用 $1，sqlite/mysql 用 ?——按方言重试（Scan 断言辅助的方言分叉收敛）
		q := strings.ReplaceAll(`SELECT COUNT(*) FROM mailbox_messages WHERE mailbox_id = $1`, "$1", perfPlaceholder(e.driver, 1))
		if err = e.db.QueryRow(q, e.mailboxID).Scan(&n); err != nil {
			e.t.Fatalf("[%s] 计数: %v", e.driver, err)
		}
	}
	if n != perfDatasetScale {
		e.t.Fatalf("[%s] 落库行数应 %d: %d", e.driver, perfDatasetScale, n)
	}
}

// folderPlan 预生成每封的目标文件夹 id 序列（85/5/5/3/2 分布——rng 确定性）。
func (e *perfEnv) folderPlan(rng *mathrand.Rand) []int64 {
	plan := make([]int64, perfDatasetScale)
	inbox, ok := e.folders["inbox"]
	if !ok {
		e.t.Fatalf("[%s] inbox 文件夹缺失", e.driver)
	}
	for i := range plan {
		switch p := rng.Intn(100); {
		case p < 85:
			plan[i] = inbox
		case p < 90:
			plan[i] = e.folderOf("sent", inbox)
		case p < 95:
			plan[i] = e.folderOf("drafts", inbox)
		case p < 98:
			plan[i] = e.folderOf("junk", inbox)
		default:
			plan[i] = e.folderOf("trash", inbox)
		}
	}
	return plan
}

// folderOf 取指定 kind 文件夹 id（缺省回退 inbox——防御：邮箱初始化五系统必有）。
func (e *perfEnv) folderOf(kind string, fallback int64) int64 {
	if id, ok := e.folders[kind]; ok {
		return id
	}
	return fallback
}

// perfSubjectOf 生成第 i 封主题：变长词组合+序号；每 10 封植入命中词（TC-017 锚）。
func perfSubjectOf(rng *mathrand.Rand, i int) string {
	words := perfSubjectPool[rng.Intn(len(perfSubjectPool))]
	if i%10 == 0 {
		return fmt.Sprintf("%s-%s-%d", words, perfHitKeyword, i)
	}
	return fmt.Sprintf("%s-%d", words, i)
}

// perfBodyCacheOf 正文缓存截断（沿 U16 bodyCacheMaxBytes=65536 上限内取 512B 采样）。
func perfBodyCacheOf(body []byte) string {
	if len(body) > 512 {
		return string(body[:512])
	}
	return string(body)
}

// perfRandomHex 测试辅助：n 字节随机 hex（TC-018 会话/凭据构造备用）。
func perfRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TestPerfDatasetBuild 构造器自检：十万封三库（SQLite 本地必跑；MySQL/PG compose
// 就绪时跑——netDialProbe 跳过语义沿 u11 先例）。行数+耗时落档输出。
func TestPerfDatasetBuild(t *testing.T) {
	for _, c := range []struct{ driver, dsn string }{
		{"sqlite", ""},
		{"mysql", perfMySQLDSN},
		{"postgres", perfPGDSN},
	} {
		t.Run(c.driver, func(t *testing.T) {
			t.Parallel() // 三库独立连接——库级并行（测试间保持串行防同库清表竞争）
			if c.driver != "sqlite" && !perfDBReady(t, c.driver) {
				t.Skipf("%s 容器未就绪——跳过（沿 u11 环境口径；实录见 CHANGE5）", c.driver)
			}
			env := perfOpenEnv(t, c.driver, c.dsn)
			env.perfBuildDataset(context.Background())
			// 采样命中锚断言：命中词行数 ≈ 10%（词植入确定性——i%10）
			var hits int
			q := fmt.Sprintf(`SELECT COUNT(*) FROM messages WHERE subject LIKE %s`,
				perfLikeArg(c.driver))
			if err := env.db.QueryRow(q, "%"+perfHitKeyword+"%").Scan(&hits); err != nil {
				t.Fatalf("[%s] 命中计数: %v", c.driver, err)
			}
			if hits < perfDatasetScale/10-100 || hits > perfDatasetScale/10+100 {
				t.Fatalf("[%s] 命中词行数异常: %d（期望≈%d）", c.driver, hits, perfDatasetScale/10)
			}
			t.Logf("[%s] 构造完成：规模=%d 耗时=%v 命中词行≈%d", c.driver, perfDatasetScale, env.buildCost, hits)
		})
	}
}

// perfLikeArg LIKE 通配参数占位符（PG 与 sqlite/mysql 同用单参占位形态——经方言占位符收敛）。
func perfLikeArg(driver string) string { return perfPlaceholder(driver, 1) }

// perfDBReady 真库探活（沿 u11 netDialProbe 语义——external 包内重实现）。
func perfDBReady(t *testing.T, driver string) bool {
	t.Helper()
	addr := "127.0.0.1:13306"
	if driver == "postgres" {
		addr = "127.0.0.1:15432"
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// perfP95 升序采样序列的第 95 百分位（计划书 2.3-4 口径：⌈0.95×N⌉ 位）。
func perfP95(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	idx := (95*len(sorted) + 99) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// perfRandIntn 密码学随机辅助（TC-018 操作循环分布用——CSPRNG 与构造 seed 独立）。
func perfRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0 // CSPRNG 失败兜底 0（采样循环容错——非安全路径）
	}
	return int(v.Int64())
}
