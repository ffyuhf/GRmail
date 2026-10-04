//go:build perf

// 性能基准验证批次 P-B：TC-017 十万封级查询响应 P95 采样（NFR-001——确认测试
// 计划 v1.1.0 TC-017 判定标准「P95 ≤ 2 秒」逐项兑现）。
// 采样口径（计划书 2.3-4）：
//   - 分页：PageList 随机页码 ×100（25 条/页——Webmail 缺省页深，inbox 文件夹）
//   - 搜索：Search 命中词 ×50（≈10% 行命中面）+ 未命中词 ×50（全表扫描路径）
//   - 预热 10 轮剔除（冷启动页缓存/JIT 偏差）；P95=升序 ⌈0.95×N⌉ 位
//   - 断言 P95 ≤ 2s（超标→t.Fatalf 登记缺陷数据——计划书 4.2-1：本批次不优化）
//
// 修改历史：
//
//	2026-10-03 11:58:00 | 新建 | 性能基准验证批次 P-B（G2 批准 2026-10-03 11:51:26）
package storage_test

import (
	"context"
	"testing"
	"time"

	"GRmail/internal/storage"
)

// perfTC017Limits TC-017 采样常量（判定标准口径：各 ≥100 次采样）。
const (
	perfPageSamples  = 100             // 分页采样数
	perfHitSamples   = 50              // 搜索命中采样数
	perfMissSamples  = 50              // 搜索未命中采样数
	perfWarmupRounds = 10              // 预热剔除轮数
	perfPageLimit    = 25              // Webmail 缺省页深
	perfP95Budget    = 2 * time.Second // NFR-001 目标值
)

// TestPerfTC017ResponseTime TC-017 三库全量采样（SQLite 必跑；MySQL/PG compose 就绪
// 时跑——S3-W Q2-B 裁决；未就绪 Skip 沿 u11 环境口径如实登记）。
func TestPerfTC017ResponseTime(t *testing.T) {
	for _, c := range []struct{ driver, dsn string }{
		{"sqlite", ""},
		{"mysql", perfMySQLDSN},
		{"postgres", perfPGDSN},
	} {
		t.Run(c.driver, func(t *testing.T) {
			t.Parallel() // 三库独立连接——库级并行
			if c.driver != "sqlite" && !perfDBReady(t, c.driver) {
				t.Skipf("%s 容器未就绪——跳过（降级登记口径见 CHANGE5 第四章）", c.driver)
			}
			env := perfOpenEnv(t, c.driver, c.dsn)
			env.perfBuildDataset(context.Background())
			env.perfRunTC017(t)
		})
	}
}

// perfRunTC017 单库采样执行：预热→分页×100+搜索×100→P95 统计→断言。
func (e *perfEnv) perfRunTC017(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	inbox, ok := e.folders["inbox"]
	if !ok {
		t.Fatalf("[%s] inbox 文件夹缺失", e.driver)
	}

	// 1. 预热 10 轮（分页+搜索各半——页缓存与连接池热身；不计入统计）
	for i := 0; i < perfWarmupRounds; i++ {
		if _, _, err := e.repos.Messages.PageList(ctx, storage.ListQuery{
			MailboxID: e.mailboxID, FolderID: inbox,
			Limit: perfPageLimit, Offset: int32(i * perfPageLimit),
		}); err != nil {
			t.Fatalf("[%s] 预热分页 %d: %v", e.driver, i, err)
		}
		kw := perfHitKeyword
		if i%2 == 1 {
			kw = perfMissKeyword
		}
		if _, _, err := e.repos.Messages.Search(ctx, storage.SearchQuery{
			MailboxID: e.mailboxID, Keyword: kw, Limit: perfPageLimit,
		}); err != nil {
			t.Fatalf("[%s] 预热搜索 %d: %v", e.driver, i, err)
		}
	}

	// 2. 分页采样 ×100（随机页码——覆盖头部/中部/尾部页分布；
	//    页码上界按 inbox 实际行数计算〔构造 85% 分布 ≈8.5 万——全域推算越界〕）
	_, inboxTotal, err := e.repos.Messages.PageList(ctx, storage.ListQuery{
		MailboxID: e.mailboxID, FolderID: inbox, Limit: 1,
	})
	if err != nil || inboxTotal <= 0 {
		t.Fatalf("[%s] inbox 行数探测: total=%d err=%v", e.driver, inboxTotal, err)
	}
	maxPage := int(inboxTotal)/perfPageLimit - 1
	pageSamples := make([]time.Duration, 0, perfPageSamples)
	for i := 0; i < perfPageSamples; i++ {
		page := perfRandIntn(maxPage)
		start := time.Now()
		items, total, err := e.repos.Messages.PageList(ctx, storage.ListQuery{
			MailboxID: e.mailboxID, FolderID: inbox,
			Limit: perfPageLimit, Offset: int32(page * perfPageLimit),
		})
		cost := time.Since(start)
		if err != nil {
			t.Fatalf("[%s] 分页采样 %d: %v", e.driver, i, err)
		}
		if len(items) == 0 || total == 0 {
			t.Fatalf("[%s] 分页采样 %d 空结果: page=%d", e.driver, i, page)
		}
		pageSamples = append(pageSamples, cost)
	}

	// 3. 搜索采样 ×100（命中 50+未命中 50——两种查询计划覆盖）
	hitSamples := make([]time.Duration, 0, perfHitSamples)
	missSamples := make([]time.Duration, 0, perfMissSamples)
	for i := 0; i < perfHitSamples; i++ {
		start := time.Now()
		items, total, err := e.repos.Messages.Search(ctx, storage.SearchQuery{
			MailboxID: e.mailboxID, Keyword: perfHitKeyword, Limit: perfPageLimit,
		})
		cost := time.Since(start)
		if err != nil {
			t.Fatalf("[%s] 命中采样 %d: %v", e.driver, i, err)
		}
		if total == 0 || len(items) == 0 {
			t.Fatalf("[%s] 命中采样 %d 零命中（构造锚失效）", e.driver, i)
		}
		hitSamples = append(hitSamples, cost)
	}
	for i := 0; i < perfMissSamples; i++ {
		start := time.Now()
		_, _, err := e.repos.Messages.Search(ctx, storage.SearchQuery{
			MailboxID: e.mailboxID, Keyword: perfMissKeyword, Limit: perfPageLimit,
		})
		missSamples = append(missSamples, time.Since(start))
		if err != nil {
			t.Fatalf("[%s] 未命中采样 %d: %v", e.driver, i, err)
		}
	}

	// 4. P95 统计与断言（NFR-001 判定锚——超标即 FAIL 保留缺陷数据落 t.Logf）
	pageP95, hitP95, missP95 := perfP95(pageSamples), perfP95(hitSamples), perfP95(missSamples)
	t.Logf("[%s] TC-017 采样结果：分页P95=%v 命中P95=%v 未命中P95=%v（n=%d/%d/%d）",
		e.driver, pageP95, hitP95, missP95,
		len(pageSamples), len(hitSamples), len(missSamples))
	if pageP95 > perfP95Budget {
		t.Fatalf("[%s] NFR-001 分页 P95 超标: %v > %v（缺陷数据已落档——计划书 4.2-1 转裁决）",
			e.driver, pageP95, perfP95Budget)
	}
	if hitP95 > perfP95Budget {
		t.Fatalf("[%s] NFR-001 命中搜索 P95 超标: %v > %v", e.driver, hitP95, perfP95Budget)
	}
	if missP95 > perfP95Budget {
		t.Fatalf("[%s] NFR-001 未命中搜索 P95 超标: %v > %v", e.driver, missP95, perfP95Budget)
	}
}
