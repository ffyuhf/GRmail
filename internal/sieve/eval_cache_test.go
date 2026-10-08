// 性能批 F5（B-P4，评审修复批次 7）验收测试：Sieve 编译缓存。
// 依据：性能批_计划_20261008_10-08-00_v1.0.0 步骤 2（G2 批准 2026-10-08 10:13:49）；
// rfc5228 §2.10.6 错误即停行为保持（缓存不得改变求值语义）。
package sieve

import (
	"testing"

	grmail "GRmail/internal/mail"
)

// TestParseCachedSameContentHits 同内容二次解析命中缓存——返回同一 AST 指针
// （Parse 全流程零开销；AST 只读共享安全）。
func TestParseCachedSameContentHits(t *testing.T) {
	r := NewRunner(nil)
	src := "require \"fileinto\";\nif header :contains \"subject\" \"x\" { fileinto \"F\"; }"
	a1, err := r.parseCached(src)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := r.parseCached(src)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatal("同内容应命中缓存返回同一 AST 指针")
	}
}

// TestParseCachedContentChangeInvalidates 内容变更天然失效（哈希键不同即新条目——
// PUTSCRIPT/DELETE 零联动成本）。
func TestParseCachedContentChangeInvalidates(t *testing.T) {
	r := NewRunner(nil)
	a1, err := r.parseCached("keep;")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := r.parseCached("stop;")
	if err != nil {
		t.Fatal(err)
	}
	if a1 == a2 {
		t.Fatal("不同内容应为不同条目")
	}
}

// TestParseCachedSyntaxErrorNotCached 解析失败不入缓存（每次重试——错误即停语义
// 保持，rfc5228 §2.10.6）。
func TestParseCachedSyntaxErrorNotCached(t *testing.T) {
	r := NewRunner(nil)
	if _, err := r.parseCached("if x {"); err == nil {
		t.Fatal("语法错误应返回错误")
	}
	if len(r.astCache) != 0 {
		t.Fatalf("解析失败不应入缓存, cache=%d", len(r.astCache))
	}
}

// TestCachedEvalResultEquivalent 缓存路径与直连 Parse 路径求值结果等价
// （行为等价锚——缓存不改变求值输出）。
func TestCachedEvalResultEquivalent(t *testing.T) {
	r := NewRunner(nil)
	src := "if header :contains \"subject\" \"promo\" { fileinto \"Ads\"; }"
	evalCtx := &grmail.EvalContext{Headers: map[string][]string{"subject": {"weekly promo"}}}
	ast, err := r.parseCached(src)
	if err != nil {
		t.Fatal(err)
	}
	viaCache, err := evalScript(ast, evalCtx)
	if err != nil {
		t.Fatal(err)
	}
	directAST, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := evalScript(directAST, evalCtx)
	if err != nil {
		t.Fatal(err)
	}
	if viaCache.FileInto != direct.FileInto || viaCache.Discard != direct.Discard ||
		viaCache.FlagSeen != direct.FlagSeen || viaCache.FlagFlagged != direct.FlagFlagged ||
		len(viaCache.Redirects) != len(direct.Redirects) {
		t.Fatalf("缓存求值结果应与直连一致: cache=%+v direct=%+v", viaCache, direct)
	}
	if viaCache.FileInto != "Ads" {
		t.Fatalf("求值命中应产生 fileinto Ads, got %q", viaCache.FileInto)
	}
}

// TestParseCachedEvictionOverLimit 超上限淘汰不 panic（sieveCacheMax 上限防御）。
func TestParseCachedEvictionOverLimit(t *testing.T) {
	r := NewRunner(nil)
	for i := 0; i < sieveCacheMax+10; i++ {
		src := "keep; # variant " + string(rune('a'+i%26)) + string(rune('0'+i/26))
		if _, err := r.parseCached(src); err != nil {
			t.Fatalf("第 %d 条解析失败: %v", i, err)
		}
	}
	if len(r.astCache) > sieveCacheMax {
		t.Fatalf("缓存条目应不超上限 %d, got %d", sieveCacheMax, len(r.astCache))
	}
}
