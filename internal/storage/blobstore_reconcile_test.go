// storage 域 F7 单测：blob 目录对账（D2/B-R1——流程设计第四章第 2 条既有承诺
// 兑现：孤儿删除+DB 引用而文件缺失告警不删行）。
// SRS 条目：CON-004（2.3 伴随——存储完整性维度）；NFR-016（告警可观测）；TC-021 关联锚。
// 修改历史：
//
//	2026-10-07 09:07:00 | 新建 | 队列防丢信收口批（计划书 2.3 新增测试⑤；
//	G2 批准 2026-10-07 01:03:52）
package storage

import (
	"context"
	"log/slog"
	"testing"
)

// TestReconcileBlobDirOrphanAndMissing F7 双态：仅文件系统存在→孤儿删除；
// 仅 DB 引用→missing 告警计数（文件不删——人工介入面）；被引用文件保留。
func TestReconcileBlobDirOrphanAndMissing(t *testing.T) {
	ctx := context.Background()
	s := NewFileSystemBlobStore(t.TempDir())
	kRef := ComputeBlobKey([]byte("referenced"))
	kOrphan := ComputeBlobKey([]byte("orphan"))
	if err := s.Write(ctx, kRef, []byte("referenced")); err != nil {
		t.Fatalf("写入被引用 blob: %v", err)
	}
	if err := s.Write(ctx, kOrphan, []byte("orphan")); err != nil {
		t.Fatalf("写入孤儿 blob: %v", err)
	}
	kMissing := ComputeBlobKey([]byte("missing-from-fs")) // DB 引用而文件不存在
	referenced := func(context.Context) ([]string, error) {
		return []string{kRef, kMissing}, nil
	}
	orphans, missing := ReconcileBlobDir(ctx, s, referenced, slog.Default())
	if orphans != 1 || missing != 1 {
		t.Fatalf("对账结果应 orphans=1 missing=1: %d/%d", orphans, missing)
	}
	if ok, _ := s.Exists(ctx, kRef); !ok {
		t.Fatalf("被引用文件不应删除（误删零容忍——计划书 4.2 失败判定⑥防线）")
	}
	if ok, _ := s.Exists(ctx, kOrphan); ok {
		t.Fatalf("孤儿文件应已删除")
	}
}

// TestReconcileBlobDirCleanState F7 正常态：全引用零动作（orphans=0/missing=0，
// 文件全保留）。
func TestReconcileBlobDirCleanState(t *testing.T) {
	ctx := context.Background()
	s := NewFileSystemBlobStore(t.TempDir())
	k1 := ComputeBlobKey([]byte("one"))
	k2 := ComputeBlobKey([]byte("two"))
	for k, d := range map[string][]byte{k1: []byte("one"), k2: []byte("two")} {
		if err := s.Write(ctx, k, d); err != nil {
			t.Fatalf("写入 %s: %v", k, err)
		}
	}
	referenced := func(context.Context) ([]string, error) { return []string{k1, k2}, nil }
	orphans, missing := ReconcileBlobDir(ctx, s, referenced, slog.Default())
	if orphans != 0 || missing != 0 {
		t.Fatalf("正常态应零动作: %d/%d", orphans, missing)
	}
	for _, k := range []string{k1, k2} {
		if ok, _ := s.Exists(ctx, k); !ok {
			t.Fatalf("正常态文件应全保留: %s", k)
		}
	}
}
