// 性能批 F3（B-P3②，评审修复批次 7）验收测试：uidToSeq map 索引一致性。
// 依据：性能批_计划_20261008_10-08-00_v1.0.0 步骤 4（G2 批准 2026-10-08 10:13:49）；
// map 查找与切片线性语义一致（序号=下标+1，rfc9051 2.3.1.2）。
package imap

import "testing"

// TestUIDIndexConsistency map 索引与切片序号一致+未命中返回 0（已 EXPUNGE 防御）。
func TestUIDIndexConsistency(t *testing.T) {
	s := &Session{uids: []int64{10, 20, 30, 40}}
	s.rebuildUIDIndex()
	for i, u := range s.uids {
		if got := s.uidToSeq(u); got != uint32(i+1) {
			t.Fatalf("uid %d: want seq %d, got %d", u, i+1, got)
		}
	}
	if s.uidToSeq(99) != 0 {
		t.Fatal("不存在的 UID 应返回 0")
	}
}

// TestUIDToSeqFallbackLinearScan map 未构建防御态回退线性扫描（nil map 容错）。
func TestUIDToSeqFallbackLinearScan(t *testing.T) {
	s := &Session{uids: []int64{5, 6, 7}}
	if got := s.uidToSeq(6); got != 2 {
		t.Fatalf("防御态线性回退应命中 seq 2, got %d", got)
	}
	if got := s.uidToSeq(8); got != 0 {
		t.Fatalf("防御态未命中应返回 0, got %d", got)
	}
}

// TestUIDIndexClearedOnUnselect Unselect 清空索引（选中态生命周期一致）。
func TestUIDIndexClearedOnUnselect(t *testing.T) {
	s := &Session{uids: []int64{1, 2}}
	s.rebuildUIDIndex()
	if err := s.Unselect(); err != nil {
		t.Fatal(err)
	}
	if s.uids != nil || s.uidIdx != nil {
		t.Fatal("Unselect 应清空 uids 与索引")
	}
}
