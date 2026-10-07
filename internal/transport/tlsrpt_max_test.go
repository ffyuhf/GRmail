// transport 域 F9 单测：TLS-RPT 聚合域数上限（M8——聚合 map 以策略域为键日界
// 重置前无上限，单日大量不同外域收件内存单调增长；tlsrptMaxDomains 上限+超限
// 丢弃新域+限频 Warn）。
// SRS 条目：NFR-002（4.1 伴随——512MB 内存上限防御面）；TC-018 关联锚。
// 修改历史：
//
//	2026-10-07 09:07:00 | 新建 | 队列防丢信收口批（计划书 2.3 新增测试④；
//	G2 批准 2026-10-07 01:03:52）
package transport

import (
	"fmt"
	"testing"
)

// TestTLSRPTAggregatorDomainCap F9：域数达 tlsrptMaxDomains 后新域丢弃（既有域
// 继续累计——上限约束键集非总量）；SnapshotAndReset 清零后新域恢复可记。
func TestTLSRPTAggregatorDomainCap(t *testing.T) {
	agg := NewTLSRPTAggregator()
	for i := 0; i < tlsrptMaxDomains; i++ {
		agg.Record(fmt.Sprintf("d%d.example", i), "mx1", TLSRPTSuccess, nil)
	}
	// 满态下：新域丢弃+既有域继续累计（键集约束非总量——同一满态窗口内验证）
	agg.Record("overflow.example", "mx1", TLSRPTSuccess, nil)      // 超限新域丢弃
	agg.Record("d0.example", "mx1", TLSRPTSuccess, nil)            // 既有域累计（第 2 次）
	agg.Record("d0.example", "mx1", TLSRPTCertificateExpired, nil) // 既有域失败计数同样累计
	snap := agg.SnapshotAndReset()
	if len(snap) != tlsrptMaxDomains {
		t.Fatalf("快照域数应=上限: %d", len(snap))
	}
	if _, ok := snap["overflow.example"]; ok {
		t.Fatalf("超限新域不应入统计")
	}
	st0, ok := snap["d0.example"]
	if !ok {
		t.Fatalf("上限内域应保留")
	}
	if st0.Success != 2 || st0.Failures[tlsrptFailureKey{ResultType: TLSRPTCertificateExpired, MXHost: "mx1"}] != 1 {
		t.Fatalf("既有域满态下应继续累计: %+v", st0)
	}
	snap2 := agg.SnapshotAndReset()
	if len(snap2) != 0 {
		t.Fatalf("读后即清保证窗口不重叠: %d", len(snap2))
	}

	// 日界重置后恢复：新域可再记（报告语义尽力——窗口自愈）
	agg.Record("fresh.example", "mx1", TLSRPTCertificateExpired, nil)
	snap3 := agg.SnapshotAndReset()
	st, ok := snap3["fresh.example"]
	if !ok || st.Failures[tlsrptFailureKey{ResultType: TLSRPTCertificateExpired, MXHost: "mx1"}] != 1 {
		t.Fatalf("重置后新域应恢复可记: %+v", st)
	}
}
