// U17 富文本构造测试（NFR-015 全离线——纯函数直驱）。
// 覆盖：①multipart/alternative 结构（递增序——plain part 在前+html part 在后，
// rfc2046 §5.1.4 构造方 MUST）②附件 mixed 嵌套（外层 mixed+首 part alternative+
// 两层 boundary 互异——L1183-1187）③纯文本路径等价（htmlBody 空=U16 末态形态）
// ④htmlToPlain 派生矩阵（块级换行/实体解码/标签剥离/空行压缩/畸形容错）。
// 依据：U17 计划书 1.5⑥⑦⑪（Q3 裁决断言锚）；契约 v1.13.0 2.3 v1.13.0 变更注释。
// 修改历史：
//
//	2026-09-24 23:10:00 | 新建 | U17 富文本编辑器（计划书步骤 5，G2 批准 2026-09-24 22:51:39）
//	2026-09-29 12:20:00 | 修正 | RFC规范修正批次 G3 整改（审计项 10 补测试锚——计划书
//	  v1.0.0 G2 批准 2026-09-28 22:16:57+G3 审计 4.3 整改要求+整改批准 2026-09-29 12:18:52）：
//	  F-L6 断言（MIME-Version 三路径）+F-L1 存储实证（LF→CRLF+不重复展开）两用例落本文件
//	2026-09-29 17:32:00 | 修正 | RFC候选修正批次 RF-H：F-L8 构造面——正文 part 按内容
//	  按需 CTE: 8bit 断言（rfc2045 §6）
package mail

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestU17AlternativeStructure 富文本无附件：顶层 multipart/alternative+递增序
// （text/plain part 在前、text/html part 在后——rfc2046 §5.1.4 L1388-1392）。
func TestU17AlternativeStructure(t *testing.T) {
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "富文本主题", "", "<p>你好<b>世界</b></p><p>第二段</p>", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "Content-Type: multipart/alternative; boundary=") {
		t.Fatalf("顶层 Content-Type 非 multipart/alternative:\n%s", head(raw, 400))
	}
	plainIdx := strings.Index(s, "Content-Type: text/plain; charset=utf-8")
	htmlIdx := strings.Index(s, "Content-Type: text/html; charset=utf-8")
	if plainIdx < 0 || htmlIdx < 0 {
		t.Fatalf("alternative 双 part 缺失（plain=%d html=%d）", plainIdx, htmlIdx)
	}
	if plainIdx > htmlIdx {
		t.Fatalf("递增序违规——plain part 必须在 html part 之前（rfc2046 §5.1.4）: plain=%d html=%d", plainIdx, htmlIdx)
	}
	if !strings.Contains(s, "你好世界") {
		t.Fatalf("派生纯文本 part 内容缺失（htmlToPlain 产物）")
	}
	if !strings.Contains(s, "<p>你好<b>世界</b></p>") {
		t.Fatalf("html 原文 part 内容缺失")
	}
}

// TestU17MixedNesting 富文本+附件：外层 multipart/mixed+首 part 为 alternative 子实体
// （Content-Type 头携带子 boundary）+附件 part 存在+两层 boundary 互异（L1183-1187）。
func TestU17MixedNesting(t *testing.T) {
	atts := []OutgoingAttachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte("attach-body")}}
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "", "<p>正文</p>", atts)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "Content-Type: multipart/mixed; boundary=") {
		t.Fatalf("外层 Content-Type 非 multipart/mixed")
	}
	altIdx := strings.Index(s, "Content-Type: multipart/alternative; boundary=")
	attIdx := strings.Index(s, "Content-Disposition: attachment")
	if altIdx < 0 || attIdx < 0 {
		t.Fatalf("嵌套结构缺失（alternative=%d attachment=%d）", altIdx, attIdx)
	}
	if altIdx > attIdx {
		t.Fatalf("alternative 子实体必须先于附件 part")
	}
	// 两层 boundary 互异：外层 boundary 值不等于内层 boundary 值
	mixedB := extractBoundary(s, "multipart/mixed; boundary=")
	altB := extractBoundary(s, "multipart/alternative; boundary=")
	if mixedB == "" || altB == "" || mixedB == altB {
		t.Fatalf("两层 boundary 必须互异（rfc2046 L1183-1187）: mixed=%q alt=%q", mixedB, altB)
	}
	// F-L7（RFC规范修正 RF-A）：附件 part CTE: base64+内容 base64 编码
	//（rfc2045 §2.7/§6——二进制附件 7bit 通道安全）
	if !strings.Contains(s, "Content-Transfer-Encoding: base64") {
		t.Fatalf("附件 part 缺 CTE: base64（F-L7）")
	}
	if !strings.Contains(s, base64.StdEncoding.EncodeToString([]byte("attach-body"))) {
		t.Fatalf("附件内容 base64 编码缺失（F-L7）")
	}
}

// TestU17PlainTextPathEquivalence 纯文本路径（htmlBody 空=U16 末态形态）：
// 无附件单一 text/plain；有附件 mixed{plain, attachment}——无 alternative 残留。
func TestU17PlainTextPathEquivalence(t *testing.T) {
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "纯文本正文", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "Content-Type: text/plain; charset=utf-8") || strings.Contains(s, "multipart/") {
		t.Fatalf("无附件纯文本应为单一 text/plain（非 multipart）")
	}
	if !strings.Contains(s, "纯文本正文") {
		t.Fatalf("纯文本正文缺失")
	}

	atts := []OutgoingAttachment{{Filename: "n.txt", Data: []byte("x")}}
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "纯文本正文", "", atts)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s = string(raw)
	if !strings.Contains(s, "Content-Type: multipart/mixed; boundary=") || strings.Contains(s, "multipart/alternative") {
		t.Fatalf("有附件纯文本应为 mixed{plain,att} 无 alternative")
	}
}

// TestU17HtmlToPlainMatrix htmlToPlain 派生矩阵：块级换行/实体解码/标签剥离/
// 空行压缩/畸形容错/空输入。
func TestU17HtmlToPlainMatrix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"段落换行", "<p>第一段</p><p>第二段</p>", "第一段\n\n第二段"},
		{"br 换行", "行一<br>行二", "行一\n行二"},
		{"标签剥离", "<p>你好<b>世界</b></p>", "你好世界"},
		// 实体解码：入参拼接构造防工具传输层实体预解码——UnescapeString 产文本
		// 「A & B <x>」（<x> 为字面文本非标签——剥离先行不误伤）
		{"实体解码", "<p>A &" + "amp; B &" + "lt;x&" + "gt;</p>", "A & B <" + "x>"},
		{"行尾空白修剪", "<p>文本  </p>", "文本"},
		{"空输入", "", ""},
		{"无标签原样", "纯文本无标签", "纯文本无标签"},
		{"畸形未闭合", "<p>未闭合段落", "未闭合段落"},
	}
	for _, c := range cases {
		if got := htmlToPlain(c.in); got != c.want {
			t.Fatalf("%s 派生不符:\n入: %q\n得: %q\n期: %q", c.name, c.in, got, c.want)
		}
	}
	// 连续空行压缩：三连换行→两连
	if got := htmlToPlain("<p>a</p><div></div><div></div><p>b</p>"); !isCollapsed(got) {
		t.Fatalf("三连以上换行未压缩为两连: %q", got)
	}
}

// TestU17RFCMimeVersionHeader F-L6（RFC规范修正 RF-A）：构造产物头区恒含
// MIME-Version: 1.0（rfc2045 §4 L478-479——顶层消息必须；纯文本/富文本/附件三路径）。
// SRS：FR-013（3.8）/FR-005（3.2）；TC：TC-013/TC-005。G3 整改锚①（审计项 10）。
func TestU17RFCMimeVersionHeader(t *testing.T) {
	// 纯文本路径（htmlBody 空=单形态）
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "正文", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if !strings.Contains(string(raw), "MIME-Version: 1.0") {
		t.Fatalf("纯文本路径缺 MIME-Version: 1.0（F-L6）:\n%s", head(raw, 300))
	}

	// 富文本路径（alternative 双形态）
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "", "<p>正文</p>", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if !strings.Contains(string(raw), "MIME-Version: 1.0") {
		t.Fatalf("富文本路径缺 MIME-Version: 1.0（F-L6）:\n%s", head(raw, 300))
	}

	// 附件路径（mixed 嵌套）
	atts := []OutgoingAttachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte("x")}}
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "正文", "", atts)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if !strings.Contains(string(raw), "MIME-Version: 1.0") {
		t.Fatalf("附件路径缺 MIME-Version: 1.0（F-L6）:\n%s", head(raw, 300))
	}
}

// TestU17RFCCRLFNormalization F-L1（RFC规范修正 RF-A）：LF 输入正文构造产物 CRLF
// 形态实证（rfc5322bis §2.3 L527-528「CR and LF MUST only occur together as CRLF」
// ——存储态合规，F-P1 收敛根因）；CRLF 既有输入不重复展开；富文本 html 原文入口同锚。
// SRS：FR-005（3.2）/FR-013（3.8）；TC：TC-005/TC-013。G3 整改锚②（审计项 10）。
func TestU17RFCCRLFNormalization(t *testing.T) {
	// LF 输入 → CRLF 存储形态（正文段无孤立 LF）
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "行一\n行二\n", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "行一\r\n行二\r\n") {
		t.Fatalf("LF 输入未规范化为 CRLF（F-L1）:\n%q", s)
	}
	if strings.Contains(s, "行一\n行") {
		t.Fatalf("产物残留孤立 LF（F-L1）:\n%q", s)
	}

	// CRLF 既有输入不重复展开（无 \r\r\n）
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "行一\r\n行二\r\n", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s = string(raw)
	if strings.Contains(s, "\r\r\n") {
		t.Fatalf("CRLF 输入被重复展开（F-L1）:\n%q", s)
	}
	if !strings.Contains(s, "行一\r\n行二\r\n") {
		t.Fatalf("CRLF 输入形态缺失（F-L1）:\n%q", s)
	}

	// 富文本 html 原文入口同锚（html part 内容 CRLF 化——L120 第二入口）
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "", "行一<br>\n行二", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if s = string(raw); !strings.Contains(s, "行一<br>\r\n行二") {
		t.Fatalf("html 原文 part 未 CRLF 规范化（F-L1）:\n%q", s)
	}
}

// TestU17RFCBodyCTE F-L8 构造面（RFC候选修正批次 RF-H）：UTF-8 正文 part 显式
// CTE: 8bit（rfc2045 §6——UTF-8 正文与缺省 7bit 声明矛盾）；纯 ASCII 保持缺省
// （零 CTE 头合规）；富文本 alternative plain/html part 各自按内容判定。
func TestU17RFCBodyCTE(t *testing.T) {
	// 中文正文（8bit）单形态 → CTE: 8bit
	raw, err := BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "中文正文", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if s := string(raw); !strings.Contains(s, "Content-Transfer-Encoding: 8bit") {
		t.Fatalf("UTF-8 正文应显式 CTE: 8bit（F-L8——rfc2045 §6）:\n%s", head(raw, 300))
	}

	// 纯 ASCII 正文 → 保持缺省（无 CTE 头——7bit 声明与内容一致合规）
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "subj", "plain ascii body", "", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if s := string(raw); strings.Contains(s, "Content-Transfer-Encoding") {
		t.Fatalf("纯 ASCII 正文不应有 CTE 头（缺省 7bit 合规——F-L8）:\n%s", head(raw, 300))
	}

	// 富文本 alternative：中文派生 plain 与中文 html 两 part 各自 CTE 8bit
	//（htmlToPlain 派生内容含中文——两 part 按各自内容独立判定；注：multipart
	// CreatePart 头按字母序写出，CTE 行位于各 part 的 Content-Type 行之前）
	raw, err = BuildOutgoingMail("from@a.com", "to@b.com", "", "主题", "", "<p>中文</p>", nil)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	s := string(raw)
	if n := strings.Count(s, "Content-Transfer-Encoding: 8bit"); n != 2 {
		t.Fatalf("中文富文本 plain+html 两 part 应各有一处 CTE: 8bit（实得 %d 处——F-L8）:\n%s", n, s)
	}
	if !strings.Contains(s, "Content-Type: text/plain") || !strings.Contains(s, "Content-Type: text/html") {
		t.Fatalf("alternative 双 part 缺失（F-L8 断言前提）")
	}
}

// extractBoundary 从 Content-Type 头行提取 boundary 参数值（至行尾）。
func extractBoundary(s, marker string) string {
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if j := strings.IndexByte(rest, '\r'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// isCollapsed 判定文本不含三连换行（段落间距上限两连）。
func isCollapsed(s string) bool {
	return !strings.Contains(s, "\n\n\n")
}

// head 取前 n 字节预览（失败诊断输出用）。
func head(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}
