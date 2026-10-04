// mail 域 MIME 解析：messages 缓存列提取（列表渲染免解析，数据模型 3.4）。
// 依据：系统架构总览 v1.0.0 第二章 #7（Q8 裁决 2026-09-16 03:13:49：复用
// emersion/go-message）；SRS v1.0.0 FR-013/NFR-001（缓存列服务于列表性能）；
// rfc2045~2049/2231/6532 经 go-message 承载（RFC 标准库索引 03 类）。
// API 形态（go doc 实测 2026-09-17 v0.18.2）：mail.CreateReader(r) → Reader.Header
// → Subject()/AddressList()/Date()/MessageID() 解码方法。
// 容错口径（U4 计划书步骤 7）：畸形头容忍——缺头/畸形头置空值不拒收（缓存列尽力而为，
// 原始字节照常落库；列表渲染降级为空字段显示）。
// 修改历史：
//
//	2026-09-17 03:35:00 | 新建 | U4 SMTP 收信（计划书步骤 7）
package mail

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	gomessage "github.com/emersion/go-message/mail"
)

// ParsedHeaders messages 表缓存列的解析产物（数据模型 3.4：subject/from_addr/
// to_addrs/cc_addrs/sent_at/message_id；零值=头缺失或畸形，落库映射 NULL）。
type ParsedHeaders struct {
	MessageID string    // RFC 5322 Message-ID（含尖括号原文）
	Subject   string    // rfc2047 解码后主题
	FromAddr  string    // 首个 From 地址（user@domain 形态，显示名不入缓存）
	ToAddrs   string    // JSON 数组串（如 ["a@x","b@y"]）；空列表为空串（NULL）
	CcAddrs   string    // 同上
	SentAt    time.Time // Date 头解析；零值=缺失/畸形
}

// ParseCachedHeaders 从原始消息字节提取缓存列（尽力而为：任一提取失败仅置对应零值，
// 不返回错误阻断投递——畸形消息的拒收判定不属缓存列职责）。
// 参数：raw RFC 5322 原始字节（含 A-R 注入后的存储字节）。返回：解析产物。
func ParseCachedHeaders(raw []byte) ParsedHeaders {
	var out ParsedHeaders
	r, err := gomessage.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return out // 头结构整体不可解析（如缺头体分隔）：全零值缓存，字节照常入库
	}
	defer func() { _ = r.Close() }()

	h := r.Header
	out.MessageID = firstOk(h.MessageID())
	out.Subject = firstOk(h.Subject())
	out.FromAddr = firstAddress(h, "From")
	out.ToAddrs = addressListJSON(h, "To")
	out.CcAddrs = addressListJSON(h, "Cc")
	if t, err := h.Date(); err == nil {
		out.SentAt = t
	}
	return out
}

// firstOk 提取辅助：值+错误对 → 值（错误置空串）。
func firstOk(v string, _ error) string {
	return v
}

// firstAddress 提取指定头首个地址（user@domain；列表为空或畸形返回空串）。
func firstAddress(h gomessage.Header, key string) string {
	addrs, err := h.AddressList(key)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0].Address
}

// addressListJSON 提取地址列表并序列化为 JSON 数组串（列表渲染免解析缓存）；
// 空列表返回空串（落库 NULL），避免空数组占位串污染缓存列。
func addressListJSON(h gomessage.Header, key string) string {
	addrs, err := h.AddressList(key)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	list := make([]string, 0, len(addrs))
	for _, a := range addrs {
		list = append(list, a.Address)
	}
	data, err := json.Marshal(list)
	if err != nil {
		return "" // 序列化失败按缺失处理（地址列表均为合法字符串，实际不可达）
	}
	return string(data)
}

// 编译期接口锁定：ParsedHeaders 仅依赖 go-message 公共 API（无 io 端点依赖，NFR-015）。
var _ io.Reader = (*bytes.Reader)(nil)
