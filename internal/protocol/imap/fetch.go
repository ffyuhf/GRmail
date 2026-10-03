// imap FETCH 实现（rfc9051 6.4.8）：数据项组装——标志/UID/大小/内部日期走元数据
// 缓存列（免解析）；ENVELOPE/BODYSTRUCTURE/BODY[] 分节走原文（BlobStore 读取）经
// imapserver 库级 Extract* 辅助（beta.8 自带——part path 寻址/HEADER/TEXT/
// HEADER.FIELDS/Partial 全语义由库承载，本包零手写 MIME 遍历）。
// 覆盖条目：FR-006（读取）；NFR-015（可脱离端点——Session 方法可直接驱动测试）。
// 修改历史：
//
//	2026-09-18 00:42:00 | 新建 | U6 IMAP 集成（计划书步骤 5，G2 批准 2026-09-18 00:09:22）
package imap

import (
	"bytes"
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"

	"GRmail/internal/storage"
)

// Fetch 拉取消息数据项（numSet 序号/UID 类型判定语义；逐消息写响应）。
// 参数：w FETCH 响应写入器；numSet 消息集；options 请求项。返回：处理错误。
func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	ctx := context.Background()
	uids, _ := s.resolveNumSet(numSet)
	for _, uid := range uids {
		detail := s.detailForUID(ctx, uid)
		if detail == nil {
			continue // 已 EXPUNGE 行跳过（rfc9051 6.4.8 宽容语义）
		}
		seq := s.uidToSeq(uid)
		if seq == 0 {
			continue
		}
		if err := s.writeFetchItem(ctx, w.CreateMessage(seq), uid, detail, options); err != nil {
			return err
		}
	}
	return nil
}

// writeFetchItem 单消息数据项写入（缓存列项免解析；原文项惰性读取一次复用）。
// 参数：fw 单消息写入器；uid 消息 UID；detail 元数据；options 请求项。返回：写入错误。
func (s *Session) writeFetchItem(ctx context.Context, fw *imapserver.FetchResponseWriter,
	uid int64, detail *storage.Detail, options *imap.FetchOptions) error {
	if options.UID {
		fw.WriteUID(imap.UID(uid))
	}
	if options.Flags {
		fw.WriteFlags(detailFlags(detail))
	}
	if options.InternalDate {
		// F-I4/F-I5：指定态 internal date 优先（APPEND date-time/COPY 保留承载）；
		// nil=未指定→落库时刻（收信时间语义）；Date 头缺失兜底一致（既有口径）
		internal := detail.CreatedAt
		if detail.InternalDate != nil {
			internal = *detail.InternalDate
		}
		if internal.IsZero() {
			internal = detail.SentAt
		}
		fw.WriteInternalDate(internal)
	}
	if options.RFC822Size {
		fw.WriteRFC822Size(detail.RawSize)
	}
	needRaw := options.Envelope || options.BodyStructure != nil || len(options.BodySection) > 0
	if !needRaw {
		return fw.Close()
	}
	raw, err := s.server.blobs.Read(ctx, detail.BlobKey)
	if err != nil {
		return err
	}
	if options.Envelope {
		if err = s.writeEnvelope(fw, raw); err != nil {
			return err
		}
	}
	if options.BodyStructure != nil {
		fw.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
	}
	for _, item := range options.BodySection {
		if err = s.writeBodySection(fw, raw, item); err != nil {
			return err
		}
	}
	return fw.Close()
}

// writeEnvelope 信封写入（原文头解析→库级 ExtractEnvelope——地址解码/主题解码由库承载）。
func (s *Session) writeEnvelope(fw *imapserver.FetchResponseWriter, raw []byte) error {
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil {
		// 畸形消息容错：空信封呈现（FETCH 不因单封畸形失败——NFR-011 客户端兼容口径）
		fw.WriteEnvelope(&imap.Envelope{})
		return nil
	}
	// message.Header 内嵌 textproto.Header——传嵌入字段对齐 ExtractEnvelope 签名
	fw.WriteEnvelope(imapserver.ExtractEnvelope(entity.Header.Header))
	return nil
}

// writeBodySection BODY[] 分节写入（库级 ExtractBodySection——含 Part/Specifier/
// HeaderFields/Partial 全语义；size 前置声明后流式写）。
func (s *Session) writeBodySection(fw *imapserver.FetchResponseWriter, raw []byte, item *imap.FetchItemBodySection) error {
	data := imapserver.ExtractBodySection(bytes.NewReader(raw), item)
	wc := fw.WriteBodySection(item, int64(len(data)))
	if _, err := wc.Write(data); err != nil {
		return err
	}
	return wc.Close()
}
