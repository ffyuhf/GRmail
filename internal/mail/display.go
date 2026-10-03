// mail 域 Webmail 展示模型解析（U9）：part 遍历（正文双形态+附件清单+CID）与
// 附件 part 定位读取。
// 依据：架构总览 v1.0.1 第三章（mail 模块职责「MIME 解析封装(go-message)」——part
// 遍历属业务解析，web 接入层仅消费展示模型，第四章 web→mail 单向合法）；
// 架构选型 #7（emersion/go-message v0.18.2，Q8 裁决 2026-09-16 03:13:49）；
// SRS v1.0.1 FR-013 核心子集（详情正文渲染/附件卡片/CID 内联——契约 3.2）；
// rfc2045/2046/2047/2231（RFC 库索引 v1.3.0 三类）经 go-message 承载。
// API 形态（go doc 实测 v0.18.2）：mail.NewReader → NextPart()（io.EOF 终止）→
// Part{Header: InlineHeader|AttachmentHeader, Body}；AttachmentHeader.Filename()；
// Header.ContentType()/Get 继承 message.Header。
// 修改历史：
//
//	2026-09-19 10:18:00 | 新建 | U9 Webmail 核心（计划书步骤 6 配套解析层，G2 批准 2026-09-19 10:00:41）
package mail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	gomail "github.com/emersion/go-message/mail"
)

// AttachmentView 附件清单行（详情页卡片与 CID 内联判定输入）。
// Part 为 NextPart 顺序序号（与 LoadAttachmentPart 同计数口径——接入层以该序号寻址下载）。
type AttachmentView struct {
	Part        int    // part 遍历序号（0 起）
	Filename    string // AttachmentHeader.Filename（rfc2047/2231 解码由库承载；空=展示层兜底）
	ContentType string // part Content-Type
	Size        int64  // 字节数（读取后统计）
}

// Display Webmail 详情展示模型（正文双形态：HTML 优先渲染/纯文本回退——渲染策略归
// 接入层（iframe sandbox/转义），本结构只承载原文与 CID 集）。
type Display struct {
	BodyHTML    string           // 首个 text/html inline part 原文
	BodyText    string           // 首个 text/plain inline part 原文
	HasBody     bool             // 任一正文 part 存在
	CIDs        map[string]bool  // 内联图 Content-ID 集（含尖括号原文——HTML cid: 引用匹配键）
	Attachments []AttachmentView // 附件清单（CID 内联图含于其中——下载端点同源服务）
}

// ErrPartNotFound 附件 part 序号越界（非法寻址）。
var ErrPartNotFound = errors.New("mail: 附件 part 不存在")

// ParseDisplay 从原始字节提取 Webmail 展示模型（尽力语义与 ParseCachedHeaders 同源：
// 单 part 提取失败仅跳过该 part 不整体失败）。
// 参数：raw RFC 5322 原始字节（CAS 存储态）。返回：展示模型。
func ParseDisplay(raw []byte) (Display, error) {
	out := Display{Attachments: make([]AttachmentView, 0, 4), CIDs: make(map[string]bool)}
	r, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return out, fmt.Errorf("消息不可解析: %w", err)
	}
	defer func() { _ = r.Close() }()

	partIdx := -1
	for {
		p, perr := r.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			return out, fmt.Errorf("part 遍历中断: %w", perr)
		}
		partIdx++
		switch h := p.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			body, readErr := io.ReadAll(p.Body)
			if readErr != nil {
				continue // 单 part 失败跳过（尽力语义）
			}
			switch ct {
			case "text/html":
				if out.BodyHTML == "" {
					out.BodyHTML = string(body)
				}
				out.HasBody = true
			case "text/plain":
				if out.BodyText == "" {
					out.BodyText = string(body)
				}
				out.HasBody = true
			default:
				// text/* 之外的 inline part（如内联图 image/png）按附件呈现
				ct, _, _ := h.ContentType()
				out.appendAttachment(partIdx, "", ct, body)
			}
			if cid := h.Get("Content-Id"); cid != "" {
				out.CIDs[cid] = true
			}
		case *gomail.AttachmentHeader:
			body, readErr := io.ReadAll(p.Body)
			if readErr != nil {
				continue
			}
			fn, _ := h.Filename()
			ct, _, _ := h.ContentType()
			out.appendAttachment(partIdx, fn, ct, body)
		}
	}
	return out, nil
}

// appendAttachment 附件清单追加（文件名解码失败兜底空串）。
func (d *Display) appendAttachment(part int, filename, contentType string, body []byte) {
	d.Attachments = append(d.Attachments, AttachmentView{
		Part: part, Filename: filename, ContentType: contentType, Size: int64(len(body)),
	})
}

// LoadAttachmentPart 按 NextPart 序号读取附件 part 字节（下载端点寻址）。
// 参数：raw 原始字节；part part 序号。返回：文件名、Content-Type、字节。
func LoadAttachmentPart(raw []byte, part int) (filename, contentType string, data []byte, err error) {
	r, rerr := gomail.CreateReader(bytes.NewReader(raw))
	if rerr != nil {
		return "", "", nil, fmt.Errorf("消息不可解析: %w", rerr)
	}
	defer func() { _ = r.Close() }()
	partIdx := -1
	for {
		p, perr := r.NextPart()
		if errors.Is(perr, io.EOF) {
			return "", "", nil, ErrPartNotFound
		}
		if perr != nil {
			return "", "", nil, fmt.Errorf("part 遍历中断: %w", perr)
		}
		partIdx++
		if partIdx != part {
			continue
		}
		body, readErr := io.ReadAll(p.Body)
		if readErr != nil {
			return "", "", nil, fmt.Errorf("读取 part: %w", readErr)
		}
		fn, ct := "", ""
		switch h := p.Header.(type) {
		case *gomail.AttachmentHeader:
			if f, ferr := h.Filename(); ferr == nil {
				fn = f
			}
			ct, _, _ = h.ContentType()
		case *gomail.InlineHeader:
			ct, _, _ = h.ContentType()
		}
		return fn, ct, body, nil
	}
}

// LoadAttachmentPartByCID 按 Content-ID 定位附件 part（HTML 正文 cid: 内联资源寻址；
// CID 规范化：补尖括号比对 Content-Id 头原文）。
// 参数：raw 原始字节；cid Content-ID（可缺尖括号）。返回同 LoadAttachmentPart。
func LoadAttachmentPartByCID(raw []byte, cid string) (filename, contentType string, data []byte, err error) {
	want := cid
	if !strings.HasPrefix(want, "<") {
		want = "<" + want
	}
	if !strings.HasSuffix(want, ">") {
		want = want + ">"
	}
	r, rerr := gomail.CreateReader(bytes.NewReader(raw))
	if rerr != nil {
		return "", "", nil, fmt.Errorf("消息不可解析: %w", rerr)
	}
	defer func() { _ = r.Close() }()
	partIdx := -1
	for {
		p, perr := r.NextPart()
		if errors.Is(perr, io.EOF) {
			return "", "", nil, ErrPartNotFound
		}
		if perr != nil {
			return "", "", nil, fmt.Errorf("part 遍历中断: %w", perr)
		}
		partIdx++
		cidHeader := ""
		switch h := p.Header.(type) {
		case *gomail.InlineHeader:
			cidHeader = h.Get("Content-Id")
		case *gomail.AttachmentHeader:
			cidHeader = h.Get("Content-Id")
		}
		if strings.TrimSpace(cidHeader) != want {
			continue
		}
		body, readErr := io.ReadAll(p.Body)
		if readErr != nil {
			return "", "", nil, fmt.Errorf("读取 part: %w", readErr)
		}
		fn, ct := "", ""
		if ah, ok := p.Header.(*gomail.AttachmentHeader); ok {
			if f, ferr := ah.Filename(); ferr == nil {
				fn = f
			}
		}
		if ih, ok := p.Header.(*gomail.InlineHeader); ok {
			ct, _, _ = ih.ContentType()
		} else if ah, ok := p.Header.(*gomail.AttachmentHeader); ok {
			ct, _, _ = ah.ContentType()
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		return fn, ct, body, nil
	}
}

// DecodeSubjectWord rfc2047 编码词解码（列表缓存列兜底——解析层已解码，此处仅供
// 展示层二次兜底；非编码词原样返回）。
func DecodeSubjectWord(s string) string {
	dec := new(mime.WordDecoder)
	if out, err := dec.DecodeHeader(s); err == nil {
		return out
	}
	return s
}
