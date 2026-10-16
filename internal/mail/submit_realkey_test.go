// E-乙（生产缺陷修复批 v1.52.0，G2 批准 2026-10-17 02:30「批准，乙 C」）：
// Submit 返回键=落盘 staged 字节的真实 CAS 键——Sent 副本消费锚（archiveSentCopy
// 幽灵行缺陷〔K2 重算且永不写盘〕终结的接口契约回归锚）。
package mail

import (
	"context"
	"strings"
	"testing"

	"GRmail/internal/auth"
)

// TestSubmitReturnsRealBlobKey 成功路径恒返回真实键：键非空+按键可读+内容为
// staged 形态（含前置 Received 头——证明键源自签名前置后的字节而非构造原文）。
// 依赖同包 u5_test 既有桩（keylessSigner/newMemBlobs/stubSubmissionStore/stubAdmins——
// NFR-015 复用先例，零新桩）。
func TestSubmitReturnsRealBlobKey(t *testing.T) {
	ctx := context.Background()
	blobs := newMemBlobs()
	svc := NewSubmissionPipelineService(&keylessSigner{}, blobs,
		&stubSubmissionStore{}, &stubAdmins{admins: map[string]bool{"boss": true}}, "t.io")
	key, err := svc.Submit(ctx, &Submission{
		Envelope:   auth.Envelope{MailFrom: "boss@t.io", Helo: "cli"},
		AuthUser:   "boss@t.io",
		Recipients: []string{"x@ext.io"},
	}, []byte("From: boss@t.io\r\nSubject: k\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if key == "" {
		t.Fatal("Submit 成功路径返回键为空（E-乙契约：恒返回真实键）")
	}
	raw, rerr := blobs.Read(ctx, key)
	if rerr != nil {
		t.Fatalf("按返回键读取 blob 失败（键非真实落盘键）: %v", rerr)
	}
	if !strings.Contains(string(raw), "Received:") {
		t.Fatal("返回键对应内容非 staged 形态（缺前置 Received 头——键源校验失败）")
	}
}
