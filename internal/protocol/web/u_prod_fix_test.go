// 生产缺陷修复批 web 侧回归锚（E-乙——G2 批准 2026-10-17 02:30「批准，乙 C」；
// v1.52.0）：Sent 副本行引用 Submit 返回的真实投递键——archiveSentCopy 直调断言，
// 终结对 raw 重算 K2（≠落盘 K1 且永不写盘）的幽灵行缺陷（U16 起存量：全部
// Webmail 发件的 Sent 副本点不开）。
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"GRmail/internal/storage"
	"GRmail/web/templates"
)

// TestUProdFixArchiveSentCopyUsesRealKey 直调 archiveSentCopy：Sent 文件夹副本行
// 的 blob 键==传入真实键（且≠对 raw 重算的键——幽灵行形态的反向证明）。
func TestUProdFixArchiveSentCopyUsesRealKey(t *testing.T) {
	env := newU9Env(t)
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/compose", nil)

	view := &mailboxView{MailboxID: env.mailbox.ID}
	raw := []byte("From: u9@t.io\r\nTo: x@ext.io\r\nSubject: sent-key\r\n\r\nbody\r\n")
	// 测试键≠raw 重算键（断言有效前提——真实键在产线源自 staged=raw+前置头+DKIM，
	// 恒不等于对 raw 的重算值，即原缺陷形态下永不落盘的 K2 之反例）。
	realKey := strings.Repeat("ab", 32)
	if recomputed := storage.ComputeBlobKey(raw); recomputed == realKey {
		t.Fatal("测试键与 raw 重算键相同——断言失效（更换 realKey）")
	}
	// 前提构造（E-乙产线真实形态）：Submit 已按真实键落盘 blob——StoreAppend 契约
	// 「Blob 已由调用方先行写入」（首版测试漏此前提——实现层防御校验拒绝落行）。
	if werr := env.blobs.Write(context.Background(), realKey, raw); werr != nil {
		t.Fatalf("预写真实键 blob: %v", werr)
	}
	env.srv.archiveSentCopy(c, view, &templates.ComposeData{}, raw, realKey)

	ctx := context.Background()
	folders, err := env.fds.List(ctx, env.mailbox.ID)
	if err != nil {
		t.Fatalf("列文件夹: %v", err)
	}
	var sentID int64
	for _, f := range folders {
		if f.Kind == storage.FolderKindSent {
			sentID = f.ID
			break
		}
	}
	if sentID == 0 {
		t.Fatal("Sent 系统文件夹缺位（EnsureSystemFolders 异常）")
	}
	items, _, lerr := env.db.PageList(ctx, storage.ListQuery{MailboxID: env.mailbox.ID, FolderID: sentID, Limit: 10})
	if lerr != nil {
		t.Fatalf("PageList: %v", lerr)
	}
	if len(items) == 0 {
		t.Fatal("Sent 文件夹无副本行（archiveSentCopy 未写入——sentFolderIDOf/StoreAppend 异常）")
	}
	// 键比对经 GetDetail（ListItem 列集不投影 blob_key——首版断言路径缺陷修正：
	// 改走公开仓储接口二次读键）。
	found := false
	for _, it := range items {
		d, derr := env.db.GetDetail(ctx, env.mailbox.ID, it.ID)
		if derr != nil {
			t.Fatalf("GetDetail(%d): %v", it.ID, derr)
		}
		if d.BlobKey == realKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Sent 副本行未引用传入真实键（K2 重算幽灵行回归——E-乙失效）")
	}
}
