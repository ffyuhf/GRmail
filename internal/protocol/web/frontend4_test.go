package web

// 前端四缺陷修复批 E-2-A 测试锚（G2 批准 2026-10-19 19:18「全A」）：
// 管理员草稿 From 回填——保存时输入的非管理员邮箱在重新打开时保留（不被
// composeGET 预填主邮箱覆盖）；空 FromAddr 草稿维持预填兜底（D12 语义保持）。
// 形态：fillFromDraft 包内直调（stub 注入 MessageRepo/BlobStore——blob 读失败
// 静默跳过正文回填为既有语义，From 回填独立于 blob 链）。

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"GRmail/internal/storage"
	"GRmail/web/templates"

	"github.com/gin-gonic/gin"
)

// fd4Repo MessageRepo stub——仅 GetDetail 消费面（嵌入接口承载其余方法签名）。
type fd4Repo struct {
	storage.MessageRepo
	d *storage.Detail
}

func (r fd4Repo) GetDetail(ctx context.Context, mailboxID, msgPK int64) (*storage.Detail, error) {
	return r.d, nil
}

// fd4Blobs BlobStore stub——Read 恒失败（fillFromDraft 正文回填静默跳过锚）。
type fd4Blobs struct{}

func (fd4Blobs) Write(ctx context.Context, key string, b []byte) error { return nil }
func (fd4Blobs) Read(ctx context.Context, key string) ([]byte, error) {
	return nil, errors.New("fd4: no blob")
}
func (fd4Blobs) Delete(ctx context.Context, key string) error         { return nil }
func (fd4Blobs) Exists(ctx context.Context, key string) (bool, error) { return false, nil }
func (fd4Blobs) List(ctx context.Context) ([]string, error)           { return nil, nil }
func (fd4Blobs) Open(ctx context.Context, key string) (io.ReadSeekCloser, error) {
	return nil, errors.New("fd4: no blob")
}

// fd4Run fillFromDraft 直调辅助（gin 测试上下文构造）。
func fd4Run(s *Server, view *mailboxView, data *templates.ComposeData, id int64) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	s.fillFromDraft(c, view, data, id)
}

// TestFrontend4DraftFromRefill E-2-A 主锚：草稿 FromAddr 非空→回填覆盖管理员
// 预填（原输入保留）；空 FromAddr→维持预填兜底（D12 语义）。
func TestFrontend4DraftFromRefill(t *testing.T) {
	s := &Server{
		messages: fd4Repo{d: &storage.Detail{ID: 7, FromAddr: "custom@t.io"}},
		blobs:    fd4Blobs{},
	}
	view := &mailboxView{MailboxID: 1, IsAdmin: true, Label: "admin@t.io"}

	// ①非空 FromAddr：管理员预填被草稿原值覆盖
	data := &templates.ComposeData{From: "admin@t.io"}
	fd4Run(s, view, data, 7)
	if data.From != "custom@t.io" {
		t.Fatalf("草稿 From 应回填原值 custom@t.io（不被主邮箱预填覆盖）: %q", data.From)
	}

	// ②空 FromAddr：维持 composeGET 预填兜底
	s2 := &Server{
		messages: fd4Repo{d: &storage.Detail{ID: 8, FromAddr: ""}},
		blobs:    fd4Blobs{},
	}
	data2 := &templates.ComposeData{From: "admin@t.io"}
	fd4Run(s2, view, data2, 8)
	if data2.From != "admin@t.io" {
		t.Fatalf("空 FromAddr 草稿应维持预填兜底 admin@t.io: %q", data2.From)
	}
}
