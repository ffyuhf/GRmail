// 性能批 F7（D11，评审修复批次 7）验收测试：BlobStore.Open 流式句柄等价性。
// 依据：性能批_计划_20261008_10-08-00_v1.0.0 步骤 6（G2 批准 2026-10-08 10:13:49）；
// Open 与 Read 字节一致+Seek 正确+缺失语义一致（契约 v1.36.0）。
package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// TestBlobOpenMatchesRead Open 读取字节与 Read 全量一致（等价性锚）。
func TestBlobOpenMatchesRead(t *testing.T) {
	s := NewFileSystemBlobStore(t.TempDir())
	ctx := context.Background()
	payload := "hello streaming world"
	key := ComputeBlobKey([]byte(payload))
	if err := s.Write(ctx, key, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := rc.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if string(got) != payload {
		t.Fatalf("Open 读取 %q 应等于 Read %q", got, payload)
	}
}

// TestBlobOpenSeek Seek 定位正确（多用途复用句柄的前提——FETCH 多 item 重绕）。
func TestBlobOpenSeek(t *testing.T) {
	s := NewFileSystemBlobStore(t.TempDir())
	ctx := context.Background()
	payload := "0123456789"
	key := ComputeBlobKey([]byte(payload))
	if err := s.Write(ctx, key, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if _, err = rc.Seek(4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	part, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(part) != "456789" {
		t.Fatalf("Seek(4) 后应读到 456789, got %q", part)
	}
	if _, err = rc.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(all) != payload {
		t.Fatalf("Seek(0) 重绕后应读全文, got %q", all)
	}
}

// TestBlobOpenMissing 缺失 key 返回 os.ErrNotExist 包装语义（与 Read 一致锚）。
func TestBlobOpenMissing(t *testing.T) {
	s := NewFileSystemBlobStore(t.TempDir())
	if _, err := s.Open(context.Background(), strings.Repeat("ab", 32)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("缺失 key 应返回 ErrNotExist 语义, got %v", err)
	}
	// 非法 key 形态拒绝（validateKey 防线复用）
	if _, err := s.Open(context.Background(), "short"); err == nil {
		t.Fatal("非法 key 应拒绝")
	}
}
