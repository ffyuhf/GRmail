// BlobStore 文件系统实现单测（NFR-015：核心逻辑脱离网络端点独立驱动）。
// 修改历史：
//
//	2026-09-16 04:44:00 | 新建 | U1 工程骨架
package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestBlobStoreWriteReadRoundtrip 写入→读取往返一致性（CAS 语义基础）
func TestBlobStoreWriteReadRoundtrip(t *testing.T) {
	root := t.TempDir()
	store := NewFileSystemBlobStore(root)
	ctx := context.Background()
	key := ComputeBlobKey([]byte("hello GRmail"))

	if err := store.Write(ctx, key, []byte("hello GRmail")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got, err := store.Read(ctx, key)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(got) != "hello GRmail" {
		t.Fatalf("往返不一致: %q", got)
	}
	// 布局验证：<root>/he/l l 前缀分目录
	want := filepath.Join(root, key[0:2], key[2:4], key)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("目录布局不符合 ab/cd 约定: %v", err)
	}
}

// TestBlobStoreWriteIdempotent 重复写入幂等（内容寻址去重语义）
func TestBlobStoreWriteIdempotent(t *testing.T) {
	store := NewFileSystemBlobStore(t.TempDir())
	ctx := context.Background()
	key := ComputeBlobKey([]byte("dup"))
	if err := store.Write(ctx, key, []byte("dup")); err != nil {
		t.Fatalf("首次写入: %v", err)
	}
	if err := store.Write(ctx, key, []byte("dup")); err != nil {
		t.Fatalf("二次写入应幂等: %v", err)
	}
}

// TestBlobStoreDeleteNonexistent 删除不存在键不报错（对账清理幂等要求）
func TestBlobStoreDeleteNonexistent(t *testing.T) {
	store := NewFileSystemBlobStore(t.TempDir())
	key := ComputeBlobKey([]byte("ghost"))
	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatalf("删除不存在键应成功: %v", err)
	}
}

// TestBlobStoreValidateKey 非法键拒绝（防路径穿越）
func TestBlobStoreValidateKey(t *testing.T) {
	store := NewFileSystemBlobStore(t.TempDir())
	ctx := context.Background()
	for _, bad := range []string{"", "abc", "../etc/passwd", "ZZ" + string(make([]byte, 62))} {
		if err := store.Write(ctx, bad, []byte("x")); err == nil {
			t.Fatalf("非法键 %q 应被拒绝", bad)
		}
	}
}
