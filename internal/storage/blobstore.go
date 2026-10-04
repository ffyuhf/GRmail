// BlobStore 文件系统实现：原始邮件字节的内容寻址存储（Q13 裁决）。
// 布局：<root>/ab/cd/<64位sha256hex>（前 2+2 字符分目录，防单目录文件膨胀）。
// 写入语义：临时文件 + fsync + rename（崩溃安全）；幂等（已存在直接成功）。
// 修改历史：
//
//	2026-09-16 04:36:00 | 新建 | U1 工程骨架（依据：数据库表结构 v1.0.0 第一章 1.2/1.3）
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// BlobStore 原始字节存取抽象（接口契约见模块接口契约 v1.0.0；预留 S3Store/DBStore 扩展位）
type BlobStore interface {
	Write(ctx context.Context, key string, data []byte) error // 内容寻址写入（幂等）
	Read(ctx context.Context, key string) ([]byte, error)     // 读原始字节
	Delete(ctx context.Context, key string) error             // 删除（调用方保证引用计数为 0）
	Exists(ctx context.Context, key string) (bool, error)     // 存在性检查
}

// FileSystemBlobStore 本地文件系统实现
type FileSystemBlobStore struct {
	root string // blob 根目录（如 data/blobs）
}

// NewFileSystemBlobStore 构造 FS 实现；root 为空时回退默认目录
func NewFileSystemBlobStore(root string) *FileSystemBlobStore {
	if root == "" {
		root = "data/blobs"
	}
	return &FileSystemBlobStore{root: root}
}

// blobPath 由 key 推导物理路径：<root>/ab/cd/<key>
func (s *FileSystemBlobStore) blobPath(key string) string {
	return filepath.Join(s.root, key[0:2], key[2:4], key)
}

// validateKey 校验 key 形态（64 位小写 hex，SHA-256 输出约定），防止路径穿越
func validateKey(key string) error {
	if len(key) != sha256.Size*2 {
		return fmt.Errorf("非法 blob key 长度: %d（应为 64）", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("非法 blob key 编码（需 hex）: %w", err)
	}
	return nil
}

// Write 写入原始字节：存在即幂等返回；否则临时文件→fsync→rename 原子落盘。
// 参数：ctx 上下文；key SHA-256 hex；data 原始字节。返回：写入失败原因。
func (s *FileSystemBlobStore) Write(_ context.Context, key string, data []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	final := s.blobPath(key)
	if ok, err := fileExists(final); err != nil {
		return fmt.Errorf("检查 blob 存在性: %w", err)
	} else if ok {
		return nil // 内容寻址幂等：同 key 即同内容
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return fmt.Errorf("创建 blob 目录: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(final), ".tmp-blob-*")
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	tmpName := tmp.Name()
	// 失败清理：任何错误路径都保证不留半截临时文件
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写入临时文件: %w", err)
	}
	if err = tmp.Sync(); err != nil { // fsync：崩溃后不产生截断的 blob（防丢信链路一环）
		_ = tmp.Close()
		return fmt.Errorf("同步临时文件: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时文件: %w", err)
	}
	if err = os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("原子重命名: %w", err)
	}
	return nil
}

// Read 读取原始字节；不存在时返回包装的 os.ErrNotExist 语义错误
func (s *FileSystemBlobStore) Read(_ context.Context, key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.blobPath(key))
	if err != nil {
		return nil, fmt.Errorf("读取 blob: %w", err)
	}
	return data, nil
}

// Delete 删除 blob 文件；不存在视为成功（对账清理的幂等要求）
func (s *FileSystemBlobStore) Delete(_ context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := os.Remove(s.blobPath(key)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除 blob: %w", err)
	}
	return nil
}

// Exists 检查 blob 是否存在
func (s *FileSystemBlobStore) Exists(_ context.Context, key string) (bool, error) {
	if err := validateKey(key); err != nil {
		return false, err
	}
	return fileExists(s.blobPath(key))
}

// ComputeBlobKey 计算内容的 CAS 键（SHA-256 hex）；收信管道写入前调用
func ComputeBlobKey(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fileExists 本地文件存在性探测
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// compile-time 接口实现校验
var _ BlobStore = (*FileSystemBlobStore)(nil)
