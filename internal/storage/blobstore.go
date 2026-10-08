// BlobStore 文件系统实现：原始邮件字节的内容寻址存储（Q13 裁决）。
// 布局：<root>/ab/cd/<64位sha256hex>（前 2+2 字符分目录，防单目录文件膨胀）。
// 写入语义：临时文件 + fsync + rename（崩溃安全）；幂等（已存在直接成功）。
// F7（队列防丢信收口批/D2）：List 枚举接口——对账 cron（流程设计第四章第 2 条
// 「遍历 data/blobs/** 与 messages.blob_key 比对」既有承诺的兑现承载；契约 v1.32.0）。
// 性能批 F7（D11）：Open 流式读取接口——Read 返回整封 []byte 的单请求全量驻留消除
// （IMAP FETCH 大响应/附件下载改流式消费；契约 v1.36.0）。
// 修改历史：
//
//	2026-09-16 04:36:00 | 新建 | U1 工程骨架（依据：数据库表结构 v1.0.0 第一章 1.2/1.3）
//	2026-10-07 08:55:00 | 扩展 | 队列防丢信收口批 F7：List 枚举（G2 批准 2026-10-07 08:41:07）
//	2026-10-08 10:20:00 | 扩展 | 性能批 F7（D11）：Open 流式句柄（G2 批准 2026-10-08
//	  10:13:49）——io.ReadSeekCloser 形态，os.File 直返零拷贝构造
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// BlobStore 原始字节存取抽象（接口契约见模块接口契约 v1.36.0；预留 S3Store/DBStore 扩展位）
type BlobStore interface {
	Write(ctx context.Context, key string, data []byte) error // 内容寻址写入（幂等）
	Read(ctx context.Context, key string) ([]byte, error)     // 读原始字节
	Delete(ctx context.Context, key string) error             // 删除（调用方保证引用计数为 0）
	Exists(ctx context.Context, key string) (bool, error)     // 存在性检查
	// List 枚举全部现存 blob key（F7/D2：对账 cron 孤儿判定的文件侧数据源；
	// 返回 64 位 hex key 集——布局两极目录由实现展开）。
	List(ctx context.Context) ([]string, error)
	// Open 打开 blob 的流式读取句柄（性能批 F7/D11：Read 整封 []byte 的单请求
	// 全量驻留消除——FETCH 大响应/附件下载流式消费）。io.ReadSeekCloser 形态：
	// os.File 天然支持，Seek 能力供库级 Extract* 重复读与 HTTP Range 扩展。
	// 调用方负责 Close。
	Open(ctx context.Context, key string) (io.ReadSeekCloser, error)
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

// Open 打开 blob 的流式读取句柄（性能批 F7/D11——os.File 直返；key 校验复用
// validateKey 路径穿越防线；不存在时返回包装的 os.ErrNotExist 语义错误与 Read 一致）。
// 参数：ctx 上下文（保留接口一致性）；key SHA-256 hex。返回：读取句柄（调用方 Close）。
func (s *FileSystemBlobStore) Open(_ context.Context, key string) (io.ReadSeekCloser, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	f, err := os.Open(s.blobPath(key))
	if err != nil {
		return nil, fmt.Errorf("打开 blob: %w", err)
	}
	return f, nil
}

// List 枚举全部现存 blob key（F7/D2：WalkDir 遍历 <root>/ab/cd/<key> 两极布局；
// 文件名即 key——非 64 hex 的杂项文件〔如残留临时文件〕跳过并计入清理）。
// 参数：ctx 上下文（遍历中途取消即中止）。返回：现存 key 集（无序）。
func (s *FileSystemBlobStore) List(ctx context.Context) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // 根目录未建=零 blob（首启前对账容错）
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".tmp-blob-") {
			return nil // 目录与残留临时文件跳过（临时文件由写入失败路径自清理，此处防御）
		}
		if validateKey(d.Name()) == nil {
			keys = append(keys, d.Name())
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("枚举 blob 目录: %w", err)
	}
	return keys, nil
}

// ReconcileBlobDir blob 目录对账（F7/D2——流程设计第四章第 2 条既有承诺兑现：
// 「遍历 data/blobs/** 与 messages.blob_key 比对：仅存在于文件系统→孤儿→删除；
// 仅存在于 DB→丢失→标记+告警（引用计数=0 的 blob 可 Delete）」）。
// 编排纯函数（存储侧承载；引用集由调用方提供——cmd 装配层 SQL 例外条款先例
// wire.go dbMessageSource 同源口径）。尽力语义：单文件失败 Warn 跳过不中断。
// 参数：ctx 上下文；blobs BlobStore（List/Delete/Exists）；referenced 引用 key 集
// 查询闭包（messages.blob_key DISTINCT——调用方 db 句柄承载）；logger 观测出口。
// 返回：孤儿删除数；DB 引用而文件缺失数（告警不删行——人工介入面）。
func ReconcileBlobDir(ctx context.Context, blobs BlobStore, referenced func(context.Context) ([]string, error), logger *slog.Logger) (int, int) {
	fsKeys, err := blobs.List(ctx)
	if err != nil {
		logger.Error("blob 对账：文件侧枚举失败", "error", err)
		return 0, 0
	}
	dbKeys, err := referenced(ctx)
	if err != nil {
		logger.Error("blob 对账：引用侧查询失败", "error", err)
		return 0, 0
	}
	dbSet := make(map[string]struct{}, len(dbKeys))
	for _, k := range dbKeys {
		dbSet[k] = struct{}{}
	}
	fsSet := make(map[string]struct{}, len(fsKeys))
	for _, k := range fsKeys {
		fsSet[k] = struct{}{}
	}
	orphans := 0
	for _, k := range fsKeys {
		if _, ok := dbSet[k]; !ok {
			if err := blobs.Delete(ctx, k); err != nil {
				logger.Warn("blob 对账：孤儿删除失败（下轮重试）", "key", k, "error", err)
				continue
			}
			orphans++
		}
	}
	missing := 0
	for _, k := range dbKeys {
		if _, ok := fsSet[k]; !ok {
			missing++
			logger.Warn("blob 对账：DB 引用而文件缺失（标记告警——禁止自动删行，人工介入面）", "key", k)
		}
	}
	if orphans > 0 || missing > 0 {
		logger.Info("blob 对账完成", "orphans_deleted", orphans, "missing_referenced", missing)
	}
	return orphans, missing
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
