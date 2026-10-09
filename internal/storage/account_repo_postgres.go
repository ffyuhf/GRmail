// Package storage account 域 PostgreSQL 实现（U11 Q2-A 三套生成；契约 2.1 签名零变更）。
// 依据：数据库表结构 v1.1.0 第五章（PG TIMESTAMPTZ/BOOLEAN——sqlc 生成 time.Time/bool）；
// U11 计划书 1.5⑤（PG 无 LastInsertId——CreateMailbox 经 :one+RETURNING id 直取主键）。
// 覆盖条目：FR-014（TC-014 account 域 PostgreSQL 格）。
// 修改历史：
//
//	2026-09-20 05:29:00 | 新增 | U11 三库验收（计划书步骤 4）
//	2026-10-09 23:52:00 | 扩展 | SCRAM认证批（G2 批准 2026-10-09 23:37:36）：Create/
//	  SetCredentials 四元组原子写（3.1-A）+GetSCRAMCredentialsByAddress+scramColsPG
//	  辅助（BYTEA→[]byte 直传方言——迁移 00014；契约 v1.39.0）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbgen "GRmail/internal/storage/dbgen/postgres"
)

// 编译期断言：契约 2.1 接口实现锁定（PostgreSQL 形态）。
var (
	_ MailboxRepo = (*PostgresMailboxRepo)(nil)
	_ FolderRepo  = (*PostgresFolderRepo)(nil)
)

// PostgresMailboxRepo MailboxRepo 的 PostgreSQL 实现。
type PostgresMailboxRepo struct {
	db *sql.DB
	q  *dbgen.Queries
	ck constraintChecker
}

// NewPostgresMailboxRepo 构造邮箱仓储（PostgreSQL）。
// 参数：db 已迁移就绪的 PostgreSQL 连接。返回：仓储实例。
func NewPostgresMailboxRepo(db *sql.DB) *PostgresMailboxRepo {
	return &PostgresMailboxRepo{db: db, q: dbgen.New(db), ck: pgChecker{}}
}

// Create 创建邮箱并事务内初始化五系统文件夹（语义同 SQLite 实现）。
func (r *PostgresMailboxRepo) Create(ctx context.Context, m *Mailbox) error {
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	qtx := r.q.WithTx(tx)
	sk, ek, ss, si := scramColsPG(m.SCRAM) // SCRAM认证批：四元组随 PHC 同 INSERT 原子落库
	id, err := qtx.CreateMailbox(ctx, dbgen.CreateMailboxParams{
		LocalPart:       m.LocalPart,
		Domain:          m.Domain,
		Address:         m.Address,
		PasswordHash:    nullString(m.PasswordHash),
		ScramStoredKey:  sk,
		ScramServerKey:  ek,
		ScramSalt:       ss,
		ScramIterations: si,
		Status:          string(m.Status),
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		if r.ck.uniqueViolation(err) {
			return ErrMailboxExists
		}
		return fmt.Errorf("插入邮箱: %w", err)
	}
	if err = insertSystemFoldersPG(ctx, qtx, id, now); err != nil {
		return err
	}
	// U25：postmaster 邮箱附加聚合文件夹（影子来信管理视图——FR-003 承载；其余邮箱零增量）
	if m.LocalPart == postmasterLocalPart {
		if err = insertAggregateFolderPG(ctx, qtx, id, now, r.ck); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交邮箱创建事务: %w", err)
	}
	m.ID, m.CreatedAt, m.UpdatedAt = id, now, now
	return nil
}

// FindByAddress 按地址查询邮箱（NULL 凭据映射空串）。
func (r *PostgresMailboxRepo) FindByAddress(ctx context.Context, addr string) (*Mailbox, error) {
	row, err := r.q.GetMailboxByAddress(ctx, addr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询邮箱: %w", err)
	}
	return &Mailbox{
		ID:           row.ID,
		LocalPart:    row.LocalPart,
		Domain:       row.Domain,
		Address:      row.Address,
		PasswordHash: row.PasswordHash.String,
		Status:       MailboxStatus(row.Status),
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

// ListByStatus 按状态列举邮箱（按 id 稳定序）。
func (r *PostgresMailboxRepo) ListByStatus(ctx context.Context, status MailboxStatus) ([]*Mailbox, error) {
	rows, err := r.q.ListMailboxesByStatus(ctx, string(status))
	if err != nil {
		return nil, fmt.Errorf("列举邮箱: %w", err)
	}
	out := make([]*Mailbox, 0, len(rows))
	for _, row := range rows {
		out = append(out, &Mailbox{
			ID:           row.ID,
			LocalPart:    row.LocalPart,
			Domain:       row.Domain,
			Address:      row.Address,
			PasswordHash: row.PasswordHash.String,
			Status:       MailboxStatus(row.Status),
			CreatedAt:    row.CreatedAt,
			UpdatedAt:    row.UpdatedAt,
		})
	}
	return out, nil
}

// SetCredentials 设凭据并激活（REQ-020 影子→激活原地继承；安全原子性批 F2
// 2026-10-06：原状态限定+RowsAffected——disabled 改密被拒，见 sqlite 版注记）。
// SCRAM认证批（v1.39.0 候选 3.1-A）：PHC 与 SCRAM 四元组单语句原子写。
func (r *PostgresMailboxRepo) SetCredentials(ctx context.Context, id int64, hash string, scram *SCRAMCredentials) error {
	sk, ek, ss, si := scramColsPG(scram)
	res, err := r.q.SetMailboxCredentials(ctx, dbgen.SetMailboxCredentialsParams{
		PasswordHash:    nullString(hash),
		ScramStoredKey:  sk,
		ScramServerKey:  ek,
		ScramSalt:       ss,
		ScramIterations: si,
		UpdatedAt:       time.Now().UTC(),
		ID:              id,
	})
	if err != nil {
		return fmt.Errorf("设置邮箱凭据: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("设置邮箱凭据（受影响行数）: %w", err)
	}
	if n == 0 {
		return ErrMailboxStatusConflict
	}
	return nil
}

// SetStatus 变更邮箱状态（FR-002）。
func (r *PostgresMailboxRepo) SetStatus(ctx context.Context, id int64, status MailboxStatus) error {
	if err := r.q.SetMailboxStatus(ctx, dbgen.SetMailboxStatusParams{
		Status:    string(status),
		UpdatedAt: time.Now().UTC(),
		ID:        id,
	}); err != nil {
		return fmt.Errorf("设置邮箱状态: %w", err)
	}
	return nil
}

// GetSCRAMCredentialsByAddress 按地址取 SCRAM 四元组（v1.39.0 SCRAM认证批——PG
// BYTEA 列 []byte 直取〔nil=NULL〕；任一键列 NULL=未配备哨兵〔3.2-A 存量态〕）。
func (r *PostgresMailboxRepo) GetSCRAMCredentialsByAddress(ctx context.Context, addr string) (*SCRAMCredentials, error) {
	row, err := r.q.GetSCRAMCredentialsByAddress(ctx, addr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询 SCRAM 凭据: %w", err)
	}
	if row.ScramStoredKey == nil || row.ScramServerKey == nil || row.ScramSalt == nil {
		return nil, ErrSCRAMNotProvisioned
	}
	return &SCRAMCredentials{
		StoredKey:  row.ScramStoredKey,
		ServerKey:  row.ScramServerKey,
		Salt:       row.ScramSalt,
		Iterations: int(row.ScramIterations.Int32),
	}, nil
}

// scramColsPG 四元组拆 PG 列组（v1.39.0；nil→三 nil 列+无效迭代——BYTEA []byte
// 直传、INTEGER 经 NullInt32）。
func scramColsPG(sc *SCRAMCredentials) (storedKey, serverKey, salt []byte, iterations sql.NullInt32) {
	if sc == nil {
		return nil, nil, nil, sql.NullInt32{}
	}
	return sc.StoredKey, sc.ServerKey, sc.Salt, sql.NullInt32{Int32: int32(sc.Iterations), Valid: true}
}

// PostgresFolderRepo FolderRepo 的 PostgreSQL 实现。
type PostgresFolderRepo struct {
	q  *dbgen.Queries
	ck constraintChecker
}

// NewPostgresFolderRepo 构造文件夹仓储（PostgreSQL）。
func NewPostgresFolderRepo(db *sql.DB) *PostgresFolderRepo {
	return &PostgresFolderRepo{q: dbgen.New(db), ck: pgChecker{}}
}

// EnsureSystemFolders 幂等初始化五系统文件夹。
func (r *PostgresFolderRepo) EnsureSystemFolders(ctx context.Context, mailboxID int64) error {
	return insertSystemFoldersPG(ctx, r.q, mailboxID, time.Now().UTC())
}

// EnsureAggregateFolder 幂等初始化聚合文件夹（U25——postmaster 第六系统文件夹；
// 存量邮箱/管道防御路径调用，UNIQUE(mailbox_id,name) 冲突视为完成）。
func (r *PostgresFolderRepo) EnsureAggregateFolder(ctx context.Context, mailboxID int64) error {
	return insertAggregateFolderPG(ctx, r.q, mailboxID, time.Now().UTC(), r.ck)
}

// List 列举邮箱全部文件夹（系统五类固定序+custom 按名序）。
func (r *PostgresFolderRepo) List(ctx context.Context, mailboxID int64) ([]*Folder, error) {
	rows, err := r.q.ListFoldersByMailbox(ctx, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("列举文件夹: %w", err)
	}
	out := make([]*Folder, 0, len(rows))
	for _, row := range rows {
		out = append(out, &Folder{
			ID:        row.ID,
			MailboxID: row.MailboxID,
			Name:      row.Name,
			Kind:      FolderKind(row.Kind),
			CreatedAt: row.CreatedAt,
		})
	}
	return out, nil
}

// CreateCustom 创建自定义文件夹；同名返回 ErrFolderExists。
func (r *PostgresFolderRepo) CreateCustom(ctx context.Context, mailboxID int64, name string) error {
	_, err := r.q.CreateCustomFolder(ctx, dbgen.CreateCustomFolderParams{
		MailboxID: mailboxID,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	})
	if r.ck.uniqueViolation(err) {
		return ErrFolderExists
	}
	if err != nil {
		return fmt.Errorf("创建文件夹: %w", err)
	}
	return nil
}

// Rename 重命名自定义文件夹（预检语义同 SQLite 实现）。
func (r *PostgresFolderRepo) Rename(ctx context.Context, id int64, name string) error {
	row, err := r.q.GetFolderByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFolderNotFound
	}
	if err != nil {
		return fmt.Errorf("查询文件夹: %w", err)
	}
	if row.Kind != string(FolderKindCustom) {
		return ErrFolderIsSystem
	}
	rows, err := r.q.RenameCustomFolder(ctx, dbgen.RenameCustomFolderParams{Name: name, ID: id})
	if err != nil {
		if r.ck.uniqueViolation(err) {
			return ErrFolderExists
		}
		return fmt.Errorf("重命名文件夹: %w", err)
	}
	if rows == 0 {
		return ErrFolderNotFound
	}
	return nil
}

// Delete 删除自定义文件夹（非空被 FK 拒绝——PG 23503）。
func (r *PostgresFolderRepo) Delete(ctx context.Context, id int64) error {
	row, err := r.q.GetFolderByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFolderNotFound
	}
	if err != nil {
		return fmt.Errorf("查询文件夹: %w", err)
	}
	if row.Kind != string(FolderKindCustom) {
		return ErrFolderIsSystem
	}
	rows, err := r.q.DeleteCustomFolder(ctx, id)
	if err != nil {
		if r.ck.fkViolation(err) {
			return ErrFolderNotEmpty
		}
		return fmt.Errorf("删除文件夹: %w", err)
	}
	if rows == 0 {
		return ErrFolderNotFound
	}
	return nil
}

// UnreadCounts 各文件夹未读计数（is_read=false 排除软删除行——BOOLEAN 映射 bool）。
func (r *PostgresFolderRepo) UnreadCounts(ctx context.Context, mailboxID int64) (map[int64]int64, error) {
	rows, err := r.q.CountUnreadByFolder(ctx, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("统计未读: %w", err)
	}
	out := make(map[int64]int64, len(rows))
	for _, row := range rows {
		out[row.FolderID] = row.UnreadCount
	}
	return out, nil
}

// insertSystemFoldersPG PostgreSQL 版五系统文件夹写入（幂等：UNIQUE 冲突视为成功）。
func insertSystemFoldersPG(ctx context.Context, q *dbgen.Queries, mailboxID int64, now time.Time) error {
	err := q.InsertSystemFolders(ctx, dbgen.InsertSystemFoldersParams{
		MailboxID: mailboxID, CreatedAt: now,
		MailboxID_2: mailboxID, CreatedAt_2: now,
		MailboxID_3: mailboxID, CreatedAt_3: now,
		MailboxID_4: mailboxID, CreatedAt_4: now,
		MailboxID_5: mailboxID, CreatedAt_5: now,
	})
	ck := pgChecker{}
	if ck.uniqueViolation(err) {
		return nil // 幂等：系统文件夹已初始化
	}
	if err != nil {
		return fmt.Errorf("初始化系统文件夹: %w", err)
	}
	return nil
}

// insertAggregateFolderPG 写入聚合文件夹单行（U25：Create 事务内 / EnsureAggregateFolder
// 幂等路径共用；UNIQUE 冲突视为成功——防御性幂等语义）。
func insertAggregateFolderPG(ctx context.Context, q *dbgen.Queries, mailboxID int64, now time.Time, ck constraintChecker) error {
	err := q.InsertAggregateFolder(ctx, dbgen.InsertAggregateFolderParams{
		MailboxID: mailboxID, CreatedAt: now,
	})
	if ck.uniqueViolation(err) {
		return nil // 幂等：聚合文件夹已存在
	}
	if err != nil {
		return fmt.Errorf("初始化聚合文件夹: %w", err)
	}
	return nil
}
