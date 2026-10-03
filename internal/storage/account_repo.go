// Package storage 追加账号域仓储：MailboxRepo/FolderRepo 接口族与 SQLite 实现。
// 依据：模块接口契约 v1.0.0 第 2.1 节（签名逐字落地，零偏离）；
// 数据库表结构 v1.0.0 第 3.2/3.3 节（mailboxes/folders 表，U1 迁移已建）；
// 系统架构总览 v1.0.0 第四章（storage 不 import 业务模块，仅暴露领域接口）。
// 覆盖条目：FR-001/002/003/004/012（TC-001~004/012 存储层锚点）。
// 实现范围：Q2-A 裁决（来源：用户确认 2026-09-17 01:09:48）——U2 仅 SQLite 工程，
// MySQL/PostgreSQL 生成与接入归 U11 三库验收单元。
// queries 文件注释形态说明：sqlc v1.31.1 实测（2026-09-17 01:35 诊断）对注解外注释行/块注释
// 解析失败，故 queries/*.sql 仅存注解与语句；全部溯源说明落位于本文件与代码修改文档。
// 修改历史：
//
//	2026-09-17 01:42:00 | 新建 | U2 account 模块（计划书步骤 3，G2 批准 2026-09-17 01:31:40）
//	2026-10-01 16:50:00 | 扩展 | U24 双因素认证（G2 批准 2026-10-01 16:41:08）：MailboxRepo
//	  增 2FA 方法族七方法+TwoFactorState 域类型（契约 v1.20.0 2.1 增量——沿 v1.x
//	  增量先例；迁移 00009 三库；SQLite 实现落 twofactor_repo.go）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 域类型（数据模型 3.2/3.3） ─────────────────────────

// MailboxStatus 邮箱状态机枚举（REQ-020 影子状态机：shadow→active 原地继承；disabled 由 FR-002 管理员操作）
type MailboxStatus string

// 邮箱状态三态（与迁移 DDL CHECK 约束一致）
const (
	MailboxStatusActive   MailboxStatus = "active"   // 正常：可登录可收信
	MailboxStatusShadow   MailboxStatus = "shadow"   // 影子：无凭据不可登录，来信按址归档（FR-004）
	MailboxStatusDisabled MailboxStatus = "disabled" // 禁用：管理员操作（FR-002），不参与收信判定
)

// FolderKind 文件夹类别（单层模型 REQ-021：系统+custom；kind=custom 之外不可改名/删除）
type FolderKind string

// 文件夹七类（与迁移 DDL CHECK 约束一致——U25 起 00010 迁移扩展第七值 unregistered；
// 存储名为客户端互操作标准名，i18n 显示名归 U8/U9）
const (
	FolderKindInbox        FolderKind = "inbox"
	FolderKindSent         FolderKind = "sent"
	FolderKindDrafts       FolderKind = "drafts"
	FolderKindJunk         FolderKind = "junk"
	FolderKindTrash        FolderKind = "trash"
	FolderKindUnregistered FolderKind = "unregistered" // U25：影子来信聚合（仅 postmaster 初始化——S3-W Q2-B1）
	FolderKindCustom       FolderKind = "custom"
)

// Mailbox 邮箱账号域模型（表 mailboxes；address 小写规范化，三库统一口径）
type Mailbox struct {
	ID           int64
	LocalPart    string
	Domain       string
	Address      string // local@domain（小写）
	PasswordHash string // argon2id PHC 串（Q12）；空串=无凭据（shadow 态）
	Status       MailboxStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TwoFactorState 邮箱 2FA 绑定态快照（FR-018；表结构 v1.7.0 3.2 增列组——U24）。
// 列映射：PendingSecret←totp_secret（Base32 明文——S4-W Q3-A 裁决 2026-10-01 16:44:56）；
// CodesHash←recovery_codes（JSON 数组·SHA-256 hex 哈希态——S4-W Q2-A，沿 token_hash 先例）；
// Required←two_factor_required（管理员强制标记 REQ-20261001-004）；LastTOTPStep←
// totp_last_step（rfc6238 §5.2 L343-347 同窗重放拒绝 MUST 承载；0=从未验证——NULL 映射）。
type TwoFactorState struct {
	PendingSecret string   // 非空=已发起绑定（pending 或已绑定）
	CodesHash     []string // 恢复码哈希集（非空=绑定确认完成）
	Required      bool     // 管理员强制标记（不改变已绑定态——仅引导未绑定账号）
	LastTOTPStep  int64    // 最近 TOTP 验证成功时间步（X=30s——rfc6238 §4.1）
}

// Bound 绑定完成判定：密钥与恢复码同时非空（FR-018 登录二步生效条件；pending 态
// 〔仅密钥无恢复码〕不生效——防绑定中途中断导致无 authenticator 即被要求二步的死锁）。
func (s *TwoFactorState) Bound() bool { return s.PendingSecret != "" && len(s.CodesHash) > 0 }

// Folder 文件夹域模型（表 folders；无 ParentID——单层模型 REQ-021）
type Folder struct {
	ID        int64
	MailboxID int64
	Name      string
	Kind      FolderKind
	CreatedAt time.Time
}

// ───────────────────────── 哨兵错误（上层友好判定） ─────────────────────────

var (
	// ErrMailboxExists 地址已被占用（mailboxes.address UNIQUE 冲突）
	ErrMailboxExists = errors.New("mailbox: 地址已存在")
	// ErrMailboxNotFound 邮箱不存在（FindByAddress 无行 / sql.ErrNoRows 映射）
	ErrMailboxNotFound = errors.New("mailbox: 邮箱不存在")
	// ErrFolderExists 同名文件夹已存在（folders UNIQUE(mailbox_id,name) 冲突）
	ErrFolderExists = errors.New("folder: 同名文件夹已存在")
	// ErrFolderNotFound 文件夹不存在
	ErrFolderNotFound = errors.New("folder: 文件夹不存在")
	// ErrFolderIsSystem 系统文件夹不允许改名/删除（TC-012 判定：系统文件夹不可删）
	ErrFolderIsSystem = errors.New("folder: 系统文件夹不允许此操作")
	// ErrFolderNotEmpty 文件夹内仍有邮件引用，禁止删除（FK 约束拒绝；表现层提示归 U8/U9）
	ErrFolderNotEmpty = errors.New("folder: 文件夹内仍有邮件")
)

// ───────────────────────── 接口族（契约 2.1 逐字） ─────────────────────────

// MailboxRepo 邮箱账号仓储（account 域）
type MailboxRepo interface {
	// Create 创建邮箱；m.ID/CreatedAt/UpdatedAt 回填。
	// 语义含事务内五系统文件夹初始化（数据模型 3.3），返回 ErrMailboxExists 表示地址占用。
	Create(ctx context.Context, m *Mailbox) error
	// FindByAddress 按地址查邮箱（地址须已小写规范化）；无行返回 ErrMailboxNotFound。
	FindByAddress(ctx context.Context, addr string) (*Mailbox, error)
	// ListByStatus 按状态列举邮箱（FR-003 catch-all 聚合用 status=shadow 查询）。
	ListByStatus(ctx context.Context, status MailboxStatus) ([]*Mailbox, error)
	// SetCredentials 设凭据并激活（影子→激活原地继承：status 置 active，历史邮件不动；REQ-020）。
	SetCredentials(ctx context.Context, id int64, hash string) error
	// SetStatus 变更状态（FR-002 管理员禁用/激活）。
	SetStatus(ctx context.Context, id int64, status MailboxStatus) error

	// ── U24 增量（契约 v1.20.0，FR-018 双因素认证——迁移 00009 三库）──

	// GetTwoFactor 读取邮箱 2FA 绑定态（四列快照；绑定完成判定见 TwoFactorState.Bound）。
	GetTwoFactor(ctx context.Context, mailboxID int64) (*TwoFactorState, error)
	// SetTwoFactorSecret 发起绑定：写入 pending TOTP 密钥（覆盖式——重复发起以最新
	// 密钥为准；SQL 内联清 totp_last_step 重置重放基线）。绑定未确认期间登录判定不生效。
	SetTwoFactorSecret(ctx context.Context, mailboxID int64, secret string) error
	// ConfirmTwoFactor 绑定确认：TOTP 验证通过后写入恢复码哈希集（自此 Bound()=true，
	// 登录二步生效）。恢复码明文仅生成时一次性展示，本接口只落哈希态。
	ConfirmTwoFactor(ctx context.Context, mailboxID int64, codeHashes []string) error
	// MarkTOTPStep 记录最近一次 TOTP 验证成功的时间步（rfc6238 §5.2 L343-347：
	// 同窗验证成功后 MUST NOT 接受第二次——后续验证仅接受严格更大步）。
	MarkTOTPStep(ctx context.Context, mailboxID, step int64) error
	// ConsumeRecoveryCode 消耗一枚恢复码：事务内哈希匹配→移除该枚→写回剩余集；
	// 返回是否命中（false=集合中无此码——重放或伪造拒绝；TC-028 判定①锚）。
	ConsumeRecoveryCode(ctx context.Context, mailboxID int64, codeHash string) (bool, error)
	// ClearTwoFactor 停用 2FA：清空密钥/恢复码/重放步（调用方须先完成第二因子验证——
	// TC-028 判定②锚；强制标记 Required 不随停用清除，仅管理员可操作）。
	ClearTwoFactor(ctx context.Context, mailboxID int64) error
	// SetTwoFactorRequired 管理员强制标记（FR-018 判定④；标记账号未绑定时登录后
	// 引导先完成绑定——TC-028 判定③锚）。
	SetTwoFactorRequired(ctx context.Context, mailboxID int64, required bool) error
	// FindMailboxByID 按 ID 查邮箱（U24：2FA otpauth label/顶栏主体名需地址反查；
	// 无行返回 ErrMailboxNotFound）。
	FindMailboxByID(ctx context.Context, id int64) (*Mailbox, error)
}

// FolderRepo 文件夹仓储
type FolderRepo interface {
	// EnsureSystemFolders 幂等初始化五系统文件夹（Create 已内含，本方法供修复/补偿场景）。
	EnsureSystemFolders(ctx context.Context, mailboxID int64) error
	// EnsureAggregateFolder 幂等初始化聚合文件夹（U25——postmaster 第六系统文件夹；
	// 存量邮箱/迁移兜底场景调用，UNIQUE(mailbox_id,name) 冲突视为完成）。
	EnsureAggregateFolder(ctx context.Context, mailboxID int64) error
	// List 列举邮箱全部文件夹（系统五类固定序 + custom 按名序，REQ-021 侧边栏顺序）。
	List(ctx context.Context, mailboxID int64) ([]*Folder, error)
	// CreateCustom 创建自定义文件夹；同名返回 ErrFolderExists。
	CreateCustom(ctx context.Context, mailboxID int64, name string) error
	// Rename 重命名自定义文件夹；系统文件夹返回 ErrFolderIsSystem，不存在返回 ErrFolderNotFound。
	Rename(ctx context.Context, id int64, name string) error
	// Delete 删除自定义文件夹（kind=custom 仅限）；非空（被邮件引用）返回 ErrFolderNotEmpty。
	Delete(ctx context.Context, id int64) error
	// UnreadCounts 各文件夹未读计数（排除软删除行；REQ-021 侧边栏数据源）。
	UnreadCounts(ctx context.Context, mailboxID int64) (map[int64]int64, error)
}

// compile-time 接口实现校验（签名偏离契约时在此处编译失败）
var (
	_ MailboxRepo = (*SQLiteMailboxRepo)(nil)
	_ FolderRepo  = (*SQLiteFolderRepo)(nil)
)

// ───────────────────────── SQLite 实现 ─────────────────────────

// SQLiteMailboxRepo MailboxRepo 的 SQLite 实现（sqlc dbgen 后端）
type SQLiteMailboxRepo struct {
	db *sql.DB
	q  *dbgen.Queries
}

// NewSQLiteMailboxRepo 构造邮箱仓储。
// 参数：db 已迁移就绪的数据库连接（storage.Open 产物）；返回：仓储实例。
func NewSQLiteMailboxRepo(db *sql.DB) *SQLiteMailboxRepo {
	return &SQLiteMailboxRepo{db: db, q: dbgen.New(db)}
}

// Create 创建邮箱并事务内初始化五系统文件夹（原子：半截邮箱禁止存在）。
// 参数：ctx 上下文；m 待建邮箱（LocalPart/Domain/Address/PasswordHash/Status 须就绪，空 hash 映射 NULL）。
// 返回：ErrMailboxExists 地址占用；其他 error 为事务/存储故障。
func (r *SQLiteMailboxRepo) Create(ctx context.Context, m *Mailbox) error {
	now := time.Now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 提交后回滚为无害空操作

	qtx := r.q.WithTx(tx)
	res, err := qtx.CreateMailbox(ctx, dbgen.CreateMailboxParams{
		LocalPart:    m.LocalPart,
		Domain:       m.Domain,
		Address:      m.Address,
		PasswordHash: hashOrNil(m.PasswordHash),
		Status:       string(m.Status),
		CreatedAt:    formatTimestamp(now),
		UpdatedAt:    formatTimestamp(now),
	})
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrMailboxExists
		}
		return fmt.Errorf("插入邮箱: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("获取邮箱 ID: %w", err)
	}
	if err := insertSystemFolders(ctx, qtx, id, now); err != nil {
		return err
	}
	// U25：postmaster 邮箱附加聚合文件夹（影子来信管理视图——FR-003 承载；其余邮箱零增量）
	if m.LocalPart == postmasterLocalPart {
		if err = insertAggregateFolder(ctx, qtx, id, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交邮箱创建事务: %w", err)
	}
	m.ID, m.CreatedAt, m.UpdatedAt = id, now, now
	return nil
}

// FindByAddress 按地址查询邮箱。
// 参数：ctx 上下文；addr 小写规范化地址。返回：邮箱（NULL 凭据映射空串）；ErrMailboxNotFound 无行。
func (r *SQLiteMailboxRepo) FindByAddress(ctx context.Context, addr string) (*Mailbox, error) {
	row, err := r.q.GetMailboxByAddress(ctx, addr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMailboxNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询邮箱: %w", err)
	}
	return mailboxFromRow(row.ID, row.LocalPart, row.Domain, row.Address, row.PasswordHash, row.Status, row.CreatedAt, row.UpdatedAt), nil
}

// ListByStatus 按状态列举邮箱（按 id 稳定序）。
func (r *SQLiteMailboxRepo) ListByStatus(ctx context.Context, status MailboxStatus) ([]*Mailbox, error) {
	rows, err := r.q.ListMailboxesByStatus(ctx, string(status))
	if err != nil {
		return nil, fmt.Errorf("列举邮箱: %w", err)
	}
	out := make([]*Mailbox, 0, len(rows))
	for _, row := range rows {
		out = append(out, mailboxFromRow(row.ID, row.LocalPart, row.Domain, row.Address, row.PasswordHash, row.Status, row.CreatedAt, row.UpdatedAt))
	}
	return out, nil
}

// SetCredentials 设凭据并激活（SQL 内联 status='active'：REQ-020 影子→激活原地继承）。
func (r *SQLiteMailboxRepo) SetCredentials(ctx context.Context, id int64, hash string) error {
	if err := r.q.SetMailboxCredentials(ctx, dbgen.SetMailboxCredentialsParams{
		PasswordHash: hashOrNil(hash),
		UpdatedAt:    formatTimestamp(time.Now().UTC()),
		ID:           id,
	}); err != nil {
		return fmt.Errorf("设置邮箱凭据: %w", err)
	}
	return nil
}

// SetStatus 变更邮箱状态（FR-002 管理员禁用/激活）。
func (r *SQLiteMailboxRepo) SetStatus(ctx context.Context, id int64, status MailboxStatus) error {
	if err := r.q.SetMailboxStatus(ctx, dbgen.SetMailboxStatusParams{
		Status:    string(status),
		UpdatedAt: formatTimestamp(time.Now().UTC()),
		ID:        id,
	}); err != nil {
		return fmt.Errorf("设置邮箱状态: %w", err)
	}
	return nil
}

// SQLiteFolderRepo FolderRepo 的 SQLite 实现
type SQLiteFolderRepo struct {
	q *dbgen.Queries
}

// NewSQLiteFolderRepo 构造文件夹仓储。
// 参数：db 数据库连接；返回：仓储实例。
func NewSQLiteFolderRepo(db *sql.DB) *SQLiteFolderRepo {
	return &SQLiteFolderRepo{q: dbgen.New(db)}
}

// EnsureSystemFolders 幂等初始化五系统文件夹（已存在时 UNIQUE 冲突视为完成）。
func (r *SQLiteFolderRepo) EnsureSystemFolders(ctx context.Context, mailboxID int64) error {
	return insertSystemFolders(ctx, r.q, mailboxID, time.Now().UTC())
}

// EnsureAggregateFolder 幂等初始化聚合文件夹（U25——postmaster 第六系统文件夹；
// 存量邮箱/管道防御路径调用，UNIQUE(mailbox_id,name) 冲突视为完成）。
func (r *SQLiteFolderRepo) EnsureAggregateFolder(ctx context.Context, mailboxID int64) error {
	return insertAggregateFolder(ctx, r.q, mailboxID, time.Now().UTC())
}

// List 列举邮箱全部文件夹（侧边栏序：系统五类固定 + custom 按名）。
func (r *SQLiteFolderRepo) List(ctx context.Context, mailboxID int64) ([]*Folder, error) {
	rows, err := r.q.ListFoldersByMailbox(ctx, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("列举文件夹: %w", err)
	}
	out := make([]*Folder, 0, len(rows))
	for _, row := range rows {
		createdAt, err := parseTimestamp(row.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("解析文件夹时间（id=%d）: %w", row.ID, err)
		}
		out = append(out, &Folder{
			ID:        row.ID,
			MailboxID: row.MailboxID,
			Name:      row.Name,
			Kind:      FolderKind(row.Kind),
			CreatedAt: createdAt,
		})
	}
	return out, nil
}

// CreateCustom 创建自定义文件夹；同名（UNIQUE(mailbox_id,name)）返回 ErrFolderExists。
func (r *SQLiteFolderRepo) CreateCustom(ctx context.Context, mailboxID int64, name string) error {
	_, err := r.q.CreateCustomFolder(ctx, dbgen.CreateCustomFolderParams{
		MailboxID: mailboxID,
		Name:      name,
		CreatedAt: formatTimestamp(time.Now().UTC()),
	})
	if isUniqueConstraint(err) {
		return ErrFolderExists
	}
	if err != nil {
		return fmt.Errorf("创建文件夹: %w", err)
	}
	return nil
}

// Rename 重命名自定义文件夹（FR-012：重命名对象为自定义文件夹）。
// 预检语义：不存在→ErrFolderNotFound；系统文件夹→ErrFolderIsSystem；重名冲突→ErrFolderExists。
func (r *SQLiteFolderRepo) Rename(ctx context.Context, id int64, name string) error {
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
		if isUniqueConstraint(err) {
			return ErrFolderExists
		}
		return fmt.Errorf("重命名文件夹: %w", err)
	}
	if rows == 0 {
		return ErrFolderNotFound // 预检与执行间被并发删除的兜底
	}
	return nil
}

// Delete 删除自定义文件夹（TC-012：系统文件夹不可删）。
// 非空文件夹（mailbox_messages.folder_id FK 引用）返回 ErrFolderNotEmpty。
func (r *SQLiteFolderRepo) Delete(ctx context.Context, id int64) error {
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
		if isForeignKeyConstraint(err) {
			return ErrFolderNotEmpty // FK（无 CASCADE）拒绝删除被引用文件夹
		}
		return fmt.Errorf("删除文件夹: %w", err)
	}
	if rows == 0 {
		return ErrFolderNotFound
	}
	return nil
}

// UnreadCounts 各文件夹未读计数（is_read=0 AND status='normal'，排除软删除）。
// 返回：map[folderID]unread；空文件夹不出现在 map 中（调用方按零处理）。
func (r *SQLiteFolderRepo) UnreadCounts(ctx context.Context, mailboxID int64) (map[int64]int64, error) {
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

// ───────────────────────── 内部工具 ─────────────────────────

// insertSystemFolders 写入五系统文件夹（共享路径：Create 事务内 / EnsureSystemFolders 独立幂等）。
// 幂等语义：已存在（UNIQUE 冲突）视为成功——供 EnsureSystemFolders 补偿场景。
func insertSystemFolders(ctx context.Context, q *dbgen.Queries, mailboxID int64, now time.Time) error {
	ts := formatTimestamp(now)
	err := q.InsertSystemFolders(ctx, dbgen.InsertSystemFoldersParams{
		MailboxID: mailboxID, CreatedAt: ts,
		MailboxID_2: mailboxID, CreatedAt_2: ts,
		MailboxID_3: mailboxID, CreatedAt_3: ts,
		MailboxID_4: mailboxID, CreatedAt_4: ts,
		MailboxID_5: mailboxID, CreatedAt_5: ts,
	})
	if isUniqueConstraint(err) {
		return nil // 幂等：系统文件夹已初始化
	}
	if err != nil {
		return fmt.Errorf("初始化系统文件夹: %w", err)
	}
	return nil
}

// postmasterLocalPart 聚合承载邮箱的本地部分（U25——运行期聚合投递目标
// postmaster@主域，与 buildShadowNotice 通知目标同载体）。
const postmasterLocalPart = "postmaster"

// insertAggregateFolder 写入聚合文件夹单行（U25：Create 事务内 / EnsureAggregateFolder
// 幂等路径共用；UNIQUE 冲突视为成功——防御性幂等语义）。
func insertAggregateFolder(ctx context.Context, q *dbgen.Queries, mailboxID int64, now time.Time) error {
	err := q.InsertAggregateFolder(ctx, dbgen.InsertAggregateFolderParams{
		MailboxID: mailboxID, CreatedAt: formatTimestamp(now),
	})
	if isUniqueConstraint(err) {
		return nil // 幂等：聚合文件夹已存在
	}
	if err != nil {
		return fmt.Errorf("初始化聚合文件夹: %w", err)
	}
	return nil
}

// isUniqueConstraint 判定 SQLite 唯一约束冲突。
// 依据：modernc.org/sqlite v1.59.0 无导出哨兵变量（go doc 实测 2026-09-17 01:43），
// 错误码经 *sqlite.Error.Code() 判定；lib.SQLITE_CONSTRAINT_UNIQUE=2067。
func isUniqueConstraint(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == lib.SQLITE_CONSTRAINT_UNIQUE
}

// isForeignKeyConstraint 判定 SQLite 外键约束冲突（lib.SQLITE_CONSTRAINT_FOREIGNKEY=787）。
func isForeignKeyConstraint(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == lib.SQLITE_CONSTRAINT_FOREIGNKEY
}

// mailboxFromRow dbgen 行 → 域模型（NULL 凭据映射空串；时间 RFC3339 解析）。
func mailboxFromRow(id int64, localPart, domain, address string, hash any, status, createdAt, updatedAt string) *Mailbox {
	created, _ := parseTimestamp(createdAt) // 写入路径统一 formatTimestamp，解析失败以零值容错
	updated, _ := parseTimestamp(updatedAt)
	return &Mailbox{
		ID:           id,
		LocalPart:    localPart,
		Domain:       domain,
		Address:      address,
		PasswordHash: hashToString(hash),
		Status:       MailboxStatus(status),
		CreatedAt:    created,
		UpdatedAt:    updated,
	}
}

// hashOrNil 空 hash → nil（shadow 无凭据，DDL NULL 语义）；否则原样返回。
func hashOrNil(hash string) any {
	if hash == "" {
		return nil
	}
	return hash
}

// hashToString dbgen interface{} 凭据列 → string（nil→空串）。
func hashToString(hash any) string {
	if s, ok := hash.(string); ok {
		return s
	}
	return ""
}

// formatTimestamp time.Time → RFC3339 UTC 字符串（数据模型第五章：SQLite TEXT 统一口径）。
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// parseTimestamp RFC3339 字符串 → time.Time（与 formatTimestamp 互逆）。
func parseTimestamp(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
