// Package storage 追加邮件元数据仓储：MessageRepo 接口族与 SQLite 实现（收信+访问路径）。
// 依据：模块接口契约 v1.3.0 第 2.1 节（十一方法签名逐字复刻——v1.3.0 增 StoreAppend/
// IMAPSearch 两方法与 FlagPatch.Deleted 字段，Q3-A 裁决 2026-09-18 00:06:55）；
// 数据库表结构 v1.0.0 第 3.4/3.5 节（messages/mailbox_messages，U1 迁移已建）＋1.3 节
// （双写顺序：Blob 先、DB 后；messages+mailbox_messages 同事务）；
// 关键流程设计 v1.0.0 第一章要点 4（单邮件多收件人：一次 Blob 写入、多条 mailbox_messages 同事务）。
// 覆盖条目：FR-005（收信落库）/FR-003/FR-004（影子归档+通知邮件行）/NFR-007（事务原子性锚点）/
// FR-006（IMAP 访问路径：PageList/GetDetail/SetFlags/Move/SoftDelete/HardDelete/StoreAppend/IMAPSearch）。
// 实现范围（U6 计划书步骤 3 + U9 计划书步骤 3）：U6 补齐 IMAP 路径八实现（PageList/
// GetDetail/SetFlags/Move/SoftDelete/HardDelete/StoreAppend/IMAPSearch）；U9 落地 Search
// （Q6-A：仅元数据缓存列 OR LIKE，Bob 构建——见 webmail_query.go）并扩展 ListQuery/ListItem
// 的 Webmail 过滤与状态可视化字段（U9 已兑现——零契约签名变更，字段集属 storage 域
// 代码层结构，契约 v1.5.0 2.1 末注）。
// IMAPSearch 经 Bob 动态构建（架构选型 #8；实现见 imap_search.go，storage 零协议类型依赖）。
// 修改历史：
//
//	2026-09-17 03:30:00 | 新建 | U4 SMTP 收信（计划书步骤 6，G2 批准 2026-09-17 03:12:40）
//	2026-09-18 00:16:00 | 扩展 | U6 IMAP 集成（计划书步骤 3，G2 批准 2026-09-18 00:09:22）
//	2026-09-19 10:10:00 | 扩展 | U9 Webmail 核心（计划书步骤 3，G2 批准 2026-09-19 10:00:41）：
//	  ListQuery 增 UnreadOnly/FlaggedOnly/ExcludeDeleted 三过滤位+ListItem 增 Deleted 状态
//	  可视化字段+PageList 分流（任一过滤位真→Bob Webmail 路径，normal 基线；零值保持 U6
//	  IMAP 全量语义）+Search 实现落地（占位哨兵移除）
//	2026-09-24 12:02:00 | 扩展 | U16 Webmail 体验收尾（计划书步骤 2/3，G2 批准 2026-09-24 11:51:57）：
//	  MessageMeta 增 BodyCache 字段（Q3-A 正文缓存列——数据模型 v1.3.0 3.4）+insertMessageRow
//	  增列+MessageRepo 增 ListBodyCachePending/FillBodyCache 两方法（存量回填任务消费——契约
//	  v1.12.0 2.1 增量）+BodyCacheBackfill 域类型
//	2026-09-28 09:35:00 | 修正 | R5R6收敛：两处过时 TODO(U9) 注释残留清理（头部依据
//	注释+Search 接口注释——Search 已 U9 落地；Q2-A 最小定点裁决边界；依据：R5R6收敛
//	计划书 v1.0.0 步骤 5，G2 批准 2026-09-28 09:31:53）
//	2026-09-30 23:50:00 | 扩展 | D8登记项处置批次 K-A：IMAP keyword 持久存储
//	  （mailbox_keywords 表+迁移 00008——D8 #1；Detail/AppendMeta 增 Keywords、
//	  SearchFilter 增 Keywords/NotKeywords、MessageRepo 增 SetKeywords、
//	  GetDetail 回填/StoreAppend·CopyAtomic 写入/HardDelete·MOVE 删源前清理；
//	  rfc9051 §2.3.2 L565-569/§6.4.4 L3908·L3980/§6.4.6 L4570-4592/L573-574；
//	  依据：D8登记项处置_计划_20260930_23-45-00_v1.0.0 1.2#1，G2 批准 23:40:58）
//	2026-10-03 06:30:00 | 扩展 | U25影子邮箱聚合可达（G2 批准 2026-10-02 19:41:00）：
//	  RecipientTarget 增 Aggregate 标记（聚合副本目标——applySieve 跳过锚）、
//	  MessageRepo 增 ListShadowBackfill/CopyToAggregateFolder（存量回填——S3-W Q4）、
//	  HardDelete 内联级联展开（聚合文件夹行删除→同 message_id 全部关联行并入——
//	  S3-W Q2 附加指示「删聚合=删真实邮件」；FR-003 承载扩展，迁移 00010 三库）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	dbgen "GRmail/internal/storage/dbgen/sqlite"
)

// ───────────────────────── 域类型（数据模型 3.4/3.5） ─────────────────────────

// MessageMeta messages 行元数据（收信管道解析与验证结论的落库载体；空串映射 NULL）。
type MessageMeta struct {
	MessageID         string    // RFC 5322 Message-ID 头
	BlobKey           string    // SHA-256 hex（注入 A-R 头后的存储字节，Q13 CAS）
	RawSize           int64     // 存储字节数（SIZE 上限校验口径）
	Subject           string    // 解析缓存（rfc2047 解码后）
	FromAddr          string    // 规范化缓存（首个 From 地址）
	ToAddrs           string    // JSON 数组缓存（列表渲染免解析）
	CcAddrs           string    // JSON 数组缓存
	BodyCache         string    // 正文纯文本截断缓存（U16 Q3-A——≤bodyCacheMaxBytes；空串映射 NULL，存量行经回填任务补齐）
	SentAt            time.Time // Date 头时间（零值映射 NULL）
	SPFResult         string    // 验证结论缓存（U3 VerifyResults 四元组）
	DKIMResult        string
	DMARCResult       string
	ARCResult         string
	AuthResultsHeader string // rfc8601 原文
}

// RecipientTarget 单收件人投递目标（收信默认入收件箱；U12 兑现 Sieve 扩展位——
// 计划书 1.5②：FolderName=fileinto 目标文件夹名，folder_id 解析归 StoreInbound
// 落库前置（mailbox_id+name 查询）；Address 供 Sieve envelope "to" 与执行主体定位；
// 标志初值为 imap4flags \Seen/\Flagged 映射——rfc5232 §3 :flags 语义）。
type RecipientTarget struct {
	MailboxID   int64
	Address     string // 收件地址（小写规范化）
	FolderName  string // Sieve fileinto 目标文件夹名（空=收件箱默认——既有调用零影响）
	FlagSeen    bool   // 落库行 is_read 初值（U12 imap4flags）
	FlagFlagged bool   // 落库行 is_flagged 初值（U12 imap4flags）
	// Aggregate 聚合副本标记（U25——FR-003 承载扩展）：true=影子来信的 postmaster
	// 聚合投递目标（FolderName 固定 Unregistered）；applySieve 跳过该目标（S3-W
	// Q3 裁决——管理员聚合视图不被个人脚本重排）；既有调用零置位零影响。
	Aggregate bool
}

// NoticeMeta 影子邮箱通知邮件（Q4-A 裁决 2026-09-17 03:06:39：与来信元数据同事务落库，
// 目标 postmaster@主域——TC-004 判定①「管理员收到通知」的实体判定物）。
type NoticeMeta struct {
	Message   MessageMeta // 通知邮件的 messages 行
	MailboxID int64       // postmaster 邮箱 ID（管道先行确保存在）
}

// InboundMeta 单次收信落库事务的完整输入（契约 2.1 StoreInbound 入参载体）：
// 单条 messages 行+多条 mailbox_messages 行+可选通知邮件行，单事务原子提交。
type InboundMeta struct {
	Message    MessageMeta       // 来信元数据（全部收件人共享，流程设计第一章要点 4）
	Recipients []RecipientTarget // 各收件人 mailbox_messages 行输入
	Notice     *NoticeMeta       // 本次投递触发影子建立时的通知邮件（无则为 nil）
}

// ───────────────────────── 契约引用类型（U6/U9 扩展位） ─────────────────────────

// ListQuery 列表分页查询输入（NFR-001 主路径）。
// 过滤位语义（U9）：零值（三过滤位全 false）＝U6 IMAP 全量语义（含 \Deleted 行）——
// 既有调用方行为不变；任一过滤位为真 → 走 Webmail Bob 路径（status='normal' 基线，
// \Deleted 中间态对用户隐藏——U9 计划书 1.5 口径，G14 两段式删除由上层承载）。
type ListQuery struct {
	MailboxID      int64
	FolderID       int64
	Limit          int32
	Offset         int32
	UnreadOnly     bool // 仅未读（is_read=0；状态可视化入口 G11）
	FlaggedOnly    bool // 仅星标（is_flagged=1）
	ExcludeDeleted bool // 排除 \Deleted 行（触发 Webmail 语义路径——与上两位任一真等效分流）
}

// SearchQuery 关键词搜索输入（U9 已实现：Bob 动态构建——OR 命中 subject/from_addr/
// to_addrs 三缓存列，Q6-A 裁决零数据模型演进；跨文件夹全局搜索，mailbox 限定隔离）。
type SearchQuery struct {
	MailboxID int64
	Keyword   string
	Limit     int32
	Offset    int32
}

// ListItem 列表行（subject/from/时间等渲染免解析缓存列；状态可视化字段 U9 扩展；
// 配置并发批 F10〔M3〕增 Size/BlobKey——IMAPSearch 单查询直取，POP3 登录期逐条
// GetDetail N+1 消除；沿契约 v1.3.0 注记「字段集由消费单元按需扩展」先例）。
type ListItem struct {
	ID        int64
	UID       int64
	Subject   string
	FromAddr  string
	SentAt    time.Time
	IsRead    bool
	IsFlagged bool
	Deleted   bool   // status=deleted（IMAP \Deleted 中间态；Webmail 路径不产出该态）
	Size      int64  // F10：messages.raw_size（IMAPSearch 列集尾部直取；零值=未选择该列的旧调用面）
	BlobKey   string // F10：messages.blob_key（同上——POP3 maildrop 快照单查询承载）
}

// Detail 邮件详情（U6 IMAP FETCH / U9 Webmail 详情消费）。
// ID 语义：mailbox_messages.id（账号视角的邮件行主键——IMAP 视角一封邮件在该账号的唯一载体）。
type Detail struct {
	ID         int64 // mailbox_messages.id
	UID        int64 // IMAP UID（mailbox 内单调，rfc9051）
	MailboxID  int64
	FolderID   int64
	MessagePK  int64  // messages.id（关联元数据行）
	BlobKey    string // CAS 寻址（原始字节读取入口）
	Subject    string
	FromAddr   string
	ToAddrs    string // JSON 数组缓存
	CcAddrs    string
	SentAt     time.Time // Date 头（零值=缺失）
	RawSize    int64
	IsRead     bool
	IsFlagged  bool
	IsAnswered bool // RF-J/F-I16：IMAP \Answered 系统标志（rfc9051 §2.3.2/§7.3.5）
	IsDraft    bool // RF-J/F-I16：IMAP \Draft 系统标志
	Deleted    bool // status=deleted（IMAP \Deleted）
	CreatedAt  time.Time

	InternalDate *time.Time // F-I4/F-I5：IMAP internal date（nil=未指定——读侧回退 CreatedAt 既有语义；APPEND date-time/COPY 保留承载）

	// Keywords IMAP keyword 集（D8#1——rfc9051 §2.3.2 L565-569「A keyword is
	// defined by the server implementation. Keywords do not begin with "\"」；
	// 独立表 mailbox_keywords 持久承载；nil/空=无 keyword——FETCH FLAGS/STORE 终态
	// 计算与 COPY/MOVE 保留（L573-574 SHOULD）的消费载体）
	Keywords []string
}

// FlagPatch 标志位补丁（U6 IMAP STORE 消费；nil 字段=不变更——三值补丁语义）。
// v1.3.0 扩展（Q3-A）：Deleted 映射 mailbox_messages.status（true→'deleted'/false→'normal'），
// 即 IMAP \Deleted 系统标志承载（rfc9051 2.3.2；EXPUNGE 前置标记）。
// v1.16.0 扩展（RF-J/F-I16，Q2-A 裁决 RFC 化）：IsAnswered/IsDraft 承载
// \Answered/\Draft 系统标志（五系统标志全承载——rfc9051 §2.3.2/§7.3.5）。
type FlagPatch struct {
	IsRead     *bool
	IsFlagged  *bool
	IsAnswered *bool
	IsDraft    *bool
	Deleted    *bool
}

// AppendMeta IMAP APPEND 落库输入（契约 v1.3.0 2.1；rfc9051 6.3.12）。
// 双写顺序对齐数据模型 1.3：调用方（protocol/imap）先行 BlobStore.Write，本结构仅承载元数据。
type AppendMeta struct {
	Message MessageMeta // 客户端提交邮件的解析元数据
	Flags   FlagPatch   // APPEND 可选标志初值（\Seen/\Flagged/\Deleted/\Answered/\Draft——v1.16.0 五标志）
	// InternalDate APPEND 可选 date-time 参数（F-I5——rfc9051 §6.3.12 L3440-3442
	// 「If a date-time is specified, the internal date SHOULD be set」；nil=缺省落库时刻；
	// COPY/MOVE 路径承载源行保留语义 F-I4——§6.4.7 L4615-4617/§6.4.8 L4663-4665）
	InternalDate *time.Time
	// Keywords APPEND 可选 keyword 初值/COPY·MOVE 源行保留（D8#1——rfc9051
	// §6.3.12 APPEND flag list 可含 keyword+L573-574「allowed and preserved in
	// APPEND, COPY, and MOVE commands」SHOULD；空=无）
	Keywords []string
}

// IMAPSearchQuery IMAP SEARCH 动态查询输入（契约 v1.3.0 2.1；中性条件——
// 协议语义由 protocol/imap 翻译为 SearchFilter，storage 零协议依赖，架构第三章）。
type IMAPSearchQuery struct {
	MailboxID int64
	FolderID  int64
	Filter    SearchFilter
}

// SearchFilter 搜索条件交集（多字段同真 AND；Not/Or 一层嵌套；契约 v1.3.0 2.1）。
// 覆盖 rfc9051 6.4.4 常用键子集：SUBJECT/FROM/TO/BODY/TEXT/UID/SINCE/BEFORE/
// SENTBEFORE/SENTSINCE/LARGER/SMALLER/SEEN/UNSEEN/FLAGGED/DELETED/UNDELETED/NOT/OR。
type SearchFilter struct {
	UIDs         []int64
	Since        *time.Time
	Before       *time.Time
	SentSince    *time.Time
	SentBefore   *time.Time
	From         string
	To           string
	Subject      string
	Body         string
	Text         string
	Larger       int64
	Smaller      int64
	FlagSeen     *bool
	FlagFlagged  *bool
	FlagAnswered *bool // RF-J/F-I10：ANSWERED/UNANSWERED 键承载（rfc9051 §6.4.4）
	FlagDraft    *bool // RF-J/F-I10：DRAFT/UNDRAFT 键承载
	FlagDeleted  *bool
	Not          *SearchFilter
	Or           [][2]SearchFilter
	// Keywords KEYWORD <flag-keyword> 键承载（D8#1——rfc9051 §6.4.4 L3908-3909
	// 「Messages with the specified keyword flag set」；多键 AND——每键一条
	// EXISTS 子查询；空=不约束）
	Keywords []string
	// NotKeywords UNKEYWORD <flag-keyword> 键承载（L3980-3981「Messages that
	// do not have the specified keyword flag set」；多键逐键 NOT EXISTS——
	// NOT k1 AND NOT k2 交集语义；空=不约束）
	NotKeywords []string
}

// ───────────────────────── 接口族（契约 2.1 逐字） ─────────────────────────

// MessageRepo 邮件元数据+关联仓储（列表查询经 Bob 动态构建）。
type MessageRepo interface {
	// StoreInbound messages+mailbox_messages 同事务（数据模型 1.3；U4 实现收信路径）。
	StoreInbound(ctx context.Context, txmeta *InboundMeta) error
	// PageList 分页+过滤（NFR-001 主路径）。U6 实现并启用。
	PageList(ctx context.Context, q ListQuery) ([]*ListItem, int64, error)
	// Search 关键词（Bob LIKE 安全转义；U9 落地——subject/from_addr/to_addrs/body_cache 四列 OR）。
	Search(ctx context.Context, q SearchQuery) ([]*ListItem, int64, error)
	// GetDetail 邮件详情（msgPK=mailbox_messages.id）。U6 实现并启用。
	GetDetail(ctx context.Context, mailboxID, msgPK int64) (*Detail, error)
	// SetFlags 标志位变更（三值补丁：nil 不变更）。U6 实现并启用。
	SetFlags(ctx context.Context, id int64, flags FlagPatch) error
	// Move 文件夹移动（folder_id 更新；UID 保留——mailbox 域全局序列语义）。U6 实现并启用。
	Move(ctx context.Context, id, folderID int64) error
	// SoftDelete 软删除（status=deleted，IMAP \Deleted）。U6 实现并启用。
	SoftDelete(ctx context.Context, ids []int64) error
	// HardDelete 硬删除（关联行删除+孤儿 messages 行清理；blob 由对账清理）。U6 实现并启用。
	HardDelete(ctx context.Context, ids []int64) error
	// NextUID mailbox 内下一 UID（IMAP UID 语义；U4 实现供收信分配参考）。
	NextUID(ctx context.Context, mailboxID int64) (int64, error)
	// StoreAppend IMAP APPEND 落库（Blob 先行写入后调用；契约 v1.3.0，U6）。
	StoreAppend(ctx context.Context, mailboxID, folderID int64, meta *AppendMeta) (int64, error)
	// CopyAtomic 批量复制单事务（RF-J/F-I13——rfc9051 §6.4.7 L4627-4630
	// 「partial copy MUST NOT be done」；契约 v1.16.0；moveSources 非空时同事务
	// 删源行+清孤儿——rfc6851 MOVE 原子性；返回逐条分配的 UID 列表）。
	CopyAtomic(ctx context.Context, mailboxID, destFolderID int64, metas []*AppendMeta, moveSources []int64) ([]int64, error)
	// IMAPSearch IMAP SEARCH 动态查询（Bob 构建；契约 v1.3.0，U6）。
	IMAPSearch(ctx context.Context, q IMAPSearchQuery) ([]*ListItem, error)
	// ListBodyCachePending 待回填正文缓存的批查（WHERE body_cache IS NULL；契约 v1.12.0，U16）。
	ListBodyCachePending(ctx context.Context, limit int) ([]BodyCacheBackfill, error)
	// FillBodyCache 单行正文缓存回填（缓存维度尽力语义；契约 v1.12.0，U16）。
	FillBodyCache(ctx context.Context, id int64, body string) error
	// SetKeywords keyword 终态替换（D8#1——契约 v1.19.0；id=mailbox_messages.id；
	// 终态全量替换语义：先清后插单事务，终态计算归协议层 flagPatchFromOp 同源
	// 模式；rfc9051 §6.4.6 STORE FLAGS(±/Set) 三态的 keyword 承载）
	SetKeywords(ctx context.Context, id int64, keywords []string) error
	// ── U25 增量（影子邮箱聚合可达，FR-003 承载扩展——契约 v1.22.0）──
	// ListShadowBackfill 存量回填批查（S3-W Q4 裁决：shadow 邮箱归档行中尚无聚合
	// 副本的 message_id 集——DISTINCT+NOT EXISTS 幂等锚，重跑自然跳过）。
	ListShadowBackfill(ctx context.Context, limit int) ([]int64, error)
	// CopyToAggregateFolder 单事务聚合副本补写（回填任务消费：postmaster 聚合文件夹
	// 追加 mailbox_messages 行——同 message_id 复用 messages 主体与 blob〔CAS 零字节
	// 重复〕；UID 事务内分配；标志初值未读未标——管理员视角"新出现"）。
	CopyToAggregateFolder(ctx context.Context, mailboxID, messageID int64) error
}

// BodyCacheBackfill 回填任务批查行（契约 v1.12.0 2.1——id+blob_key 两字段回填数据源）。
type BodyCacheBackfill struct {
	ID      int64
	BlobKey string
}

// 接口断言（U6 启用——IMAP 路径八实现补齐，U4 登记的推迟口径兑现）。
var _ MessageRepo = (*SQLiteMessageRepo)(nil)

// ───────────────────────── SQLite 实现（收信路径） ─────────────────────────

// SQLiteMessageRepo MessageRepo 的 SQLite 实现（U4 范围：StoreInbound/NextUID）。
type SQLiteMessageRepo struct {
	db *sql.DB
	q  *dbgen.Queries
}

// NewSQLiteMessageRepo 构造邮件仓储。
// 参数：db 已迁移就绪的数据库连接（storage.Open 产物）。返回：仓储实例。
func NewSQLiteMessageRepo(db *sql.DB) *SQLiteMessageRepo {
	return &SQLiteMessageRepo{db: db, q: dbgen.New(db)}
}

// StoreInbound 收信落库单事务：来信 messages 行→各收件人 mailbox_messages 行（UID 事务内
// MAX+1 分配，SQLite 写事务串行保证 UNIQUE(mailbox_id,uid) 不冲突）→可选影子通知邮件行。
// 任一步失败整体回滚（零半截数据——CON-004 防丢信：调用方据此返回 451 促对端重试）。
// 参数：ctx 上下文（携带 LogID logger）；txmeta 落库输入。返回：事务失败原因。
func (r *SQLiteMessageRepo) StoreInbound(ctx context.Context, txmeta *InboundMeta) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启收信事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 提交后回滚为无害空操作

	qtx := r.q.WithTx(tx)
	now := formatTimestamp(time.Now().UTC())

	// 1. 来信 messages 行（全部收件人共享单行，流程设计第一章要点 4）
	msgPK, err := insertMessageRow(ctx, qtx, txmeta.Message, now)
	if err != nil {
		return err
	}

	// 2. 各收件人 mailbox_messages 行（收件箱 kind=inbox 固定；UID 事务内递增分配）
	if err := archiveToInbox(ctx, qtx, txmeta.Recipients, msgPK, now); err != nil {
		return err
	}

	// 3. 影子通知邮件行（Q4-A：与来信同事务；通知目标 postmaster 邮箱由管道先行确保）
	if txmeta.Notice != nil {
		noticePK, nerr := insertMessageRow(ctx, qtx, txmeta.Notice.Message, now)
		if nerr != nil {
			return nerr
		}
		if nerr = archiveToInbox(ctx, qtx, []RecipientTarget{{MailboxID: txmeta.Notice.MailboxID}}, noticePK, now); nerr != nil {
			return nerr
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交收信事务: %w", err)
	}
	return nil
}

// NextUID 返回 mailbox 内下一可用 UID（MAX(uid)+1；空邮箱返回 1，rfc9051 UID 从 1 起）。
// 参数：ctx 上下文；mailboxID 邮箱 ID。返回：下一 UID。
func (r *SQLiteMessageRepo) NextUID(ctx context.Context, mailboxID int64) (int64, error) {
	v, err := r.q.GetMaxMailboxUID(ctx, mailboxID)
	if err != nil {
		return 0, fmt.Errorf("查询最大 UID: %w", err)
	}
	return coalesceInt64(v) + 1, nil
}

// ───────────────────────── 事务内辅助 ─────────────────────────

// insertMessageRow 插入 messages 行并回填主键。
func insertMessageRow(ctx context.Context, qtx *dbgen.Queries, m MessageMeta, now string) (int64, error) {
	res, err := qtx.InsertMessage(ctx, dbgen.InsertMessageParams{
		MessageID:         nullIfEmpty(m.MessageID),
		BlobKey:           m.BlobKey,
		RawSize:           m.RawSize,
		Subject:           nullIfEmpty(m.Subject),
		FromAddr:          nullIfEmpty(m.FromAddr),
		ToAddrs:           nullIfEmpty(m.ToAddrs),
		CcAddrs:           nullIfEmpty(m.CcAddrs),
		BodyCache:         nullIfEmpty(m.BodyCache),
		SentAt:            nullIfZeroTime(m.SentAt),
		SpfResult:         nullIfEmpty(m.SPFResult),
		DkimResult:        nullIfEmpty(m.DKIMResult),
		DmarcResult:       nullIfEmpty(m.DMARCResult),
		ArcResult:         nullIfEmpty(m.ARCResult),
		AuthResultsHeader: nullIfEmpty(m.AuthResultsHeader),
		CreatedAt:         now,
	})
	if err != nil {
		return 0, fmt.Errorf("插入邮件元数据: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("获取邮件 ID: %w", err)
	}
	return id, nil
}

// archiveToInbox 逐收件人写 mailbox_messages 行（UID 事务内 MAX+1；U12 扩展：
// FolderName 非空时按 mailbox_id+name 解析目标文件夹（Sieve fileinto——rfc5228 §4.1
// 「MAY treat as error」取错误分支：不存在返回错误由管道按 implicit keep 兜底重归
// 收件箱；FlagSeen/FlagFlagged 为 imap4flags 初值——rfc5232 :flags 语义）。
func archiveToInbox(ctx context.Context, qtx *dbgen.Queries, targets []RecipientTarget, msgPK int64, now string) error {
	for _, t := range targets {
		uid, err := nextUIDInTx(ctx, qtx, t.MailboxID)
		if err != nil {
			return err
		}
		var folderID int64
		if t.FolderName == "" {
			if folderID, err = inboxFolderIDInTx(ctx, qtx, t.MailboxID); err != nil {
				return err
			}
		} else {
			row, ferr := qtx.GetFolderByName(ctx, dbgen.GetFolderByNameParams{
				MailboxID: t.MailboxID, Name: t.FolderName,
			})
			if ferr != nil {
				return fmt.Errorf("sieve fileinto 文件夹 %q 解析失败（收件人按 implicit keep 兜底）: %w", t.FolderName, ferr)
			}
			folderID = row.ID
		}
		if _, err = qtx.InsertMailboxMessageWithFlags(ctx, dbgen.InsertMailboxMessageWithFlagsParams{
			MailboxID: t.MailboxID,
			MessageID: msgPK,
			FolderID:  folderID,
			Uid:       uid,
			IsRead:    t.FlagSeen,
			IsFlagged: t.FlagFlagged,
			Status:    "normal",
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("插入邮箱关联行: %w", err)
		}
	}
	return nil
}

// nextUIDInTx 事务内查询 mailbox 下一 UID（与 StoreInbound 同事务保证分配串行）。
func nextUIDInTx(ctx context.Context, qtx *dbgen.Queries, mailboxID int64) (int64, error) {
	v, err := qtx.GetMaxMailboxUID(ctx, mailboxID)
	if err != nil {
		return 0, fmt.Errorf("查询邮箱最大 UID: %w", err)
	}
	return coalesceInt64(v) + 1, nil
}

// inboxFolderIDInTx 事务内查询邮箱收件箱文件夹 ID（邮箱创建事务保证五系统文件夹存在）。
func inboxFolderIDInTx(ctx context.Context, qtx *dbgen.Queries, mailboxID int64) (int64, error) {
	f, err := qtx.GetSystemFolderByKind(ctx, dbgen.GetSystemFolderByKindParams{
		MailboxID: mailboxID,
		Kind:      string(FolderKindInbox),
	})
	if err != nil {
		return 0, fmt.Errorf("查询收件箱文件夹: %w", err)
	}
	return f.ID, nil
}

// nullIfEmpty 空串 → NULL（messages 可空缓存列统一口径）。
func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// nullIfZeroTime 零值时间 → NULL（Date 头缺失场景，解析层已容错）。
func nullIfZeroTime(t time.Time) sql.NullString {
	return sql.NullString{String: formatTimestamp(t), Valid: !t.IsZero()}
}

// coalesceInt64 SQLite COALESCE 聚合结果 interface{} → int64（驱动返回形态兜底）。
func coalesceInt64(v any) int64 {
	if i, ok := v.(int64); ok {
		return i
	}
	return 0
}

// ───────────────────────── U6 IMAP 路径实现（契约 v1.3.0 2.1） ─────────────────────────

// ErrMessageNotFound 邮箱关联行不存在（GetDetail/SetFlags/Move 目标缺失语义，
// 供 protocol/imap 映射 IMAP NO 应答）。
var ErrMessageNotFound = errors.New("storage: 邮件不存在")

// PageList 文件夹分页列表（UID 降序——最新在前；NFR-001 主查询路径索引命中）。
// 分流（U9）：q 三过滤位零值 → sqlc 静态全量路径（U6 IMAP 语义：含 normal+deleted，
// \Deleted 状态经 ListItem.Deleted 由调用方处置）；任一过滤位真 → Bob Webmail 路径
// （normal 基线+可选未读/星标，实现见 webmail_query.go）。
// 参数：q 查询输入。返回：行列表、总数。
func (r *SQLiteMessageRepo) PageList(ctx context.Context, q ListQuery) ([]*ListItem, int64, error) {
	if q.UnreadOnly || q.FlaggedOnly || q.ExcludeDeleted {
		return r.pageListWebmail(ctx, q)
	}
	total, err := r.q.CountMessagesByFolder(ctx, dbgen.CountMessagesByFolderParams{
		MailboxID: q.MailboxID, FolderID: q.FolderID,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("统计文件夹邮件数: %w", err)
	}
	rows, err := r.q.ListMessagesByFolderPage(ctx, dbgen.ListMessagesByFolderPageParams{
		MailboxID: q.MailboxID, FolderID: q.FolderID,
		Limit: int64(q.Limit), Offset: int64(q.Offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("分页查询邮件列表: %w", err)
	}
	items := make([]*ListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, &ListItem{
			ID:        row.MmID,
			UID:       row.MmUid,
			Subject:   row.MSubject.String,
			FromAddr:  row.MFromAddr.String,
			SentAt:    parseTimestampOrZero(row.MSentAt),
			IsRead:    row.MmIsRead,
			IsFlagged: row.MmIsFlagged,
			Deleted:   row.MmStatus == "deleted",
		})
	}
	return items, total, nil
}

// pageListWebmail Webmail 过滤列表路径（U9）：Bob 构建分页+总数两查询（normal 基线），
// 扫描列对齐 webmailListColumns（NULL 列防御性经 sql.NullString 容错）。
func (r *SQLiteMessageRepo) pageListWebmail(ctx context.Context, q ListQuery) ([]*ListItem, int64, error) {
	countSQL, countArgs, err := buildWebmailListCountSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建 Webmail 计数: %w", err)
	}
	var total int64
	if err = r.db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计 Webmail 列表: %w", err)
	}
	pageSQL, pageArgs, err := buildWebmailListPageSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建 Webmail 分页: %w", err)
	}
	items, err := r.queryWebmailItems(ctx, pageSQL, pageArgs)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// queryWebmailItems 执行 Webmail 形态查询并扫描行（8 列，对齐 webmailListColumns）。
func (r *SQLiteMessageRepo) queryWebmailItems(ctx context.Context, query string, args []any) ([]*ListItem, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("执行 Webmail 查询: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]*ListItem, 0, 32)
	for rows.Next() {
		var it ListItem
		var sentAt, subject, fromAddr, status sql.NullString
		if err = rows.Scan(&it.ID, &it.UID, &sentAt, &subject, &fromAddr, &it.IsRead, &it.IsFlagged, &status); err != nil {
			return nil, fmt.Errorf("扫描 Webmail 行: %w", err)
		}
		it.SentAt = parseTimestampOrZero(sentAt)
		it.Subject, it.FromAddr = subject.String, fromAddr.String
		it.Deleted = status.Valid && status.String == "deleted"
		items = append(items, &it)
	}
	return items, rows.Err()
}

// GetDetail 单行详情（msgPK=mailbox_messages.id；mailboxID 双重限定保证账号隔离 FR-001）。
func (r *SQLiteMessageRepo) GetDetail(ctx context.Context, mailboxID, msgPK int64) (*Detail, error) {
	row, err := r.q.GetMailboxMessageDetail(ctx, dbgen.GetMailboxMessageDetailParams{
		MailboxID: mailboxID, ID: msgPK,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMessageNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("查询邮件详情: %w", err)
	}
	detail := &Detail{
		ID:           row.MmID,
		UID:          row.MmUid,
		MailboxID:    row.MmMailboxID,
		FolderID:     row.MmFolderID,
		MessagePK:    row.MmMessagePk,
		BlobKey:      row.MBlobKey,
		Subject:      row.MSubject.String,
		FromAddr:     row.MFromAddr.String,
		ToAddrs:      row.MToAddrs.String,
		CcAddrs:      row.MCcAddrs.String,
		SentAt:       parseTimestampOrZero(row.MSentAt),
		RawSize:      row.MRawSize,
		IsRead:       row.MmIsRead,
		IsFlagged:    row.MmIsFlagged,
		IsAnswered:   row.MmIsAnswered,
		IsDraft:      row.MmIsDraft,
		Deleted:      row.MmStatus == "deleted",
		CreatedAt:    parseTimestampOrZero(sql.NullString{String: row.MmCreatedAt, Valid: row.MmCreatedAt != ""}),
		InternalDate: internalDateOf(row.MmInternalDate), // F-I4/F-I5：指定态读回（nil=未指定回退 CreatedAt）
	}
	detail.Keywords = messageKeywordsOf(ctx, r.q, msgPK) // D8#1：keyword 二次查询回填
	return detail, nil
}

// messageKeywordsOf 单行 keyword 读回（D8#1——mailbox_keywords 二次查询；空集安全形态）。
func messageKeywordsOf(ctx context.Context, q interface {
	ListMessageKeywords(ctx context.Context, mailboxMessageID int64) ([]string, error)
}, msgPK int64) []string {
	kws, err := q.ListMessageKeywords(ctx, msgPK)
	if err != nil || len(kws) == 0 {
		return nil
	}
	return kws
}

// SetKeywords keyword 终态替换（D8#1——契约 v1.19.0：先清后插单事务；终态计算归调用方
// 〔协议层 keywordsFromOp——STORE FLAGS/Set/Add/Del 三态〕；输入去重+长度防御〔≤255
// ——迁移列宽对齐〕；空集=清空该行全部 keyword）。
// 参数：ctx 上下文；id mailbox_messages.id；keywords 终态集。返回：事务失败原因。
func (r *SQLiteMessageRepo) SetKeywords(ctx context.Context, id int64, keywords []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启 keyword 事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	if err = qtx.DeleteKeywordsByMessageID(ctx, id); err != nil {
		return fmt.Errorf("清空 keyword: %w", err)
	}
	now := formatTimestamp(time.Now().UTC())
	seen := make(map[string]struct{}, len(keywords))
	for _, kw := range keywords {
		if kw == "" || len(kw) > 255 { // 防御：空串与超宽（协议层已保证 atom 合法性）
			continue
		}
		if _, dup := seen[kw]; dup {
			continue
		}
		seen[kw] = struct{}{}
		if err = qtx.InsertMailboxKeyword(ctx, dbgen.InsertMailboxKeywordParams{
			MailboxMessageID: id, Keyword: kw, CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("插入 keyword: %w", err)
		}
	}
	return tx.Commit()
}

// internalDateOf SQLite internal_date 列读回（TEXT RFC3339 或 NULL——驱动经 interface{} 承载）。
func internalDateOf(v any) *time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	t, err := parseTimestamp(s)
	if err != nil {
		return nil
	}
	return &t
}

// internalDateArgSQLite *time.Time → sqlite internal_date 参数（nil/零值=NULL 缺省口径）。
func internalDateArgSQLite(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return formatTimestamp(*t)
}

// internalDateOfNullTime MySQL/PG internal_date 列读回（sql.NullTime——invalid=未指定 nil）。
func internalDateOfNullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

// internalDateArgNullTime *time.Time → MySQL/PG internal_date 参数（nil/零值=Invalid NULL）。
func internalDateArgNullTime(t *time.Time) sql.NullTime {
	if t == nil || t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// SetFlags 三值补丁更新（配置并发批 F4/B-C1：单 SQL 原子化——守卫参数 NULL 时
// CASE 回退现值，三值语义 SQL 内承载；原读-改-写两条独立自动提交语句在并发
// 标志更新下互相覆盖丢失更新〔三库皆然——评审 B-C1 复核修正口径〕——竞态窗口收口）。
func (r *SQLiteMessageRepo) SetFlags(ctx context.Context, id int64, flags FlagPatch) error {
	n, err := r.q.UpdateMailboxMessageFlags(ctx, dbgen.UpdateMailboxMessageFlagsParams{
		ReadSet:     guardSetSQLite(flags.IsRead),
		ReadVal:     valOf(flags.IsRead),
		FlaggedSet:  guardSetSQLite(flags.IsFlagged),
		FlaggedVal:  valOf(flags.IsFlagged),
		AnsweredSet: guardSetSQLite(flags.IsAnswered),
		AnsweredVal: valOf(flags.IsAnswered),
		DraftSet:    guardSetSQLite(flags.IsDraft),
		DraftVal:    valOf(flags.IsDraft),
		DeletedSet:  guardSetSQLite(flags.Deleted),
		DeletedFlag: flagStrOf(flags.Deleted),
		ID:          id,
	})
	if err != nil {
		return fmt.Errorf("更新标志位: %w", err)
	}
	if n == 0 {
		return ErrMessageNotFound
	}
	return nil
}

// guardSetSQLite 三值补丁守卫参数（F4 sqlite interface{} 形态：nil=该列不修改；
// 非 nil 任意真值=按对应 *Val 修改——SQL 侧仅判定 IS NULL）。
func guardSetSQLite(b *bool) any {
	if b == nil {
		return nil
	}
	return true
}

// valOf 三值补丁值参数（nil 时取 false 占位——守卫 NULL 短路不消费该值）。
func valOf(b *bool) bool {
	return b != nil && *b
}

// flagStrOf deleted_flag 文本形态（F4 sqlite/mysql 生成物为 string——"1"=deleted/
// "0"=normal；守卫 NULL 时取空占位不消费）。
func flagStrOf(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "1"
	}
	return "0"
}

// Move 跨文件夹移动（folder_id 更新；UID 保留——mailbox 域全局序列，
// UNIQUE(mailbox_id,uid) 保证目标 folder 内无冲突，rfc9051 UID 跳号合法）。
func (r *SQLiteMessageRepo) Move(ctx context.Context, id, folderID int64) error {
	n, err := r.q.MoveMailboxMessage(ctx, dbgen.MoveMailboxMessageParams{
		FolderID: folderID, ID: id,
	})
	if err != nil {
		return fmt.Errorf("移动邮件: %w", err)
	}
	if n == 0 {
		return ErrMessageNotFound
	}
	return nil
}

// SoftDelete 批量置 \Deleted（status=deleted；EXPUNGE 前置标记，rfc9051 6.4.3）。
func (r *SQLiteMessageRepo) SoftDelete(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.q.MarkMailboxMessagesDeleted(ctx, ids); err != nil {
		return fmt.Errorf("批量软删除: %w", err)
	}
	return nil
}

// HardDelete 批量硬删除（单事务：关联行删除→孤儿 messages 行清理；
// blob 字节由对账任务按引用计数清理，数据模型 1.3 要点 2/4）。
func (r *SQLiteMessageRepo) HardDelete(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启硬删除事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	// U25 删除级联（S3-W Q2 附加指示「删除聚合文件夹内邮件→真实邮件一并删除」）：
	// 被删行属聚合文件夹（kind=unregistered）时，同 message_id 的全部其他关联行并入
	// 删除集——删聚合副本=删影子邮箱真实邮件；反向不级联（非聚合行触发零并入）。
	if ids, err = expandAggregateCascadeSQLite(ctx, qtx, ids); err != nil {
		return err
	}
	if _, err = qtx.DeleteKeywordsByMessageIDs(ctx, ids); err != nil { // D8#1：keyword 行先行清理（不依赖 FK 执行开关——三库行为一致）
		return fmt.Errorf("清理 keyword 行: %w", err)
	}
	if _, err = qtx.DeleteMailboxMessages(ctx, ids); err != nil {
		return fmt.Errorf("删除邮箱关联行: %w", err)
	}
	if _, err = qtx.DeleteOrphanMessages(ctx); err != nil {
		return fmt.Errorf("清理孤儿邮件行: %w", err)
	}
	return tx.Commit()
}

// expandAggregateCascadeSQLite 级联删除集展开（U25——三步单表查询规避 sqlc 引擎
// JOIN×切片参数重写限制）：①取被删行元数据②聚合文件夹 id 集③同 message_id 同胞行；
// 自身排除（集合差）后并入原 ids。零聚合文件夹/零命中时原样返回。
func expandAggregateCascadeSQLite(ctx context.Context, qtx *dbgen.Queries, ids []int64) ([]int64, error) {
	rows, err := qtx.GetMailboxMessageRows(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("级联关联行查询: %w", err)
	}
	aggFolders, err := qtx.ListAggregateFolderIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("聚合文件夹查询: %w", err)
	}
	if len(aggFolders) == 0 {
		return ids, nil
	}
	aggSet := make(map[int64]bool, len(aggFolders))
	for _, fid := range aggFolders {
		aggSet[fid] = true
	}
	original := make(map[int64]bool, len(ids))
	var cascadeMsgIDs []int64
	for _, id := range ids {
		original[id] = true
	}
	for _, row := range rows {
		if aggSet[row.FolderID] {
			cascadeMsgIDs = append(cascadeMsgIDs, row.MessageID)
		}
	}
	if len(cascadeMsgIDs) == 0 {
		return ids, nil
	}
	siblings, err := qtx.SelectIDsByMessageIDs(ctx, cascadeMsgIDs)
	if err != nil {
		return nil, fmt.Errorf("级联同胞行查询: %w", err)
	}
	out := append([]int64{}, ids...)
	for _, id := range siblings {
		if !original[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// ListShadowBackfill 存量回填批查（U25——shadow 归档行无聚合副本的 message_id 集）。
func (r *SQLiteMessageRepo) ListShadowBackfill(ctx context.Context, limit int) ([]int64, error) {
	return r.q.ListShadowBackfill(ctx, int64(limit))
}

// CopyToAggregateFolder 单事务聚合副本补写（U25——回填任务消费；契约 v1.22.0）。
func (r *SQLiteMessageRepo) CopyToAggregateFolder(ctx context.Context, mailboxID, messageID int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启聚合副本事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	folder, err := qtx.GetSystemFolderByKind(ctx, dbgen.GetSystemFolderByKindParams{
		MailboxID: mailboxID, Kind: string(FolderKindUnregistered),
	})
	if err != nil {
		return fmt.Errorf("聚合文件夹解析: %w", err)
	}
	uid, err := nextUIDInTx(ctx, qtx, mailboxID)
	if err != nil {
		return err
	}
	if _, err = qtx.InsertMailboxMessageWithFlags(ctx, dbgen.InsertMailboxMessageWithFlagsParams{
		MailboxID: mailboxID, MessageID: messageID, FolderID: folder.ID, Uid: uid,
		Status: "normal", CreatedAt: formatTimestamp(time.Now().UTC()),
	}); err != nil {
		return fmt.Errorf("插入聚合副本行: %w", err)
	}
	return tx.Commit()
}

// StoreAppend IMAP APPEND 落库（Blob 已由调用方先行写入；契约 v1.3.0）：
// 事务内 folder 归属校验→messages 行→mailbox_messages 行（标志初值+UID 事务内分配）。
// 参数：mailboxID/folderID 目标；meta 元数据与标志初值。返回：分配的 UID（APPENDUID）。
func (r *SQLiteMessageRepo) StoreAppend(ctx context.Context, mailboxID, folderID int64, meta *AppendMeta) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("开启 APPEND 事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)

	// folder 归属校验（跨账号 folder 注入防线，FR-001 隔离）
	folder, err := qtx.GetFolderByID(ctx, folderID)
	if err != nil || folder.MailboxID != mailboxID {
		return 0, ErrFolderNotFound
	}

	msgPK, err := insertMessageRow(ctx, qtx, meta.Message, formatTimestamp(time.Now().UTC()))
	if err != nil {
		return 0, err
	}
	uid, err := nextUIDInTx(ctx, qtx, mailboxID)
	if err != nil {
		return 0, err
	}
	isRead, isFlagged, isAnswered, isDraft, status := false, false, false, false, "normal"
	if meta.Flags.IsRead != nil {
		isRead = *meta.Flags.IsRead
	}
	if meta.Flags.IsFlagged != nil {
		isFlagged = *meta.Flags.IsFlagged
	}
	if meta.Flags.IsAnswered != nil {
		isAnswered = *meta.Flags.IsAnswered
	}
	if meta.Flags.IsDraft != nil {
		isDraft = *meta.Flags.IsDraft
	}
	if meta.Flags.Deleted != nil && *meta.Flags.Deleted {
		status = "deleted"
	}
	if _, err = qtx.InsertMailboxMessageWithFlags(ctx, dbgen.InsertMailboxMessageWithFlagsParams{
		MailboxID: mailboxID, MessageID: msgPK, FolderID: folderID, Uid: uid,
		IsRead: isRead, IsFlagged: isFlagged, IsAnswered: isAnswered, IsDraft: isDraft, Status: status,
		InternalDate: internalDateArgSQLite(meta.InternalDate), // F-I5：APPEND date-time 承载
		CreatedAt:    formatTimestamp(time.Now().UTC()),
	}); err != nil {
		return 0, fmt.Errorf("插入 APPEND 关联行: %w", err)
	}
	// D8#1：APPEND keyword 初值（rfc9051 §6.3.12 flag list 可含 keyword——新行 id 经
	// (mailbox_id, uid) 事务内点查回取，三库同构零方言分叉）
	if len(meta.Keywords) > 0 {
		newID, kerr := qtx.GetMailboxMessageIDByUID(ctx, dbgen.GetMailboxMessageIDByUIDParams{
			MailboxID: mailboxID, Uid: uid,
		})
		if kerr != nil {
			return 0, fmt.Errorf("回取 APPEND 新行 ID: %w", kerr)
		}
		if kerr = insertKeywordsSQLite(ctx, qtx, newID, meta.Keywords, formatTimestamp(time.Now().UTC())); kerr != nil {
			return 0, kerr
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("提交 APPEND 事务: %w", err)
	}
	return uid, nil
}

// insertKeywordsSQLite 事务内 keyword 行批量插入（D8#1——去重+空串/超宽防御同
// SetKeywords；SQLite dbgen 参数形态）。
// 参数：ctx 上下文；qtx 事务查询器；id mailbox_messages.id；keywords 输入集；now 时间戳。
// 返回：插入失败原因。
func insertKeywordsSQLite(ctx context.Context, qtx *dbgen.Queries, id int64, keywords []string, now string) error {
	seen := make(map[string]struct{}, len(keywords))
	for _, kw := range keywords {
		if kw == "" || len(kw) > 255 {
			continue
		}
		if _, dup := seen[kw]; dup {
			continue
		}
		seen[kw] = struct{}{}
		if err := qtx.InsertMailboxKeyword(ctx, dbgen.InsertMailboxKeywordParams{
			MailboxMessageID: id, Keyword: kw, CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("插入 keyword: %w", err)
		}
	}
	return nil
}

// CopyAtomic 批量复制单事务（RF-J/F-I13——rfc9051 §6.4.7 L4627-4630「partial
// copy MUST NOT be done」：任一条失败全部回滚；moveSources 非空=MOVE——同事务
// 删源行+清孤儿 messages 行（rfc6851 原子性））。逐条插新 messages 行（沿 Copy
// 既有形态——blob CAS 幂等，元数据行每副本一行）+mailbox_messages 行（UID 事务
// 内串行分配）。参数：mailboxID 账号；destFolderID 目标；metas 批量输入；
// moveSources 源行 ID（nil=COPY）。返回：逐条分配 UID。
func (r *SQLiteMessageRepo) CopyAtomic(ctx context.Context, mailboxID, destFolderID int64, metas []*AppendMeta, moveSources []int64) ([]int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开启复制事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)

	folder, err := qtx.GetFolderByID(ctx, destFolderID)
	if err != nil || folder.MailboxID != mailboxID {
		return nil, ErrFolderNotFound
	}
	now := formatTimestamp(time.Now().UTC())
	uids := make([]int64, 0, len(metas))
	for _, m := range metas {
		msgPK, err := insertMessageRow(ctx, qtx, m.Message, now)
		if err != nil {
			return nil, err
		}
		uid, err := nextUIDInTx(ctx, qtx, mailboxID)
		if err != nil {
			return nil, err
		}
		isRead, isFlagged, isAnswered, isDraft, status := false, false, false, false, "normal"
		if m.Flags.IsRead != nil {
			isRead = *m.Flags.IsRead
		}
		if m.Flags.IsFlagged != nil {
			isFlagged = *m.Flags.IsFlagged
		}
		if m.Flags.IsAnswered != nil {
			isAnswered = *m.Flags.IsAnswered
		}
		if m.Flags.IsDraft != nil {
			isDraft = *m.Flags.IsDraft
		}
		if m.Flags.Deleted != nil && *m.Flags.Deleted {
			status = "deleted"
		}
		if _, err = qtx.InsertMailboxMessageWithFlags(ctx, dbgen.InsertMailboxMessageWithFlagsParams{
			MailboxID: mailboxID, MessageID: msgPK, FolderID: destFolderID, Uid: uid,
			IsRead: isRead, IsFlagged: isFlagged, IsAnswered: isAnswered, IsDraft: isDraft, Status: status,
			InternalDate: internalDateArgSQLite(m.InternalDate), // F-I4：COPY/MOVE internal date 保留
			CreatedAt:    now,
		}); err != nil {
			return nil, fmt.Errorf("插入复制关联行: %w", err)
		}
		// D8#1：COPY/MOVE keyword 保留（rfc9051 L573-574「allowed and preserved in
		// APPEND, COPY, and MOVE commands」SHOULD——源行集经 appendMetaOf 随 metas 承载）
		if len(m.Keywords) > 0 {
			newID, kerr := qtx.GetMailboxMessageIDByUID(ctx, dbgen.GetMailboxMessageIDByUIDParams{
				MailboxID: mailboxID, Uid: uid,
			})
			if kerr != nil {
				return nil, fmt.Errorf("回取复制新行 ID: %w", kerr)
			}
			if kerr = insertKeywordsSQLite(ctx, qtx, newID, m.Keywords, now); kerr != nil {
				return nil, kerr
			}
		}
		uids = append(uids, uid)
	}
	if len(moveSources) > 0 {
		if _, err = qtx.DeleteKeywordsByMessageIDs(ctx, moveSources); err != nil { // D8#1：MOVE 源行 keyword 先行清理
			return nil, fmt.Errorf("MOVE 清理源行 keyword: %w", err)
		}
		if _, err = qtx.DeleteMailboxMessages(ctx, moveSources); err != nil {
			return nil, fmt.Errorf("MOVE 删源行: %w", err)
		}
		if _, err = qtx.DeleteOrphanMessages(ctx); err != nil {
			return nil, fmt.Errorf("MOVE 清孤儿邮件行: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交复制事务: %w", err)
	}
	return uids, nil
}

// Search 关键词搜索（U9 落地，Q6-A：Keyword 命中 subject/from_addr/to_addrs 三缓存列
// OR LIKE——Bob 构建见 webmail_query.go；mailbox 限定隔离 FR-001；normal 基线与列表一致；
// IMAP SEARCH 走 IMAPSearch 动态路径，两者形态分离——契约 v1.3.0 2.1 既有记载）。
// 空白关键词：空结果零错误（上层负责回列表呈现）。
func (r *SQLiteMessageRepo) Search(ctx context.Context, q SearchQuery) ([]*ListItem, int64, error) {
	if strings.TrimSpace(q.Keyword) == "" {
		return nil, 0, nil
	}
	countSQL, countArgs, err := buildWebmailSearchCountSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建搜索计数: %w", err)
	}
	var total int64
	if err = r.db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计搜索命中: %w", err)
	}
	pageSQL, pageArgs, err := buildWebmailSearchPageSQL(ctx, q)
	if err != nil {
		return nil, 0, fmt.Errorf("构建搜索分页: %w", err)
	}
	items, err := r.queryWebmailItems(ctx, pageSQL, pageArgs)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// IMAPSearch IMAP SEARCH 动态查询（SQL 经 Bob 构建见 imap_search.go；架构选型 #8；
// 配置并发批 F10：扫描尾部增 raw_size/blob_key 两列〔9 列〕——POP3 maildrop 单查询承载）。
// 参数：q 中性条件（MailboxID/FolderID/Filter）。返回：命中行（UID 升序）。
func (r *SQLiteMessageRepo) IMAPSearch(ctx context.Context, q IMAPSearchQuery) ([]*ListItem, error) {
	query, args, err := buildIMAPSearchSQL(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("构建 IMAP 搜索 SQL: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("执行 IMAP 搜索: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]*ListItem, 0, 32)
	for rows.Next() {
		var it ListItem
		var sentAt sql.NullString
		if err = rows.Scan(&it.ID, &it.UID, &sentAt, &it.Subject, &it.FromAddr, &it.IsRead, &it.IsFlagged, &it.Size, &it.BlobKey); err != nil {
			return nil, fmt.Errorf("扫描搜索行: %w", err)
		}
		it.SentAt = parseTimestampOrZero(sentAt)
		items = append(items, &it)
	}
	return items, rows.Err()
}

// ListFolderUIDsASC 文件夹全量 UID 升序列表（IMAP 序号↔UID 映射构建输入，
// protocol/imap 会话消费；十万封级内存可承受——单账号 8×10^5 字节量级）。
// 参数：mailboxID/folderID 定位。返回：UID 升序切片。
func (r *SQLiteMessageRepo) ListFolderUIDsASC(ctx context.Context, mailboxID, folderID int64) ([]int64, error) {
	return r.q.ListFolderUIDsASC(ctx, dbgen.ListFolderUIDsASCParams{
		MailboxID: mailboxID, FolderID: folderID,
	})
}

// parseTimestampOrZero RFC3339 可空列 → time.Time（NULL/空/解析失败归零值——
// Date 头缺失与异常数据容错，IMAP INTERNALDATE 兜底语义）。
func parseTimestampOrZero(s sql.NullString) time.Time {
	if !s.Valid || s.String == "" {
		return time.Time{}
	}
	t, err := parseTimestamp(s.String)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ───────────────────────── U16 正文缓存回填（契约 v1.12.0 2.1 增量） ─────────────────────────

// ListBodyCachePending 待回填正文缓存批查（WHERE body_cache IS NULL LIMIT——存量回填
// 任务数据源；U16 Q3-A，缓存维度尽力语义）。
// 参数：limit 批大小。返回：待回填行（id+blob_key）。
func (r *SQLiteMessageRepo) ListBodyCachePending(ctx context.Context, limit int) ([]BodyCacheBackfill, error) {
	rows, err := r.q.ListBodyCachePending(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("查询待回填正文缓存: %w", err)
	}
	out := make([]BodyCacheBackfill, 0, len(rows))
	for _, row := range rows {
		out = append(out, BodyCacheBackfill{ID: row.ID, BlobKey: row.BlobKey})
	}
	return out, nil
}

// FillBodyCache 单行正文缓存回填（空串写入 NULL——无正文邮件保持不命中语义）。
// 参数：id messages 行主键；body 截断后纯文本。返回：错误（调用方按尽力语义吸收）。
func (r *SQLiteMessageRepo) FillBodyCache(ctx context.Context, id int64, body string) error {
	_, err := r.q.FillBodyCache(ctx, dbgen.FillBodyCacheParams{
		BodyCache: nullIfEmpty(body), ID: id,
	})
	if err != nil {
		return fmt.Errorf("回填正文缓存 %d: %w", id, err)
	}
	return nil
}
