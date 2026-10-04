// Package storage message 域 MySQL 实现（U11 Q2-A 三套生成；契约 2.1 十一方法签名零变更）。
// 依据：数据库表结构 v1.1.0 第五章（MySQL TIMESTAMP(6) 可空列——sqlc 生成 sql.NullTime）；
// U11 计划书 1.5④⑦⑧（ClaimDue 归 queue 域；UID 事务内 MAX+1 沿用+UNIQUE 兜底；
// 时间参数 time.Time 直传）。
// 动态查询（Webmail 过滤/搜索/IMAP SEARCH）经 dynQueryRunner MySQL 方言构建器执行。
// 覆盖条目：FR-014（TC-014 message 域 MySQL 格）。
// 修改历史：
//
//	2026-09-20 05:30:00 | 新增 | U11 三库验收（计划书步骤 4）
//	2026-09-30 17:52:00 | 修正 | 阶段复审冒烟批次：archiveToInbox 对齐 SQLite 完整形态——
//	  Sieve fileinto FolderName 解析分支+InsertMailboxMessageWithFlags 标志初值
//	  （RecipientTarget 三字段三库一致承载；依据：阶段复审冒烟_计划_20260930_
//	  17-50-00_v1.0.0 1.1#1，G2 批准 2026-09-30 17:51:51）
//	2026-09-30 23:52:00 | 扩展 | D8登记项处置批次 K-A：IMAP keyword 持久存储同构
//	  （GetDetail 回填/SetKeywords/StoreAppend·CopyAtomic 写入/HardDelete·MOVE 清理；
//	  依据：D8登记项处置_计划_20260930_23-45-00_v1.0.0 1.2#1，G2 批准 23:40:58）
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	dbgen "GRmail/internal/storage/dbgen/mysql"
)

// 编译期断言：契约 2.1 接口实现锁定（MySQL 形态）。
var _ MessageRepo = (*MySQLMessageRepo)(nil)

// MySQLMessageRepo MessageRepo 的 MySQL 实现。
type MySQLMessageRepo struct {
	db  *sql.DB
	q   *dbgen.Queries
	ck  constraintChecker
	dyn dynQueryRunner
}

// NewMySQLMessageRepo 构造邮件仓储（MySQL；动态查询走 MySQL 方言构建器）。
// 参数：db 已迁移就绪的 MySQL 连接。返回：仓储实例。
func NewMySQLMessageRepo(db *sql.DB) *MySQLMessageRepo {
	return &MySQLMessageRepo{
		db:  db,
		q:   dbgen.New(db),
		ck:  mysqlChecker{},
		dyn: newDynQueryRunner(DriverMySQL, db),
	}
}

// StoreInbound 收信落库单事务（语义同 SQLite 实现：messages 行→多收件人关联行→可选通知行，
// 任一步失败整体回滚——CON-004 防丢信，调用方据此 451）。
func (r *MySQLMessageRepo) StoreInbound(ctx context.Context, txmeta *InboundMeta) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启收信事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	qtx := r.q.WithTx(tx)
	now := time.Now().UTC()

	msgPK, err := insertMessageRowMySQL(ctx, qtx, txmeta.Message, now)
	if err != nil {
		return err
	}
	if err = archiveToInboxMySQL(ctx, qtx, txmeta.Recipients, msgPK, now); err != nil {
		return err
	}
	if txmeta.Notice != nil {
		noticePK, nerr := insertMessageRowMySQL(ctx, qtx, txmeta.Notice.Message, now)
		if nerr != nil {
			return nerr
		}
		if nerr = archiveToInboxMySQL(ctx, qtx, []RecipientTarget{{MailboxID: txmeta.Notice.MailboxID}}, noticePK, now); nerr != nil {
			return nerr
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交收信事务: %w", err)
	}
	return nil
}

// PageList 分页+过滤（U9 分流：零值走静态全量；任一过滤位走 Webmail 动态路径）。
func (r *MySQLMessageRepo) PageList(ctx context.Context, q ListQuery) ([]*ListItem, int64, error) {
	if q.UnreadOnly || q.FlaggedOnly || q.ExcludeDeleted {
		return r.dyn.webmailList(ctx, q)
	}
	total, err := r.q.CountMessagesByFolder(ctx, dbgen.CountMessagesByFolderParams{
		MailboxID: q.MailboxID, FolderID: q.FolderID,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("统计文件夹邮件数: %w", err)
	}
	rows, err := r.q.ListMessagesByFolderPage(ctx, dbgen.ListMessagesByFolderPageParams{
		MailboxID: q.MailboxID, FolderID: q.FolderID,
		Limit: q.Limit, Offset: q.Offset,
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
			SentAt:    zeroTimeIfInvalid(row.MSentAt),
			IsRead:    row.MmIsRead,
			IsFlagged: row.MmIsFlagged,
			Deleted:   row.MmStatus == "deleted",
		})
	}
	return items, total, nil
}

// Search 关键词搜索（Bob MySQL 方言构建；空白关键词空结果）。
func (r *MySQLMessageRepo) Search(ctx context.Context, q SearchQuery) ([]*ListItem, int64, error) {
	if strings.TrimSpace(q.Keyword) == "" {
		return nil, 0, nil
	}
	return r.dyn.webmailSearch(ctx, q)
}

// GetDetail 单行详情（mailboxID 双重限定隔离 FR-001）。
func (r *MySQLMessageRepo) GetDetail(ctx context.Context, mailboxID, msgPK int64) (*Detail, error) {
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
		SentAt:       zeroTimeIfInvalid(row.MSentAt),
		RawSize:      row.MRawSize,
		IsRead:       row.MmIsRead,
		IsFlagged:    row.MmIsFlagged,
		IsAnswered:   row.MmIsAnswered,
		IsDraft:      row.MmIsDraft,
		Deleted:      row.MmStatus == "deleted",
		CreatedAt:    row.MmCreatedAt,
		InternalDate: internalDateOfNullTime(row.MmInternalDate), // F-I4/F-I5
	}
	detail.Keywords = messageKeywordsOf(ctx, r.q, msgPK) // D8#1：keyword 二次查询回填
	return detail, nil
}

// SetKeywords keyword 终态替换（D8#1——契约 v1.19.0；先清后插单事务，语义同 SQLite 实现）。
func (r *MySQLMessageRepo) SetKeywords(ctx context.Context, id int64, keywords []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启 keyword 事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	if err = qtx.DeleteKeywordsByMessageID(ctx, id); err != nil {
		return fmt.Errorf("清空 keyword: %w", err)
	}
	if err = insertKeywordsMySQL(ctx, qtx, id, keywords, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// SetFlags 三值补丁更新（读改写两步——语义同 SQLite 实现）。
func (r *MySQLMessageRepo) SetFlags(ctx context.Context, id int64, flags FlagPatch) error {
	cur, err := r.q.GetMailboxMessageFlags(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMessageNotFound
	}
	if err != nil {
		return fmt.Errorf("读取标志现值: %w", err)
	}
	isRead, isFlagged, isAnswered, isDraft, status := cur.IsRead, cur.IsFlagged, cur.IsAnswered, cur.IsDraft, cur.Status
	if flags.IsRead != nil {
		isRead = *flags.IsRead
	}
	if flags.IsFlagged != nil {
		isFlagged = *flags.IsFlagged
	}
	if flags.IsAnswered != nil {
		isAnswered = *flags.IsAnswered
	}
	if flags.IsDraft != nil {
		isDraft = *flags.IsDraft
	}
	if flags.Deleted != nil {
		if *flags.Deleted {
			status = "deleted"
		} else {
			status = "normal"
		}
	}
	n, err := r.q.UpdateMailboxMessageFlags(ctx, dbgen.UpdateMailboxMessageFlagsParams{
		IsRead: isRead, IsFlagged: isFlagged, IsAnswered: isAnswered, IsDraft: isDraft, Status: status, ID: id,
	})
	if err != nil {
		return fmt.Errorf("更新标志位: %w", err)
	}
	if n == 0 {
		return ErrMessageNotFound
	}
	return nil
}

// Move 跨文件夹移动（UID 保留——mailbox 域全局序列语义）。
func (r *MySQLMessageRepo) Move(ctx context.Context, id, folderID int64) error {
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

// SoftDelete 批量置 \Deleted。
func (r *MySQLMessageRepo) SoftDelete(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.q.MarkMailboxMessagesDeleted(ctx, ids); err != nil {
		return fmt.Errorf("批量软删除: %w", err)
	}
	return nil
}

// HardDelete 批量硬删除（单事务：关联行删除→孤儿 messages 行清理）。
func (r *MySQLMessageRepo) HardDelete(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	return withTxCompat(ctx, r.db, func(tx *sql.Tx) error {
		qtx := r.q.WithTx(tx)
		// U25 删除级联（S3-W Q2 附加指示）：聚合文件夹行删除→同 message_id 全部
		// 其他关联行并入删除集（删聚合副本=删影子邮箱真实邮件；反向不级联）。
		ids, err := expandAggregateCascadeMySQL(ctx, qtx, ids)
		if err != nil {
			return err
		}
		if _, err = qtx.DeleteKeywordsByMessageIDs(ctx, ids); err != nil { // D8#1：keyword 行先行清理
			return fmt.Errorf("清理 keyword 行: %w", err)
		}
		if _, err := qtx.DeleteMailboxMessages(ctx, ids); err != nil {
			return fmt.Errorf("删除邮箱关联行: %w", err)
		}
		if _, err := qtx.DeleteOrphanMessages(ctx); err != nil {
			return fmt.Errorf("清理孤儿邮件行: %w", err)
		}
		return nil
	})
}

// expandAggregateCascadeMySQL 级联删除集展开（U25——三步单表查询，语义同 SQLite 版）。
func expandAggregateCascadeMySQL(ctx context.Context, qtx *dbgen.Queries, ids []int64) ([]int64, error) {
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
func (r *MySQLMessageRepo) ListShadowBackfill(ctx context.Context, limit int) ([]int64, error) {
	return r.q.ListShadowBackfill(ctx, int32(limit))
}

// CopyToAggregateFolder 单事务聚合副本补写（U25——回填任务消费；契约 v1.22.0）。
func (r *MySQLMessageRepo) CopyToAggregateFolder(ctx context.Context, mailboxID, messageID int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启聚合副本事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)
	folder, ferr := qtx.GetSystemFolderByKind(ctx, dbgen.GetSystemFolderByKindParams{
		MailboxID: mailboxID, Kind: string(FolderKindUnregistered),
	})
	if ferr != nil {
		return fmt.Errorf("聚合文件夹解析: %w", ferr)
	}
	uid, err := nextUIDInTxMySQL(ctx, qtx, mailboxID)
	if err != nil {
		return err
	}
	if _, err = qtx.InsertMailboxMessageWithFlags(ctx, dbgen.InsertMailboxMessageWithFlagsParams{
		MailboxID: mailboxID, MessageID: messageID, FolderID: folder.ID, Uid: uid,
		Status: "normal", CreatedAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("插入聚合副本行: %w", err)
	}
	return tx.Commit()
}

// NextUID 返回 mailbox 内下一可用 UID（MAX+1；1.5⑦ UNIQUE 兜底口径）。
func (r *MySQLMessageRepo) NextUID(ctx context.Context, mailboxID int64) (int64, error) {
	v, err := r.q.GetMaxMailboxUID(ctx, mailboxID)
	if err != nil {
		return 0, fmt.Errorf("查询最大 UID: %w", err)
	}
	return coalesceInt64(v) + 1, nil
}

// StoreAppend IMAP APPEND 落库（Blob 先行；folder 归属校验+UID 事务内分配）。
func (r *MySQLMessageRepo) StoreAppend(ctx context.Context, mailboxID, folderID int64, meta *AppendMeta) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("开启 APPEND 事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	qtx := r.q.WithTx(tx)

	folder, err := qtx.GetFolderByID(ctx, folderID)
	if err != nil || folder.MailboxID != mailboxID {
		return 0, ErrFolderNotFound
	}
	msgPK, err := insertMessageRowMySQL(ctx, qtx, meta.Message, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	uid, err := nextUIDInTxMySQL(ctx, qtx, mailboxID)
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
		InternalDate: internalDateArgNullTime(meta.InternalDate), // F-I5：APPEND date-time 承载
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		return 0, fmt.Errorf("插入 APPEND 关联行: %w", err)
	}
	// D8#1：APPEND keyword 初值（新行 id 经 (mailbox_id, uid) 事务内点查回取）
	if len(meta.Keywords) > 0 {
		newID, kerr := qtx.GetMailboxMessageIDByUID(ctx, dbgen.GetMailboxMessageIDByUIDParams{
			MailboxID: mailboxID, Uid: uid,
		})
		if kerr != nil {
			return 0, fmt.Errorf("回取 APPEND 新行 ID: %w", kerr)
		}
		if kerr = insertKeywordsMySQL(ctx, qtx, newID, meta.Keywords, time.Now().UTC()); kerr != nil {
			return 0, kerr
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("提交 APPEND 事务: %w", err)
	}
	return uid, nil
}

// CopyAtomic 批量复制单事务（F-I13——语义同 SQLite 实现；MySQL 事务形态）。
func (r *MySQLMessageRepo) CopyAtomic(ctx context.Context, mailboxID, destFolderID int64, metas []*AppendMeta, moveSources []int64) ([]int64, error) {
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
	now := time.Now().UTC()
	uids := make([]int64, 0, len(metas))
	for _, m := range metas {
		msgPK, err := insertMessageRowMySQL(ctx, qtx, m.Message, now)
		if err != nil {
			return nil, err
		}
		uid, err := nextUIDInTxMySQL(ctx, qtx, mailboxID)
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
			InternalDate: internalDateArgNullTime(m.InternalDate), // F-I4：COPY/MOVE internal date 保留
			CreatedAt:    now,
		}); err != nil {
			return nil, fmt.Errorf("插入复制关联行: %w", err)
		}
		// D8#1：COPY/MOVE keyword 保留（rfc9051 L573-574 SHOULD）
		if len(m.Keywords) > 0 {
			newID, kerr := qtx.GetMailboxMessageIDByUID(ctx, dbgen.GetMailboxMessageIDByUIDParams{
				MailboxID: mailboxID, Uid: uid,
			})
			if kerr != nil {
				return nil, fmt.Errorf("回取复制新行 ID: %w", kerr)
			}
			if kerr = insertKeywordsMySQL(ctx, qtx, newID, m.Keywords, now); kerr != nil {
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

// IMAPSearch IMAP SEARCH 动态查询（Bob MySQL 方言构建）。
func (r *MySQLMessageRepo) IMAPSearch(ctx context.Context, q IMAPSearchQuery) ([]*ListItem, error) {
	return r.dyn.imapSearch(ctx, q)
}

// ListFolderUIDsASC 文件夹全量 UID 升序列表（IMAP 序号↔UID 映射输入）。
func (r *MySQLMessageRepo) ListFolderUIDsASC(ctx context.Context, mailboxID, folderID int64) ([]int64, error) {
	return r.q.ListFolderUIDsASC(ctx, dbgen.ListFolderUIDsASCParams{
		MailboxID: mailboxID, FolderID: folderID,
	})
}

// insertKeywordsMySQL 事务内 keyword 行批量插入（D8#1——去重+防御口径同 SQLite 实现）。
func insertKeywordsMySQL(ctx context.Context, qtx *dbgen.Queries, id int64, keywords []string, now time.Time) error {
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

// ───────────────────────── MySQL 事务内辅助 ─────────────────────────

// insertMessageRowMySQL 插入 messages 行并回填主键（LastInsertId）。
func insertMessageRowMySQL(ctx context.Context, qtx *dbgen.Queries, m MessageMeta, now time.Time) (int64, error) {
	res, err := qtx.InsertMessage(ctx, dbgen.InsertMessageParams{
		MessageID:         nullIfEmpty(m.MessageID),
		BlobKey:           m.BlobKey,
		RawSize:           m.RawSize,
		Subject:           nullIfEmpty(m.Subject),
		FromAddr:          nullIfEmpty(m.FromAddr),
		ToAddrs:           nullIfEmpty(m.ToAddrs),
		CcAddrs:           nullIfEmpty(m.CcAddrs),
		BodyCache:         nullIfEmpty(m.BodyCache),
		SentAt:            nullZeroTime(m.SentAt),
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

// archiveToInboxMySQL 逐收件人写 mailbox_messages 行（UID 事务内 MAX+1）。
// 阶段复审冒烟批次对齐 SQLite 完整形态（三库一致化）：Sieve fileinto 的
// FolderName 解析分支（空=收件箱默认；非空=GetFolderByName 解析，失败按
// implicit keep 兜底——rfc5228 §4.1 错误分支，管道层兜底归收件箱）+
// InsertMailboxMessageWithFlags 承载 :flags 标志初值（IsRead/IsFlagged——
// rfc5232 §3；IsAnswered/IsDraft 收信路径恒 false——Sieve imap4flags 映射表
// 不含 \Answered/\Draft，契约 v1.16.0 2.1 RecipientTarget 语义）。
func archiveToInboxMySQL(ctx context.Context, qtx *dbgen.Queries, targets []RecipientTarget, msgPK int64, now time.Time) error {
	for _, t := range targets {
		uid, err := nextUIDInTxMySQL(ctx, qtx, t.MailboxID)
		if err != nil {
			return err
		}
		var folderID int64
		if t.FolderName == "" {
			if folderID, err = inboxFolderIDInTxMySQL(ctx, qtx, t.MailboxID); err != nil {
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
			MailboxID:  t.MailboxID,
			MessageID:  msgPK,
			FolderID:   folderID,
			Uid:        uid,
			IsRead:     t.FlagSeen,
			IsFlagged:  t.FlagFlagged,
			IsAnswered: false,
			IsDraft:    false,
			Status:     "normal",
			CreatedAt:  now,
		}); err != nil {
			return fmt.Errorf("插入邮箱关联行: %w", err)
		}
	}
	return nil
}

// nextUIDInTxMySQL 事务内下一 UID（1.5⑦：UNIQUE 兜底，冲突由事务失败回 451 收敛）。
func nextUIDInTxMySQL(ctx context.Context, qtx *dbgen.Queries, mailboxID int64) (int64, error) {
	v, err := qtx.GetMaxMailboxUID(ctx, mailboxID)
	if err != nil {
		return 0, fmt.Errorf("查询邮箱最大 UID: %w", err)
	}
	return coalesceInt64(v) + 1, nil
}

// inboxFolderIDInTxMySQL 事务内查询收件箱文件夹 ID。
func inboxFolderIDInTxMySQL(ctx context.Context, qtx *dbgen.Queries, mailboxID int64) (int64, error) {
	f, err := qtx.GetSystemFolderByKind(ctx, dbgen.GetSystemFolderByKindParams{
		MailboxID: mailboxID,
		Kind:      string(FolderKindInbox),
	})
	if err != nil {
		return 0, fmt.Errorf("查询收件箱文件夹: %w", err)
	}
	return f.ID, nil
}

// ───────────────────────── U16 正文缓存回填（契约 v1.12.0 2.1 增量） ─────────────────────────

// ListBodyCachePending 待回填正文缓存批查（WHERE body_cache IS NULL LIMIT——存量回填
// 任务数据源；U16 Q3-A，缓存维度尽力语义）。
// 参数：limit 批大小。返回：待回填行（id+blob_key）。
func (r *MySQLMessageRepo) ListBodyCachePending(ctx context.Context, limit int) ([]BodyCacheBackfill, error) {
	rows, err := r.q.ListBodyCachePending(ctx, int32(limit))
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
func (r *MySQLMessageRepo) FillBodyCache(ctx context.Context, id int64, body string) error {
	_, err := r.q.FillBodyCache(ctx, dbgen.FillBodyCacheParams{
		BodyCache: nullIfEmpty(body), ID: id,
	})
	if err != nil {
		return fmt.Errorf("回填正文缓存 %d: %w", id, err)
	}
	return nil
}
