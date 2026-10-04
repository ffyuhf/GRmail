// imap Session 实现（go-imap v2 体系）：协议命令 → account/storage 映射。
// 依据：契约 v1.3.0 2.4（v2 Session 术语+FLAGS 三标志映射，Q3-A）；
// rfc9051 命令语义；rfc2177 §3（IDLE：激活期服务器可随时发送 EXISTS——事件驱动，Q2-A）；
// rfc9051 5.1（INBOX 大小写不敏感）。
// 覆盖条目：FR-006（命令集）/FR-001（Login 三入口之一）/FR-012（文件夹双入口 IMAP 侧）。
// 错误语义：beta.8 库层仅导出 ErrAuthFailed 哨兵；文件夹/消息不存在等以普通错误
// 透传 NO 应答文本（客户端对 NO 文本无严格解析要求）。
// 修改历史：
//
//	2026-09-18 00:32:00 | 新建 | U6 IMAP 集成（计划书步骤 5，G2 批准 2026-09-18 00:09:22）
//	2026-09-18 00:37:00 | 修正 | 按 go-imap v2.0.0-beta.8 实际 API 对齐（StoreOptions 无 UID
//	字段——UID 语义按 numSet 类型判定；StatusOptions 为 bool 字段；库级 Extract* 辅助采用）
//	2026-09-29 21:58:00 | 修正 | RFC候选修正批次 RF-J：F-I16 五系统标志全承载（FLAGS/
//	PERMANENTFLAGS/STORE/FETCH/SEARCH/APPEND 六面）+F-I10 ANSWERED·DRAFT·KEYWORD
//	键承载（keyword 恒空集——无关键字存储已知限制）+F-I13 Copy/Move 原子化
//	（CopyAtomic 批量单事务——rfc9051 §6.4.7 partial copy MUST NOT）+F-I6
//	mailbox 名 NFC（rfc9051 §5.1——x/text/norm 依赖 indirect→direct）
//	2026-09-30 11:22:00 | 修正 | G3审计收尾批次 Q-07：①selectFolder FLAGS/
//	PERMANENTFLAGS 应答面补 \Answered/\Draft（五系统标志——上批宣称「六面承载」
//	中该面未兑现，契约 v1.16.0 2.4 收口；rfc9051 §2.3.2 定义+§6.3.2 SELECT
//	示例形态）②appendDetail 死代码删除（F-I13 改造后零调用者——复扫实证）
//	（依据：G3审计收尾计划书 v1.0.0 步骤 2，G2 批准 2026-09-30 11:20:40）
package imap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"golang.org/x/text/unicode/norm"

	"GRmail/internal/mail"
	"GRmail/internal/storage"
)

// 命令错误（普通错误透传 NO 应答文本——beta.8 无库级 NoSuch 哨兵）。
var (
	errNoSuchMailbox = errors.New("no such mailbox")
	errNotSelected   = errors.New("no mailbox selected")
	errAuthFailed    = imapserver.ErrAuthFailed
)

// Session 单个 IMAP 连接会话（未认证→已认证→已选中三态由 imapserver 驱动）。
type Session struct {
	server  *Server
	logID   string
	mbox    *storage.Mailbox // 登录后（VerifyCredentials 产物）
	folder  *storage.Folder  // SELECT/EXAMINE 后
	uids    []int64          // 选中文件夹 UID 升序缓存（序号=下标+1，rfc9051 2.3.1.2）
	lastNum uint32           // 上次已通知消息数（Poll/Idle 增量判定）
	cancel  func()           // IDLE 订阅注销（Idle 返回时执行）
}

// Close 连接关闭（注销 IDLE 订阅——防泄漏）。
func (s *Session) Close() error {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	return nil
}

// Login 认证（FR-001 三入口之一）：account.VerifyCredentials 注入
// （影子/禁用/密码错误统一拒绝——防枚举口径复用 U2）。
func (s *Session) Login(username, password string) error {
	m, err := s.server.accounts.VerifyCredentials(context.Background(), username, password)
	if err != nil {
		return errAuthFailed
	}
	s.mbox = m
	return nil
}

// ───────────────────────── 文件夹命令（FR-012 IMAP 侧） ─────────────────────────

// findFolder 按名查文件夹（INBOX 大小写不敏感——rfc9051 5.1；其余精确匹配）。
// 参数：name IMAP mailbox 名。返回：文件夹；不存在返回 errNoSuchMailbox。
func (s *Session) findFolder(ctx context.Context, name string) (*storage.Folder, error) {
	folders, err := s.server.accounts.ListFolders(ctx, s.mbox.ID)
	if err != nil {
		return nil, err
	}
	for _, f := range folders {
		if f.Name == name || (strings.EqualFold(f.Name, "INBOX") && strings.EqualFold(name, "INBOX")) {
			return f, nil
		}
	}
	return nil, errNoSuchMailbox
}

// Select 选中文件夹（构建序号↔UID 映射；UIDVALIDITY=1/UIDNEXT=全局 MAX+1，Q4-A）。
func (s *Session) Select(name string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	ctx := context.Background()
	f, err := s.findFolder(ctx, name)
	if err != nil {
		return nil, err
	}
	data, err := s.selectFolder(ctx, f)
	if err != nil {
		return nil, err
	}
	s.folder = f
	if err = s.refreshUIDs(ctx); err != nil {
		return nil, err
	}
	s.lastNum = data.NumMessages
	return data, nil
}

// selectFolder 组装 SELECT 应答（FLAGS/PERMANENTFLAGS 五系统标志+通配——契约
// v1.16.0 2.4 F-I16 RFC 化「六面承载」收口（G3审计收尾批次 Q-07-①）：原三标志
// 应答面与契约宣称不一致；rfc9051 §2.3.2 五系统标志定义+§6.3.2 SELECT 示例
// 「* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)」形态——REQUIRED untagged
// response；RFC822Size 缓存列免解析）。
func (s *Session) selectFolder(ctx context.Context, f *storage.Folder) (*imap.SelectData, error) {
	uids, err := s.folderUIDsASC(ctx, f.ID)
	if err != nil {
		return nil, err
	}
	next, err := s.server.messages.NextUID(ctx, s.mbox.ID)
	if err != nil {
		return nil, err
	}
	flags := []imap.Flag{imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted, imap.FlagAnswered, imap.FlagDraft}
	perms := append(append([]imap.Flag{}, flags...), imap.FlagWildcard)
	return &imap.SelectData{
		Flags:          flags,
		PermanentFlags: perms,
		NumMessages:    uint32(len(uids)),
		UIDNext:        imap.UID(next),
		UIDValidity:    uidValidity,
		List:           &imap.ListData{Mailbox: f.Name, Delim: '/', Attrs: folderAttrs(f)},
	}, nil
}

// folderAttrs 系统文件夹特殊属性（SPECIAL-USE 形态呈现，客户端侧栏映射）。
func folderAttrs(f *storage.Folder) []imap.MailboxAttr {
	switch f.Kind {
	case "sent":
		return []imap.MailboxAttr{imap.MailboxAttrSent}
	case "drafts":
		return []imap.MailboxAttr{imap.MailboxAttrDrafts}
	case "junk":
		return []imap.MailboxAttr{imap.MailboxAttrJunk}
	case "trash":
		return []imap.MailboxAttr{imap.MailboxAttrTrash}
	default:
		return nil // INBOX 与自定义文件夹无特殊属性（rfc9051 6.3.9 示例形态）
	}
}

// Create 创建自定义文件夹（FR-012：单层——名称含层级分隔符 '/' 拒绝，G16 裁决口径；
// RF-J/F-I6：mailbox 名 NFC 规范化——rfc9051 §5.1 L950-954「servers MAY accept a
// denormalized UTF-8 mailbox name and convert it to NFC」；OLDNAME LIST 应答为
// SHOULD 级，go-imap v2 Session 接口无该应答承载位——合规降级登记修改文档）。
func (s *Session) Create(name string, _ *imap.CreateOptions) error {
	if strings.Contains(name, "/") {
		return errors.New("cannot create hierarchical mailbox (flat model)")
	}
	return s.server.accounts.CreateFolder(context.Background(), s.mbox.ID, norm.NFC.String(name))
}

// Delete 删除自定义文件夹（系统文件夹拒绝——TC-012 判定；非空 FK 约束转译 NO）。
func (s *Session) Delete(name string) error {
	ctx := context.Background()
	f, err := s.findFolder(ctx, name)
	if err != nil {
		return err
	}
	if f.Kind != "custom" {
		return errors.New("cannot delete system mailbox")
	}
	return s.server.accounts.DeleteFolder(ctx, f.ID)
}

// Rename 重命名自定义文件夹（系统文件夹拒绝；RF-J/F-I6：新名 NFC 规范化——§5.1
// rfc9051 L2109-2117 RENAME 同口径；OLDNAME 承载降级同 Create 注记）。
func (s *Session) Rename(name, newName string, _ *imap.RenameOptions) error {
	ctx := context.Background()
	f, err := s.findFolder(ctx, name)
	if err != nil {
		return err
	}
	if f.Kind != "custom" {
		return errors.New("cannot rename system mailbox")
	}
	if strings.Contains(newName, "/") {
		return errors.New("cannot create hierarchical mailbox (flat model)")
	}
	return s.server.accounts.RenameFolder(ctx, f.ID, norm.NFC.String(newName))
}

// Subscribe/Unsubscribe 订阅模型最小实现（LIST 默认全量呈现，订阅集不持久——
// 阶段二 sieve/webmail 偏好落地；此处仅校验存在性）。
func (s *Session) Subscribe(name string) error {
	_, err := s.findFolder(context.Background(), name)
	return err
}

func (s *Session) Unsubscribe(name string) error {
	_, err := s.findFolder(context.Background(), name)
	return err
}

// List 列举文件夹（库级 MatchList 匹配——* 与 % 单层模型下等价语义）。
func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, _ *imap.ListOptions) error {
	folders, err := s.server.accounts.ListFolders(context.Background(), s.mbox.ID)
	if err != nil {
		return err
	}
	for _, f := range folders {
		if !matchAnyPattern(f.Name, ref, patterns) {
			continue
		}
		if err = w.WriteList(&imap.ListData{
			Mailbox: f.Name,
			Delim:   '/',
			Attrs:   folderAttrs(f),
		}); err != nil {
			return err
		}
	}
	return nil
}

// matchAnyPattern 任一 pattern 命中即列出（imapserver.MatchList 库级通配语义）。
func matchAnyPattern(name, ref string, patterns []string) bool {
	for _, p := range patterns {
		if imapserver.MatchList(name, '/', ref, p) {
			return true
		}
	}
	return false
}

// Status 文件夹状态（MESSAGES/UIDNEXT/UIDVALIDITY/UNSEEN/DELETED——bool 请求项）。
func (s *Session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	ctx := context.Background()
	f, err := s.findFolder(ctx, name)
	if err != nil {
		return nil, err
	}
	data := &imap.StatusData{Mailbox: name, UIDValidity: uidValidity}
	needList := options.NumMessages || options.NumUnseen
	if needList {
		items, _, terr := s.server.messages.PageList(ctx, storage.ListQuery{
			MailboxID: s.mbox.ID, FolderID: f.ID, Limit: 1 << 30,
		})
		if terr != nil {
			return nil, terr
		}
		if options.NumMessages {
			n := uint32(len(items))
			data.NumMessages = &n
		}
		if options.NumUnseen {
			var n uint32
			for _, it := range items {
				if !it.IsRead {
					n++
				}
			}
			data.NumUnseen = &n
		}
	}
	if options.UIDNext {
		next, terr := s.server.messages.NextUID(ctx, s.mbox.ID)
		if terr != nil {
			return nil, terr
		}
		data.UIDNext = imap.UID(next)
	}
	if options.NumDeleted {
		n, terr := s.statusDeletedCount(ctx, f.ID)
		if terr != nil {
			return nil, terr
		}
		data.NumDeleted = &n
	}
	if options.Size {
		// F-I7（RFC规范修正 RF-C，G2 批准 2026-09-28 22:16:57）：SIZE 实装——逐行
		// Detail.RawSize 累加（沿 Store 逐 UID detailForUID 先例；rfc9051 §6.3.11
		// L3394-3398「MUST be equal to or greater than the sum of the values of
		// the RFC822.SIZE FETCH message data items」——原恒 0 违反非空邮箱下限）
		var total int64
		if uids, uerr := s.folderUIDsASC(ctx, f.ID); uerr == nil {
			for _, uid := range uids {
				if d := s.detailForUID(ctx, uid); d != nil {
					total += d.RawSize
				}
			}
		}
		data.Size = &total
	}
	return data, nil
}

// errTryCreate 目标邮箱不存在时构造 NO [TRYCREATE] 应答错误（F-I8——仅
// errNoSuchMailbox 哨兵命中转换，其余错误原样上抛；imapserver conn.go 经
// errors.As(*imap.Error) 携带 Type/Code/Text 写出 tagged NO）。
// 参数：err findFolder 返回错误。返回：应答错误。
func errTryCreate(err error) error {
	if !errors.Is(err, errNoSuchMailbox) {
		return err
	}
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeTryCreate,
		Text: "destination mailbox does not exist",
	}
}

// statusDeletedCount 精确 \Deleted 计数（IMAPSearch FlagDeleted 路径）。
func (s *Session) statusDeletedCount(ctx context.Context, folderID int64) (uint32, error) {
	del := true
	items, err := s.server.messages.IMAPSearch(ctx, storage.IMAPSearchQuery{
		MailboxID: s.mbox.ID, FolderID: folderID,
		Filter: storage.SearchFilter{FlagDeleted: &del},
	})
	if err != nil {
		return 0, err
	}
	return uint32(len(items)), nil
}

// ───────────────────────── 消息命令 ─────────────────────────

// refreshUIDs 刷新序号↔UID 映射（SELECT/操作前——保证 EXISTS/EXPUNGE 序号一致）。
func (s *Session) refreshUIDs(ctx context.Context) error {
	uids, err := s.folderUIDsASC(ctx, s.folder.ID)
	if err != nil {
		return err
	}
	s.uids = uids
	return nil
}

// resolveNumSet 序号集/UID 集 → UID 列表（类型判定 UID 语义；越界序号忽略）。
// 参数：numSet 命令消息集。返回：命中 UID 升序列表+是否 UID 集。
func (s *Session) resolveNumSet(numSet imap.NumSet) ([]int64, bool) {
	var out []int64
	byUID := false
	switch set := numSet.(type) {
	case imap.SeqSet:
		for _, rng := range set {
			for seq := rng.Start; seq <= rng.Stop; seq++ {
				if int(seq) <= len(s.uids) {
					out = append(out, s.uids[seq-1])
				}
			}
		}
	case imap.UIDSet:
		byUID = true
		for _, rng := range set {
			for uid := rng.Start; uid <= rng.Stop; uid++ {
				out = append(out, int64(uid))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, byUID
}

// uidToSeq UID → 序号（0=未找到——已 EXPUNGE 防御）。
func (s *Session) uidToSeq(uid int64) uint32 {
	for i, u := range s.uids {
		if u == uid {
			return uint32(i + 1)
		}
	}
	return 0
}

// detailForUID UID → Detail（IMAPSearch 定位行 id→GetDetail；nil=已删）。
func (s *Session) detailForUID(ctx context.Context, uid int64) *storage.Detail {
	items, err := s.server.messages.IMAPSearch(ctx, storage.IMAPSearchQuery{
		MailboxID: s.mbox.ID, FolderID: s.folder.ID,
		Filter: storage.SearchFilter{UIDs: []int64{uid}},
	})
	if err != nil || len(items) == 0 {
		return nil
	}
	d, err := s.server.messages.GetDetail(ctx, s.mbox.ID, items[0].ID)
	if err != nil {
		return nil
	}
	return d
}

// Unselect 退出选中（不 EXPUNGE——rfc9051 6.4.2）。
func (s *Session) Unselect() error {
	s.folder = nil
	s.uids = nil
	return nil
}

// Expunge 物理删除 \Deleted 行（uids 非空时仅删集合内——UID EXPUNGE 形态）。
// WriteExpunge 用删除前序号、按 UID 降序删（避免后续行序号二次偏移）。
func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	ctx := context.Background()
	del := true
	items, err := s.server.messages.IMAPSearch(ctx, storage.IMAPSearchQuery{
		MailboxID: s.mbox.ID, FolderID: s.folder.ID,
		Filter: storage.SearchFilter{FlagDeleted: &del},
	})
	if err != nil {
		return err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UID > items[j].UID })
	var ids []int64
	for _, it := range items {
		if uids != nil && !uids.Contains(imap.UID(it.UID)) {
			continue
		}
		ids = append(ids, it.ID)
		if seq := s.uidToSeq(it.UID); seq > 0 {
			if err = w.WriteExpunge(seq); err != nil {
				return err
			}
		}
	}
	if len(ids) > 0 {
		if err = s.server.messages.HardDelete(ctx, ids); err != nil {
			return err
		}
	}
	return s.refreshUIDs(ctx)
}

// Search 搜索（criteria→SearchFilter 中性翻译→storage.IMAPSearch，契约 v1.3.0 2.1）。
func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	ctx := context.Background()
	filter, err := translateCriteria(criteria)
	if err != nil {
		return nil, err
	}
	items, err := s.server.messages.IMAPSearch(ctx, storage.IMAPSearchQuery{
		MailboxID: s.mbox.ID, FolderID: s.folder.ID, Filter: filter,
	})
	if err != nil {
		return nil, err
	}
	if err = s.refreshUIDs(ctx); err != nil {
		return nil, err
	}
	if kind == imapserver.NumKindUID {
		var uidSet imap.UIDSet
		for _, it := range items {
			uidSet.AddNum(imap.UID(it.UID))
		}
		return &imap.SearchData{All: uidSet}, nil
	}
	var set imap.SeqSet
	for _, it := range items {
		if seq := s.uidToSeq(it.UID); seq > 0 {
			set.AddNum(seq)
		}
	}
	return &imap.SearchData{All: set}, nil
}

// folderUIDsASC 文件夹全量 UID 升序（统一走契约 IMAPSearch 空 filter 全量形态——
// 零接口扩展；返回行即文件夹全量，序号=下标+1）。
func (s *Session) folderUIDsASC(ctx context.Context, folderID int64) ([]int64, error) {
	items, err := s.server.messages.IMAPSearch(ctx, storage.IMAPSearchQuery{
		MailboxID: s.mbox.ID, FolderID: folderID, Filter: storage.SearchFilter{},
	})
	if err != nil {
		return nil, err
	}
	uids := make([]int64, len(items))
	for i, it := range items {
		uids[i] = it.UID
	}
	return uids, nil
}

// translateCriteria rfc9051 6.4.4 键子集 → 中性 SearchFilter（字段交集；NOT/OR 一层）。
// 未承载头键（缓存列之外）以不可能匹配子串语义返回空集。
func translateCriteria(criteria *imap.SearchCriteria) (storage.SearchFilter, error) {
	f := storage.SearchFilter{}
	for _, us := range criteria.UID {
		for _, rng := range us {
			for uid := rng.Start; uid <= rng.Stop; uid++ {
				f.UIDs = append(f.UIDs, int64(uid))
			}
		}
	}
	if !criteria.Since.IsZero() {
		t := criteria.Since
		f.Since = &t
	}
	if !criteria.Before.IsZero() {
		t := criteria.Before
		f.Before = &t
	}
	if !criteria.SentSince.IsZero() {
		t := criteria.SentSince
		f.SentSince = &t
	}
	if !criteria.SentBefore.IsZero() {
		t := criteria.SentBefore
		f.SentBefore = &t
	}
	for _, hf := range criteria.Header {
		switch strings.ToUpper(hf.Key) {
		case "FROM":
			f.From = hf.Value
		case "TO":
			f.To = hf.Value
		case "SUBJECT":
			f.Subject = hf.Value
		default:
			f.Subject = "\x00unsupported-header\x00" // 无缓存列承载——空集语义
		}
	}
	f.Body = strings.Join(criteria.Body, " ")
	f.Text = strings.Join(criteria.Text, " ")
	f.Larger, f.Smaller = criteria.Larger, criteria.Smaller
	for _, flag := range criteria.Flag {
		switch flag {
		case imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted, imap.FlagAnswered, imap.FlagDraft:
			v := true
			applyFlagCond(&f, flag, &v)
		default:
			// D8#1：KEYWORD <flag-keyword> 真实承载（废止 v1.16.0 恒空集口径——
			// mailbox_keywords 持久化后 §6.4.4 L3908-3909「Messages with the
			// specified keyword flag set」经 EXISTS 子查询命中；多键 AND 交集）
			f.Keywords = append(f.Keywords, string(flag))
		}
	}
	for _, flag := range criteria.NotFlag {
		switch flag {
		case imap.FlagSeen, imap.FlagFlagged, imap.FlagDeleted, imap.FlagAnswered, imap.FlagDraft:
			v := false
			applyFlagCond(&f, flag, &v)
		default:
			// D8#1：UNKEYWORD <flag-keyword> 真实承载（废止恒真口径——§6.4.4
			// L3980-3981「Messages that do not have the specified keyword flag
			// set」经 NOT EXISTS 命中；多键逐键交集）
			f.NotKeywords = append(f.NotKeywords, string(flag))
		}
	}
	if len(criteria.Not) > 0 {
		inner, err := translateCriteria(&criteria.Not[0])
		if err != nil {
			return f, err
		}
		f.Not = &inner
	}
	for _, pair := range criteria.Or {
		left, err := translateCriteria(&pair[0])
		if err != nil {
			return f, err
		}
		right, err := translateCriteria(&pair[1])
		if err != nil {
			return f, err
		}
		f.Or = append(f.Or, [2]storage.SearchFilter{left, right})
	}
	return f, nil
}

// applyFlagCond 标志条件落入对应维度。
func applyFlagCond(f *storage.SearchFilter, flag imap.Flag, v *bool) {
	switch flag {
	case imap.FlagSeen:
		f.FlagSeen = v
	case imap.FlagFlagged:
		f.FlagFlagged = v
	case imap.FlagAnswered: // RF-J/F-I10：ANSWERED/UNANSWERED（F-I16 列）
		f.FlagAnswered = v
	case imap.FlagDraft: // DRAFT/UNDRAFT
		f.FlagDraft = v
	case imap.FlagDeleted:
		f.FlagDeleted = v
	}
}

// Store 标志变更（五系统标志映射契约 v1.16.0 2.4——F-I16 RFC 化；
// UID 语义按 numSet 类型判定——beta.8 StoreOptions 无 UID 字段）。
func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	ctx := context.Background()
	uids, byUID := s.resolveNumSet(numSet)
	for _, uid := range uids {
		detail := s.detailForUID(ctx, uid)
		if detail == nil {
			continue // 已 EXPUNGE 行跳过（rfc9051 6.4.8 宽容语义）
		}
		patch := flagPatchFromOp(flags, detail)
		if err := s.server.messages.SetFlags(ctx, detail.ID, patch); err != nil {
			return err
		}
		// D8#1：keyword 终态替换（STORE FLAGS(±/Set) 三态的 keyword 承载——
		// rfc9051 §6.4.6 L4570-4592；含 keyword 变更时才触达存储零空写）
		if kws := keywordsFromOp(flags, detail.Keywords); !equalKeywords(kws, detail.Keywords) {
			if err := s.server.messages.SetKeywords(ctx, detail.ID, kws); err != nil {
				return err
			}
		}
		if flags.Silent {
			continue
		}
		updated, err := s.server.messages.GetDetail(ctx, s.mbox.ID, detail.ID)
		if err != nil {
			return err
		}
		seq := s.uidToSeq(uid)
		if seq == 0 {
			continue
		}
		fw := w.CreateMessage(seq)
		if byUID {
			fw.WriteUID(imap.UID(uid))
		}
		fw.WriteFlags(detailFlags(updated))
		if err = fw.Close(); err != nil {
			return err
		}
	}
	return nil
}

// flagPatchFromOp 按 STORE 操作语义合成补丁（Set=全量覆盖含清除；Add/Remove 增删；
// 不持久标志跳过；F-I16：五系统标志全承载）。
func flagPatchFromOp(op *imap.StoreFlags, d *storage.Detail) storage.FlagPatch {
	seen, flagged, answered, drafted, deleted := d.IsRead, d.IsFlagged, d.IsAnswered, d.IsDraft, d.Deleted
	for _, f := range op.Flags {
		on := op.Op != imap.StoreFlagsDel
		switch f {
		case imap.FlagSeen:
			seen = on
		case imap.FlagFlagged:
			flagged = on
		case imap.FlagAnswered:
			answered = on
		case imap.FlagDraft:
			drafted = on
		case imap.FlagDeleted:
			deleted = on
		}
	}
	if op.Op == imap.StoreFlagsSet {
		if !containsFlag(op.Flags, imap.FlagSeen) {
			seen = false
		}
		if !containsFlag(op.Flags, imap.FlagFlagged) {
			flagged = false
		}
		if !containsFlag(op.Flags, imap.FlagAnswered) {
			answered = false
		}
		if !containsFlag(op.Flags, imap.FlagDraft) {
			drafted = false
		}
		if !containsFlag(op.Flags, imap.FlagDeleted) {
			deleted = false
		}
	}
	return storage.FlagPatch{IsRead: &seen, IsFlagged: &flagged, IsAnswered: &answered, IsDraft: &drafted, Deleted: &deleted}
}

// containsFlag 标志列表包含判定。
func containsFlag(flags []imap.Flag, f imap.Flag) bool {
	for _, v := range flags {
		if v == f {
			return true
		}
	}
	return false
}

// detailFlags Detail → IMAP 标志列表（五系统标志映射——F-I16；keyword 追加——D8#1
// FETCH FLAGS/STORE 应答共用输出点：§7.3.5「Flags other than the system flags can
// also exist, depending on server implementation」——keyword 原样输出）。
func detailFlags(d *storage.Detail) []imap.Flag {
	var out []imap.Flag
	if d.IsRead {
		out = append(out, imap.FlagSeen)
	}
	if d.IsFlagged {
		out = append(out, imap.FlagFlagged)
	}
	if d.IsAnswered {
		out = append(out, imap.FlagAnswered)
	}
	if d.IsDraft {
		out = append(out, imap.FlagDraft)
	}
	if d.Deleted {
		out = append(out, imap.FlagDeleted)
	}
	for _, kw := range d.Keywords {
		out = append(out, imap.Flag(kw)) // D8#1：keyword 集（不带 "\" 前缀——§2.3.2）
	}
	return out
}

// keywordsFromOp STORE 操作语义的 keyword 终态计算（D8#1——纯函数镜像
// flagPatchFromOp 模式：Set=全量覆盖（未列清除）/Add=追加/Del=移除；
// rfc9051 §6.4.6 L4570-4592 三态语义；输入集仅取非 "\" 前缀 flag——协议解析保证）。
func keywordsFromOp(op *imap.StoreFlags, cur []string) []string {
	ops := make([]string, 0, len(op.Flags))
	for _, f := range op.Flags {
		if s := string(f); !strings.HasPrefix(s, "\\") {
			ops = append(ops, s)
		}
	}
	if op.Op == imap.StoreFlagsSet {
		return dedupKeywords(ops) // Set：终态=操作数全集（未列 keyword 即清除）
	}
	next := make([]string, 0, len(cur)+len(ops))
	next = append(next, cur...)
	if op.Op == imap.StoreFlagsDel {
		remove := make(map[string]struct{}, len(ops))
		for _, kw := range ops {
			remove[kw] = struct{}{}
		}
		filtered := next[:0]
		for _, kw := range next {
			if _, gone := remove[kw]; !gone {
				filtered = append(filtered, kw)
			}
		}
		return dedupKeywords(filtered)
	}
	next = append(next, ops...) // Add：追加
	return dedupKeywords(next)
}

// dedupKeywords 去重（保序——终态集形态稳定）。
func dedupKeywords(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, kw := range in {
		if kw == "" {
			continue
		}
		if _, dup := seen[kw]; dup {
			continue
		}
		seen[kw] = struct{}{}
		out = append(out, kw)
	}
	return out
}

// equalKeywords 集相等判定（顺序无关——STORE 空写防护）。
func equalKeywords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, kw := range a {
		set[kw] = struct{}{}
	}
	for _, kw := range b {
		if _, ok := set[kw]; !ok {
			return false
		}
	}
	return true
}

// Copy 复制到目标文件夹（新行新 UID——COPYUID 应答，rfc9051 7.1；F-I8：目标不存在
// NO [TRYCREATE]；F-I13：批量单事务原子化——rfc9051 §6.4.7 L4627-4630
// 「partial copy MUST NOT be done」）。
func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	ctx := context.Background()
	f, err := s.findFolder(ctx, dest)
	if err != nil {
		return nil, errTryCreate(err)
	}
	metas, srcUIDs, _, err := s.collectCopyMetas(ctx, numSet)
	if err != nil {
		return nil, err
	}
	newUIDs, err := s.server.messages.CopyAtomic(ctx, s.mbox.ID, f.ID, metas, nil)
	if err != nil {
		return nil, err
	}
	var srcSet, dstSet imap.UIDSet
	for i := range newUIDs {
		srcSet.AddNum(imap.UID(srcUIDs[i]))
		dstSet.AddNum(imap.UID(newUIDs[i]))
	}
	return &imap.CopyData{UIDValidity: uidValidity, SourceUIDs: srcSet, DestUIDs: dstSet}, nil
}

// collectCopyMetas 序号集→批量复制输入（metas 与源 UID/源行 ID 对齐收集；
// Copy/Move 共用——F-I13 批量事务前置）。
func (s *Session) collectCopyMetas(ctx context.Context, numSet imap.NumSet) ([]*storage.AppendMeta, []int64, []int64, error) {
	var metas []*storage.AppendMeta
	var srcUIDs, srcIDs []int64
	uids, _ := s.resolveNumSet(numSet)
	for _, uid := range uids {
		detail := s.detailForUID(ctx, uid)
		if detail == nil {
			continue
		}
		metas = append(metas, appendMetaOf(detail))
		srcUIDs = append(srcUIDs, uid)
		srcIDs = append(srcIDs, detail.ID)
	}
	return metas, srcUIDs, srcIDs, nil
}

// appendMetaOf Detail → 复制元数据（blob CAS 幂等——仅元数据行；五标志承载 F-I16；
// internal date 保留承载 F-I4——rfc9051 §6.4.7 L4615-4617/§6.4.8 L4663-4665
// 「The flags and internal date of the message(s) SHOULD be preserved in the copy」；
// 源行未指定（nil）时回落落库时刻语义=复制时刻，沿既有缺省口径）。
func appendMetaOf(d *storage.Detail) *storage.AppendMeta {
	return &storage.AppendMeta{
		Message: storage.MessageMeta{
			BlobKey: d.BlobKey, RawSize: d.RawSize,
			Subject: d.Subject, FromAddr: d.FromAddr, ToAddrs: d.ToAddrs, CcAddrs: d.CcAddrs,
			SentAt: d.SentAt,
		},
		Flags:        storage.FlagPatch{IsRead: &d.IsRead, IsFlagged: &d.IsFlagged, IsAnswered: &d.IsAnswered, IsDraft: &d.IsDraft, Deleted: &d.Deleted},
		InternalDate: d.InternalDate, // F-I4：COPY/MOVE 保留（nil=未指定→存储缺省）
		Keywords:     d.Keywords,     // D8#1：COPY/MOVE keyword 保留（L573-574 SHOULD）
	}
}

// Move 移动（rfc6851：复制+删除源行同事务——F-I13 原子化；MOVE 能力已通告；
// F-I8：目标不存在 NO [TRYCREATE]——rfc9051 §6.4.8 L4697-4699）。
func (s *Session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	ctx := context.Background()
	f, err := s.findFolder(ctx, dest)
	if err != nil {
		return errTryCreate(err)
	}
	metas, srcUIDs, srcIDs, err := s.collectCopyMetas(ctx, numSet)
	if err != nil {
		return err
	}
	newUIDs, err := s.server.messages.CopyAtomic(ctx, s.mbox.ID, f.ID, metas, srcIDs)
	if err != nil {
		return err
	}
	var srcSet, dstSet imap.UIDSet
	for i := range newUIDs {
		srcSet.AddNum(imap.UID(srcUIDs[i]))
		dstSet.AddNum(imap.UID(newUIDs[i]))
	}
	if err = w.WriteCopyData(&imap.CopyData{UIDValidity: uidValidity, SourceUIDs: srcSet, DestUIDs: dstSet}); err != nil {
		return err
	}
	return s.refreshUIDs(ctx)
}

// Append 追加邮件（rfc9051 6.3.12；Blob 先写（CAS）→StoreAppend 单事务——
// 双写顺序对齐数据模型 1.3；APPENDUID 应答；F-I8：目标不存在 NO [TRYCREATE]
// ——rfc9051 §6.3.12 L3451-3453）。
func (s *Session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	ctx := context.Background()
	f, err := s.findFolder(ctx, mailbox)
	if err != nil {
		return nil, errTryCreate(err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > s.server.maxAppendSize() {
		return nil, errors.New("message too big")
	}
	sum := sha256.Sum256(raw)
	parsed := mail.ParseCachedHeaders(raw)
	meta := &storage.AppendMeta{
		Message: storage.MessageMeta{
			MessageID: parsed.MessageID, BlobKey: hex.EncodeToString(sum[:]),
			RawSize: int64(len(raw)), Subject: parsed.Subject, FromAddr: parsed.FromAddr,
			ToAddrs: parsed.ToAddrs, CcAddrs: parsed.CcAddrs, SentAt: parsed.SentAt,
			BodyCache: mail.BodyCacheOf(raw), // U16 Q3-A：APPEND 正文缓存（四写入路径之三）
		},
		Flags:    appendFlagsToPatch(options.Flags),
		Keywords: appendKeywordsOf(options.Flags), // D8#1：APPEND keyword 初值（§6.3.12 flag list）
		InternalDate: func() *time.Time { // F-I5：APPEND 可选 date-time（rfc9051 §6.3.12
			// L3440-3442「If a date-time is specified, the internal date SHOULD be set」；
			// go-imap v2 AppendOptions.Time 承载——零值=未指定→存储缺省落库时刻）
			if options != nil && !options.Time.IsZero() {
				return &options.Time
			}
			return nil
		}(),
	}
	if err = s.server.blobs.Write(ctx, meta.Message.BlobKey, raw); err != nil {
		return nil, err
	}
	uid, err := s.server.messages.StoreAppend(ctx, s.mbox.ID, f.ID, meta)
	if err != nil {
		return nil, err
	}
	return &imap.AppendData{UID: imap.UID(uid), UIDValidity: uidValidity}, nil
}

// appendKeywordsOf APPEND flag list 的 keyword 分量（D8#1——非 "\" 前缀 flag；
// 去重保序；空集=无初值；rfc9051 §6.3.12 flag list 可含 keyword）。
func appendKeywordsOf(flags []imap.Flag) []string {
	var out []string
	for _, f := range flags {
		if s := string(f); !strings.HasPrefix(s, "\\") {
			out = append(out, s)
		}
	}
	return dedupKeywords(out)
}

// appendFlagsToPatch APPEND 可选标志 → 初值补丁（五系统标志——F-I16）。
func appendFlagsToPatch(flags []imap.Flag) storage.FlagPatch {
	seen, flagged, answered, drafted, deleted := false, false, false, false, false
	for _, f := range flags {
		switch f {
		case imap.FlagSeen:
			seen = true
		case imap.FlagFlagged:
			flagged = true
		case imap.FlagAnswered:
			answered = true
		case imap.FlagDraft:
			drafted = true
		case imap.FlagDeleted:
			deleted = true
		}
	}
	return storage.FlagPatch{IsRead: &seen, IsFlagged: &flagged, IsAnswered: &answered, IsDraft: &drafted, Deleted: &deleted}
}

// ───────────────────────── 推送（rfc2177，Q2-A 事件驱动） ─────────────────────────

// writeNumMessagesIfChanged 计数变化时发送 EXISTS+刷新映射（unsolicited 容忍但避免噪音）。
func (s *Session) writeNumMessagesIfChanged(ctx context.Context, w *imapserver.UpdateWriter) error {
	uids, err := s.folderUIDsASC(ctx, s.folder.ID)
	if err != nil {
		return err
	}
	if n := uint32(len(uids)); n != s.lastNum {
		if err = w.WriteNumMessages(n); err != nil {
			return err
		}
		s.lastNum = n
		s.uids = uids
	}
	return nil
}

// Poll 即时刷新（NOOP 通道——IDLE 外的变更发现路径）。
func (s *Session) Poll(w *imapserver.UpdateWriter, _ bool) error {
	if s.folder == nil {
		return nil
	}
	return s.writeNumMessagesIfChanged(context.Background(), w)
}

// Idle 空转等推（rfc2177：事件到达→EXISTS；DONE/断开→返回）。
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.folder == nil {
		return errNotSelected
	}
	ch, cancel := s.server.notifier.Subscribe(s.mbox.ID)
	s.cancel = cancel
	defer func() {
		cancel()
		s.cancel = nil
	}()
	ctx := context.Background()
	if err := s.writeNumMessagesIfChanged(ctx, w); err != nil {
		return err
	}
	for {
		select {
		case <-stop:
			return nil
		case <-ch:
			if err := s.writeNumMessagesIfChanged(ctx, w); err != nil {
				return err
			}
		}
	}
}

// Namespace 个人命名空间（前缀空+分隔符 '/'——单层模型）。
func (s *Session) Namespace() (*imap.NamespaceData, error) {
	return &imap.NamespaceData{
		Personal: []imap.NamespaceDescriptor{{Prefix: "", Delim: '/'}},
	}, nil
}
