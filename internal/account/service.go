// account 域服务：邮箱生命周期（创建/影子/激活/禁用）、凭据校验、文件夹管理、catch-all 支撑查询。
// 依据：SRS v1.0.0 FR-001（三入口认证域基础）/FR-002（管理员管理）/FR-003（catch-all 聚合支撑）/
// FR-004（影子状态机 shadow→active 原地继承）/FR-012（单层文件夹）；
// 关键流程设计 v1.0.0 第二章（影子判定流程 account 侧）；
// 系统架构总览 v1.0.0 第四章（account → storage 单向依赖，不 import protocol/*）。
// 修改历史：
//
//	2026-09-17 01:44:00 | 新建 | U2 account 模块（计划书步骤 5，G2 批准 2026-09-17 01:31:40）
package account

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"GRmail/internal/storage"
)

// ───────────────────────── 哨兵错误 ─────────────────────────

var (
	// ErrInvalidAddress 地址格式非法（规范化校验失败；判定口径见 NormalizeAddress）
	ErrInvalidAddress = errors.New("account: 非法邮箱地址")
	// ErrInvalidCredentials 凭据校验失败——统一拒绝语义：不区分「邮箱不存在 / 影子无凭据 /
	// 状态非 active / 密码错误」，防账号枚举（OWASP 会话管理指南登录失败统一口径）
	ErrInvalidCredentials = errors.New("account: 凭据无效")
	// ErrEmptyPassword 明文密码为空（创建/激活场景的输入校验，与登录拒绝语义分离）
	ErrEmptyPassword = errors.New("account: 密码不能为空")
	// ErrEmptyFolderName 文件夹名为空或超长（name ≤255，对齐 DDL VARCHAR 语义）
	ErrEmptyFolderName = errors.New("account: 文件夹名不能为空")
	// ErrInvalidStatus 非法状态值（未在 MailboxStatus 三态枚举内）
	ErrInvalidStatus = errors.New("account: 非法邮箱状态")
)

// folderNameMaxLen 文件夹名长度上限（数据模型 3.3 name VARCHAR(255) 语义对齐）
const folderNameMaxLen = 255

// Service 邮箱账号域服务（协议端点 U4/U6/U7/U8 经注入本服务访问账号域）
type Service struct {
	mailboxes storage.MailboxRepo
	folders   storage.FolderRepo
}

// NewService 构造账号域服务。
// 参数：mailboxes 邮箱仓储；folders 文件夹仓储。返回：服务实例。
func NewService(mailboxes storage.MailboxRepo, folders storage.FolderRepo) *Service {
	return &Service{mailboxes: mailboxes, folders: folders}
}

// ───────────────────────── 地址规范化（数据模型 3.2/第五章） ─────────────────────────

// NormalizeAddress 规范化邮箱地址：去首尾空白、整体小写、按首个 @ 拆分并校验。
// 判定口径（数据模型 3.2 列定义）：local 非空且 ≤64；domain 非空且 ≤255；整体 ≤320；
// 不含空白与控制字符；domain 不强制含点（默认配置 Domain=localhost 场景合法）。
// 参数：addr 原始输入。返回：local、domain；非法返回 ErrInvalidAddress。
func NormalizeAddress(addr string) (local string, domain string, err error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" || len(addr) > 320 {
		return "", "", ErrInvalidAddress
	}
	at := strings.Index(addr, "@")
	if at <= 0 || at == len(addr)-1 { // 无 @ / local 空 / domain 空
		return "", "", ErrInvalidAddress
	}
	local, domain = addr[:at], addr[at+1:]
	if len(local) > 64 || len(domain) > 255 {
		return "", "", ErrInvalidAddress
	}
	if strings.ContainsAny(addr, " \t\r\n\x00") {
		return "", "", ErrInvalidAddress
	}
	return local, domain, nil
}

// ───────────────────────── 邮箱生命周期 ─────────────────────────

// CreateMailbox 创建 active 邮箱（管理员/注册流程入口；FR-001）。
// 参数：ctx 上下文；addr 邮箱地址（自动规范化）；password 登录明文密码（内部即刻哈希，零明文持久化）。
// 返回：已建邮箱（ID 与时间回填）；ErrInvalidAddress / ErrEmptyPassword / storage.ErrMailboxExists。
func (s *Service) CreateMailbox(ctx context.Context, addr, password string) (*storage.Mailbox, error) {
	if password == "" {
		return nil, ErrEmptyPassword
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	return s.createMailbox(ctx, addr, hash, storage.MailboxStatusActive)
}

// CreateShadowMailbox 创建 shadow 影子邮箱（无凭据不可登录；U4 SMTP RCPT 判定「地址不存在」
// 分支调用；FR-004 判定①：影子归档+管理员通知的存储前提）。
// 参数：ctx 上下文；addr 未注册地址（自动规范化）。返回：已建影子邮箱。
func (s *Service) CreateShadowMailbox(ctx context.Context, addr string) (*storage.Mailbox, error) {
	return s.createMailbox(ctx, addr, "", storage.MailboxStatusShadow)
}

// createMailbox 创建邮箱的共享路径（规范化 → 组装 → 建库含五系统文件夹事务）。
func (s *Service) createMailbox(ctx context.Context, addr, hash string, status storage.MailboxStatus) (*storage.Mailbox, error) {
	local, domain, err := NormalizeAddress(addr)
	if err != nil {
		return nil, err
	}
	m := &storage.Mailbox{
		LocalPart:    local,
		Domain:       domain,
		Address:      local + "@" + domain,
		PasswordHash: hash,
		Status:       status,
	}
	if err := s.mailboxes.Create(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}

// ActivateMailbox 影子邮箱注册激活（FR-004 判定②：原地激活设凭据，历史邮件保留）。
// 参数：ctx 上下文；addr 已存在的影子邮箱地址；password 新登录密码。
// 返回：ErrMailboxNotFound 地址未建过影子；其余错误同仓储层。
func (s *Service) ActivateMailbox(ctx context.Context, addr, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	m, err := s.GetMailbox(ctx, addr)
	if err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	// 原地继承：仅设凭据+置 active，mailbox_messages 历史行零触碰（REQ-020）
	return s.mailboxes.SetCredentials(ctx, m.ID, hash)
}

// VerifyCredentials 登录凭据校验（FR-001 三入口共用：IMAP U6 / POP3 U7 / Webmail U8 注入点）。
// 参数：ctx 上下文；addr 登录地址；password 明文。
// 返回：校验通过的邮箱（仅 active 态）；一切拒绝统一为 ErrInvalidCredentials（防枚举）。
func (s *Service) VerifyCredentials(ctx context.Context, addr, password string) (*storage.Mailbox, error) {
	m, err := s.GetMailbox(ctx, addr)
	if err != nil {
		return nil, ErrInvalidCredentials // 不存在 → 统一拒绝
	}
	if m.Status != storage.MailboxStatusActive || m.PasswordHash == "" {
		return nil, ErrInvalidCredentials // 影子（无凭据不可登录，FR-004）/禁用 → 统一拒绝
	}
	ok, err := VerifyPassword(password, m.PasswordHash)
	if err != nil || !ok {
		return nil, ErrInvalidCredentials
	}
	return m, nil
}

// GetMailbox 按地址取邮箱（原始语义查询，不做人因混淆；U4 RCPT 判定三态分支使用）。
func (s *Service) GetMailbox(ctx context.Context, addr string) (*storage.Mailbox, error) {
	local, domain, err := NormalizeAddress(addr)
	if err != nil {
		return nil, err
	}
	return s.mailboxes.FindByAddress(ctx, local+"@"+domain)
}

// SetMailboxStatus 管理员状态管理（FR-002：禁用 disabled / 激活 active）。
func (s *Service) SetMailboxStatus(ctx context.Context, addr string, status storage.MailboxStatus) error {
	if status != storage.MailboxStatusActive && status != storage.MailboxStatusDisabled {
		return fmt.Errorf("%w: %s（仅允许 active/disabled）", ErrInvalidStatus, status)
	}
	m, err := s.GetMailbox(ctx, addr)
	if err != nil {
		return err
	}
	return s.mailboxes.SetStatus(ctx, m.ID, status)
}

// ListShadowMailboxes 列举全部影子邮箱（FR-003 catch-all 聚合视图数据源，
// Web 端 /admin/mailboxes/unregistered 呈现归 U8）。
func (s *Service) ListShadowMailboxes(ctx context.Context) ([]*storage.Mailbox, error) {
	return s.mailboxes.ListByStatus(ctx, storage.MailboxStatusShadow)
}

// EnsureAggregateFolder 幂等初始化聚合文件夹（U25——postmaster 第六系统文件夹；
// mail 管道窄接口消费位：聚合副本目标解析的运行期防御路径）。
func (s *Service) EnsureAggregateFolder(ctx context.Context, mailboxID int64) error {
	return s.folders.EnsureAggregateFolder(ctx, mailboxID)
}

// EnsurePostmasterMailbox 确保 postmaster@主域 邮箱存在并具备聚合文件夹（U25 回填
// 任务消费——不存在建影子归档沿管道 buildShadowNotice 先例；文件夹确保幂等双保险）。
// 参数：ctx 上下文；domain 主域。返回：postmaster 邮箱。
func (s *Service) EnsurePostmasterMailbox(ctx context.Context, domain string) (*storage.Mailbox, error) {
	postmaster := "postmaster@" + domain
	m, err := s.GetMailbox(ctx, postmaster)
	if err != nil {
		if !errors.Is(err, storage.ErrMailboxNotFound) {
			return nil, err
		}
		if m, err = s.CreateShadowMailbox(ctx, postmaster); err != nil {
			return nil, err
		}
	}
	if ferr := s.folders.EnsureAggregateFolder(ctx, m.ID); ferr != nil {
		return nil, ferr
	}
	return m, nil
}

// ───────────────────────── 文件夹管理（FR-012 单层模型） ─────────────────────────

// ListFolders 列举邮箱全部文件夹（侧边栏序；含五系统文件夹）。
func (s *Service) ListFolders(ctx context.Context, mailboxID int64) ([]*storage.Folder, error) {
	return s.folders.List(ctx, mailboxID)
}

// UnreadCounts 各文件夹未读计数（REQ-021 侧边栏数据源；未出现于 map 的文件夹未读为 0）。
func (s *Service) UnreadCounts(ctx context.Context, mailboxID int64) (map[int64]int64, error) {
	return s.folders.UnreadCounts(ctx, mailboxID)
}

// CreateFolder 创建自定义文件夹（FR-012：自定义文件夹单层，无父子）。
// 参数：name 非空且 ≤255。返回：ErrEmptyFolderName / storage.ErrFolderExists。
func (s *Service) CreateFolder(ctx context.Context, mailboxID int64, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > folderNameMaxLen {
		return ErrEmptyFolderName
	}
	return s.folders.CreateCustom(ctx, mailboxID, name)
}

// RenameFolder 重命名自定义文件夹（系统文件夹拒绝，TC-012 判定）。
func (s *Service) RenameFolder(ctx context.Context, folderID int64, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > folderNameMaxLen {
		return ErrEmptyFolderName
	}
	return s.folders.Rename(ctx, folderID, name)
}

// DeleteFolder 删除自定义文件夹（系统文件夹拒绝；非空文件夹由 FK 约束拒绝并转译友好错误）。
func (s *Service) DeleteFolder(ctx context.Context, folderID int64) error {
	return s.folders.Delete(ctx, folderID)
}
