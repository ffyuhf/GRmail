// templates 包双语文案表（U16，Q2-A 裁决 2026-09-24 11:47:58——服务端文案表双语（U17 增补编辑器工具栏键；
// U19 工具栏 title 追加 Quill 内置快捷键提示——bold/italic/underline/link 四键，2.0.3 源码核对）：
// G29 参照「前端全量文案双语」的 SSR 形态承载）。
// 判定序：cookie lang（zh|en）→缺省 zh（与 U15 末态行为一致——零回归锚）；
// lang 属性联动（Layout/AppLayout lang 参数）；切换经 GET /lang 端点（web 包承载）。
// 覆盖：登录/首页/顶栏/列表/写信/详情/设置八对核心模板全部界面文案+web 层校验错误文案；
// U18 深级收口：admin/sieve/tokens/settings/setup 五对管理模板深级文案+登录失败模糊
// 文案（U16 登记项③收口——管理域/设置深级/向导域键族全量补齐）。
// SRS 条目：FR-013（3.8 中英双语子项）；TC-013；契约 v1.12.0 3.1 /lang 行。
// 修改历史：
//
//	2026-09-24 16:46:00 | 新建 | U16 Webmail 体验收尾（计划书步骤 4，G2 批准 2026-09-24 11:51:57）
//	2026-09-26 15:40:00 | 扩展 | U18 登记项收尾：深级管理域键族增补（login.err×2+admin×16+
//	sieve×21+tokens×26+settings×27+setup×38——五对模板深级 Tr 化与 web 层错误文案消费）
//	（依据：U18 计划书 v1.0.0 步骤 3/1.5④，G2 批准 2026-09-26 15:25:47；U16 登记项③收口）
//	2026-09-26 17:10:00 | 扩展 | U19 编辑器体验收尾：工具栏 title 追加内置快捷键提示（bold/
//	italic/underline/link 四键 Ctrl+B/I/U/K——Quill 2.0.3 keyboard 源码+官方文档双源核对；
//	其余九键无内置绑定零触碰）
//	（依据：U19 计划书 v1.0.0 步骤 2/1.5②③，G2 批准 2026-09-26 16:45:48；U17 登记项④收口）
//	2026-09-27 10:55:00 | 扩展 | U22 富文本高级特性：八组内置控件键族增补（size×5/font×4/
//	color/background/align×4/indent×2/undo/redo×2——Quill 2.0.3 toolbar/uploader 源码双源
//	核对；undo/redo 无 toolbar 内置按钮经 history 模块 handler 桥接）
//	（依据：U22 计划书 v1.0.0 步骤 3/1.5①⑥，G2 批准 2026-09-27 10:38:20；S3-W 候选 B 裁决）
//	2026-10-03 07:40:00 | 扩展 | 编辑器收尾与e2e批次：E-B（D8#13）表格按钮键增补
//	（E-A ⌘ 记法零键增量——JS 运行时改写 title，文案键保持 Ctrl 初值锚）
//	（依据：编辑器收尾与e2e计划书 v1.0.0 步骤 3/4，G2 批准 2026-10-03 07:34:18）
//	2026-10-03 17:14:00 | 扩展 | 发布准备批次：本文件承载 //go:generate 锚——
//	go generate ./... 单命令触发 templ generate 全量再生成（.templ→*_templ.go），
//	消除逐次手动执行；生成物入库形态不变（CI 直接构建零生成依赖）
//	（依据：发布准备计划书 v1.0.0 1.2-MF 组/阶段 2，G2 批准 2026-10-03 17:09:00）

//go:generate templ generate
package templates

import "fmt"

// Lang 界面语言（cookie lang 承载；缺省 zh）。
type Lang string

// 支持语言枚举。
const (
	LangZH Lang = "zh"
	LangEN Lang = "en"
)

// NormalizeLang 语言值规范化（非法/空值归 zh——缺省档与既有行为一致）。
func NormalizeLang(v string) Lang {
	if v == string(LangEN) {
		return LangEN
	}
	return LangZH
}

// messages 双语文案表（key → zh/en；缺 key 缺语言回落中文原文——机械兜底）。
var messages = map[string][2]string{
	// ── 通用 ──
	"common.logout":  {"登出", "Log out"},
	"common.back":    {"返回列表", "Back to list"},
	"common.save":    {"保存（热加载生效）", "Save (hot-reload)"},
	"common.create":  {"创建", "Create"},
	"common.rename":  {"重命名", "Rename"},
	"common.delete":  {"删除", "Delete"},
	"common.execute": {"执行", "Apply"},
	"common.cancel":  {"取消", "Cancel"},
	// F15：危险操作确认（data-confirm 属性默认文案——Webmail界面精修批次 2026-10-03）
	"common.confirm": {"确定执行该操作？", "Proceed with this action?"},
	// ── Webmail管理职能批次键族（G1 密码三通道/G2 双枢纽/G3 规则入口/G4 管理增强/G6 插件页；
	// S3-W 三裁决 A A A——2026-10-05 15:14）──
	"top.settingsHub": {"个人设置", "My settings"},
	"top.password":    {"修改密码", "Change password"},
	// 改密页（pw.*——双通道共用：mailbox /settings/password·admin /admin/password）
	"pw.title":       {"修改密码", "Change Password"},
	"pw.user":        {"管理员用户名", "Admin username"},
	"pw.old":         {"当前密码", "Current password"},
	"pw.new":         {"新密码", "New password"},
	"pw.confirm":     {"确认新密码", "Confirm new password"},
	"pw.hint":        {"修改成功后将自动重建会话（其他已登录设备需重新登录）。", "Your session will be renewed after changing (other devices must sign in again)."},
	"pw.submit":      {"修改密码", "Change password"},
	"pw.errEmpty":    {"新密码不能为空。", "New password cannot be empty."},
	"pw.errMismatch": {"两次输入的新密码不一致。", "The two new passwords do not match."},
	"pw.errWrongOld": {"当前密码验证失败。", "Current password verification failed."},
	"pw.changed":     {"密码已修改，会话已重建。", "Password changed, session renewed."},
	// 个人设置枢纽（hub.*——mailbox 主体四分区）
	"hub.title":         {"个人设置", "My Settings"},
	"hub.account":       {"当前账号", "Account"},
	"hub.password":      {"修改密码", "Change Password"},
	"hub.passwordDesc":  {"更改本邮箱账号的登录密码。", "Change the login password of this mailbox."},
	"hub.twofactor":     {"双因素认证", "Two-Factor Auth"},
	"hub.twofactorDesc": {"绑定 TOTP 验证器，为登录增加第二道防线。", "Bind a TOTP authenticator for a second login factor."},
	"hub.rules":         {"过滤规则", "Filter Rules"},
	"hub.rulesDesc":     {"管理 Sieve 过滤脚本（移动/转发/丢弃来信）。", "Manage Sieve filter scripts (file/redirect/discard)."},
	"hub.mails":         {"返回邮箱", "Back to Mailbox"},
	"hub.mailsDesc":     {"回到收件箱列表。", "Back to the inbox list."},
	// 管理枢纽导航（settings.nav*——/admin/settings 六分区）
	"settings.navTitle":     {"管理导航", "Admin navigation"},
	"settings.navService":   {"服务配置", "Service Config"},
	"settings.navMailboxes": {"邮箱管理", "Mailboxes"},
	"settings.navAggregate": {"聚合视图", "Aggregate View"},
	"settings.navTokens":    {"API Token", "API Tokens"},
	"settings.navPlugins":   {"插件", "Plugins"},
	"settings.navAdminPw":   {"管理员改密", "Admin Password"},
	// 邮箱管理增强（admin.* G4——2FA 列/创建时间/搜索/行内改密）
	"admin.colCreated":     {"创建日期", "Created"},
	"admin.tfBound":        {"已绑定", "bound"},
	"admin.tfNone":         {"未绑定", "not bound"},
	"admin.tfUnboundReq":   {"未绑定·强制", "not bound · forced"},
	"admin.tfRequiredMark": {"管理员已设强制标记", "forced by admin"},
	"admin.setPwd":         {"改密", "Set password"},
	"admin.newPassPh":      {"新密码", "new password"},
	"admin.searchPh":       {"过滤地址…", "Filter addresses…"},
	// 插件状态页（plugins.* G6——只读呈现）
	"plugins.title":      {"插件", "Plugins"},
	"plugins.hint":       {"只读运行状态（插件崩溃后重启主程序恢复——不支持自动重拉）。", "Read-only status (restart the server to recover a crashed plugin — no auto-restart)."},
	"plugins.colName":    {"名称", "Name"},
	"plugins.colVer":     {"版本", "Version"},
	"plugins.colCaps":    {"能力", "Capabilities"},
	"plugins.colStatus":  {"状态", "Status"},
	"plugins.alive":      {"运行中", "running"},
	"plugins.dead":       {"已崩溃", "crashed"},
	"plugins.emptyTitle": {"暂无插件", "No plugins"},
	"plugins.empty":      {"将插件二进制放入 plugins/ 目录后重启主程序即可加载。", "Place plugin binaries in the plugins/ directory and restart to load them."},
	// ── 登录页 ──
	"login.adminTitle": {"GRmail · 管理员登录", "GRmail · Admin Login"},
	"login.mailTitle":  {"GRmail · 邮箱登录", "GRmail · Mailbox Login"},
	"login.username":   {"用户名", "Username"},
	"login.address":    {"邮箱地址", "Email address"},
	"login.password":   {"密码", "Password"},
	"login.submit":     {"登录", "Sign in"},
	// ── 占位首页（F23：文案更新为降级/引导态语义——Webmail界面精修批次 2026-10-03）──
	"home.loggedin":  {"已登录", "Signed in as"},
	"home.adminKind": {"管理员", "administrator"},
	"home.mailKind":  {"邮箱账号", "mailbox account"},
	"home.wip":       {"功能视图加载前的占位页（邮箱列表就绪后自动进入）。", "Placeholder before the functional view loads (enters mailbox list once ready)."},
	"home.noMailbox": {"当前主体暂无邮箱视图（部署引导期或邮箱未就绪）。", "No mailbox view for this identity yet (setup phase or mailbox not ready)."},
	"home.hintKind":  {"提示", "Notice"},
	// ── 顶栏 ──
	"top.compose":   {"写信", "Compose"},
	"top.adminMail": {"邮箱管理", "Mailboxes"},
	"top.aggregate": {"聚合视图", "Unregistered"},
	"top.lang":      {"English", "中文"},
	// ── 列表页 ──
	"mail.title":      {"邮件", "Mail"},
	"mail.searchHint": {"搜索主题/发件人/收件人/正文", "Search subject/from/to/body"},
	// ── WEB模板缺陷修正批次（组B/组C承载键）──
	"settings.dkimAlgoPh": {"rsa-sha256 | ed25519-sha256（留空=未配置）", "rsa-sha256 | ed25519-sha256 (blank = unset)"},
	"settings.ruaPh":      {"postmaster@域名（留空=缺省）", "postmaster@<domain> (blank = default)"},
	"settings.hostPh":     {"主域", "your domain"},
	"compose.fromPh":      {"admin@域名（任意本域地址）", "admin@<domain> (any local address)"},
	"detail.editDraft":    {"编辑草稿", "Edit draft"},
	"detail.attachFmt":    {"%s（%s，%s）", "%s (%s, %s)"},
	"mail.search":         {"搜索", "Search"},
	"mail.folderName":     {"文件夹名", "Folder name"},
	"mail.newName":        {"新名称", "New name"},
	"mail.selectAll":      {"全选", "Select all"},
	"mail.markRead":       {"标为已读", "Mark read"},
	"mail.markUnread":     {"标为未读", "Mark unread"},
	"mail.addFlag":        {"加星标", "Add star"},
	"mail.removeFlag":     {"去星标", "Remove star"},
	"mail.moveTo":         {"移动到…", "Move to…"},
	"mail.totalFmt":       {"共 %d 封", "%d total"},
	"mail.clearUnread":    {"取消未读过滤", "Clear unread filter"},
	"mail.unreadOnly":     {"只看未读", "Unread only"},
	"mail.exitSearch":     {"退出搜索", "Exit search"},
	"mail.noMatchFmt":     {"无匹配「%s」的邮件。", "No messages matching “%s”."},
	"mail.emptyFolder":    {"此文件夹暂无邮件。", "This folder is empty."},
	// 视觉重构批次空状态主文案（Nothing 形态——h3 主标题+副文案两行）
	"mail.emptyTitle":     {"空空如也", "Nothing here yet"},
	"mail.noResultTitle":  {"没有找到邮件", "No messages found"},
	"mail.colStatus":      {"状态", "State"},
	"mail.colSubject":     {"主题", "Subject"},
	"mail.colFrom":        {"发件人", "From"},
	"mail.colTime":        {"时间", "Time"},
	"mail.prevPage":       {"上一页", "Prev"},
	"mail.nextPage":       {"下一页", "Next"},
	"mail.pageFmt":        {"第 %d / %d 页", "Page %d / %d"},
	"mail.noSubject":      {"（无主题）", "(no subject)"},
	"mail.pagesizeSelect": {"每页", "Per page"},
	// ── 写信页 ──
	"compose.title":          {"写信", "Compose"},
	"compose.to":             {"收件人（To，逗号分隔）", "To (comma separated)"},
	"compose.cc":             {"抄送（Cc）", "Cc"},
	"compose.bcc":            {"密送（Bcc）", "Bcc"},
	"compose.from":           {"发件地址（本域任意地址）", "From (any local address)"},
	"compose.subject":        {"主题", "Subject"},
	"compose.body":           {"正文（富文本）", "Body (rich text)"},
	"compose.attach":         {"附件（可多选）", "Attachments (multiple)"},
	"compose.fullscreen":     {"全屏书写", "Fullscreen"},
	"compose.exitFullscreen": {"退出全屏", "Exit fullscreen"},
	// ── 写信页编辑器工具栏（U17——自定义 toolbar 容器按钮 title 双语——G3 语言跟随；
	// U19：有内置快捷键的四键 title 追加组合键提示——shortKey=平台自适应 Mac ⌘/Win+Linux Ctrl，
	// 统一 Ctrl 记法不分支（Quill 2.0.3 官方文档 keyboard 章原文）──
	"compose.tb.bold":        {"加粗 (Ctrl+B)", "Bold (Ctrl+B)"},
	"compose.tb.italic":      {"斜体 (Ctrl+I)", "Italic (Ctrl+I)"},
	"compose.tb.underline":   {"下划线 (Ctrl+U)", "Underline (Ctrl+U)"},
	"compose.tb.strike":      {"删除线", "Strikethrough"},
	"compose.tb.h1":          {"标题 1", "Heading 1"},
	"compose.tb.h2":          {"标题 2", "Heading 2"},
	"compose.tb.blockquote":  {"引用", "Blockquote"},
	"compose.tb.codeBlock":   {"代码块", "Code block"},
	"compose.tb.table":       {"插入表格 (2×2)", "Insert table (2×2)"},
	"compose.tb.listOrdered": {"有序列表", "Ordered list"},
	"compose.tb.listBullet":  {"无序列表", "Bullet list"},
	"compose.tb.link":        {"链接 (Ctrl+K)", "Link (Ctrl+K)"},
	"compose.tb.image":       {"插入图片（base64 内联）", "Insert image (base64 inline)"},
	"compose.tb.clean":       {"清除格式", "Clear formatting"},
	// ── U22 富文本高级特性：内置模块八组控件（S3-W 候选 B 裁决 2026-09-27 10:36:05——
	// Quill 2.0.3 源码双源核对：size whitelist small/large/huge；font whitelist
	// serif/monospace；align 值集 ""/center/right/justify；indent value ±1；色板
	// option 无文案（picker 色块渲染）仅 select title 承载双语）──
	"compose.tb.size":         {"字号", "Font size"},
	"compose.tb.sizeSmall":    {"小", "Small"},
	"compose.tb.sizeNormal":   {"标准", "Normal"},
	"compose.tb.sizeLarge":    {"大", "Large"},
	"compose.tb.sizeHuge":     {"特大", "Huge"},
	"compose.tb.font":         {"字体", "Font"},
	"compose.tb.fontDefault":  {"默认", "Default"},
	"compose.tb.fontSerif":    {"衬线", "Serif"},
	"compose.tb.fontMono":     {"等宽", "Monospace"},
	"compose.tb.color":        {"文字颜色", "Text color"},
	"compose.tb.background":   {"背景色", "Background color"},
	"compose.tb.alignLeft":    {"左对齐", "Align left"},
	"compose.tb.alignCenter":  {"居中对齐", "Align center"},
	"compose.tb.alignRight":   {"右对齐", "Align right"},
	"compose.tb.alignJustify": {"两端对齐", "Justify"},
	"compose.tb.indentLess":   {"减少缩进", "Decrease indent"},
	"compose.tb.indentMore":   {"增加缩进", "Increase indent"},
	"compose.tb.undo":         {"撤销 (Ctrl+Z)", "Undo (Ctrl+Z)"},
	"compose.tb.redo":         {"重做 (Ctrl+Y)", "Redo (Ctrl+Y)"},
	"compose.tb.headerNormal": {"正文", "Normal"},
	"compose.csvErr":          {"CSV 解析失败", "CSV parse failed"},
	"compose.send":            {"发送", "Send"},
	"compose.saveDraft":       {"存草稿", "Save draft"},
	"compose.csvImport":       {"CSV 批量导入收件人", "Import recipients from CSV"},
	"compose.csvParse":        {"解析", "Parse"},
	"compose.csvConfirm":      {"导入所选", "Import selected"},
	// ── 详情 ──
	"detail.reply":   {"回复", "Reply"},
	"detail.from":    {"发件人", "From"},
	"detail.to":      {"收件人", "To"},
	"detail.cc":      {"抄送", "Cc"},
	"detail.time":    {"时间", "Time"},
	"detail.size":    {"大小", "Size"},
	"detail.attach":  {"附件", "Attachments"},
	"detail.unnamed": {"未命名附件", "unnamed attachment"},
	// ── 设置页 ──
	"settings.title":          {"GRmail · 系统设置", "GRmail · Settings"},
	"settings.h1":             {"系统设置", "Settings"},
	"settings.authLegend":     {"认证与反伪造栈（FR-009：保存即热加载，无需重启）", "Auth & anti-spoofing stack (FR-009: hot-reload on save)"},
	"settings.deliveryLegend": {"投递与聚合", "Delivery & aggregation"},
	"settings.sessionLegend":  {"会话与登录限流（U8 常量 config 化——Q7-C）", "Session & login throttling"},
	"settings.tlsLegend":      {"传输安全（U13：FR-010——MTA-STS/TLS-RPT 默认启用、Web 可关闭，热加载生效）", "Transport security (U13 / FR-010)"},
	"settings.dnsLegend":      {"DNS 发布建议（只读——在域名服务商处发布后外部验证器可校验，FR-010 判定①）", "DNS publishing suggestions (read-only)"},
	// ── web 层错误文案（compose 校验——compose.go i18n 化消费）──
	"err.toRequired":      {"收件人不能为空", "Recipients required"},
	"err.subjectRequired": {"主题不能为空", "Subject required"},
	"err.bodyRequired":    {"正文不能为空", "Body required"},
	"err.fromRequired":    {"发件地址不能为空", "From address required"},
	"err.fromLocalOnly":   {"发件地址须为本域地址（FR-002）", "From must be a local address (FR-002)"},
	"err.fromResolve":     {"发件身份解析失败，请稍后重试", "Failed to resolve identity, retry later"},
	"err.fromAbnormal":    {"发件身份解析失败（邮箱状态异常）", "Identity resolve failed (mailbox abnormal)"},
	"err.rcptInvalid":     {"收件人地址非法", "Invalid recipient address"},
	"err.sendFailed":      {"发送失败（已记录，请稍后重试）", "Send failed (logged, retry later)"},
	"err.buildFailed":     {"邮件构造失败", "Mail build failed"},
	"err.draftNoFolder":   {"草稿文件夹不可用", "Drafts folder unavailable"},
	"err.draftSave":       {"草稿保存失败", "Draft save failed"},
	"err.attachTooLarge":  {"附件总大小超限（35MiB）", "Attachments exceed limit (35MiB)"},
	// ── 登录失败模糊文案（U18——login.go 常量 Tr 化收口，U16 登记项③）──
	"login.errInvalid": {"用户名或密码错误", "Invalid username or password"},
	"login.errLocked":  {"尝试次数过多，请稍后再试", "Too many attempts, try later"},
	// ── 管理页·邮箱管理（U18——admin.templ/admin.go 深级双语收口，U16 登记项③）──
	"admin.title":         {"邮箱管理", "Mailboxes"},
	"admin.h2":            {"邮箱账号", "Mailbox accounts"},
	"admin.colAddr":       {"地址", "Address"},
	"admin.colAction":     {"操作", "Actions"},
	"admin.enable":        {"启用", "Enable"},
	"admin.disable":       {"禁用", "Disable"},
	"admin.setPass":       {"设密码激活", "Set password to activate"},
	"admin.activate":      {"激活", "Activate"},
	"admin.deactivate":    {"取消激活", "Deactivate"}, // Sieve编辑器缺口修复批次 #31——与 admin.activate 对称（激活行专属）
	"admin.createMailbox": {"创建邮箱", "Create mailbox"},
	"admin.addrPh":        {"地址", "address"},
	"admin.passPh":        {"密码", "password"},
	// F09：邮箱状态枚举双语映射（badge 呈现——Webmail界面精修批次 2026-10-03）
	"admin.statusActive":   {"启用中", "active"},
	"admin.statusShadow":   {"影子", "shadow"},
	"admin.statusDisabled": {"已禁用", "disabled"},
	"admin.aggTitle":       {"聚合视图", "Unregistered"},
	"admin.aggH2":          {"未注册来信聚合（影子邮箱）", "Unregistered senders (shadow mailboxes)"},
	"admin.aggEmpty":       {"暂无影子邮箱（未注册地址来信后自动建立）。", "No shadow mailboxes yet (created automatically on first unregistered delivery)."},
	"admin.aggArchived":    {"来信归档于", "Archived in"},
	"admin.shadowFmt":      {"影子邮箱 #%d", "Shadow mailbox #%d"},
	"admin.errAddr":        {"邮箱地址非法", "Invalid mailbox address"},
	"admin.errEmptyPass":   {"密码不能为空", "Password must not be empty"},
	"admin.errStatus":      {"状态变更非法", "Invalid status change"},
	"admin.errExists":      {"邮箱已存在", "Mailbox already exists"},
	"admin.errMissing":     {"邮箱不存在（激活须先经来信建影子）", "Mailbox not found (activate requires a prior shadow)"},
	"admin.errOpFmt":       {"操作失败：%s", "Operation failed: %s"},
	// ── 管理页·Sieve（U18——sieve.templ/sieve.go 深级双语收口）──
	"sieve.title":       {"Sieve 过滤规则", "Sieve rules"},
	"sieve.nav":         {"过滤规则", "Rules"},
	"sieve.h2":          {"Sieve 过滤脚本", "Sieve scripts"},
	"sieve.newLink":     {"＋ 新建脚本", "＋ New script"},
	"sieve.manageHint":  {"（经 Web 编辑器或 ManageSieve 客户端（4190）管理）", "(manage via Web editor or ManageSieve client, port 4190)"},
	"sieve.empty":       {"暂无脚本——来信将直接投递到收件箱（implicit keep）。", "No scripts yet — mail is delivered to INBOX (implicit keep)."},
	"sieve.colName":     {"脚本名", "Name"},
	"sieve.active":      {"已激活", "active"},
	"sieve.inactive":    {"未激活", "inactive"},
	"sieve.editTitle":   {"编辑 Sieve 脚本", "Edit Sieve script"},
	"sieve.editH2":      {"编辑脚本：%s", "Editing script: %s"},
	"sieve.save":        {"保存（语法校验）", "Save (syntax check)"},
	"sieve.syntaxHint":  {"语法：rfc5228（require / if / fileinto / redirect / discard / setflag 等）；保存时执行编译期校验。", "Syntax: rfc5228 (require / if / fileinto / redirect / discard / setflag …); compiled and validated on save."},
	"sieve.errName":     {"脚本名无效", "Invalid script name"},
	"sieve.errSyntax":   {"语法错误（未保存）：%s", "Syntax error (not saved): %s"},
	"sieve.errSave":     {"保存失败：%s", "Save failed: %s"},
	"sieve.errList":     {"脚本列举失败：%s", "List scripts failed: %s"},
	"sieve.errGet":      {"脚本读取失败：%s", "Read script failed: %s"},
	"sieve.notFound":    {"脚本不存在", "Script not found"},
	"sieve.errDisabled": {"Sieve 未启用", "Sieve not enabled"},
	"sieve.newH2":       {"新建脚本", "New script"}, // Sieve编辑器缺口修复批次 #30——new 态独立标题
	"sieve.nameLabel":   {"脚本名", "Script name"}, // #30——名称输入框 label（无 placeholder：label 文案承载指引）
	// ── 管理页·Token（U18——tokens.templ/tokens.go 深级双语收口）──
	"tokens.title":     {"API Token 管理", "API tokens"},
	"tokens.generated": {"Token 已生成（仅此一次展示，请立即复制保存）：", "Token generated (shown only once — copy it now):"},
	"tokens.h2Gen":     {"生成 Token", "Generate token"},
	"tokens.expires":   {"有效期：", "Validity:"},
	"tokens.forever":   {"永久", "Forever"},
	"tokens.7d":        {"7 天", "7 days"},
	"tokens.30d":       {"30 天", "30 days"},
	"tokens.bindIP":    {"绑定 IP（可选，留空不绑定）：", "Bind IP (optional):"},
	"tokens.ipPh":      {"如 203.0.113.10", "e.g. 203.0.113.10"},
	"tokens.h2List":    {"已有 Token", "Existing tokens"},
	"tokens.colCreate": {"创建时间", "Created"},
	"tokens.colExp":    {"有效期", "Validity"},
	"tokens.colIP":     {"绑定 IP", "Bound IP"},
	"tokens.colUsed":   {"最后使用", "Last used"},
	"tokens.empty":     {"暂无 Token", "No tokens yet"},
	"tokens.revoke":    {"撤销", "Revoke"},
	"tokens.notBound":  {"不绑定", "not bound"},
	"tokens.progHead":  {"程序化访问：请求头", "Programmatic access: header"},
	"tokens.progTail":  {"访问既有 Webmail 端点（/mails、/compose、/search 等）。", "against existing Webmail endpoints (/mails, /compose, /search, …)."},
	"tokens.errTier":   {"有效期档位无效", "Invalid validity tier"},
	"tokens.errGen":    {"Token 生成失败", "Token generation failed"},
	"tokens.errRevoke": {"Token 撤销失败", "Token revoke failed"},
	// ── 设置页深级（U18——settings.templ/adminsettings.go；title/h1/legend 系 U16 已埋键本单元接线）──
	"settings.spf":         {"SPF 验证（rfc7208）", "SPF verification (rfc7208)"},
	"settings.dkim":        {"DKIM 验证与签名（rfc6376）", "DKIM verify & sign (rfc6376)"},
	"settings.dmarc":       {"DMARC 验证（rfc9989）", "DMARC verification (rfc9989)"},
	"settings.arc":         {"ARC 验证与封装（rfc8617）", "ARC verify & seal (rfc8617)"},
	"settings.dkimSel":     {"DKIM 选择器", "DKIM selector"},
	"settings.dkimKey":     {"DKIM 私钥路径", "DKIM private key path"},
	"settings.dkimAlgo":    {"DKIM 算法", "DKIM algorithm"},
	"settings.catchAll":    {"catch-all 聚合（未注册来信转交管理员——FR-003）", "catch-all aggregation (FR-003)"},
	"settings.maxSize":     {"邮件大小上限（MiB）", "Max message size (MiB)"},
	"settings.retryBase":   {"退避基数（秒）", "Retry base (seconds)"},
	"settings.retryFactor": {"退避倍数", "Retry factor"},
	"settings.retryCap":    {"退避封顶（秒）", "Retry cap (seconds)"},
	"settings.maxAttempts": {"最大尝试次数", "Max attempts"},
	"settings.idle":        {"会话空闲超时（分钟）", "Session idle timeout (minutes)"},
	"settings.absolute":    {"会话绝对超时（小时）", "Session absolute timeout (hours)"},
	"settings.limitWin":    {"登录失败窗口（分钟）", "Login failure window (minutes)"},
	"settings.limitThr":    {"失败锁定阈值（次）", "Lockout threshold (attempts)"},
	"settings.stsPub":      {"MTA-STS 策略发布（rfc8461——关闭即策略端点停发）", "MTA-STS policy publishing (rfc8461)"},
	"settings.stsMode":     {"MTA-STS 模式", "MTA-STS mode"},
	"settings.stsAge":      {"MTA-STS max_age（秒）", "MTA-STS max_age (seconds)"},
	"settings.tlsrptPub":   {"TLS-RPT 记录发布（rfc8460——关闭即建议值停显）", "TLS-RPT record publishing (rfc8460)"},
	"settings.rua":         {"TLS-RPT 报告地址（rua）", "TLS-RPT report address (rua)"},
	"settings.stsHint":     {"策略端点：", "Policy endpoint:"},
	"settings.stsSanHint":  {"（证书须含 mta-sts 主域前缀 SAN——ACME 模式自动扩展）", "(certificate must cover mta-sts subdomain SAN — auto-extended in ACME mode)"},
	"settings.errAlgo":     {"DKIM 算法必须为 rsa-sha256 或 ed25519-sha256（留空=未配置）", "DKIM algorithm must be rsa-sha256 or ed25519-sha256 (blank = unset)"},
	"settings.errSave":     {"保存失败（系统故障），请重试", "Save failed (system error), please retry"},
	// F01 扩展：保存成功 notice+校验拒绝串 Tr 化（settingsReject 11 处——Webmail界面精修批次 2026-10-03）
	"settings.saved":          {"已保存（热加载生效）", "Saved (hot-reload applied)"},
	"settings.errMaxSize":     {"邮件大小上限必须为正整数（MiB）", "Max message size must be a positive integer (MiB)"},
	"settings.errRetryBase":   {"退避基数必须为正整数（秒）", "Retry base must be a positive integer (seconds)"},
	"settings.errRetryFactor": {"退避倍数必须为正整数", "Retry factor must be a positive integer"},
	"settings.errRetryCap":    {"退避封顶必须为正整数（秒）", "Retry cap must be a positive integer (seconds)"},
	"settings.errMaxAttempts": {"最大尝试次数必须为正整数", "Max attempts must be a positive integer"},
	"settings.errIdle":        {"会话空闲超时必须为正整数（分钟）", "Session idle timeout must be a positive integer (minutes)"},
	"settings.errAbsolute":    {"会话绝对超时必须为正整数（小时）", "Session absolute timeout must be a positive integer (hours)"},
	"settings.errLimitWin":    {"限流窗口必须为正整数（分钟）", "Throttle window must be a positive integer (minutes)"},
	"settings.errLimitThr":    {"限流阈值必须为正整数（次）", "Lockout threshold must be a positive integer"},
	"settings.errStsMode":     {"MTA-STS 模式必须为 enforce 或 testing", "MTA-STS mode must be enforce or testing"},
	"settings.errStsAge":      {"MTA-STS max_age 必须为 1..31557600 秒（rfc8461 §3.2）", "MTA-STS max_age must be 1..31557600 seconds (rfc8461 §3.2)"},
	// ── Setup 向导深级（U18——setup.templ/setup.go 深级双语收口）──
	"setup.title":         {"GRmail · 初始部署向导", "GRmail · Setup wizard"},
	"setup.h1":            {"GRmail 初始部署（第 %d / %d 步：%s）", "GRmail setup (step %d / %d: %s)"},
	"setup.s1Legend":      {"数据库选择（SQLite / MySQL / PostgreSQL 三种可选）", "Database (SQLite / MySQL / PostgreSQL)"},
	"setup.s1Ref":         {"需求条目 FR-014", "Requirement FR-014"},
	"setup.sqlite":        {"SQLite（内置默认，零配置）", "SQLite (built-in default, zero config)"},
	"setup.dsn":           {"连接串 DSN（SQLite 留空=默认 data/grmail.db；MySQL/PostgreSQL 必填）", "DSN (blank = default SQLite file; required for MySQL/PostgreSQL)"},
	"setup.dsnKeepPh":     {"已配置——留空保持不变", "Configured — leave blank to keep"},
	"setup.s1Hint":        {"切换数据库在重启后生效；连接将即时探活校验。", "Database switch applies after restart; connection probed on save."},
	"setup.next":          {"下一步", "Next"},
	"setup.s2Legend":      {"管理员账户（本系统设一名管理员，管理全部邮箱）", "Admin account (this system has one admin managing all mailboxes)"},
	"setup.s2Ref":         {"单管理员模型——数据模型 3.1", "Single-admin model — data model 3.1"},
	"setup.adminExists":   {"管理员已创建——可直接跳过此步", "Admin already created — you can skip this step"},
	"setup.confirm":       {"确认密码", "Confirm password"},
	"setup.adminPrefix":   {"管理员邮箱前缀（主邮箱=前缀@域名；postmaster 地址保留）", "Admin mailbox prefix (primary = prefix@domain; postmaster retained)"},
	"mail.noticedCreated": {"文件夹已创建", "Folder created"},
	"mail.noticedRenamed": {"文件夹已重命名", "Folder renamed"},
	"mail.noticedDeleted": {"文件夹已删除", "Folder deleted"},
	"nav.backSettings":    {"返回设置中心", "Back to settings"},
	"admin.filterAll":     {"全部", "All"},
	"setup.createGo":      {"创建并继续", "Create and continue"},
	"setup.s2Hint":        {"已部署过（管理员已存在）？", "Already deployed (admin exists)?"},
	"setup.skip":          {"跳过此步", "Skip this step"},
	"setup.s3Legend":      {"主域名（发信身份 / 收信判定 / 证书域名）", "Primary domain (identity / delivery / certificate)"},
	"setup.domain":        {"域名", "Domain"},
	"setup.s4Legend":      {"DNS 记录建议（请在域名服务商处发布后继续）", "DNS records (publish at your provider, then continue)"},
	"setup.colType":       {"类型", "Type"},
	"setup.colHost":       {"主机名", "Host"},
	"setup.colValue":      {"值", "Value"},
	"setup.colNote":       {"说明", "Note"},
	"setup.dnsDone":       {"我已完成 DNS 发布，下一步", "DNS published, continue"},
	"setup.s5Legend":      {"证书（HTTPS 加密——自动申请或导入已有）", "Certificate (HTTPS — auto-issue or import)"},
	"setup.s5Ref":         {"需求条目 FR-015", "Requirement FR-015"},
	"setup.acme":          {"自动申请（Let's Encrypt 免费证书，推荐）", "Auto-issue (Let's Encrypt free certificate, recommended)"},
	"setup.acmeMail":      {"联系邮箱（证书到期提醒用——可填你的任意邮箱）", "Contact email (expiry notices — any of your emails)"},
	"setup.staging":       {"使用测试通道（测试证书不受浏览器信任——正式部署请保持不勾选）", "Use staging (test certificate NOT trusted by browsers — keep unchecked in production)"},
	"setup.http01":        {"验证方式：HTTP 验证（推荐——服务器 80 端口可公网访问时）", "Verification: HTTP (recommended when port 80 is publicly reachable)"},
	"setup.dns01":         {"验证方式：DNS 验证（高级——无 80 端口时经 Cloudflare，需 API Token）", "Verification: DNS (advanced — via Cloudflare when no port 80; needs API Token)"},
	"setup.dnsWaitHint":   {"选择 DNS 验证时：DNS 记录传播与缓存刷新需要时间，签发可能等待 10-30 分钟", "With DNS verification: propagation and cache refresh may take 10-30 minutes"},
	"setup.dnsToken":      {"Cloudflare API Token（Zone·DNS·Edit 权限）", "Cloudflare API Token (Zone.DNS.Edit)"},
	"setup.manual":        {"手动导入（已有证书文件）", "Manual import (existing files)"},
	"setup.certFile":      {"证书路径（fullchain.pem）", "Certificate path (fullchain.pem)"},
	"setup.keyFile":       {"私钥路径（key.pem）", "Private key path"},
	"setup.portWarnTitle": {"注意：当前 HTTP 端口不是 80", "Note: HTTP port is not 80"},
	"setup.portWarnBody":  {"自动证书的 HTTP 验证依赖 80 端口。请改用 80 端口启动，或在反向代理上将 /.well-known/* 路由转发到本服务；也可改选 DNS 验证方式。", "HTTP verification relies on port 80. Restart on port 80, or reverse-proxy /.well-known/* to this service; alternatively choose DNS verification."},
	"setup.s6Legend":      {"完成部署", "Finish"},
	"setup.s6Intro":       {"部署即将完成。接下来：", "Setup is finishing. Next:"},
	"setup.s6Domain":      {"主域名：", "Primary domain:"},
	"setup.s6Restart":     {"停止程序（按 Ctrl+C）后再次运行，全部服务随之启动", "Stop the program (Ctrl+C) and run it again — all services then start"},
	"setup.s6Acme":        {"自动证书：完成后后台自动申请（每天检查，到期前 30 天自动续期）", "Auto certificate: issued in background (checked daily, renewed 30 days before expiry)"},
	"setup.finish":        {"完成设置", "Finish setup"},
	"setup.stepsNav":      {"步骤：", "Steps:"},
	"setup.stepDB":        {"数据库", "Database"},
	"setup.stepAdmin":     {"管理员", "Admin"},
	"setup.stepDomain":    {"域名", "Domain"},
	"setup.stepDNS":       {"DNS", "DNS"},
	"setup.stepSSL":       {"证书", "TLS"},
	"setup.stepDone":      {"完成", "Done"},
	"setup.errSystem":     {"系统故障，请重试", "System error, please retry"},
	// ── Setup 新手可用性批次（P2 欢迎与每步说明/P8 TTL 列/P9 连接参数与子域/P11 DSN 双模式/P13 完成页）──
	"setup.welcome":         {"欢迎使用 GRmail 邮件服务器", "Welcome to GRmail mail server"},
	"setup.welcomeDesc":     {"接下来将指引你完成初始配置，全程无需编辑任何配置文件。如果你已有旧配置，可用其覆盖运行目录后跳过相应步骤。", "This wizard guides you through initial setup without editing any config file. If you already have a previous configuration, copy it over the runtime directory and skip steps as needed."},
	"setup.desc1":           {"选择数据存放位置：SQLite 开箱即用（推荐新手）；MySQL/PostgreSQL 适合已有数据库服务的场景。", "Choose where data is stored: SQLite works out of the box (recommended); MySQL/PostgreSQL suit an existing database service."},
	"setup.desc2":           {"设置管理员账号——用于登录网页管理后台，可管理全部邮箱。", "Set the admin account — used to sign in to the web admin panel and manage all mailboxes."},
	"setup.desc3":           {"填写你的邮件域名（如 example.com）——发信身份、收信判定与证书都以它为准。", "Enter your mail domain (e.g. example.com) — sender identity, delivery and certificate are all based on it."},
	"setup.desc4":           {"将下表记录添加到你的域名服务商处（全部照抄即可）。添加完成后进入下一步。", "Add the records below at your DNS provider (copy them as-is), then continue."},
	"setup.desc5":           {"为网页与邮件传输配置 HTTPS 证书。不确定如何选时保持默认（自动申请+HTTP 验证）。", "Configure the HTTPS certificate for web and mail transport. Keep defaults when unsure (auto-issue + HTTP verification)."},
	"setup.desc6":           {"配置已完成——查看下方启动与访问指引。", "Configuration complete — see the startup and access guide below."},
	"setup.colTTL":          {"TTL 建议", "TTL"},
	"setup.dsnModeBasic":    {"分字段填写（推荐）", "Field-by-field (recommended)"},
	"setup.dsnModeAdvanced": {"直接填写连接串（高级）", "Raw DSN (advanced)"},
	"setup.dsnHost":         {"数据库主机", "Database host"},
	"setup.dsnPort":         {"端口（空=", "Port (blank = "},
	"setup.dsnPortM":        {"3306", "3306"},
	"setup.dsnPortP":        {"5432", "5432"},
	"setup.dsnUser":         {"用户名", "Username"},
	"setup.dsnPassword":     {"密码", "Password"},
	"setup.dsnDBName":       {"数据库名", "Database name"},
	"setup.dsnSwitch":       {"切换为直接填写连接串", "Switch to raw DSN input"},
	"setup.dsnSwitchBack":   {"切换为分字段填写", "Switch back to field-by-field"},
	"setup.visitTitle":      {"访问邮箱网页版", "Open the webmail"},
	"setup.visitDesc":       {"浏览器打开", "Open in browser"},
	"setup.loginTitle":      {"登录", "Sign in"},
	"setup.loginAdmin":      {"管理员（本向导第二步设置的账号）经管理入口登录；邮箱账号创建后经邮箱入口登录。", "Admin (the account from step 2) signs in at the admin entrance; mailbox accounts sign in at the webmail entrance."},
	"setup.restartTitle":    {"重启服务使全部功能生效", "Restart to activate all services"},
	"setup.acmeWaitTitle":   {"证书申请等待期（自动证书）", "Certificate issuance wait (auto)"},
	"setup.acmeWaitDesc":    {"证书在完成后数十秒至数分钟内自动签发，期间用 https:// 访问可能失败属正常——稍后刷新即可。", "The certificate is issued within seconds to minutes after finishing; https:// may fail during this window — refresh later."},
	"setup.portLegend":      {"服务端口一览（重启后生效）", "Service ports (after restart)"},
	"setup.port25":          {"25 — 接收外部来信", "25 — incoming mail"},
	"setup.port465":         {"465 — 发信（SSL）", "465 — submission (SSL)"},
	"setup.port587":         {"587 — 发信（STARTTLS）", "587 — submission (STARTTLS)"},
	"setup.port993":         {"993 — IMAP 收件（SSL）", "993 — IMAP (SSL)"},
	"setup.port995":         {"995 — POP3 收件（SSL）", "995 — POP3 (SSL)"},
	"setup.port443":         {"443 — 网页版（HTTPS）", "443 — webmail (HTTPS)"},
	"setup.clientLegend":    {"邮件客户端配置参数（域名即第三步所填）", "Email client settings (domain = step 3)"},
	"setup.clientIMAP":      {"IMAP 收件服务器", "IMAP server"},
	"setup.clientPOP3":      {"POP3 收件服务器", "POP3 server"},
	"setup.clientSMTP":      {"SMTP 发信服务器", "SMTP server"},
	"setup.clientSSL":       {"SSL/TLS", "SSL/TLS"},
	"setup.clientStartTLS":  {"STARTTLS", "STARTTLS"},
	"setup.clientWebmail":   {"网页版", "Webmail"},
	"setup.techDetails":     {"技术细节", "Technical details"},
	"setup.techCompleted":   {"完成本步将把 setupCompleted=true 写入 config.json（运行目录），随后由反向代理/服务管理器重启进程。", "Finishing writes setupCompleted=true into config.json (runtime directory); the process is then restarted via your service manager."},
	// ── Setup 步 3 DKIM 密钥区（向导占位符与布局修复批次——强度四档裁决三a）──
	"setup.dkimLegend":   {"DKIM 签名密钥（自动生成——发信签名用）", "DKIM signing key (auto-generated)"},
	"setup.dkimStrength": {"密钥强度", "Key strength"},
	"setup.dkimRegen":    {"重新生成密钥（不勾选则沿用已有密钥）", "Regenerate key (reuse existing if unchecked)"},
	"setup.dkimExisting": {"已生成密钥——下一步 DNS 建议将包含其公钥记录", "Key exists — its public record appears in the next step"},
	// ── 2FA（U24——twofactor.templ/登录二步/顶栏入口/admin 强制标记）──
	"top.twofactor":         {"2FA 设置", "2FA Settings"},
	"twofactor.title":       {"双因素认证（2FA）", "Two-Factor Authentication (2FA)"},
	"twofactor.intro":       {"为您的账号添加第二重登录保护：密码之外需输入验证器 App 的动态验证码。", "Add a second login factor: besides your password, a dynamic code from your authenticator app is required."},
	"twofactor.bound":       {"已绑定：每次登录需输入验证码或恢复码。", "Enabled: each login requires a code or recovery code."},
	"twofactor.setup":       {"启用 2FA", "Enable 2FA"},
	"twofactor.qr":          {"使用验证器 App（如 Google Authenticator）扫描二维码：", "Scan with an authenticator app (e.g. Google Authenticator):"},
	"twofactor.secret":      {"无法扫码？手动输入密钥", "Cannot scan? Enter the key manually"},
	"twofactor.confirmCode": {"输入 App 当前显示的 6 位验证码完成绑定", "Enter the current 6-digit code to confirm"},
	"twofactor.confirm":     {"确认绑定", "Confirm binding"},
	"twofactor.recovery":    {"备用恢复码", "Recovery codes"},
	"twofactor.recoveryTip": {"每枚仅可使用一次；请立即保存到安全位置，页面关闭后不再显示。", "Each code can be used only once; save them now — they will not be shown again."},
	"twofactor.disable":     {"停用 2FA", "Disable 2FA"},
	"twofactor.disableCode": {"停用须先通过一次第二因子验证（验证码或恢复码）", "A valid second factor (code or recovery code) is required to disable"},
	"twofactor.forced":      {"管理员已对本账号启用强制 2FA：请先完成绑定方可继续使用。", "An administrator requires 2FA for this account: complete binding to continue."},
	"login2fa.title":        {"GRmail · 两步验证", "GRmail · Two-Step Verification"},
	"login2fa.code":         {"验证码 / 恢复码", "Code / Recovery code"},
	"login2fa.submit":       {"验证", "Verify"},
	"login2fa.recovery":     {"验证器不可用时，可输入一枚未使用的恢复码。", "If your authenticator is unavailable, enter an unused recovery code."},
	"login2fa.errInvalid":   {"验证失败，请重试", "Verification failed, please retry"},
	"login2fa.errExpired":   {"登录会话已过期，请重新登录", "Login session expired, please sign in again"},
	"2fa.errBound":          {"2FA 已绑定", "2FA already enabled"},
	"2fa.errNotBound":       {"2FA 未绑定", "2FA not enabled"},
	"2fa.errCode":           {"第二因子验证失败", "Second-factor verification failed"},
	"2fa.errFormat":         {"验证码格式非法", "Invalid code format"},
	"2fa.errQR":             {"二维码生成失败", "QR code generation failed"},
	"admin.2faSection":      {"2FA 强制策略", "2FA enforcement"},
	"admin.2faAddr":         {"邮箱地址", "Mailbox address"},
	"admin.require2fa":      {"强制启用", "Require"},
	"admin.unrequire2fa":    {"取消强制", "Unrequire"},
	// ── Webmail设计系统重构批次（阶段A~D 新 UI 文案——纯增量，既有键零改写）──
	"top.manage":          {"管理", "Manage"},
	"top.settings":        {"系统设置", "Settings"},
	"top.tokens":          {"API Token", "API Tokens"},
	"top.account":         {"账户菜单", "Account menu"},
	"mail.folders":        {"文件夹", "Folders"},
	"mail.manageFolders":  {"管理文件夹", "Manage folders"},
	"mail.selectedFmt":    {"已选 %d 封", "%d selected"},
	"mail.flagged":        {"已加星标", "Starred"},
	"mail.unreadDot":      {"未读", "Unread"},
	"compose.rcpt":        {"收件人", "Recipients"},
	"compose.subjectPh":   {"邮件主题", "Email subject"},
	"detail.bodyFrame":    {"邮件正文", "Message body"},
	"login2fa.stepChip":   {"第二步验证", "Step 2"},
	"admin.aggEmptyTitle": {"暂无未注册来信", "No unregistered mail"},
	"sieve.emptyTitle":    {"暂无脚本", "No scripts"},
	"sieve.backList":      {"返回列表", "Back to list"},
	"home.goMail":         {"进入邮箱", "Go to mailbox"},
	// ── 侧栏交互缺陷修复批次（D5——系统文件夹名 i18n；folders.name 列存英文规范名，
	// 呈现层按 kind 经 Tr 映射；custom 与未知 kind 回退原 Name——DB 零改动）──
	"folder.inbox":        {"收件箱", "INBOX"},
	"folder.sent":         {"已发送", "Sent"},
	"folder.drafts":       {"草稿箱", "Drafts"},
	"folder.trash":        {"已删除", "Trash"},
	"folder.junk":         {"垃圾邮件", "Junk"},
	"folder.unregistered": {"未注册来信", "Unregistered"},
}

// folderDisplayName 文件夹呈现名（D5——系统文件夹按 kind 本地化，custom/未知 kind 回退原 Name）。
// 参数：lang 界面语言；kind 文件夹类型（folders.kind 规范值）；name 数据库原始名（回退承载）。
// 返回：当前语言的呈现名。依据：侧栏交互缺陷修复计划书 v1.0.0 1.2 G4（2026-10-05 18:41:43 G2 批准）。
func folderDisplayName(lang Lang, kind, name string) string {
	if tr, ok := messages["folder."+kind]; ok {
		if lang == LangEN {
			return tr[1]
		}
		return tr[0]
	}
	return name
}

// Tr 双语文案取值（缺 key/缺语言回落中文原文——机械兜底保证渲染不空）。
// 参数：lang 语言；key 文案键。返回：当前语言文案。
func Tr(lang Lang, key string) string {
	pair, ok := messages[key]
	if !ok {
		return key
	}
	if lang == LangEN {
		return pair[1]
	}
	return pair[0]
}

// colonFor 冒号本地化（组C——冒号口径随语言：zh全角/en半角+尾空格；替代模板硬编码，
// detail五函数/home/twofactor/settings DNS行的呈现统一承载）。
func colonFor(lang Lang) string {
	if lang == LangEN {
		return ": "
	}
	return "："
}

// Trf 双语格式化文案取值（fmt.Sprintf 承载——%d/%s 占位由调用方给参）。
// 参数：lang 语言；key 文案键；args 格式化实参。返回：格式化后文案。
func Trf(lang Lang, key string, args ...any) string {
	return fmt.Sprintf(Tr(lang, key), args...)
}
