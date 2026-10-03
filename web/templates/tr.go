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
	"app.name":       {"GRmail", "GRmail"},
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
	// ── 登录页 ──
	"login.adminTitle":  {"GRmail · 管理员登录", "GRmail · Admin Login"},
	"login.mailTitle":   {"GRmail · 邮箱登录", "GRmail · Mailbox Login"},
	"login.username":    {"用户名", "Username"},
	"login.address":     {"邮箱地址", "Email address"},
	"login.password":    {"密码", "Password"},
	"login.submit":      {"登录", "Sign in"},
	"login.invalidHint": {"用户名或密码错误，或已被锁定", "Invalid credentials or account locked"},
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
	"mail.title":       {"邮件", "Mail"},
	"mail.searchHint":  {"搜索主题/发件人/收件人", "Search subject/from/to/body"},
	"mail.search":      {"搜索", "Search"},
	"mail.newFolder":   {"新建文件夹", "New folder"},
	"mail.folderName":  {"文件夹名", "Folder name"},
	"mail.manage":      {"管理", "Manage"},
	"mail.newName":     {"新名称", "New name"},
	"mail.selectAll":   {"全选", "Select all"},
	"mail.markRead":    {"标为已读", "Mark read"},
	"mail.markUnread":  {"标为未读", "Mark unread"},
	"mail.addFlag":     {"加星标", "Add star"},
	"mail.removeFlag":  {"去星标", "Remove star"},
	"mail.moveTo":      {"移动到…", "Move to…"},
	"mail.totalFmt":    {"共 %d 封", "%d total"},
	"mail.clearUnread": {"取消未读过滤", "Clear unread filter"},
	"mail.unreadOnly":  {"只看未读", "Unread only"},
	"mail.exitSearch":  {"退出搜索", "Exit search"},
	"mail.noMatchFmt":  {"无匹配「%s」的邮件。", "No messages matching “%s”."},
	"mail.emptyFolder": {"此文件夹暂无邮件。", "This folder is empty."},
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
	"mail.pagesizeFmt":    {"每页 %d 封", "%d per page"},
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
	"compose.csvUpload":       {"选择 CSV 文件", "Choose CSV file"},
	"compose.csvParse":        {"解析", "Parse"},
	"compose.csvTarget":       {"导入到", "Import into"},
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
	"settings.backMail":       {"返回邮箱", "Back to mail"},
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
	"setup.title":      {"GRmail · 初始部署向导", "GRmail · Setup wizard"},
	"setup.h1":         {"GRmail 初始部署（第 %d / %d 步：%s）", "GRmail setup (step %d / %d: %s)"},
	"setup.s1Legend":   {"数据库选择（FR-014：三库适配）", "Database (FR-014: three-database)"},
	"setup.sqlite":     {"SQLite（内置默认，零配置）", "SQLite (built-in default, zero config)"},
	"setup.dsn":        {"连接串 DSN（SQLite 留空=默认 data/grmail.db；MySQL/PostgreSQL 必填）", "DSN (blank = default SQLite file; required for MySQL/PostgreSQL)"},
	"setup.s1Hint":     {"切换数据库在重启后生效；连接将即时探活校验。", "Database switch applies after restart; connection probed on save."},
	"setup.next":       {"下一步", "Next"},
	"setup.s2Legend":   {"管理员账户（单管理员模型——数据模型 3.1）", "Admin account (single-admin model)"},
	"setup.confirm":    {"确认密码", "Confirm password"},
	"setup.createGo":   {"创建并继续", "Create and continue"},
	"setup.s2Hint":     {"已部署过（管理员已存在）？", "Already deployed (admin exists)?"},
	"setup.skip":       {"跳过此步", "Skip this step"},
	"setup.s3Legend":   {"主域名（发信身份 / 收信判定 / 证书域名）", "Primary domain (identity / delivery / certificate)"},
	"setup.domain":     {"域名", "Domain"},
	"setup.s4Legend":   {"DNS 记录建议（请在域名服务商处发布后继续）", "DNS records (publish at your provider, then continue)"},
	"setup.colType":    {"类型", "Type"},
	"setup.colHost":    {"主机名", "Host"},
	"setup.colValue":   {"值", "Value"},
	"setup.colNote":    {"说明", "Note"},
	"setup.dnsDone":    {"我已完成 DNS 发布，下一步", "DNS published, continue"},
	"setup.s5Legend":   {"证书模式（FR-015：ACME 自动 / 手动导入）", "Certificate mode (FR-015: ACME / manual)"},
	"setup.acme":       {"ACME 自动签发（Let's Encrypt · HTTP-01——需 80 端口公网可达）", "ACME auto-issue (Let's Encrypt · HTTP-01; port 80 required)"},
	"setup.acmeMail":   {"ACME 联系人邮箱", "ACME contact email"},
	"setup.staging":    {"使用 staging 环境（测试签发，避免生产配额消耗）", "Use staging environment (test issuance)"},
	"setup.http01":     {"挑战方式：HTTP-01（缺省——经 80 端口）", "Challenge: HTTP-01 (default; via port 80)"},
	"setup.dns01":      {"挑战方式：DNS-01（Cloudflare——免 80 端口依赖）", "Challenge: DNS-01 (Cloudflare; no port 80 required)"},
	"setup.dnsToken":   {"Cloudflare API Token（Zone·DNS·Edit 权限）", "Cloudflare API Token (Zone.DNS.Edit)"},
	"setup.manual":     {"手动导入（已有证书文件）", "Manual import (existing files)"},
	"setup.certFile":   {"证书路径（fullchain.pem）", "Certificate path (fullchain.pem)"},
	"setup.keyFile":    {"私钥路径（key.pem）", "Private key path"},
	"setup.s6Legend":   {"完成部署", "Finish"},
	"setup.s6Intro":    {"将把 setupCompleted 写入 config.json 并完成初始部署。要点：", "setupCompleted will be written to config.json. Summary:"},
	"setup.s6Domain":   {"主域名：", "Primary domain:"},
	"setup.s6Restart":  {"重启进程后全部协议端点（25/465/587/993/995/443）全量启动", "all protocol endpoints (25/465/587/993/995/443) start after restart"},
	"setup.s6Acme":     {"ACME 模式：证书在完成后由后台自动签发（每日检查，剩余不足 30 天自动续期）", "ACME: certificate issued in background (daily check, renew under 30 days)"},
	"setup.finish":     {"完成设置", "Finish setup"},
	"setup.stepsNav":   {"步骤：", "Steps:"},
	"setup.stepDB":     {"数据库", "Database"},
	"setup.stepAdmin":  {"管理员", "Admin"},
	"setup.stepDomain": {"域名", "Domain"},
	"setup.stepDNS":    {"DNS", "DNS"},
	"setup.stepSSL":    {"证书", "TLS"},
	"setup.stepDone":   {"完成", "Done"},
	"setup.errSystem":  {"系统故障，请重试", "System error, please retry"},
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

// Trf 双语格式化文案取值（fmt.Sprintf 承载——%d/%s 占位由调用方给参）。
// 参数：lang 语言；key 文案键；args 格式化实参。返回：格式化后文案。
func Trf(lang Lang, key string, args ...any) string {
	return fmt.Sprintf(Tr(lang, key), args...)
}
