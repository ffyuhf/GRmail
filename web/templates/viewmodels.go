// templates 包 Webmail 视图模型（U9）：跨包数据拍平结构（web 包构造、本包组件消费——
// 避免 web↔templates 循环引用；storage/mail 原生类型经组件参数直用不复制）。
// 依据：CON-002（templ SSR 范式）；契约 v1.5.0/3.2/3.3/3.4 与 v1.6.0 3.1/3.3（HTMX 局部更新约定）。
// 修改历史：
//
//	2026-09-19 15:04:00 | 新建 | U9 Webmail 核心（计划书步骤 5 配套，G2 批准 2026-09-19 10:00:41）
//	2026-09-20 01:20:00 | 扩展 | U10 Setup 向导与 ACME：SetupData/SettingsData/DNSRecordView
//	（计划书步骤 6/7 配套，G2 批准 2026-09-20 00:32:33）
//	2026-09-26 15:50:00 | 扩展 | U18 登记项收尾：SetupData 增 Lang 字段（深级双语承载——
//	U16 登记项③收口；沿 SettingsData.Lang string 先例）
//	（依据：U18 计划书 v1.0.0 步骤 3/1.5④，G2 批准 2026-09-26 15:25:47）
//	2026-10-05 00:22:00 | 扩展 | Setup向导缺陷修复批次（缺陷④b）：SetupData 增
//	LangNext 字段（语言切换回跳当前步路径——/lang?next= 承载；buildSetupData 装配）
//	（依据：Setup向导缺陷修复计划书 v1.0.0 1.2 组4b，G2 批准 2026-10-05 00:21:19）
package templates

import "github.com/a-h/templ"

// checkedAttrs 布尔checked属性动态形态（WEB模板缺陷修正批次·组A——原
// checked={bool}生成checked="false"字面量，HTML布尔属性存在即生效致恒勾选/恒选末项；
// templ.Attributes展开（{ ...... }）对bool true输出裸属性、false省略属性——缺陷消除；
// 置手写文件承载：生成器为每份*_templ.go自动注入templ import，Go段再import即冲突）。
func checkedAttrs(on bool) templ.Attributes {
	if on {
		return templ.Attributes{"checked": true}
	}
	return nil
}

// selectedAttrs 布尔selected属性动态形态（组A——select option选中态；与checkedAttrs
// 同机理：bool false省略属性，替代selected={bool}的selected="false"字面量缺陷）。
func selectedAttrs(on bool) templ.Attributes {
	if on {
		return templ.Attributes{"selected": "selected"}
	}
	return nil
}

// disabledAttrs 禁用属性三态辅助（Setup向导新手可用性批次 P6——HadAdmin 态输入禁用；
// 同 checkedAttrs 机理：false 省略属性，避免 disabled="false" 布尔属性字面量缺陷）。
func disabledAttrs(on bool) templ.Attributes {
	if on {
		return templ.Attributes{"disabled": true}
	}
	return nil
}

// MailListData 列表渲染数据（整页与片段共用；侧边栏+列表+分页+过滤上下文）。
type MailListData struct {
	Lang         string // 界面语言（U16 Q2-A——cookie lang，缺省 zh）
	Label        string // 主体呈现名
	IsAdmin      bool   // admin 主体（管理入口显隐）
	Folders      []FolderEntry
	Items        []MailRow
	Total        int64
	Page         int
	PageCount    int
	Pagesize     int
	UnreadOnly   bool
	FlaggedOnly  bool
	ActiveFolder int64
	Keyword      string // 搜索场景
	IsSearch     bool
	CSRF         string
	Noticed      string // G3——D9：文件夹操作结果反馈（?noted=created|renamed|deleted 查询参）
}

// FolderEntry 侧边栏平铺行（FR-012：单层无嵌套渲染——REQ-021）。
type FolderEntry struct {
	ID     int64
	Name   string
	Kind   string // inbox/sent/drafts/junk/trash/custom
	Unread int64
	Active bool
}

// MailRow 列表行（G11 状态可视化：未读粗体/星标/时间；G15 精确 id 批量锚）。
type MailRow struct {
	ID        int64
	Subject   string
	FromAddr  string
	SentAt    string // 已格式化呈现串
	IsRead    bool
	IsFlagged bool
}

// ComposeData 写信表单数据（Q5-A：纯文本+附件；草稿回填态；U16 增 Lang 双语渲染）。
type ComposeData struct {
	Lang         string // 界面语言（U16 Q2-A）
	To           string
	Cc           string
	Bcc          string
	Subject      string
	Body         string
	From         string // admin 主体 From 输入（本域校验在 handler）
	IsAdmin      bool
	DraftID      int64 // 编辑态（>0 覆盖旧稿）
	ErrText      string
	CSRF         string
	ImageMaxEdge int           // D8#11：压缩最长边（config 注入——compose-page data-* 承载；0=缺省 1920）
	JpegQuality  float64       // D8#11：JPEG 质量档（0=缺省 0.85）
	Nav          *MailListData // 全站侧栏数据（D3 B 形态——AppFrame 承载；nil=无邮箱异常态降级）
	Domain       string        // 主域（G5——D12：from 输入 data-domain 前缀自动补 @主域）
}

// ImgMaxEdgeAttr 最长边渲染值（D8#11——零值兜底缺省 1920：模板层兜底使测试直调
// 形态（不经 handler 注入）也输出缺省档——与 JS parseInt 兜底双保险）。
func (d *ComposeData) ImgMaxEdgeAttr() int {
	if d.ImageMaxEdge > 0 {
		return d.ImageMaxEdge
	}
	return 1920
}

// JpegQualityAttr 质量档渲染值（D8#11——零值/越界兜底缺省 0.85）。
func (d *ComposeData) JpegQualityAttr() float64 {
	if d.JpegQuality > 0 && d.JpegQuality <= 1 {
		return d.JpegQuality
	}
	return 0.85
}

// ── U10 视图模型（Setup 向导与设置页）──

// SetupData 向导步骤页数据（六步共用组件按 Step 分支渲染；部分完成态回填）。
type SetupData struct {
	Lang          string // 界面语言（U18 深级双语承载——cookie lang，缺省 zh；向导无会话仍可读 cookie）
	Step          int    // 1~6
	Total         int    // 6
	Title         string
	Error         string          // 表单错误（空=无）
	Next          string          // 下一 slug（导航）
	LangNext      string          // 语言切换回跳路径（缺陷④b——/setup/<slug> 当前步；langSwitchHref next 承载）
	Driver        string          // 步 1：sqlite/mysql/postgres
	DSN           string          // 步 1：连接串（高级模式回填——分字段模式时拆解回显）
	DSNHost       string          // 步 1 分字段：数据库主机名（P11 DSN 双模式——Setup向导新手可用性批次）
	DSNPort       string          // 步 1 分字段：端口（空=按库缺省 mysql 3306/postgres 5432）
	DSNUser       string          // 步 1 分字段：用户名
	DSNPassword   string          // 步 1 分字段：密码
	DSNDBName     string          // 步 1 分字段：数据库名
	Username      string          // 步 2：缺省建议名
	HadAdmin      bool            // 步 2：管理员已存在态（P6——只读呈现+徽标；skip 路径既有保持）
	Domain        string          // 步 3
	DKIMStrength  string          // 步 3：DKIM 密钥强度选择回显（生成档位——rsa-2048 缺省；向导占位符与布局修复批次）
	DKIMGenerated bool            // 步 3：已有密钥提示态（config.DKIM.KeyPath 非空——向导占位符与布局修复批次）
	DNSRecords    []DNSRecordView // 步 4
	SSLMode       string          // 步 5：acme/manual
	ACMEMail      string
	ACMEStaging   bool
	ACMEChallenge string // 步 5 ACME 挑战方式（D8#12：http/dns——dns=Cloudflare DNS-01；缺省 http）
	HTTPPort      int    // 步 5：当前 HTTP 明文端口（P3——-p CLI 覆盖值/缺省 80；ACME 模式且 ≠80 时呈现警示条）
	CertFile      string
	KeyFile       string
	DomainFinal   string // 步 6
}

// DNSRecordView DNS 建议行（步 4 只读呈现——A/MX/SPF/DMARC/DKIM/MTA-STS/TLS-RPT/连接子域）。
type DNSRecordView struct {
	Type  string
	Name  string
	Value string
	TTL   string // TTL 建议值（P8——服务商面板直接可填；_mta-sts 短 TTL 语义 rfc8461 §3.1）
	Note  string
}

// SettingsData 设置页数据（Q7-C 四节：认证栈/catch-all/邮件限值/会话与限流；
// U13 增传输安全节：MTA-STS/TLS-RPT 开关与参数+DNS 建议值只读区）。
type SettingsData struct {
	Lang      string // 界面语言（U16 Q2-A）
	CSRFToken string
	Nav       *MailListData // 全站侧栏数据（D3 B 形态——AppFrame 承载；nil=无邮箱异常态降级）
	Message   string        // 错误提示（校验拒绝/保存失败——空=无；F01 语义更正：成功走 Notice）
	Notice    string        // 成功提示（保存成功 ?saved=1 态——空=无；F01 分型：Webmail界面精修批次 2026-10-03）
	PWChanged bool          // 改密成功反馈（Webmail管理职能批次 G1——?pwchanged=1 态；admin 改密重定向回承载）
	// 认证栈节
	SPFEnabled   bool
	DKIMEnabled  bool
	DMARCEnabled bool
	ARCEnabled   bool
	DKIMSelector string
	DKIMKeyPath  string
	DKIMAlgo     string
	// catch-all 与邮件限值节
	CatchAll         bool
	MaxMessageSizeMB int64
	RetryBaseSeconds int
	RetryFactor      int
	RetryCapSeconds  int
	MaxAttempts      int
	// 会话与限流节
	IdleMinutes        int
	AbsoluteHours      int
	LimitWindowMinutes int
	LimitThreshold     int64
	// 传输安全节（U13：FR-010——开关热加载生效，Web 关闭即端点停发/建议值停显）
	MTAStsEnabled       bool
	MTAStsMode          string // enforce | testing（rfc8461 §3.2）
	MTAStsMaxAgeSeconds int
	TLSRPTEnabled       bool
	TLSRPTRuaAddress    string // 空=缺省 postmaster@<主域>
	// DNS 建议值只读区（U13：判定①——部署者在域名服务商处发布；nil=建议区停显）
	StsPolicyURL string // https://mta-sts.<domain>/.well-known/mta-sts.txt
	StsTXTRecord string // _mta-sts.<domain> TXT 记录值
	TLSRPTRecord string // _smtp._tls.<domain> TXT 记录值（ReportEnabled=false 时空）
}
