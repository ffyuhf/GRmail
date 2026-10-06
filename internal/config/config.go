// Package config 实现运行时配置的加载、原子写入与热加载广播。
// 依据：CON-003（单一 config.json、Web 保存即写、文件变更监听自动生效）、
// 关键流程设计 v1.0.0 第五章（去抖 300ms → 解析校验 → 订阅者回调，失败回滚内存态）。
// 修改历史：
//
//	2026-09-16 04:33:00 | 新建 | U1 工程骨架（依据：系统架构总览 v1.0.0 第三章 config 模块职责）
//	2026-09-17 02:20:00 | 扩展 | U3 auth 基础：AuthStack 增设 DKIM 出站签名子配置（来源：用户确认 Q1-A 2026-09-17 02:08:38，有效性判定六条全真）
//	2026-09-17 03:20:00 | 扩展 | U4 SMTP 收信：ServerConf 增 SMTPPort、新增 MailConf{MaxMessageSizeBytes}（来源：用户确认 Q2-A 2026-09-17 03:06:39，有效性判定六条全真；SRS FR-005/rfc1870）
//	2026-09-17 11:45:00 | 扩展 | U5 SMTP 提交与投递：ServerConf 增 SubmissionPort/SubmissionTLSPort、Config 增 TLS、MailConf 增 Delivery（来源：用户确认 Q2-A/Q5-C 2026-09-17 11:28:56，有效性判定六条全真；SRS FR-005/NFR-006/rfc8314/rfc3207、CON-003）
//	2026-09-19 04:09:01 | 扩展 | U7 POP3 自研：ServerConf 增 POP3Port（来源：G2 批准 2026-09-19 04:09:01，计划书 v1.0.0 步骤 1；SRS FR-007/IR-003 rfc1939/5034）
//	2026-09-20 00:40:00 | 扩展 | U10 Setup 向导与 ACME：Config 增 SetupCompleted/Session/LoginLimit/ACME 四节
//	（来源：G2 批准 2026-09-20 00:32:33，计划书 v1.0.0 步骤 3；裁决 Q2-A setupCompleted 判定/
//	Q5-A HTTP-01+手动导入/Q7-C 会话与限流常量 config 化——U8 登记项②兑现；SRS FR-015/009/003）
//	2026-09-23 12:50:00 | 扩展 | U12b 装配收口：ServerConf 增 ManageSievePort（缺省 4190——监听器
//	启动期绑定重启生效，口径沿 U4 1.5⑪/U7 步骤 1 端口先例）
//	（来源：G2 批准 2026-09-23 12:49:06，U12b 计划书 v1.0.0 步骤 1/1.5①；SRS FR-011/IR-004 rfc5804 §1.8）
//	2026-09-23 08:24:00 | 扩展 | U13 传输安全全量：Config 增 MTASts 节（开关/Mode/MaxAge+TLS-RPT
//	开关+rua 地址——FR-010「二者默认启用、Web 可关闭」；开关热加载生效——Web 关闭即端点停发）
//	（来源：G2 批准 2026-09-23 08:19:32，U13 计划书 v1.0.0 步骤 2/1.5①；SRS FR-010/rfc8461 §3.2/rfc8460 §3）
//	2026-09-27 06:15:00 | 扩展 | U21 可观测性增强：LogConf 增 SqlSlowMs/SqlDebug/ProtocolDebug
//	三键（Q3-A 裁决——config.json 承载热加载生效；缺省 500/false/false，旧 JSON 缺键零值兼容）
//	（来源：G2 批准 2026-09-27 06:13:36，U21 计划书 v1.0.0 步骤 2/1.5②；SRS CON-003+阶段三"可以有"档）
//	2026-09-27 13:25:00 | 扩展 | U23 可观测性扩展：LogConf 增 LogFile/LogFileMaxMB/LogFileBackups
//	三键（Q1-B 裁决——Console+File 双写；空 logFile=仅 Console 现状零变化；重启生效口径沿
//	Level 先例；协议 debug 四端点热生效经既有 ProtocolDebug 快照链）
//	（来源：G2 批准 2026-09-27 13:20:53，U23 计划书 v1.0.0 步骤 2/1.5②⑦；SRS CON-002/003+NFR-016）
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// AuthStack 认证反伪造栈启停与细节（FR-009/NFR-005：Web 可配置、热加载生效）
type AuthStack struct {
	SPFEnabled   bool     `json:"spfEnabled"`   // SPF 验证开关（rfc7208）
	DKIMEnabled  bool     `json:"dkimEnabled"`  // DKIM 验证/签名开关（rfc6376）
	DMARCEnabled bool     `json:"dmarcEnabled"` // DMARC 验证开关（rfc9989，自研包）
	ARCEnabled   bool     `json:"arcEnabled"`   // ARC 验证/封装开关（rfc8617）
	DKIM         DKIMConf `json:"dkim"`         // 出站 DKIM 签名键配置（Q1-A 裁决 2026-09-17 02:08:38）
}

// DKIMConf 出站 DKIM 签名配置（Q1-A：config.json 扩展 selector/私钥路径/算法；
// 零值缺省为"未配置"——签名器显式报错，不影响验证开关与既有解析兼容）。
type DKIMConf struct {
	Selector  string `json:"selector"`  // s= 标签：DKIM 选择器（如 s1024）
	KeyPath   string `json:"keyPath"`   // 私钥 PEM 文件路径（管理员放置，E8 文件系统依赖）
	Algorithm string `json:"algorithm"` // 签名算法：rsa-sha256（rfc8301）| ed25519-sha256（rfc8463）
}

// DatabaseConf 三库连接配置（FR-014：sqlite 内置默认 / mysql / postgresql）
type DatabaseConf struct {
	Driver string `json:"driver"` // sqlite | mysql | postgres
	DSN    string `json:"dsn"`    // 连接串（sqlite 为文件路径）
}

// LogConf 日志配置（Q11：slog + phuslu/log；U21 可观测性增强三键——Q3-A 裁决 2026-09-27 06:09）。
type LogConf struct {
	Level          string `json:"level"`          // debug | info | warn | error
	SqlSlowMs      int    `json:"sqlSlowMs"`      // SQL 慢查询阈值毫秒（U21；缺省 500；0=禁用慢查询日志）
	SqlDebug       bool   `json:"sqlDebug"`       // SQL 全量 Debug 输出开关（U21；缺省 false——排障时开启，H4 ShowSQL 等价）
	ProtocolDebug  bool   `json:"protocolDebug"`  // 全协议端点（SMTP25/提交465·587/IMAP/POP3/ManageSieve/HTTP）会话帧 Debug 输出开关（U21 三协议+U23 补齐；缺省 false，H5 等价）
	LogFile        string `json:"logFile"`        // 日志文件基础路径（U23；空=仅 Console stderr 单写零变化；非空=Console+File 双写——传输安全与日志增强批次 L-D 起热重建生效）
	LogFileMaxMB   int    `json:"logFileMaxMB"`   // 当日按大小轮转阈值 MB（U23；缺省 100；0=不按大小轮转仅按备份上限）
	LogFileBackups int    `json:"logFileBackups"` // 大小轮转备份保留份数（U23；缺省 5；0=不限制备份数）
	// ── 传输安全与日志增强批次新增（G2 批准 2026-10-01 22:54:41）──
	LogRetainDays int  `json:"logRetainDays"` // 日志归档保留天数（L-E；缺省 30；0=不清理——旧 JSON 缺键零值兼容由 Load 兜底）
	SqlCommentID  bool `json:"sqlCommentId"`  // SQL 文本注释注入 log_id 开关（L-C——D8#7；缺省 false：注入改变语句文本致 prepare 缓存失效，仅排障关联 DB 侧慢查询日志时开启）
}

// BlobConf CAS 字节存储配置（Q13：元数据入库 + 原始字节外置）
type BlobConf struct {
	Dir string `json:"dir"` // blob 根目录（默认 data/blobs）
}

// ServerConf 服务端点与域名配置
type ServerConf struct {
	Domain             string `json:"domain"`             // 主域名（发信身份与收信判定；RCPT 本域判定口径）
	AdminMailbox       string `json:"adminMailbox"`       // 管理员主邮箱地址（管理员主体增强批次 G1——D4：向导步 2 前缀@主域落盘；空=admin Webmail 视图回退 postmaster@主域〔存量兼容锚〕）
	AdminMailboxPrefix string `json:"adminMailboxPrefix"` // 管理员邮箱前缀（G1：向导步 2 输入的中间态——步 3 域名确定后组合 AdminMailbox；postmaster 地址本身保留 RFC 5321 §4.5.1）
	HTTPPort           int    `json:"httpPort"`           // Webmail HTTPS 端口
	SMTPPort           int    `json:"smtpPort"`           // SMTP 25 收信监听端口（Q2-A 裁决 2026-09-17 03:06:39；缺省 25，监听器启动期绑定——重启生效，U4 计划书 1.5⑪）
	SubmissionPort     int    `json:"submissionPort"`     // SMTP 587 提交端口（STARTTLS；U5 Q2-A 2026-09-17 11:28:56；缺省 587，重启生效）
	SubmissionTLSPort  int    `json:"submissionTLSPort"`  // SMTP 465 提交端口（隐式 TLS，rfc8314 3.3；缺省 465，重启生效）
	IMAPPort           int    `json:"imapPort"`           // IMAP4rev2 993 端口（仅隐式 TLS——U6 Q1-A 2026-09-18 00:00:04，rfc8314 §1/§3.2 推荐形态；缺省 993，重启生效）
	POP3Port           int    `json:"pop3Port"`           // POP3 995 端口（仅隐式 TLS——U7 计划书 v1.0.0 步骤 1，rfc8314 §3.2；缺省 995，重启生效）
	ManageSievePort    int    `json:"manageSievePort"`    // ManageSieve 4190 端口（明文承载+STARTTLS 可选升级——U12b 计划书 1.5①，rfc5804 §1.8；缺省 4190，重启生效）
}

// TLSConf 服务端 TLS 证书配置（U5 Q2-A：transport 域最小集的输入；ACME 自动签发归 U10，
// 本结构支持手动证书路径；零值=未配置——提交 TLS 端点跳过启动并告警，U5 计划书 1.5⑫）
type TLSConf struct {
	CertFile string `json:"certFile"` // 证书 PEM 文件路径（fullchain）
	KeyFile  string `json:"keyFile"`  // 私钥 PEM 文件路径
}

// DeliveryConf 出站投递退避调度配置（U5 Q5-C 裁决 2026-09-17 11:28:56：入 config 可调，
// 缺省档取候选 A 值；流程设计 3.2 不变量 3「指数化且封顶」；worker 每次尝试读快照热生效）
type DeliveryConf struct {
	RetryBaseSeconds int `json:"retryBaseSeconds"` // 首次退避秒数（缺省 60=1min；零值兜底取缺省）
	RetryFactor      int `json:"retryFactor"`      // 退避倍数（缺省 2，指数化；零值兜底取缺省）
	RetryCapSeconds  int `json:"retryCapSeconds"`  // 退避封顶秒数（缺省 3600=60min；零值兜底取缺省）
	MaxAttempts      int `json:"maxAttempts"`      // 最大尝试次数，超过即 failed→DSN（缺省 8；零值兜底取缺省）
}

// MailConf 邮件收发限值配置（Q2-A 裁决；FR-005 + rfc1870 SIZE 能力）
type MailConf struct {
	MaxMessageSizeBytes int64        `json:"maxMessageSizeBytes"` // EHLO 通告 SIZE 值与 DATA 超限阈值（超限 552；缺省 36700160=35MiB；每连接读取快照热生效）
	Delivery            DeliveryConf `json:"delivery"`            // 出站投递退避调度（Q5-C；快照热生效）
}

// SessionConf 会话安全参数（Q7-C：U8 会话双超时代码常量 config 化；快照每请求读取热生效）
type SessionConf struct {
	IdleMinutes   int `json:"idleMinutes"`   // 空闲超时分钟（缺省 30=U8 缺省档；零值兜底取缺省）
	AbsoluteHours int `json:"absoluteHours"` // 绝对超时小时（缺省 12=U8 缺省档；零值兜底取缺省）
}

// MTAStsConf 传输安全发布侧配置（U13：FR-010——MTA-STS 策略与 TLS-RPT 记录
// 「二者默认启用、Web 可关闭」；开关热加载生效——Web 关闭即 /.well-known/mta-sts.txt
// 端点停发 404（判定③）与 DNS 建议值区停显）。
type MTAStsConf struct {
	Enabled       bool   `json:"enabled"`       // MTA-STS 发布开关（缺省 true——FR-010 默认启用；false=端点停发+ACME 清单收窄）
	Mode          string `json:"mode"`          // 策略 mode：enforce | testing（rfc8461 §3.2；缺省 enforce；非法值兜底取缺省）
	MaxAgeSeconds int    `json:"maxAgeSeconds"` // 策略 max_age 秒（rfc8461 §3.2 上限 31557600；缺省 604800=1 周；零值/越界兜底取缺省）
	ReportEnabled bool   `json:"reportEnabled"` // TLS-RPT 记录发布开关（rfc8460 §3；缺省 true——建议值区呈现 _smtp._tls 记录）
	RuaAddress    string `json:"ruaAddress"`    // TLS-RPT rua 聚合报告地址（缺省空=运行期按 postmaster@<主域> 拼接——1.5①）
}

// LoginLimitConf 登录失败限流参数（Q7-C：U8 限流常量 config 化；快照每请求读取热生效）
type LoginLimitConf struct {
	WindowMinutes int   `json:"windowMinutes"` // 失败计数滑动窗口分钟（缺省 15=U8 缺省档）
	Threshold     int64 `json:"threshold"`     // 窗口内失败次数阈值（缺省 5=U8 缺省档）
}

// ACME 目录端点常量（lego v4.35.2 无 LetsEncryptURL 导出常量——go doc 实测，计划书 1.5⑬；
// 缺省档取 Let's Encrypt 官方 production/staging directory 端点字面量）
const (
	ACMEDirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
	ACMEDirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ACMEConf ACME 自动签发配置（Q5-A：HTTP-01+手动导入双模式；Enabled=false 即手动模式，
// 本节零参与；Enabled=true 时签发/续期由 transport.ACMEManager 承载——Q6-A 落盘回写链；
// D8#12：DNS-01 挑战（FR-015 判定标准「HTTP-01/DNS-01」兑现——S4-W Q1-A 裁决仅
// Cloudflare：DNSProvider 非空=DNS-01 模式〔lego providers/dns/cloudflare——API
// Token 凭证形态〕；空=HTTP-01 既有缺省——80 挑战路由承载不变）。
type ACMEConf struct {
	Enabled        bool   `json:"enabled"`        // 启用 ACME 自动签发与续期（HTTP-01 或 DNS-01——按 DNSProvider 判定）
	Email          string `json:"email"`          // ACME 账户联系人邮箱（rfc8555 account contact）
	CADirURL       string `json:"caDirUrl"`       // ACME 目录端点（缺省 production；Staging=true 时覆盖为 staging）
	Staging        bool   `json:"staging"`        // 使用 staging 环境（测试签发，避免生产配额消耗）
	AccountKeyPath string `json:"accountKeyPath"` // ACME 账户私钥路径（缺省 data/certs/acme-account.key；ECDSA P-256）
	CertsDir       string `json:"certsDir"`       // 证书落盘根目录（缺省 data/certs；产物 <dir>/<domain>/{fullchain,privkey}.pem）
	DNSProvider    string `json:"dnsProvider"`    // DNS-01 提供商（D8#12——仅 "cloudflare"；空=HTTP-01 缺省模式）
	DNSApiToken    string `json:"dnsApiToken"`    // Cloudflare API Token（D8#12——DNS-01 凭证；DNSProvider 空时零参与）
}

// EditorConf 编辑器压缩参数（D8#11——U22 Canvas 压缩工程常量迁 config；模板 data-*
// 注入 compose 页（S4-W Q2-A 最小面裁决——改 config.json 即生效，无设置页 UI）；
// 零值兜底=U22 既有缺省档（1920/0.85）——旧 JSON 缺节兼容）。
type EditorConf struct {
	ImageMaxEdge int     `json:"imageMaxEdge"` // 压缩最长边像素（≤原样零重采样；0=缺省 1920）
	JpegQuality  float64 `json:"jpegQuality"`  // JPEG 质量档 0.0-1.0（0=缺省 0.85）
}

// Config 运行时配置根结构（config.json 唯一载体）
type Config struct {
	Server         ServerConf     `json:"server"`
	Database       DatabaseConf   `json:"database"`
	Auth           AuthStack      `json:"auth"`
	Log            LogConf        `json:"log"`
	Blob           BlobConf       `json:"blob"`
	Mail           MailConf       `json:"mail"`           // 收发限值+投递退避（Q2-A/Q5-C）
	TLS            TLSConf        `json:"tls"`            // 服务端 TLS 证书（U5 Q2-A；零值=未配置；U10 ACME 回写目标）
	CatchAll       bool           `json:"catchAll"`       // FR-003：未注册来信转交管理员聚合视图
	SetupCompleted bool           `json:"setupCompleted"` // Q2-A：Setup 六步完成判定（false=引导态——仅 80 向导端点；U10）
	Session        SessionConf    `json:"session"`        // Q7-C：会话双超时（U8 常量 config 化）
	LoginLimit     LoginLimitConf `json:"loginLimit"`     // Q7-C：登录失败限流（U8 常量 config 化）
	ACME           ACMEConf       `json:"acme"`           // Q5-A：ACME 自动签发（零值 Enabled=false=手动模式；D8#12 DNS-01 字段）
	MTASts         MTAStsConf     `json:"mtaSts"`         // U13：传输安全发布侧（FR-010——热加载生效）
	Editor         EditorConf     `json:"editor"`         // D8#11：编辑器压缩参数（缺省 1920/0.85）
}

// Default 返回内置默认配置（Setup 未完成前的引导态）
func Default() *Config {
	return &Config{
		Server:   ServerConf{Domain: "localhost", HTTPPort: 443, SMTPPort: 25, SubmissionPort: 587, SubmissionTLSPort: 465, IMAPPort: 993, POP3Port: 995, ManageSievePort: 4190},
		Database: DatabaseConf{Driver: "sqlite", DSN: "data/grmail.db"},
		Auth:     AuthStack{SPFEnabled: true, DKIMEnabled: true, DMARCEnabled: true, ARCEnabled: true},
		Log:      LogConf{Level: "info", SqlSlowMs: 500, LogFileMaxMB: 100, LogFileBackups: 5, LogRetainDays: 30}, // U21/U23 缺省档+L-E 保留窗缺省 30 天（旧 JSON 缺键零值=0 不清理——键存在性不区分，保守侧保留全部）
		Blob:     BlobConf{Dir: "data/blobs"},
		Mail: MailConf{
			MaxMessageSizeBytes: 36700160,                                                                                  // 35MiB（Q2-A 缺省档）
			Delivery:            DeliveryConf{RetryBaseSeconds: 60, RetryFactor: 2, RetryCapSeconds: 3600, MaxAttempts: 8}, // Q5-C 缺省档（候选 A 值）
		},
		TLS:        TLSConf{}, // 零值=未配置（U5 计划书 1.5⑫：TLS 端点跳过+告警）
		CatchAll:   true,
		Session:    SessionConf{IdleMinutes: 30, AbsoluteHours: 12}, // Q7-C：U8 缺省档承接
		LoginLimit: LoginLimitConf{WindowMinutes: 15, Threshold: 5}, // Q7-C：U8 缺省档承接
		ACME: ACMEConf{ // Q5-A：手动模式缺省（Enabled=false）；路径缺省档供向导 ACME 选项预填
			CADirURL:       ACMEDirectoryProduction,
			AccountKeyPath: "data/certs/acme-account.key",
			CertsDir:       "data/certs",
		},
		MTASts: MTAStsConf{ // U13：FR-010「默认启用」（bool 零值 false——旧 JSON 缺节兜底在 Load 处理）
			Enabled:       true,
			Mode:          "enforce",
			MaxAgeSeconds: 604800,
			ReportEnabled: true,
		},
		Editor: EditorConf{ImageMaxEdge: 1920, JpegQuality: 0.85}, // D8#11：U22 既有缺省档承接
	}
}

// Load 从 path 读取配置；文件不存在时返回默认配置（首次运行进入 Setup，FR-015）。
// 参数：path 配置文件路径。返回：解析后的配置指针。
// U13 注：旧 JSON 无 "mtaSts" 键时（反序列化将 Default 的缺省档覆盖为零值——bool 型
// false 与「关闭」语义冲突），按节存在性恢复缺省档（1.5①——沿端口类零值兜底思路，
// bool 型经键集合显式区分缺省与关闭）。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取配置文件: %w", err)
	}
	cfg := Default()
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("解析配置 JSON: %w", err)
	}
	var keyProbe map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keyProbe)
	if _, ok := keyProbe["mtaSts"]; !ok {
		cfg.MTASts = Default().MTASts // 旧格式缺节：恢复默认启用档（FR-010 默认启用锚）
	}
	if cfg.MTASts.Mode != "enforce" && cfg.MTASts.Mode != "testing" {
		cfg.MTASts.Mode = "enforce"
	}
	if cfg.MTASts.MaxAgeSeconds <= 0 || cfg.MTASts.MaxAgeSeconds > 31557600 {
		cfg.MTASts.MaxAgeSeconds = 604800
	}
	return cfg, nil
}

// Save 原子写入配置到 path（临时文件 + rename，崩溃安全；热加载链路第 1 步）。
// 参数：path 目标路径；c 待写入配置。
func Save(path string, c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入临时文件: %w", err)
	}
	return os.Rename(tmp, path)
}

// Subscriber 配置变更订阅者（认证栈/TLS 等组件实现本接口以接收热加载回调）
type Subscriber interface {
	// OnConfigChange 收到新配置时的回调；返回 error 仅记录告警，不中断其他订阅者
	OnConfigChange(newCfg *Config)
}

// Watcher 配置热加载器（fsnotify 监听 + 去抖 + 广播）
type Watcher struct {
	path     string
	mu       sync.RWMutex // 保护 current 与 subs 的并发读写
	current  *Config
	subs     []Subscriber
	fsnotify *fsnotify.Watcher
	debounce *time.Timer
	closed   bool
}

// Watch 启动配置监听：文件变更 → 300ms 去抖 → 解析校验 → 广播订阅者。
// 解析失败时回滚内存态并记录告警（不应用半截配置）。
// 参数：ctx 根上下文（携带 logger）；path 配置路径；initial 初始配置。
func Watch(ctx context.Context, path string, initial *Config) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("创建 fsnotify: %w", err)
	}
	// 监听所在目录而非文件本身：atomic rename 会替换 inode，目录监听才能持续收到事件
	if err := fw.Add(filepath.Dir(path)); err != nil {
		_ = fw.Close()
		return nil, fmt.Errorf("监听配置目录: %w", err)
	}
	w := &Watcher{path: path, current: initial, fsnotify: fw}
	go w.loop(ctx, path)
	return w, nil
}

// loop 事件循环：过滤目标文件事件，去抖后触发重载
func (w *Watcher) loop(ctx context.Context, path string) {
	logger := slog.Default()
	target, _ := filepath.Abs(path)
	for {
		select {
		case event, ok := <-w.fsnotify.Events:
			if !ok {
				return
			}
			eventPath, _ := filepath.Abs(event.Name)
			if eventPath != target || !(event.Has(fsnotify.Write) || event.Has(fsnotify.Create)) {
				continue
			}
			w.scheduleReload(logger)
		case err, ok := <-w.fsnotify.Errors:
			if !ok {
				return
			}
			logger.Error("配置监听异常", "error", err)
		}
	}
}

// scheduleReload 去抖：300ms 内的连续事件（编辑器多次写、原子写双事件）合并为一次重载
func (w *Watcher) scheduleReload(logger *slog.Logger) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if w.debounce != nil {
		w.debounce.Stop()
	}
	w.debounce = time.AfterFunc(300*time.Millisecond, func() {
		if err := w.Reload(); err != nil {
			logger.Error("配置热加载失败，保持内存态不变", "error", err)
		}
	})
}

// Reload 立即重载配置并广播（SIGHUP 手动触发路径同此）
func (w *Watcher) Reload() error {
	fresh, err := Load(w.path)
	if err != nil {
		return err // 失败保持 current 不变（回滚语义）
	}
	w.mu.Lock()
	w.current = fresh
	subs := make([]Subscriber, len(w.subs))
	copy(subs, w.subs)
	w.mu.Unlock()
	for _, s := range subs {
		s.OnConfigChange(fresh) // 单订阅者异常仅告警不中断（见 Subscribe 注释约定）
	}
	slog.Default().Info("配置热加载完成", "path", w.path)
	return nil
}

// Subscribe 注册配置变更订阅者（组件收拢配置重建的统一入口）
func (w *Watcher) Subscribe(s Subscriber) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.subs = append(w.subs, s)
}

// Current 返回当前生效配置的只读快照（禁止调用方缓存后绕过订阅机制）
func (w *Watcher) Current() *Config {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}

// Close 停止监听（幂等）
func (w *Watcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.debounce != nil {
		w.debounce.Stop()
	}
	return w.fsnotify.Close()
}
