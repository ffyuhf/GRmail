<div align="center">

# GRmail

**单二进制 Go 自托管邮件服务器**

SMTP / IMAP4rev2 / POP3 / ManageSieve 全协议合规 · 内置 Webmail · 双因素认证 · Sieve 过滤 · go-plugin 插件系统

> ⚠️ 项目处于测试期。发现任何 BUG，或觉得有问题、用得不舒服，都欢迎来提 Issue。

</div>

---

## 这是什么

GRmail 是一个用 Go 写的自托管邮件服务器，编译后是**单个二进制文件**，不需要额外部署 Web 服务器、数据库服务或进程管理器。

面向想真正掌控自己邮件数据的个人和小团队：

- **单管理员，无限独立邮箱账号**
- **影子邮箱**：未注册地址的来信按址归档，该地址后续注册后可原地继承全部历史邮件，聚合文件夹可直接巡览
- **全栈标准协议合规**，入站四重反伪造验证、出站 DKIM 签名、全端点 TLS
- **Webmail 双因素防护**（TOTP，可选、可强制）
- **go-plugin 多进程插件系统**承载扩展能力

## 功能特性

### 邮件协议
- **SMTP** — 25 收信 / 465、587 提交投递
- **IMAP4rev2** — 993 端口，含 IDLE 推送
- **POP3** — 995 端口，明文连接拒绝认证
- **ManageSieve** — 4190 端口

### 认证与反伪造
- 入站 **SPF / DKIM / DMARC / ARC** 四项验证 + `Authentication-Results` 头（RFC 8601）
- 出站自动 **DKIM 签名**

### 传输安全
- 全协议端点 TLS（STARTTLS + 隐式，TLS 1.3）
- **MTA-STS** 策略发布与发送侧验证
- **TLS-RPT** 报告
- **DANE / TLSA**（DNSSEC 不可用时自动降级）

### 账号模型
- 独立邮箱账号
- 管理员可用任意地址发信
- Catch-all 聚合
- **影子邮箱**：未注册来信按址归档，注册激活后原地继承历史邮件，聚合文件夹可直接巡览

### Webmail（templ + HTMX 服务端渲染）
- 邮件列表 / 富文本写信（Quill）/ 附件与 CID 内联
- 关键词搜索 / 批量操作 / 暗色模式
- 中英双语 / 移动端适配
- **双因素认证**：TOTP + 二维码 + 一次性恢复码 + 管理员强制策略

### 过滤规则
- **Sieve** 脚本引擎（RFC 5228）
- Web 脚本编辑器
- ManageSieve 远程管理

### 插件系统
- HashiCorp **go-plugin** 多进程契约
- 收信 / 发信双钩子链
- 插件崩溃不影响主程序

### 存储与部署
- **SQLite**（内置默认）/ **MySQL** / **PostgreSQL** 三库适配
- Setup 六步向导（数据库 → 管理员密码 → 域名 → DNS 建议 → SSL 模式 → 完成）
- **ACME** 自动证书（HTTP-01 / DNS-01 Cloudflare）
- `config.json` 热加载

### 可观测性
- LogID 全链路日志
- SQL 慢查询观测
- 日志文件按日切分压缩

## 快速开始

### 方式一：发布产物

从 [GitHub Releases](../../releases) 下载对应平台 tar.gz，解包得到单二进制：

```sh
tar -xzf mail-server-linux-amd64.tar.gz
./mail-server
```

浏览器访问 `http://<主机>/` 进入 Setup 向导，全程无需手工编辑配置文件。

### 方式二：Docker

```sh
docker build -t grmail --build-arg VERSION=$(git describe --tags --always) \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
  --build-arg BUILD_TIME=$(date -Iseconds) .
docker run -d -p 80:80 -p 443:443 -p 25:25 -p 465:465 -p 587:587 -p 993:993 -p 995:995 \
  -v grmail-data:/app/data grmail
```

### 方式三：源码构建

```sh
make build          # 本地构建（版本标识 = dev + 短提交哈希 + 构建时间）
make release VERSION=v1.0.0   # 五平台交叉构建 + tar.gz + SHA256SUMS（dist/）
```

### 受限端口环境（-p 参数）

设备无法绑定 80 端口时（容器 PaaS / 非特权用户 / 端口已被占用），用 `-p` 指定 HTTP 明文端口启动：

```sh
./mail-server -p 8080        # Setup 向导监听 8080——浏览器访问 http://<主机>:8080/ 进入向导
```

- `-p` 仅覆盖 HTTP 明文端口（Setup 向导承载 / ACME 挑战直答 / 301 跳转源），仅本次进程生效，不写入 `config.json`（重启无参数即回落 80）
- HTTPS 端口（默认 443）经 `config.json` 的 `server.httpPort` 字段配置
- **ACME 注意**：HTTP-01 挑战要求 CA 连入 80 端口——使用 `-p` 后 HTTP-01 不可用，请在向导 SSL 步选择 DNS-01（Cloudflare）或手动导入证书

## 版本查询

```sh
./mail-server --version
# GRmail v1.0.0 (commit=a1b2c3d built=2026-10-03T17:00:00+08:00)
```

版本三元组经构建注入：tag 构建（CI 推送 `v*` 标签自动触发）注入 tag 名；无标签构建使用 `dev` / 短提交哈希 / 构建时间标识。

## 目录结构

```
server/
├─ cmd/mail-server/     # 入口与装配（main.go/wire.go）
├─ cmd/example-plugin/  # 示例插件（go-plugin 契约四 RPC）
├─ internal/
│  ├─ protocol/         # smtp / imap / pop3 / managesieve / web（Gin+templ+HTMX）
│  ├─ mail/             # 收发管道 / DSN / 防丢信状态机
│  ├─ auth/             # SPF/DKIM/DMARC/ARC 验证与签名
│  ├─ account/          # 邮箱 / 影子邮箱 / 2FA
│  ├─ sieve/            # rfc5228 过滤引擎
│  ├─ plugin/           # go-plugin 宿主
│  ├─ transport/        # TLS / ACME / DANE / MTA-STS / TLS-RPT
│  ├─ storage/          # 三库适配（sqlc + goose + Bob）
│  ├─ config/           # config.json 读写与热加载
│  └─ observability/    # LogID / 日志装配
├─ web/                 # templ 模板与静态资源（embed 进二进制）
├─ migrations/          # goose 迁移（sqlite/mysql/postgres 三目录）
├─ proto/               # 插件 gRPC 契约
├─ Makefile / Dockerfile / sqlc.yaml
```

部署目录形态：`mail-server`（主程序单二进制）+ `config.json`（运行时配置，热加载）+ `plugins/`（插件独立二进制，可选）+ `data/`（数据库与邮件 Blob 存储）。

## 许可证 (后续版本可能调整)

**AGPL-3.0**