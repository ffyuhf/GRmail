# GRmail 邮件服务器

> 单二进制 Go 自托管邮箱服务器：单管理员拥有无限独立邮箱账号，未注册地址来信自动进入影子邮箱并可在注册后继承，全栈标准协议合规，Webmail 登录具备可选双因素防护（TOTP），扩展能力经 go-plugin 插件系统承载。

## 功能特性

- **邮件协议**：SMTP 收发（25 收信 / 465/587 提交投递）、IMAP4rev2（993，含 IDLE）、POP3（995，明文连接拒绝认证）、ManageSieve（4190）
- **认证反伪造**：SPF / DKIM / DMARC / ARC 四项验证 + Authentication-Results 头（rfc8601）；出站 DKIM 签名
- **传输安全**：全协议端点 TLS（STARTTLS 与隐式，TLS1.3）、MTA-STS 策略发布与发送侧验证、TLS-RPT 报告、DANE/TLSA（DNSSEC 不可用自动降级）
- **账号模型**：独立邮箱账号、管理员任意地址发信、catch-all 聚合、影子邮箱（未注册来信按址归档，注册激活后原地继承历史邮件，聚合文件夹可直接巡览）
- **Webmail**：templ + HTMX 服务端渲染——邮件列表 / 富文本写信（Quill）/ 附件与 CID 内联 / 关键词搜索 / 批量操作 / 暗色模式 / 中英双语 / 移动端适配 / 双因素认证（TOTP + 二维码 + 一次性恢复码 + 管理员强制策略）
- **过滤规则**：Sieve 脚本引擎（rfc5228）+ Web 脚本编辑器 + ManageSieve 远程管理
- **插件系统**：HashiCorp go-plugin 多进程契约（收信 / 发信双钩子链，插件崩溃不影响主程序）
- **存储与部署**：SQLite（内置默认）/ MySQL / PostgreSQL 三库适配；Setup 六步向导 + ACME 自动证书（HTTP-01 / DNS-01 Cloudflare）；config.json 热加载
- **可观测性**：LogID 全链路日志、SQL 慢查询观测、日志文件按日切分压缩

## 快速开始

### 方式一：发布产物

从 [GitHub Releases](../../releases) 下载对应平台 tar.gz，解包得到单二进制：

```sh
tar -xzf mail-server-linux-amd64.tar.gz
./mail-server
```

浏览器访问 `http://<主机>/` 进入 Setup 向导（数据库 → 管理员密码 → 域名 → DNS 建议 → SSL 模式 → 完成），全程无需手工编辑配置文件。

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
make build          # 本地构建（版本标识=dev+短提交哈希+构建时间）
make release VERSION=v1.0.0   # 五平台交叉构建+tar.gz+SHA256SUMS（dist/）
```

## 版本查询

```sh
./mail-server --version
# GRmail v1.0.0 (commit=a1b2c3d built=2026-10-03T17:00:00+08:00)
```

版本三元组经构建注入：tag 构建（CI 推送 `v*` 标签自动触发）注入 tag 名；无标签构建使用 `dev` / 短提交哈希 / 构建时间标识。

## CI 与发布

`.github/workflows/release.yml`：

- **tag 推送**（`v*` 前缀）→ 五平台交叉构建（linux/amd64、linux/arm64、windows/amd64、darwin/amd64、darwin/arm64）→ 版本注入抽检 → tar.gz + SHA256SUMS 自动发布至 GitHub Release 页（自动生成发布说明）
- **手动触发**（workflow_dispatch）→ 验证构建（`dev-<短哈希>` 标识，产物不发布）

误发布处置：删除 GitHub Release 条目与对应 tag 即可，重新推送 tag 会重新构建发布。

## 开发工作流

```sh
make generate        # 聚合代码生成：sqlc（SQL→Go）+ templ（模板→Go）
go generate ./...    # 单命令再生成 templ 产物（//go:generate 锚——web/templates/tr.go）
make generate-templ  # templ 单独再生成
templ watch          # 开发期常驻监听自动再生成（须另装 templ CLI；可选）
make test            # 全量测试（17 包）
make test-threedb    # 三库集成实测（MySQL/PostgreSQL 经 compose，未就绪自动跳过）
make smoke           # Docker 镜像冒烟（构建→运行→健康探测→清理）
```

> templ 生成物（`*_templ.go`）已入库——克隆后可直接构建，无需安装 templ 工具链；修改 `.templ` 模板后经上述任一通道再生成并提交。

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

## 许可与文档

项目过程文档（需求基线 / 设计物 / 模块变更记录）位于 [`项目文档/`](../项目文档/) 目录。
