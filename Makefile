# GRmail 构建入口
# 修改历史：
#   2026-09-16 04:32:00 | 新建 | U1 工程骨架（CON-001 单二进制构建目标）
#   2026-09-20 06:04:00 | 扩展 | U11 三库验收（smoke 目标——TC-026 Docker 冒烟 Q4-A）
#   2026-09-24 11:07:00 | 扩展 | U15 插件系统（build-plugin/generate-proto 两目标——Q4-A/1.5⑤⑧）
#   2026-09-27 05:43:00 | 扩展 | U20 Docker 交付优化（release 增 tar.gz 打包+SHA256SUMS 产物清单——Q1-A）
#   2026-10-03 17:14:00 | 扩展 | 发布准备批次：①LDFLAGS 版本参数化（VERSION ?= dev——
#   CI tag 构建注入 tag 名，本地零参数缺省 dev；无标签标识=dev+短哈希+构建时间）
#   ②generate-templ 细分目标+三通道注记（make generate / go generate ./... / templ watch）
#   （依据：发布准备计划书 v1.0.0 1.2-GA/MF 组，G2 批准 2026-10-03 17:09:00）

BINARY  := mail-server
PKG     := GRmail
# 版本标识（发布准备批次）：?= 三态注入——CI tag 构建传 `make release VERSION=v1.0.0`；
# 无标签构建（本地/dispatch 验证）缺省 dev；gitCommit/buildTime 保持既有注入形态
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.gitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.buildTime=$(shell date -Iseconds)

# 构建：单二进制（Web 资源经 embed 进产物）
.PHONY: build
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/mail-server

# 代码生成：sqlc（SQL→Go）与 templ（模板→Go）
# templ 生成三通道（发布准备批次注记）：①make generate（本聚合目标）②go generate ./...
# （//go:generate 锚承载于 web/templates/tr.go——单命令全量再生成）③templ watch
# （开发期常驻监听自动再生成——须另装 templ CLI）；生成物入库形态不变，CI 直接构建
.PHONY: generate
generate:
	sqlc generate
	templ generate

# templ 生成细分目标（.templ → *_templ.go——单独再生成通道；与 go generate ./... 等价面）
.PHONY: generate-templ
generate-templ:
	templ generate

# 数据库迁移（开发期手动执行；运行期由程序内嵌自动执行）
.PHONY: migrate-sqlite
migrate-sqlite:
	goose -dir migrations/sqlite sqlite3 "data/grmail.db" up

# 测试
.PHONY: test
test:
	go test ./...

# 构建示例插件（U15：TC-016 判定①载体——产物置 plugins/（SRS 第 6 章部署形态）；
# 主程序产物保持单二进制不受影响（CON-001——独立构建目标不并入）
.PHONY: build-plugin
build-plugin:
	go build -trimpath -o plugins/example-plugin ./cmd/example-plugin

# proto 生成（U15：插件 gRPC 契约——生成物入库 CI 免装 protoc；
# 本地再生成需 protoc+protoc-gen-go+protoc-gen-go-grpc（PATH 含 $(go env GOPATH)/bin））
.PHONY: generate-proto
generate-proto:
	protoc --go_out=. --go_opt=module=GRmail --go-grpc_out=. --go-grpc_opt=module=GRmail proto/grmail_plugin.proto

# Docker 冒烟（NFR-013/TC-026：镜像构建→运行→80 健康探测→清理——Q4-A 本地实录）
.PHONY: smoke
smoke:
	bash scripts/docker-smoke.sh

# 三库集成实测（FR-014/TC-014：compose 起库后执行——Q3-A；MySQL/PG 未就绪自动跳过真库格）
.PHONY: test-threedb
test-threedb:
	go test ./internal/storage/ -run "TestU11(SQLite|MySQL|Postgres)Integration" -v -timeout 180s

# 交叉构建矩阵（NFR-013：Linux amd64/arm64、Windows、macOS）
# U20：构建后逐平台 tar.gz 发布打包+SHA256SUMS 清单（发布形态——运行时部署物仍单二进制
# CON-001：解包即得裸二进制；裸二进制与 tar.gz 并存，SHA256SUMS 仅覆盖 tar.gz——Q1-A）
.PHONY: release
release:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64       ./cmd/mail-server
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64       ./cmd/mail-server
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/mail-server
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64      ./cmd/mail-server
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64      ./cmd/mail-server
	tar -czf dist/$(BINARY)-linux-amd64.tar.gz   -C dist $(BINARY)-linux-amd64
	tar -czf dist/$(BINARY)-linux-arm64.tar.gz   -C dist $(BINARY)-linux-arm64
	tar -czf dist/$(BINARY)-windows-amd64.tar.gz -C dist $(BINARY)-windows-amd64.exe
	tar -czf dist/$(BINARY)-darwin-amd64.tar.gz  -C dist $(BINARY)-darwin-amd64
	tar -czf dist/$(BINARY)-darwin-arm64.tar.gz  -C dist $(BINARY)-darwin-arm64
	cd dist && sha256sum *.tar.gz > SHA256SUMS
