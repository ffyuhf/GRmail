# GRmail 单二进制镜像（U11 Q4-A：多阶段构建——CON-001 embed 自包含）
# 冒烟判定（TC-026）：容器启动→HTTP 80 探测（Setup 未完成态 302→/setup/1）→清理
# 修改历史：
#   2026-09-20 06:02:00 | 新建 | U11 三库验收（计划书步骤 8）
#   2026-09-27 05:43:00 | 扩展 | U20 Docker 交付优化（ldflags 版本三元组注入与 Makefile
#                             #   LDFLAGS 对齐+HEALTHCHECK 健康探测——Q1-A 裁决）

# ── 构建层：Go 工具链编译单二进制 ──
# U20：版本三元组 stage 内 ARG（缺省 unknown 兜底沿 Makefile LDFLAGS 语义——无参构建
# 合法；传值形态：docker build --build-arg VERSION=... --build-arg GIT_COMMIT=...
# --build-arg BUILD_TIME=...）
FROM golang:1.26-alpine AS build
ARG VERSION=unknown
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildTime=${BUILD_TIME}" -o /out/mail-server ./cmd/mail-server

# ── 运行层：最小基底（纯 Go 静态产物，零运行时依赖） ──
FROM alpine:3.20
RUN adduser -D -u 10001 grmail && mkdir -p /app/data && chown -R grmail:grmail /app
WORKDIR /app
COPY --from=build /out/mail-server ./mail-server
# U20：容器健康探测（alpine busybox wget——GET / →302→/setup/1→200 链路健康退出 0；
# start-period 10s 容纳迁移/启动，30s 周期+S4 容器内实测验证锚——计划书 1.5③）
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q --spider http://127.0.0.1/ || exit 1
USER grmail
VOLUME ["/app/data"]
EXPOSE 80 443 25 465 587 993 995
ENTRYPOINT ["./mail-server"]
