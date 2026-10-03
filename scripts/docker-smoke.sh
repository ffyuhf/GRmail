#!/usr/bin/env bash
# GRmail Docker 冒烟脚本（U11 Q4-A/TC-026 判定：镜像可运行+健康检查）
# 流程：构建镜像→起容器（SQLite 模式）→HTTP 80 探测（Setup 引导态 302→/setup/1）→清理
# 用法：cd server && bash scripts/docker-smoke.sh
# 修改历史：
#   2026-09-20 06:03:00 | 新建 | U11 三库验收（计划书步骤 8）
set -euo pipefail

IMAGE="grmail-smoke:test"
CONTAINER="grmail-smoke"

echo "[1/4] 构建镜像 ${IMAGE} ..."
docker build -t "${IMAGE}" .

echo "[2/4] 君起容器（SQLite 模式，data 卷承载）..."
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER}" -p 18080:80 "${IMAGE}" >/dev/null

cleanup() { docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[3/4] HTTP 80 健康探测（U10 setupGate：引导态业务路径 302→/setup/1）..."
ok=0
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:18080/" || true)
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 2 "http://127.0.0.1:18080/" || true)
  if [ "${code}" = "302" ] && [[ "${loc}" == *"/setup/1"* ]]; then ok=1; break; fi
  sleep 1
done
if [ "${ok}" != "1" ]; then
  echo "冒烟失败：80 探测未达预期（code=${code} loc=${loc}）"; docker logs "${CONTAINER}" | tail -20; exit 1
fi
echo "  探测通过：GET / → 302 ${loc}"

echo "[4/4] 容器日志无致命错误 ..."
docker logs "${CONTAINER}" 2>&1 | grep -iE "fatal|panic" && { echo "发现致命日志"; exit 1; } || true
echo "Docker 冒烟通过（TC-026 健康检查半场）"
