#!/usr/bin/env bash
# 构建各平台 agent 二进制到 dist/agent-dist/（供 web 镜像内置"下载部署包"用）。
#
# 用法：bash scripts/build-agent-dist.sh
#   → dist/agent-dist/agent-linux-amd64
#     dist/agent-dist/agent-linux-arm64
#     dist/agent-dist/agent-darwin-arm64
#     dist/agent-dist/agent-darwin-amd64
#     dist/agent-dist/agent-windows-amd64.exe
#
# CI（release 流水线）在构建 web 镜像前调用它；本地想自带二进制也可以先跑一次。
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=dist/agent-dist
mkdir -p "$OUT"

build() {
  echo "  → $OUT/$3"
  GOOS="$1" GOARCH="$2" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/$3" ./cmd/sr
}

echo "== 构建 agent 分发包（web 镜像内置）"
build linux  amd64 agent-linux-amd64
build linux  arm64 agent-linux-arm64
build darwin arm64 agent-darwin-arm64
build darwin amd64 agent-darwin-amd64
build windows amd64 agent-windows-amd64.exe
ls -la "$OUT"
