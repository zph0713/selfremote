#!/bin/sh
# selfremote 网关初始化（幂等）：生成 gateway.json（网关密钥 + Web 集成路径）。
#
# 用法：bash init.sh [数据目录]     （默认 ./data，应与 .env 的 SR_CONFIG_DIR 一致）
# 环境变量（可选）：SR_IMAGE（镜像名，默认 ghcr.io/zph0713/selfremote:latest）、TUNNEL_PORT（网关 UDP 端口，默认 28333）
set -e

DIR="${1:-./data}"
PORT="${TUNNEL_PORT:-28333}"
IMG="${SR_IMAGE:-ghcr.io/zph0713/selfremote:latest}"

mkdir -p "$DIR"

if [ -f "$DIR/gateway.json" ]; then
  echo "已存在，跳过：$DIR/gateway.json"
  exit 0
fi

echo "== 使用镜像 $IMG 生成网关密钥…"
KEYS=$(docker run --rm "$IMG" genkey)
PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^private_key = //p')
PUB=$(printf '%s\n' "$KEYS" | sed -n 's/^public_key  = //p')
if [ -z "$PRIV" ]; then
  echo "错误：genkey 失败（镜像可用吗？）" >&2
  exit 1
fi

cat > "$DIR/gateway.json" <<EOF
{
  "listen": "[::]:$PORT",
  "private_key": "$PRIV",
  "tunnel_cidr": "10.77.0.1/24",
  "peers": [],
  "clients_file": "/etc/selfremote/clients.json",
  "status_file": "/etc/selfremote/status.json",
  "netinfo_file": "/etc/selfremote/netinfo.json"
}
EOF
chmod 600 "$DIR/gateway.json"

echo "已生成 $DIR/gateway.json"
echo "  网关公钥（无需手动分发，控制面会自动带进客户端配置）: $PUB"
echo "  客户端白名单由 Web 控制面维护（clients.json），有 MFA 的动态码校验"
