#!/bin/sh
# selfremote 全家桶初始化 v0.4（幂等）：一次把中转服务端 + 本机站点都准备好。
#
# 用法：bash init.sh [数据目录]      （默认 ./data，应等于 .env 的 SR_CONFIG_DIR）
# 环境变量（可选）：
#   SR_IMAGE        镜像名（默认 ghcr.io/zph0713/selfremote:latest）
#   TUNNEL_PORT     中转服务端 UDP 端口（默认 28333）
#   API_PORT        控制 API 端口（默认 8770，只给控制面容器用）
#   LAN_CIDRS       本机站点要开放的网段（逗号分隔，默认 192.168.1.0/24）
#   HOME_SITE_ID    本机站点的 agent id（默认 home）
#   HOME_SITE_NAME  本机站点显示名（默认「本机站点」）
#   AGENT_SERVER    本机站点回连服务端的地址（默认 127.0.0.1:$TUNNEL_PORT）
set -e

DIR="${1:-./data}"
PORT="${TUNNEL_PORT:-28333}"
APIPORT="${API_PORT:-8770}"
IMG="${SR_IMAGE:-ghcr.io/zph0713/selfremote:latest}"
LAN="${LAN_CIDRS:-192.168.1.0/24}"
SITE_ID="${HOME_SITE_ID:-home}"
SITE_NAME="${HOME_SITE_NAME:-本机站点}"
AGENT_SERVER="${AGENT_SERVER:-127.0.0.1:$PORT}"

mkdir -p "$DIR/preprovision"

if [ -f "$DIR/server.json" ]; then
  echo "已存在，跳过：$DIR/server.json"
else
  echo "== 使用镜像 $IMG 生成中转服务端密钥…"
  KEYS=$(docker run --rm "$IMG" genkey)
  PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^private_key = //p')
  PUB=$(printf '%s\n' "$KEYS" | sed -n 's/^public_key  = //p')
  if [ -z "$PRIV" ]; then
    echo "错误：genkey 失败（镜像可用吗？）" >&2
    exit 1
  fi
  TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')

  cat > "$DIR/server.json" <<EOF
{
  "listen": "[::]:$PORT",
  "private_key": "$PRIV",
  "public_key": "$PUB",
  "tunnel_cidr": "10.77.0.1/24",
  "clients_file": "/etc/selfremote/clients.json",
  "agents_file": "/etc/selfremote/agents.json",
  "api_listen": "0.0.0.0:$APIPORT",
  "api_token": "$TOKEN",
  "status_file": "/etc/selfremote/server-status.json",
  "netinfo_file": "/etc/selfremote/netinfo.json"
}
EOF
  chmod 600 "$DIR/server.json"
  printf '%s' "$TOKEN" > "$DIR/api-token"
  chmod 600 "$DIR/api-token"
  echo "已生成 $DIR/server.json 与 $DIR/api-token"
fi

# ---- 本机站点（agent-home）：初次部署就和 server/web 一起装好 -----------------
if [ -f "$DIR/agent-home.json" ]; then
  echo "已存在，跳过：$DIR/agent-home.json"
else
  echo "== 预置本机站点（$SITE_ID，网段 $LAN）…"
  SKEYS=$(docker run --rm "$IMG" genkey)
  SPRIV=$(printf '%s\n' "$SKEYS" | sed -n 's/^private_key = //p')
  SPUB=$(printf '%s\n' "$SKEYS" | sed -n 's/^public_key  = //p')
  HUBPUB=$(sed -n 's/.*"public_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DIR/server.json" | head -1)
  if [ -z "$HUBPUB" ]; then
    # 老版本 server.json 没写 public_key：从私钥推一遍
    HUBPUB=$(docker run --rm -v "$(cd "$DIR" && pwd):/etc/selfremote" "$IMG" pubkey -c /etc/selfremote/server.json)
  fi
  if [ -z "$SPRIV" ] || [ -z "$HUBPUB" ]; then
    echo "警告：本机站点预置失败（缺密钥），稍后可在网页上手工创建站点" >&2
  else
    ROUTES_JSON=""
    for c in $(printf '%s' "$LAN" | tr ',' ' '); do
      [ -n "$ROUTES_JSON" ] && ROUTES_JSON="$ROUTES_JSON,"
      ROUTES_JSON="$ROUTES_JSON
    { \"real\": \"$c\" }"
    done
    cat > "$DIR/agent-home.json" <<EOF
{
  "id": "$SITE_ID",
  "name": "$SITE_NAME",
  "server": "$AGENT_SERVER",
  "private_key": "$SPRIV",
  "server_public_key": "$HUBPUB",
  "tunnel_cidr": "10.77.0.100/24",
  "routes": [$ROUTES_JSON
  ]
}
EOF
    chmod 600 "$DIR/agent-home.json"
    printf '{\n  "agent_id": "%s",\n  "name": "%s",\n  "public_key": "%s",\n  "tunnel_ip": "10.77.0.100",\n  "routes": [%s\n  ],\n  "enabled": true\n}\n' \
      "$SITE_ID" "$SITE_NAME" "$SPUB" "$ROUTES_JSON" > "$DIR/preprovision/$SITE_ID.site.json"
    chmod 600 "$DIR/preprovision/$SITE_ID.site.json"
    echo "已生成 $DIR/agent-home.json 与 $DIR/preprovision/$SITE_ID.site.json"
  fi
fi

echo
echo "== 下一步"
echo "  1) docker compose up -d          # 起 db / web / nginx / server / agent-home"
echo "  2) 打开 http://<主机>:8080 注册管理员并绑定 Google Authenticator"
echo "     （注册完成的一刻，本机站点会自动挂到你名下并显示「在线」）"
echo "  3) 「客户端密钥」→ 生成密钥（勾选站点）→ 在客户端机器上运行"
echo
echo "  远程站点：目标机器上执行一行命令即可（安装码在网页「站点 Agent」页）："
echo "     curl -fsSL http://<控制面>:8080/install.sh | sudo bash -s -- --code XXXX-XXXX"
