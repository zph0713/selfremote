#!/bin/sh
# selfremote 全家桶初始化 v0.3（幂等）：生成中转服务端配置 + 控制面令牌。
#
# 用法：bash init.sh [数据目录]      （默认 ./data，应等于 .env 的 SR_CONFIG_DIR）
# 环境变量（可选）：
#   SR_IMAGE      镜像名（默认 ghcr.io/zph0713/selfremote:latest）
#   TUNNEL_PORT   中转服务端 UDP 端口（默认 28333）
#   API_PORT      控制 API 端口（默认 8770，只给控制面容器用，不要对公网开放）
set -e

DIR="${1:-./data}"
PORT="${TUNNEL_PORT:-28333}"
APIPORT="${API_PORT:-8770}"
IMG="${SR_IMAGE:-ghcr.io/zph0713/selfremote:latest}"

mkdir -p "$DIR"

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
  echo "  服务端公钥（控制面会自动带进客户端/站点配置）: $PUB"
  echo "  控制 API：容器内 http://server:$APIPORT （令牌在 $DIR/api-token；只应在内网可达）"
fi

echo
echo "== 下一步"
echo "  1) docker compose up -d            # 起 db / web / nginx / server"
echo "  2) 打开 http://<主机>:8080 注册管理员并绑定 Google Authenticator"
echo "  3) 「站点 Agent」→ 添加站点（例如 id=home，网段填本机内网 192.168.1.0/24）"
echo "  4) 下载部署包（Linux 容器方式），把包里的 <站点id>.srkey 放到 $DIR/agent-home.srkey"
echo "     （示例用 id=home；文件密码设为 .env 的 SR_AGENT_KEYPASS）"
echo "  5) docker compose up -d agent-home  # 本机站点上线，网页状态变「在线」"
echo
echo "  远程站点：同样在网页创建，把部署包拷到那台机器运行即可（只需出站 UDP）。"
