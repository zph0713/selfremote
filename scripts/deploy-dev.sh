#!/usr/bin/env bash
# 一键部署「开发栈」（与正在运行的旧版零共享）。给 AI / 运维直接执行。
#
# 用法：
#   bash scripts/deploy-dev.sh --check     # 只做环境预检，不改任何东西
#   bash scripts/deploy-dev.sh --yes       # 无交互部署（AI 用这个）
#   bash scripts/deploy-dev.sh             # 交互确认后部署
#
# 做的事：
#   1. 预检：docker / compose / 端口 / 磁盘 / 是否已存在同名项目
#   2. 构建 selfremote:dev 与 selfremote-web:dev（无 Go 工具链时改用容器内构建）
#   3. 生成 deploy/stack/.env.dev（随机数据库密码；已存在则复用，不覆盖）
#   4. init.sh 生成 data-dev（独立 hub 密钥、注册表、部署令牌）
#   5. compose up -d db web nginx server（**不起 agent-home**，避免与旧版本机站点抢 sr0/iptables）
#   6. 健康检查，打印访问地址、部署令牌、隔离自检与清理命令
#
# 绝不会：触碰项目 selfremote、push main、打 tag、拉 ghcr :latest、写 deploy/stack/data
set -euo pipefail

YES=0
CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1 ;;
    --check)  CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数: $a" >&2; exit 2 ;;
  esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STACK="$ROOT/deploy/stack"
PROJ=selfremote-dev
OLD_PROJ=selfremote
TUNNEL_PORT=28334
API_PORT=8771
HTTP_PORT=18080
HTTP_ALT_PORT=18081
CS=(-f "$STACK/docker-compose.yml" -f "$STACK/docker-compose.desktop.yml" -f "$STACK/docker-compose.dev.yml")

say() { printf '\n== %s\n' "$*"; }
die() { printf '\n!! %s\n' "$*" >&2; exit 1; }
ok()  { printf '   ok  %s\n' "$*"; }

say "0. 环境预检"
command -v docker >/dev/null || die "没有 docker"
docker info >/dev/null 2>&1 || die "docker 守护进程没运行（先启动 docker）"
docker compose version >/dev/null 2>&1 || die "缺少 docker compose v2 插件"
ok "docker $(docker version --format '{{.Server.Version}}') / compose $(docker compose version --short)"
ok "仓库：$ROOT"
ok "当前分支：$(git -C "$ROOT" rev-parse --abbrev-ref HEAD) @ $(git -C "$ROOT" log -1 --format=%h)"

port_busy() {
  if command -v ss >/dev/null 2>&1; then
    ss -H -lntu 2>/dev/null | grep -qE "[:.]$1[[:space:]]"
  else
    netstat -lntu 2>/dev/null | grep -qE "[:.]$1[[:space:]]"
  fi
}
BUSY=""
for p in "$HTTP_PORT" "$HTTP_ALT_PORT" "$TUNNEL_PORT" "$API_PORT"; do
  port_busy "$p" && BUSY="$BUSY $p"
done
[ -z "$BUSY" ] || die "端口被占用：$BUSY（换个端口或先停占用进程；这是开发栈专用端口，不应与旧版冲突）"
ok "端口 $HTTP_PORT/$HTTP_ALT_PORT/$TUNNEL_PORT/$API_PORT 都空闲"

if docker ps -a --format '{{.Label "com.docker.compose.project"}}' | grep -qx "$OLD_PROJ"; then
  ok "检测到旧版栈（项目 $OLD_PROJ）：本脚本不会触碰它"
fi
if docker ps -a --format '{{.Label "com.docker.compose.project"}}' | grep -qx "$PROJ"; then
  ok "已存在开发栈（项目 $PROJ）：将原地更新，不重新生成密钥"
fi

AVAIL_KB=$(df -Pk "$STACK" | awk 'NR==2{print $4}')
[ "${AVAIL_KB:-0}" -gt 3000000 ] || die "磁盘可用空间不足 3 GB（当前 $((AVAIL_KB/1024)) MB）"
ok "磁盘可用 $((AVAIL_KB/1024)) MB"

if [ "$CHECK_ONLY" = 1 ]; then
  say "预检完成（--check，未做任何改动）"
  exit 0
fi

if [ "$YES" != 1 ]; then
  printf '\n即将构建镜像并在项目 %s 下启动 db/web/nginx/server（不启动 agent-home）。\n' "$PROJ"
  printf '旧版项目 %s 不会被触碰。继续？[y/N] ' "$OLD_PROJ"
  read -r ans
  case "$ans" in y|Y|yes|YES) ;; *) echo "已取消"; exit 1 ;; esac
fi

say "1. 构建镜像（tag :dev，不产生 :latest）"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "不认识的架构：$ARCH" ;;
esac
mkdir -p "$ROOT/dist"
if command -v go >/dev/null 2>&1; then
  ( cd "$ROOT" && GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 \
      go build -trimpath -ldflags "-s -w" -o dist/sr-linux-"$GOARCH" ./cmd/sr )
  ok "本地 go 构建 dist/sr-linux-$GOARCH"
else
  say "   本机没有 go，用容器内 golang:1.27-alpine 构建（首次会拉镜像）"
  docker run --rm -v "$ROOT":/src -w /src -e GOARCH="$GOARCH" golang:1.27-alpine \
    sh -c 'CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o dist/sr-linux-$GOARCH ./cmd/sr'
  ok "容器内构建完成"
fi
# Dockerfile.prebuilt 固定 COPY dist/sr-linux-amd64：arm64 机器补一份同内容的副本
if [ "$GOARCH" != "amd64" ]; then cp "$ROOT/dist/sr-linux-$GOARCH" "$ROOT/dist/sr-linux-amd64"; fi
( cd "$ROOT" && docker build -q -f deploy/nas/Dockerfile.prebuilt -t selfremote:dev . >/dev/null )
ok "镜像 selfremote:dev"
( cd "$ROOT" && docker build -q -f deploy/stack/web.Dockerfile -t selfremote-web:dev . >/dev/null )
ok "镜像 selfremote-web:dev"

say "2. 环境文件 deploy/stack/.env.dev"
ENVF="$STACK/.env.dev"
if [ -f "$ENVF" ]; then
  ok "已存在，复用（不会覆盖你的密码与地址）"
else
  rnd() { if command -v openssl >/dev/null 2>&1; then openssl rand -hex 16; else od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; fi; }
  HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  [ -n "${HOST_IP:-}" ] || HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  [ -n "${HOST_IP:-}" ] || HOST_IP=127.0.0.1
  cat > "$ENVF" <<EOF
# 由 scripts/deploy-dev.sh 生成（$(date -u +%FT%TZ)）
DB_ROOT_PASSWORD=$(rnd)
DB_PASSWORD=$(rnd)
SR_CONFIG_DIR=./data-dev
SR_IMAGE=selfremote:dev
SR_WEB_IMAGE=selfremote-web:dev
HTTP_PORT=$HTTP_PORT
HTTP_ALT_PORT=$HTTP_ALT_PORT
TUNNEL_PORT=$TUNNEL_PORT
API_PORT=$API_PORT
SRV_API_URL=http://host.docker.internal:$API_PORT
SERVER_ADDR=$HOST_IP:$TUNNEL_PORT
LAN_CIDRS=${LAN_CIDRS:-192.168.99.0/24}
COOKIE_SECURE=0
EOF
  chmod 600 "$ENVF"
  ok "已生成（SERVER_ADDR=$HOST_IP:$TUNNEL_PORT；LAN_CIDRS 可改成这台机器真实内网）"
fi

say "3. 生成独立密钥与注册表（data-dev）"
( cd "$STACK" && set -a && . ./.env.dev && set +a && \
  TUNNEL_PORT="$TUNNEL_PORT" API_PORT="$API_PORT" API_BIND=0.0.0.0 \
  SR_IMAGE=selfremote:dev bash init.sh ./data-dev >/dev/null )
ok "data-dev/server.json、data-dev/agent-home.json、data-dev/preprovision 就绪"
[ -f "$STACK/data-dev/bootstrap-token" ] && ok "部署令牌：$STACK/data-dev/bootstrap-token"

say "4. 启动（项目 $PROJ：db web nginx server）"
( cd "$STACK" && docker compose -p "$PROJ" --env-file .env.dev "${CS[@]}" up -d db web nginx server >/dev/null )
ok "容器已启动"

say "5. 健康检查"
CODE=""
for i in $(seq 1 60); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/login" 2>/dev/null || true)
  [ "$CODE" = "200" ] && break
  sleep 2
done
[ "$CODE" = "200" ] || die "控制面 120 s 内没起来；看日志：cd deploy/stack && docker compose -p $PROJ --env-file .env.dev -f docker-compose.yml logs --tail=80 web nginx"
ok "控制面可访问（HTTP 200）"

API_OK=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$API_PORT/api/v1/overview" || true)
[ "$API_OK" = "401" ] && ok "管控 API 正常（无令牌 401，符合预期）" || printf '   warn 管控 API 返回 %s（预期 401）\n' "$API_OK"

say "完成"
cat <<EOF
   控制面   http://<这台机器IP>:$HTTP_PORT
   备用端口 http://<这台机器IP>:$HTTP_ALT_PORT
   隧道     UDP $TUNNEL_PORT（客户端 SERVER_ADDR=$HOST_IP:$TUNNEL_PORT）
   令牌     $STACK/data-dev/bootstrap-token
   注册     → 打开控制面用令牌注册管理员 → 绑定动态码

   隔离自检 bash scripts/check-dev-isolation.sh $OLD_PROJ $PROJ
   停栈     cd deploy/stack && docker compose -p $PROJ --env-file .env.dev -f docker-compose.yml -f docker-compose.desktop.yml down
   删栈     ... 同上加 -v，再 rm -rf data-dev（项目名必须带 $PROJ）

   没有启动 agent-home：验证站点请用另一台 LAN 机器（网页「站点 Agent」生成安装码）。
EOF
