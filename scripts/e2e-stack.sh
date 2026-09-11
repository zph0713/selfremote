#!/usr/bin/env bash
# selfremote 全家桶 e2e：Docker Compose 栈 + Web 全流程 + 客户端真实连接（含 MFA）+ 吊销验证
#
# 覆盖：nginx 反代 → web 注册/绑定 MFA/登录 → 生成加密密钥下载 →
#       clients.json → 客户端容器（.srkey + 动态码）连接 → 隧道 ping 内网设备
#       → Web 吊销 → 网关踢下线
#
# 用法：bash scripts/e2e-stack.sh
#
# 注意（Windows/git-bash）：面向 docker.exe / curl.exe 这些原生程序的路径
# 必须用 cygpath -m 的正斜杠形式（C:/...），MSYS 形式的 /c/... 会被转换坏。
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

PROJ=srstack
HTTP_PORT=8081
TUNNEL_PORT=28400
IMG=selfremote:e2e-stack
WEBIMG=selfremote-web:e2e-stack
WORK="$ROOT/dist/stack-e2e"
WORKN="$(cygpath -m "$WORK" 2>/dev/null || echo "$WORK")"   # native path for docker/curl
# curl.exe 在 git-bash 下写 /dev/null 会报 write error（exit 23），Windows 用 NUL
DEVNULL=/dev/null
if uname -s 2>/dev/null | grep -qiE 'msys|mingw|cygwin'; then DEVNULL=NUL; fi
BASE="http://127.0.0.1:$HTTP_PORT"
JAR="$WORKN/cookies.txt"
DBPW="app-$RANDOM"
GWC="$PROJ-gateway-1"
DBC="$PROJ-db-1"

say() { echo; echo "== $*"; }

say "[0] 清理旧环境"
docker rm -f sr-stack-cl sr-stack-lan >/dev/null 2>&1 || true
# 注意：down -v 必须也能通过 compose 的变量替换（缺 DB_ROOT_PASSWORD/DB_PASSWORD 会静默失败，
# 导致 db 数据卷残留 → MariaDB 沿用旧密码初始化 → web 连库被拒）
DB_ROOT_PASSWORD=cleanup DB_PASSWORD=cleanup \
  docker compose -p "$PROJ" -f deploy/stack/docker-compose.yml -f deploy/stack/docker-compose.desktop.yml down -v >/dev/null 2>&1 || true

say "[1] 构建镜像（网关 + web 控制面）"
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/sr-linux-amd64 ./cmd/sr
docker build -q -f deploy/nas/Dockerfile.prebuilt -t "$IMG" .
docker build -q -f deploy/stack/web.Dockerfile -t "$WEBIMG" .

say "[2] 准备数据目录与 .env"
rm -rf "$WORK" && mkdir -p "$WORK/data"
cat > "$WORK/.env" <<EOF
DB_ROOT_PASSWORD=root-$RANDOM
DB_PASSWORD=$DBPW
SR_CONFIG_DIR=$WORKN/data
HTTP_PORT=$HTTP_PORT
TUNNEL_PORT=$TUNNEL_PORT
SERVER_ADDR=host.docker.internal:$TUNNEL_PORT
LAN_CIDRS=192.168.99.0/24
SR_IMAGE=$IMG
SR_WEB_IMAGE=$WEBIMG
EOF
TUNNEL_PORT=$TUNNEL_PORT SR_IMAGE=$IMG bash deploy/stack/init.sh "$WORK/data"

say "[3] compose up（nginx + web + mariadb + gateway）"
docker compose -p "$PROJ" --env-file "$WORKN/.env" \
  -f deploy/stack/docker-compose.yml -f deploy/stack/docker-compose.desktop.yml up -d --quiet-pull
for i in $(seq 1 60); do
  code=$(curl -s -o "$DEVNULL" -w "%{http_code}" "$BASE/login" 2>/dev/null || true)
  [ "$code" = "200" ] && { echo "   web 就绪（经 nginx，尝试 $i 次）"; break; }
  [ "$i" = "60" ] && { echo "错误：web 未就绪"; docker logs "${PROJ}-web-1" 2>&1 | tail -20; exit 1; }
  sleep 2
done

say "[4] Web 流程：注册管理员 → 绑定 MFA"
curl -s -c "$JAR" -b "$JAR" -o "$DEVNULL" -X POST "$BASE/register" \
  --data-urlencode "username=admin" --data-urlencode "password=e2e-pass-123" --data-urlencode "confirm=e2e-pass-123"
curl -s -b "$JAR" "$BASE/settings?enroll=1" -o "$WORKN/s1.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/s1.html" | head -1 | grep -o '[0-9a-f]\{32\}')
[ -n "$CSRF" ] || { echo "错误：拿不到 CSRF"; exit 1; }
curl -s -b "$JAR" -o "$DEVNULL" -X POST "$BASE/settings/mfa/begin" --data-urlencode "csrf=$CSRF"
SECRET=$(docker exec "$DBC" mariadb -usr -p"$DBPW" -N -e "select totp_secret from users where username='admin'" selfremote | tr -d '\r')
[ -n "$SECRET" ] || { echo "错误：DB 里没有 TOTP secret"; exit 1; }
CODE=$(go run ./dist/totpgen -secret "$SECRET")
curl -s -b "$JAR" -o "$WORKN/recovery.html" -X POST "$BASE/settings/mfa/confirm" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "code=$CODE"
grep -q "MFA 已启用" "$WORK/recovery.html" || { echo "错误：MFA 绑定失败"; exit 1; }
echo "   MFA 绑定成功（恢复码已生成）"

say "[5] 用动态码重新登录 → 生成客户端密钥"
rm -f "$JAR"
CODE=$(go run ./dist/totpgen -secret "$SECRET")
curl -s -c "$JAR" -b "$JAR" -o "$DEVNULL" -X POST "$BASE/login" \
  --data-urlencode "username=admin" --data-urlencode "password=e2e-pass-123" --data-urlencode "code=$CODE"
curl -s -b "$JAR" "$BASE/devices/new" -o "$WORKN/devnew.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/devnew.html" | head -1 | grep -o '[0-9a-f]\{32\}')
curl -s -b "$JAR" -o "$WORKN/client.srkey" -w "   http=%{http_code} bytes=%{size_download}\n" -X POST "$BASE/devices/new" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "name=e2e-mac" \
  --data-urlencode "passphrase=e2e-file-pass-1" --data-urlencode "confirm=e2e-file-pass-1"
grep -q '"srkey": 1' "$WORK/client.srkey" || { echo "错误：密钥文件下载失败"; exit 1; }
echo "   clients.json:"; cat "$WORK/data/clients.json"; echo

say "[6] 客户端容器连接（.srkey 解密 + 动态码）"
sleep 3   # 等网关热加载白名单
CODE=$(go run ./dist/totpgen -secret "$SECRET")
docker run -d --name sr-stack-cl \
  --add-host host.docker.internal:host-gateway \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -e SR_KEYPASS=e2e-file-pass-1 -e SR_MFA="$CODE" \
  -v "$WORKN:/work" "$IMG" client -c /work/client.srkey >/dev/null
sleep 5
docker logs sr-stack-cl 2>&1 | tail -6
docker logs sr-stack-cl 2>&1 | grep -q "MFA 验证通过" || { echo "错误：客户端 MFA 连接失败"; exit 1; }

say "[7] 模拟内网设备 + 隧道 ping"
docker run -d --name sr-stack-lan --network bridge --cap-add NET_ADMIN --entrypoint sh "$IMG" \
  -c "ip addr add 192.168.99.5/24 dev eth0 && sleep 3600" >/dev/null
docker exec "$GWC" ip route add 192.168.99.0/24 dev eth0
docker exec sr-stack-cl ping -c 3 -W 3 192.168.99.5
echo "   status.json: $(grep -o '"online": [0-9]*' "$WORK/data/status.json" 2>/dev/null || echo '（待生成）')"

say "[8] Web 吊销 → 网关踢下线"
curl -s -b "$JAR" "$BASE/devices" -o "$WORKN/dev.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/dev.html" | head -1 | grep -o '[0-9a-f]\{32\}')
DEV_ID=$(grep -o 'name="id" value="[0-9]*"' "$WORK/dev.html" | head -1 | grep -o '[0-9]*')
curl -s -b "$JAR" -o "$DEVNULL" -X POST "$BASE/devices/revoke" --data-urlencode "csrf=$CSRF" --data-urlencode "id=$DEV_ID"
sleep 4
docker logs "$GWC" 2>&1 | grep -q "revoked" || { echo "错误：网关未收到吊销"; docker logs "$GWC" 2>&1 | tail -5; exit 1; }
if docker exec sr-stack-cl ping -c 2 -W 2 192.168.99.5 >/dev/null 2>&1; then
  echo "错误：吊销后仍能 ping 通"; exit 1
fi
echo "   吊销生效：连接已断开且不可再用"

echo
echo "== ✅ 全家桶 e2e 全部通过"
echo "   清理：docker compose -p $PROJ -f deploy/stack/docker-compose.yml -f deploy/stack/docker-compose.desktop.yml down -v && docker rm -f sr-stack-cl sr-stack-lan"
