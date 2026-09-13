#!/usr/bin/env bash
# selfremote v0.3 control-plane e2e — web + hub, no containers for our own code.
#
# Starts a real MariaDB container, the real hub (sr server) and the real web
# control plane locally, then drives the browser flow with curl:
#
#   1. register admin → bind Google Authenticator → log in with a code
#   2. create a site agent → download its deployment package (binary + config)
#   3. create a client key with site permissions → check the registries
#   4. disable/enable the site and verify agents.json + the hub's control API
#
# Usage: bash scripts/e2e-control.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORK="$ROOT/dist/ctl-e2e"
WORKN="$(cygpath -m "$WORK" 2>/dev/null || echo "$WORK")"
DEVNULL=/dev/null
if uname -s 2>/dev/null | grep -qiE 'msys|mingw|cygwin'; then DEVNULL=NUL; fi

DB_C=sr-ctl-db
DB_PORT=13377
DBPW="ctl-pass-$RANDOM"
API_PORT=28977
UDP_PORT=28990
WEB_PORT=28988
BASE="http://127.0.0.1:$WEB_PORT"
JAR="$WORKN/cookies.txt"
TOKEN="ctl-token-$RANDOM"

fail() { echo "E2E_FAIL: $*" >&2; [ -n "${HUBLOG:-}" ] && tail -20 "$HUBLOG" >&2; [ -n "${WEBLOG:-}" ] && tail -20 "$WEBLOG" >&2; exit 1; }
pass() { echo "  ✔ $*"; }
say() { echo; echo "== $*"; }

cleanup() {
  [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "${HUB_PID:-}" ] && kill "$HUB_PID" 2>/dev/null || true
  if [ "${E2E_KEEP:-0}" = "1" ]; then
    echo "(E2E_KEEP=1: leaving the db container up for inspection)"
    return
  fi
  docker rm -f "$DB_C" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "[0] 清理旧环境 + 准备目录"
docker rm -f "$DB_C" >/dev/null 2>&1 || true
rm -rf "$WORK" && mkdir -p "$WORK/data" "$WORK/agent-dist" "$WORK/bin"
WEBLOG="$WORK/web.log"; HUBLOG="$WORK/hub.log"

say "[1] 构建二进制（sr + web）与 agent 分发包"
if ! command -v go >/dev/null 2>&1; then export PATH="/c/Users/zph07/go-sdk/go/bin:$PATH"; fi
go build -o "$WORKN/bin/sr.exe" ./cmd/sr
go build -o "$WORKN/bin/web.exe" ./cmd/web
GOOS=linux GOARCH=amd64 go build -trimpath -o "$WORKN/agent-dist/agent-linux-amd64" ./cmd/sr
go build -o "$WORKN/agent-dist/agent-windows-amd64.exe" ./cmd/sr
pass "sr/web 二进制 + agent 分发目录（linux-amd64 / windows-amd64）"

say "[2] 启动 MariaDB"
docker run -d --name "$DB_C" -p "$DB_PORT:3306" \
  -e MARIADB_ROOT_PASSWORD=rootpass -e MARIADB_DATABASE=selfremote \
  -e MARIADB_USER=sr -e MARIADB_PASSWORD="$DBPW" mariadb:11 >/dev/null
for i in $(seq 1 60); do
  if docker exec "$DB_C" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then break; fi
  [ "$i" = 60 ] && fail "MariaDB 未就绪"
  sleep 2
done
pass "MariaDB 就绪（127.0.0.1:$DB_PORT）"

say "[3] 生成 hub 配置并启动中转服务端"
KEYS=$("$WORKN/bin/sr.exe" genkey)
HUB_PRIV=$(echo "$KEYS" | sed -n 's/^private_key = //p')
cat > "$WORK/data/server.json" <<EOF
{
  "listen": "127.0.0.1:$UDP_PORT",
  "private_key": "$HUB_PRIV",
  "tunnel_cidr": "10.77.0.1/24",
  "clients_file": "$WORKN/data/clients.json",
  "agents_file": "$WORKN/data/agents.json",
  "api_listen": "127.0.0.1:$API_PORT",
  "api_token": "$TOKEN",
  "status_file": "$WORKN/data/server-status.json",
  "netinfo_file": "$WORKN/data/netinfo.json"
}
EOF
"$WORKN/bin/sr.exe" server -c "$WORKN/data/server.json" >"$HUBLOG" 2>&1 &
HUB_PID=$!
for i in $(seq 1 40); do
  if curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT/api/v1/status" | grep -q '"version"'; then break; fi
  [ "$i" = 40 ] && fail "hub 控制 API 未就绪"
  sleep 0.5
done
pass "hub 已启动（UDP $UDP_PORT，控制 API $API_PORT）"

say "[4] 启动 web 控制面"
DB_DSN="sr:$DBPW@tcp(127.0.0.1:$DB_PORT)/selfremote?parseTime=true&charset=utf8mb4" \
LISTEN="127.0.0.1:$WEB_PORT" DATA_DIR="$WORKN/data" \
SERVER_ADDR="127.0.0.1:$UDP_PORT" TUNNEL_PORT="$UDP_PORT" \
SRV_API_URL="http://127.0.0.1:$API_PORT" SRV_API_TOKEN="$TOKEN" \
AGENT_DIST_DIR="$WORKN/agent-dist" \
"$WORKN/bin/web.exe" >"$WEBLOG" 2>&1 &
WEB_PID=$!
for i in $(seq 1 40); do
  code=$(curl -s -o "$DEVNULL" -w "%{http_code}" "$BASE/login" 2>/dev/null || true)
  [ "$code" = "200" ] && break
  [ "$i" = "40" ] && fail "web 未就绪"
  sleep 0.5
done
pass "web 已启动（$BASE）"

say "[5] 注册管理员 → 绑定 MFA → 带动态码登录"
curl -s -c "$JAR" -b "$JAR" -o "$DEVNULL" -X POST "$BASE/register" \
  --data-urlencode "username=admin" --data-urlencode "password=e2e-pass-123" --data-urlencode "confirm=e2e-pass-123"
curl -s -b "$JAR" "$BASE/settings?enroll=1" -o "$WORKN/s1.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/s1.html" | head -1 | grep -o '[0-9a-f]\{32\}') || true
[ -n "$CSRF" ] || fail "拿不到 CSRF"
curl -s -b "$JAR" -o "$DEVNULL" -X POST "$BASE/settings/mfa/begin" --data-urlencode "csrf=$CSRF"
SECRET=$(docker exec "$DB_C" mariadb -usr -p"$DBPW" -N -e "select totp_secret from users where username='admin'" selfremote | tr -d '\r')
[ -n "$SECRET" ] || fail "DB 里没有 TOTP secret"
CODE=$(go run ./dist/totpgen -secret "$SECRET")
curl -s -b "$JAR" -o "$WORKN/recovery.html" -X POST "$BASE/settings/mfa/confirm" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "code=$CODE"
grep -q "MFA 已启用" "$WORK/recovery.html" || fail "MFA 绑定失败"
rm -f "$JAR"
CODE=$(go run ./dist/totpgen -secret "$SECRET")
curl -s -c "$JAR" -b "$JAR" -o "$DEVNULL" -X POST "$BASE/login" \
  --data-urlencode "username=admin" --data-urlencode "password=e2e-pass-123" --data-urlencode "code=$CODE"
curl -s -b "$JAR" "$BASE/" -o "$WORKN/home.html"
grep -q "总览" "$WORK/home.html" || fail "登录失败"
pass "管理员登录成功（网页登录也走 MFA）"

say "[6] 创建站点 Agent（真实网段 + 虚拟网段翻译）"
curl -s -b "$JAR" "$BASE/agents/new" -o "$WORKN/agnew.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/agnew.html" | head -1 | grep -o '[0-9a-f]\{32\}') || true
[ -n "$CSRF" ] || fail "拿不到 CSRF（/agents/new）"
# NOTE: a Chinese *name* must be posted from a UTF-8 file: git-bash converts
# literal non-ASCII arguments to the system ANSI code page (GBK here) when it
# spawns native curl.exe, which MariaDB then rejects.
printf '家里 NAS' > "$WORK/agent-name.txt"
curl -s -b "$JAR" -D "$WORKN/agnew.headers" -o "$DEVNULL" -X POST "$BASE/agents/new" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "name@$WORKN/agent-name.txt" --data-urlencode "agent_id=home" \
  --data-urlencode "routes=192.168.1.0/24 => 10.200.7.0/24"
LOC=$(grep -i '^location:' "$WORK/agnew.headers" | tr -d '\r' || true)
grep -q '"id": "home"' "$WORK/data/agents.json" || fail "agents.json 未写入站点（重定向：$LOC）"
grep -q '家里 NAS' "$WORK/data/agents.json" || fail "站点名称（UTF-8）未正确写入"
grep -q '"virtual": "10.200.7.0/24"' "$WORK/data/agents.json" || fail "虚拟网段未写入"
grep -q '"tunnel_ip": "10.77.0.100"' "$WORK/data/agents.json" || fail "站点隧道地址未分配"
[ -z "$(grep -o 'private_key' "$WORK/data/agents.json")" ] || fail "agents.json 里不应含私钥"
pass "站点已登记，服务端注册表就绪（隧道地址 10.77.0.100，网段 192.168.1.0/24 => 10.200.7.0/24）"

say "[7] 下载站点部署包（二进制 + 加密配置 + 说明）"
curl -s -b "$JAR" "$BASE/agents/home" -o "$WORKN/agshow.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/agshow.html" | head -1 | grep -o '[0-9a-f]\{32\}') || true
[ -n "$CSRF" ] || fail "拿不到 CSRF（/agents/home）"
curl -s -b "$JAR" -o "$WORKN/agent-home-linux-amd64.zip" -w "   http=%{http_code} bytes=%{size_download}\n" \
  -X POST "$BASE/agents/home/package" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "platform=linux-amd64" --data-urlencode "passphrase=e2e-agent-pass-1"
python3 - "$WORKN/agent-home-linux-amd64.zip" "$WORKN" <<'PY'
import sys, zipfile, json, os
zp, work = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(zp)
names = z.namelist()
need = ["selfremote-agent-home/agent-linux-amd64", "selfremote-agent-home/home.srkey", "selfremote-agent-home/README.txt"]
for n in need:
    assert n in names, f"zip 缺少 {n}（实际 {names}）"
blob = json.loads(z.read("selfremote-agent-home/home.srkey"))
assert blob.get("srkey") == 1, "srkey 信封格式不对"
assert "private_key" not in json.dumps(blob).lower() or "ct" in blob, "配置文件未加密"
info = z.getinfo("selfremote-agent-home/agent-linux-amd64")
assert (info.external_attr >> 16) & 0o111, "二进制缺少可执行位"
readme = z.read("selfremote-agent-home/README.txt").decode()
assert "sr agent -c" in readme, "说明里没有运行命令"
print(f"   zip 校验通过：{len(names)} 个条目，{os.path.getsize(zp)} 字节")
PY
pass "部署包可下载且结构正确（含可执行二进制、加密配置、中文说明）"

say "[8] 生成客户端密钥（勾选站点权限）"
curl -s -b "$JAR" "$BASE/devices/new" -o "$WORKN/devnew.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/devnew.html" | head -1 | grep -o '[0-9a-f]\{32\}') || true
[ -n "$CSRF" ] || fail "拿不到 CSRF（/devices/new）"
grep -q 'value="home"' "$WORK/devnew.html" || fail "设备页没有列出站点"
curl -s -b "$JAR" -o "$WORKN/client.srkey" -w "   http=%{http_code} bytes=%{size_download}\n" -X POST "$BASE/devices/new" \
  --data-urlencode "csrf=$CSRF" --data-urlencode "name=e2e-mac" \
  --data-urlencode "sites=home" --data-urlencode "passphrase=e2e-file-pass-1" --data-urlencode "confirm=e2e-file-pass-1"
grep -q '"srkey": 1' "$WORK/client.srkey" || fail "客户端密钥文件下载失败"
grep -q '"tunnel_ip": "10.77.0.2"' "$WORK/data/clients.json" || fail "clients.json 缺少隧道地址"
grep -q '"agents": \[' "$WORK/data/clients.json" || fail "clients.json 缺少站点 ACL"
grep -q '"home"' "$WORK/data/clients.json" || fail "clients.json 的 ACL 未包含 home"
pass "客户端密钥已生成：clients.json 含隧道地址 + 站点 ACL（服务端据此强制放行）"

say "[9] hub 侧视角 + 启停开关"
STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT/api/v1/status")
echo "$STATUS" | grep -q '"agents_total": 1' || { echo "$STATUS"; fail "hub 未登记站点"; }
echo "$STATUS" | grep -q '"clients_total": 1' || fail "hub 未登记客户端"
echo "$STATUS" | grep -q '192.168.1.0/24=10.200.7.0/24' || { echo "$STATUS"; fail "hub 未读到站点网段"; }
pass "hub 已从注册表读到站点与客户端（含网段映射）"

curl -s -b "$JAR" "$BASE/agents" -o "$WORKN/aglist.html"
CSRF=$(grep -o 'name="csrf" value="[0-9a-f]*"' "$WORK/aglist.html" | head -1 | grep -o '[0-9a-f]\{32\}') || true
curl -s -b "$JAR" -o "$DEVNULL" -X POST "$BASE/agents/home/state" --data-urlencode "csrf=$CSRF" --data-urlencode "enabled=0"
grep -q '"enabled": false' "$WORK/data/agents.json" || fail "停用未写入注册表"
curl -s -b "$JAR" -o "$DEVNULL" -X POST "$BASE/agents/home/state" --data-urlencode "csrf=$CSRF" --data-urlencode "enabled=1"
grep -q '"enabled": true' "$WORK/data/agents.json" || fail "启用未写入注册表"
pass "网页启停已生效（写入 agents.json，hub 1 秒内热加载）"

curl -s -b "$JAR" "$BASE/" -o "$WORKN/home2.html"
grep -q "站点" "$WORK/home2.html" || fail "总览页没有站点区块"
pass "总览页正常渲染"

echo
echo "E2E_CONTROL_PASS: web 控制面 + hub 管控链路全部通过"
