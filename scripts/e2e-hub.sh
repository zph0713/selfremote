#!/usr/bin/env bash
# selfremote v0.3 hub end-to-end smoke test — server / agent / client split.
#
# Runs the whole v0.3 topology on ONE machine with REAL TUN devices and REAL
# kernels inside containers:
#
#   client container ──UDP──▶ hub container ──UDP──▶ agent container ──▶ site LAN
#   (10.77.0.2)              (10.77.0.1 virtual)    (10.77.0.101)        (192.168.99.5)
#
# What it proves:
#   1. the hub relays in user space: no TUN, no NET_ADMIN, no kernel forwarding
#   2. the agent dials out (works behind NAT — it listens on nothing)
#   3. BOTH links require MFA; the agent answers by itself from its .srkey
#   4. per-site addressing: the site's 192.168.99.0/24 is presented as
#      10.200.7.0/24 and rewritten at the agent edge (checksums included)
#   5. registry-driven enable/disable takes effect live, plus the control API
#
# Usage: bash scripts/e2e-hub.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORK="$ROOT/dist/e2e-hub"
IMG=selfremote:e2e-hub
PORT=28399
API_PORT=28770
LAN_SUBNET="192.168.99.0/24"
LAN_PREFIX="192.168.99."
LAN_DEVICE="192.168.99.5"
LAN_VIRTUAL="10.200.7.5"
VIRTUAL_CIDR="10.200.7.0/24"
AGENT_SECRET="JBSWY3DPEHPK3PXP"
CLIENT_SECRET="KRSXG5CTMVRXEZLU"
TOKEN="e2e-token-$$"
KPASS="e2e-file-password"
NET_HUB="sr-e2e-hub-net"
NET_LAN="sr-e2e-lan-net"

fail() { echo "E2E_FAIL: $*" >&2; exit 1; }
pass() { echo "  ✔ $*"; }

cleanup() {
  if [ "${E2E_KEEP:-0}" = "1" ]; then
    echo "(E2E_KEEP=1: leaving containers and networks up for inspection)"
    return
  fi
  docker rm -f sr-hub sr-agent sr-client sr-lan >/dev/null 2>&1 || true
  docker network rm "$NET_HUB" "$NET_LAN" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "== 1/8 build linux binary and image"
if ! command -v go >/dev/null 2>&1; then
  export PATH="/c/Users/zph07/go-sdk/go/bin:$PATH"
fi
GOOS=linux GOARCH=amd64 go build -trimpath -o dist/sr-linux-amd64 ./cmd/sr
docker build -q -f deploy/nas/Dockerfile.prebuilt -t "$IMG" . >/dev/null
pass "image $IMG built"

echo "== 2/8 generate keys and configs"
rm -rf "$WORK" && mkdir -p "$WORK"
# Native tools (go, docker) need a Windows-style path on MSYS shells.
if command -v cygpath >/dev/null 2>&1; then WORK_NATIVE=$(cygpath -m "$WORK"); else WORK_NATIVE="$WORK"; fi
keys() { docker run --rm "$IMG" genkey; }
HUB_KEYS=$(keys); HUB_PRIV=$(echo "$HUB_KEYS" | sed -n 's/^private_key = //p'); HUB_PUB=$(echo "$HUB_KEYS" | sed -n 's/^public_key  = //p')
AG_KEYS=$(keys);  AG_PRIV=$(echo "$AG_KEYS" | sed -n 's/^private_key = //p');   AG_PUB=$(echo "$AG_KEYS" | sed -n 's/^public_key  = //p')
CL_KEYS=$(keys);  CL_PRIV=$(echo "$CL_KEYS" | sed -n 's/^private_key = //p');   CL_PUB=$(echo "$CL_KEYS" | sed -n 's/^public_key  = //p')
[ -n "$HUB_PRIV" ] && [ -n "$AG_PRIV" ] && [ -n "$CL_PRIV" ] || fail "genkey produced nothing"

cat > "$WORK/server.json" <<EOF
{
  "listen": "0.0.0.0:$PORT",
  "private_key": "$HUB_PRIV",
  "tunnel_cidr": "10.77.0.1/24",
  "clients_file": "/etc/selfremote/clients.json",
  "agents_file": "/etc/selfremote/agents.json",
  "api_listen": "0.0.0.0:8770",
  "api_token": "$TOKEN",
  "status_file": "/etc/selfremote/server-status.json"
}
EOF

cat > "$WORK/clients.json" <<EOF
{
  "clients": [
    { "name": "mac", "user": "e2e", "public_key": "$CL_PUB", "tunnel_ip": "10.77.0.2",
      "totp_secret": "$CLIENT_SECRET", "agents": ["home"] }
  ]
}
EOF

cat > "$WORK/agents.json" <<EOF
{
  "agents": [
    { "id": "home", "name": "家里 NAS", "public_key": "$AG_PUB", "tunnel_ip": "10.77.0.101",
      "totp_secret": "$AGENT_SECRET", "enabled": true,
      "routes": [ { "real": "$LAN_SUBNET", "virtual": "$VIRTUAL_CIDR" } ] }
  ]
}
EOF
pass "hub config + registries written"

echo "== 3/8 start the hub (no TUN, no NET_ADMIN — on purpose)"
docker network create "$NET_HUB" >/dev/null
docker run -d --name sr-hub --network "$NET_HUB" \
  -p "127.0.0.1:$API_PORT:8770" \
  -v "$WORK:/etc/selfremote" \
  "$IMG" server -c /etc/selfremote/server.json >/dev/null
HUB_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sr-hub)
sleep 1
if docker exec sr-hub cat /proc/net/dev | grep -Eq '(^|[[:space:]])(sr0|tun0|utun)'; then
  fail "hub created a tunnel interface"
fi
pass "hub running at $HUB_IP:$PORT (no TUN/NET_ADMIN; API on host :$API_PORT)"

echo "== 4/8 start the site: agent container + simulated LAN device"
docker network create --subnet "$LAN_SUBNET" "$NET_LAN" >/dev/null
cat > "$WORK/agent.json" <<EOF
{
  "id": "home",
  "name": "家里 NAS",
  "server": "$HUB_IP:$PORT",
  "private_key": "$AG_PRIV",
  "server_public_key": "$HUB_PUB",
  "tunnel_cidr": "10.77.0.101/24",
  "mfa_secret": "$AGENT_SECRET",
  "routes": [ { "real": "$LAN_SUBNET", "virtual": "$VIRTUAL_CIDR" } ]
}
EOF
go run ./dist/mkkeyfile -in "$WORK_NATIVE/agent.json" -out "$WORK_NATIVE/agent.srkey" -pass "$KPASS"

docker run -d --name sr-lan --network "$NET_LAN" --ip "$LAN_DEVICE" alpine:3 \
  sh -c 'while true; do printf "HTTP/1.0 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nSITE-OK\n" | nc -l -p 8080; done' >/dev/null

# create → connect the site LAN → start, so both networks exist before the
# entrypoint configures forwarding and NAT (interface names are not stable).
docker create --name sr-agent \
  --network "$NET_HUB" \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=1 \
  --device /dev/net/tun:/dev/net/tun \
  -v "$WORK:/etc/selfremote" \
  "$IMG" agent -c /etc/selfremote/agent.srkey -kpass "$KPASS" >/dev/null
docker network connect "$NET_LAN" sr-agent
docker start sr-agent >/dev/null
sleep 3
docker exec sr-agent sh -c 'ip -o -4 addr show' | grep -q "$LAN_PREFIX" \
  || fail "agent has no site LAN address"
pass "agent dialing the hub from behind NAT-style networking (site LAN attached)"

echo "== 5/8 start the client with an encrypted .srkey and a live MFA code"
cat > "$WORK/client.json" <<EOF
{
  "server": "$HUB_IP:$PORT",
  "private_key": "$CL_PRIV",
  "server_public_key": "$HUB_PUB",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["$VIRTUAL_CIDR"]
}
EOF
go run ./dist/mkkeyfile -in "$WORK_NATIVE/client.json" -out "$WORK_NATIVE/client.srkey" -pass "$KPASS"
CODE=$(go run ./dist/totpgen -secret "$CLIENT_SECRET")
docker run -d --name sr-client \
  --network "$NET_HUB" \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v "$WORK:/etc/selfremote" \
  "$IMG" client -c /etc/selfremote/client.srkey -kpass "$KPASS" -mfa "$CODE" >/dev/null
sleep 5

echo "== 6/8 hub status + both MFA handshakes"
STATUS=$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT/api/v1/status")
echo "$STATUS" | grep -q '"id": "home"' || { echo "$STATUS"; fail "agent missing from hub status"; }
echo "$STATUS" | grep -q '"role": "agent"' || fail "agent role missing in status"
echo "$STATUS" | grep -q '"agents_online": 1' || { echo "$STATUS"; fail "agent not online"; }
echo "$STATUS" | grep -q '"clients_online": 1' || { echo "$STATUS"; fail "client not online"; }
echo "$STATUS" | grep -q "$VIRTUAL_CIDR" || fail "agent routes not reported"
# Two independent MFA exchanges must have happened on the hub (agent + client).
MFAS=$(docker logs sr-hub 2>&1 | grep -c "MFA passed" || true)
[ "$MFAS" -ge 2 ] || { docker logs sr-hub 2>&1 | tail -20; fail "expected 2 MFA exchanges on the hub, saw $MFAS"; }
docker logs sr-agent 2>&1 | grep -q "已通过" || fail "agent did not pass its MFA challenge"
[ -s "$WORK/server-status.json" ] || fail "hub status file not written"
pass "hub: 2 MFA exchanges (agent + client), agent routes announced, status file written"

echo "== 7/8 traffic through the hub with address translation"
docker exec sr-client ping -c 2 -W 2 "$LAN_DEVICE" >/dev/null 2>&1 \
  && fail "client reached the REAL site address — translation is broken" || true
docker exec sr-client ping -c 3 -W 3 "$LAN_VIRTUAL" > "$WORK/ping.txt" 2>&1 \
  || { cat "$WORK/ping.txt"; fail "client cannot reach the site's virtual address"; }
grep -q "0% packet loss" "$WORK/ping.txt" || { cat "$WORK/ping.txt"; fail "packet loss through the hub"; }
pass "ping $LAN_VIRTUAL (= site's $LAN_DEVICE in virtual form): $(grep -o '[0-9]*% packet loss' "$WORK/ping.txt")"

HTTP=""
for i in 1 2 3 4 5 6; do
  HTTP=$(docker exec sr-client wget -qO- -T 5 "http://$LAN_VIRTUAL:8080/" 2>&1 || true)
  case "$HTTP" in *SITE-OK*) break ;; esac
  sleep 0.4
done
case "$HTTP" in
  *SITE-OK*) pass "TCP through the hub: $(echo "$HTTP" | tr -d '\r')" ;;
  *) fail "TCP through the hub failed: $HTTP" ;;
esac

echo "== 8/8 registry enable/disable + control API kick"
sed -i 's/"enabled": true/"enabled": false/' "$WORK/agents.json"
sleep 2
docker exec sr-client ping -c 2 -W 2 "$LAN_VIRTUAL" >/dev/null 2>&1 && fail "traffic still flows after disable" || true
docker logs sr-agent 2>&1 | grep -q "停用" || fail "agent was not told to stand down"
pass "disable: hub refused the site and told the agent to stand down"

sed -i 's/"enabled": false/"enabled": true/' "$WORK/agents.json"
sleep 2
docker exec sr-client ping -c 2 -W 2 "$LAN_VIRTUAL" >/dev/null 2>&1 || fail "traffic did not resume after enable"
pass "enable: traffic resumed without touching the agent"

curl -s -X POST -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT/api/v1/agents/home/kick" | grep -q '"ok": true' \
  || fail "kick API failed"
sleep 4
docker exec sr-client ping -c 2 -W 2 "$LAN_VIRTUAL" >/dev/null 2>&1 || fail "traffic broken after kick"
pass "kick: agent reconnected by itself and traffic resumed"

echo
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT/api/v1/agents" \
  | grep -o '"id": "[^"]*"\|"routes": \[[^]]*\]\|"authed": [a-z]*' | head -6
echo
echo "== hub log tail (relay decisions)"
docker logs sr-hub 2>&1 | tail -8
echo
echo "E2E_HUB_PASS: server/agent/client split verified end to end"
