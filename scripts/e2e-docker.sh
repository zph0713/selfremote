#!/usr/bin/env bash
# selfremote Docker end-to-end smoke test (runs entirely on one machine).
#
# Verifies with REAL TUN devices inside containers:
#   1. gateway + client handshake over UDP
#   2. tunnel ping (client -> gateway tunnel IP)
#   3. forwarded + NATed access to a simulated LAN device (192.168.99.5)
#
# Usage: bash scripts/e2e-docker.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORK="$ROOT/dist/e2e"
IMG=selfremote:e2e
PORT=28399

echo "== build image ($IMG)"
docker build -f deploy/nas/Dockerfile.prebuilt -t "$IMG" .

echo "== generate keys and configs"
rm -rf "$WORK" && mkdir -p "$WORK"
GW_KEYS=$(docker run --rm "$IMG" genkey)
GW_PRIV=$(echo "$GW_KEYS" | sed -n 's/^private_key = //p')
GW_PUB=$(echo "$GW_KEYS" | sed -n 's/^public_key  = //p')
CL_KEYS=$(docker run --rm "$IMG" genkey)
CL_PRIV=$(echo "$CL_KEYS" | sed -n 's/^private_key = //p')
CL_PUB=$(echo "$CL_KEYS" | sed -n 's/^public_key  = //p')

cat > "$WORK/gateway.json" <<EOF
{
  "listen": "0.0.0.0:$PORT",
  "private_key": "$GW_PRIV",
  "tunnel_cidr": "10.77.0.1/24",
  "peers": [ { "name": "mac", "public_key": "$CL_PUB" } ]
}
EOF

echo "== start gateway container"
docker rm -f sr-gw sr-cl sr-lan >/dev/null 2>&1 || true
docker run -d --name sr-gw \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=1 \
  --device /dev/net/tun:/dev/net/tun \
  -v "$WORK:/etc/selfremote" \
  "$IMG" gateway -c /etc/selfremote/gateway.json

GW_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sr-gw)
echo "   gateway container ip: $GW_IP"
sleep 1

cat > "$WORK/client.json" <<EOF
{
  "server": "$GW_IP:$PORT",
  "private_key": "$CL_PRIV",
  "server_public_key": "$GW_PUB",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["192.168.99.0/24"]
}
EOF

echo "== start simulated LAN device (192.168.99.5)"
docker run -d --name sr-lan --cap-add NET_ADMIN --entrypoint sh "$IMG" -c "ip addr add 192.168.99.5/24 dev eth0 && sleep 3600"

echo "== teach the gateway the simulated LAN route (in production the gateway is on the LAN itself)"
docker exec sr-gw ip route add 192.168.99.0/24 dev eth0
if docker exec sr-gw ping -c 2 -W 2 192.168.99.5 >/dev/null 2>&1; then
  echo "   gateway -> lan device: ok"
else
  echo "   WARN: gateway cannot reach the lan device directly"
fi

echo "== start client container"
docker run -d --name sr-cl \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v "$WORK:/etc/selfremote" \
  "$IMG" client -c /etc/selfremote/client.json

sleep 3
echo "== gateway log:"; docker logs sr-gw 2>&1 | tail -8
echo "== client log:";  docker logs sr-cl 2>&1 | tail -8

echo "== ping gateway tunnel ip (10.77.0.1) from client"
docker exec sr-cl ping -c 3 -W 3 10.77.0.1

echo "== ping simulated LAN device (192.168.99.5) from client (through tunnel + forward + NAT)"
docker exec sr-cl ping -c 3 -W 3 192.168.99.5

echo "== all e2e checks passed"
echo "   (cleanup: docker rm -f sr-gw sr-cl sr-lan)"
