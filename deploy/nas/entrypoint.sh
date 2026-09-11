#!/bin/sh
# selfremote 容器入口。
#
# 预期运行环境：host 网络命名空间（network_mode: host）+ NET_ADMIN，
# 这样 tun 设备、转发与 NAT 规则才作用于 NAS 宿主网络栈本身。
#
# 环境变量：
#   SR_LAN_IF       出内网的 LAN 接口（默认 eth0；开启 Open vSwitch 的群晖用 ovs_eth0）
#   SR_TUNNEL_CIDR  隧道网段（默认 10.77.0.0/24，需与 gateway.json 一致）
#   SR_IPT          iptables 二进制名（默认自动：优先 iptables-legacy）
set -e

SR_TUNNEL_CIDR="${SR_TUNNEL_CIDR:-10.77.0.0/24}"
SR_LAN_IF="${SR_LAN_IF:-eth0}"

if [ -n "$SR_IPT" ]; then
  IPT="$SR_IPT"
elif command -v iptables-legacy >/dev/null 2>&1; then
  IPT=iptables-legacy
else
  IPT=iptables
fi

setup_network() {
  echo "== selfremote network setup (iface=$SR_LAN_IF tunnel=$SR_TUNNEL_CIDR iptables=$IPT)"

  # IPv4 转发：尽力而为（容器内 /proc/sys 常为只读；群晖宿主上建议用「任务计划 → 开机」固定设置）
  { echo 1 > /proc/sys/net/ipv4/ip_forward; } 2>/dev/null || true
  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
    echo "WARN: net.ipv4.ip_forward != 1 —— 内网转发会不工作。" >&2
    echo "WARN: 请在 NAS 宿主设置（DSM 任务计划 → 开机运行）: sysctl -w net.ipv4.ip_forward=1" >&2
  fi

  if ! ip link show "$SR_LAN_IF" >/dev/null 2>&1; then
    echo "WARN: 找不到 LAN 接口 '$SR_LAN_IF'，请设置 SR_LAN_IF（例如 ovs_eth0）" >&2
  fi

  # 出 LAN 口做源地址改写（幂等）
  $IPT -t nat -C POSTROUTING -s "$SR_TUNNEL_CIDR" -o "$SR_LAN_IF" -j MASQUERADE 2>/dev/null || \
    $IPT -t nat -A POSTROUTING -s "$SR_TUNNEL_CIDR" -o "$SR_LAN_IF" -j MASQUERADE

  # 转发放行（幂等）
  $IPT -C FORWARD -i sr0 -o "$SR_LAN_IF" -j ACCEPT 2>/dev/null || \
    $IPT -A FORWARD -i sr0 -o "$SR_LAN_IF" -j ACCEPT
  $IPT -C FORWARD -i "$SR_LAN_IF" -o sr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    $IPT -A FORWARD -i "$SR_LAN_IF" -o sr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  echo "== network setup done"
}

case "${1:-}" in
  gateway)
    setup_network
    ;;
esac

exec /usr/local/bin/sr "$@"
