#!/bin/sh
# selfremote 容器入口（gateway / agent 两种站点角色）。
#
# 预期运行环境：host 网络命名空间（network_mode: host）+ NET_ADMIN，
# 这样 tun 设备、转发与 NAT 规则才作用于站点的网络栈本身。
#
# 环境变量：
#   SR_LAN_IF       出内网的 LAN 接口（默认 eth0；开启 Open vSwitch 的群晖用 ovs_eth0）
#   SR_TUNNEL_CIDR  隧道网段（默认 10.77.0.0/24，需与 gateway.json 一致）
#   SR_IPT          iptables 二进制名（默认自动：优先 iptables-legacy）
set -e

SR_TUNNEL_CIDR="${SR_TUNNEL_CIDR:-10.77.0.0/24}"
# SR_LAN_IF 只用于启动日志提示；转发/SNAT 按「除 sr0 外的任何出口」生效（多网卡无需指定）
SR_LAN_IF="${SR_LAN_IF:-}"

if [ -n "$SR_IPT" ]; then
  IPT="$SR_IPT"
elif command -v iptables-legacy >/dev/null 2>&1; then
  IPT=iptables-legacy
else
  IPT=iptables
fi

setup_network() {
  echo "== selfremote network setup (lan_if=${SR_LAN_IF:-auto} tunnel=$SR_TUNNEL_CIDR iptables=$IPT)"

  # IPv4 转发：尽力而为（容器内 /proc/sys 常为只读；群晖宿主上建议用「任务计划 → 开机」固定设置）
  { echo 1 > /proc/sys/net/ipv4/ip_forward; } 2>/dev/null || true
  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
    echo "WARN: net.ipv4.ip_forward != 1 —— 内网转发会不工作。" >&2
    echo "WARN: 请在 NAS 宿主设置（DSM 任务计划 → 开机运行）: sysctl -w net.ipv4.ip_forward=1" >&2
  fi

  # SR_LAN_IF 仅用于提示；转发/SNAT 规则按「除隧道口外的任何出口」生效，
  # 这样多网卡的站点（NAS 双网口、容器多网桥）无需猜接口名。
  if [ -n "$SR_LAN_IF" ] && ! ip link show "$SR_LAN_IF" >/dev/null 2>&1; then
    echo "WARN: 找不到 LAN 接口 '$SR_LAN_IF'（DSM 开 Open vSwitch 时通常是 ovs_eth0）—— 规则不受影响" >&2
  fi

  # 出内网口做源地址改写（幂等）
  $IPT -t nat -C POSTROUTING -s "$SR_TUNNEL_CIDR" ! -o sr0 -j MASQUERADE 2>/dev/null || \
    $IPT -t nat -A POSTROUTING -s "$SR_TUNNEL_CIDR" ! -o sr0 -j MASQUERADE

  # 转发放行（幂等）
  $IPT -C FORWARD -i sr0 ! -o sr0 -j ACCEPT 2>/dev/null || \
    $IPT -A FORWARD -i sr0 ! -o sr0 -j ACCEPT
  $IPT -C FORWARD ! -i sr0 -o sr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    $IPT -A FORWARD ! -i sr0 -o sr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  echo "== network setup done"
}

case "${1:-}" in
  gateway|agent)
    # Both roles own the site's local network path: the agent needs exactly
    # the same forwarding + SNAT setup as the standalone gateway.
    #
    # First deployment of a site: the config file arrives later (created in
    # the web UI), so wait for it instead of crash-looping.
    CFG=""
    prev=""
    for a in "$@"; do
      if [ "$prev" = "-c" ]; then CFG="$a"; break; fi
      prev="$a"
    done
    if [ -n "$CFG" ] && [ ! -f "$CFG" ]; then
      echo "WARN: 找不到配置文件 $CFG"
      echo "      首次部署：在网页「站点 Agent」里创建站点并下载部署包，"
      echo "      把包里的 <站点id>.srkey 放进本容器的数据目录后会自动继续（每 5 秒检查一次）。"
      while [ ! -f "$CFG" ]; do sleep 5; done
      echo "== 检测到配置文件，继续启动"
    fi
    setup_network
    ;;
esac

exec /usr/local/bin/sr "$@"
