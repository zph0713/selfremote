#!/usr/bin/env bash
# selfremote 站点 Agent 一键安装脚本
#
# 在要接入的目标机器上（root）执行：
#   curl -fsSL __SELFREMOTE_SERVER__/install.sh | sudo bash -s -- --code XXXX-XXXX
#
# 参数：
#   --code CODE        安装码（必填；在控制面「站点 Agent」页生成）
#   --server URL       控制面地址（默认本脚本的下载来源）
#   --tunnel HOST:PORT 隧道服务端地址（默认由控制面下发）
#   --routes LIST      本站点要开放的网段，逗号分隔（建站时已填可省略）
#   --docker           用容器方式运行（默认：二进制 + systemd）
#   --image IMG        docker 模式用的镜像（默认 ghcr.io/zph0713/selfremote:latest）
#   --dir DIR          安装目录（默认 /opt/selfremote）
#   --keypass PASS     给配置文件加密（默认明文 root-only）
#   --no-service       只接入并写配置，不安装/启动服务（调试或自行托管时用）
#   --uninstall        卸载（停服务、删文件；不删 server 上的站点记录）
#
# 说明：脚本只做三件事 —— 下载 agent 二进制 → 拿安装码换注册（生成密钥对、
# 写入配置）→ 装成开机自启的服务。之后 agent 用密钥连 server，不再需要安装码。
set -euo pipefail

SERVER="__SELFREMOTE_SERVER__"
CODE=""
TUNNEL=""
ROUTES=""
MODE="binary"
IMAGE="ghcr.io/zph0713/selfremote:latest"
DIR="/opt/selfremote"
KEYPASS=""
UNINSTALL=0
NO_SERVICE=0

die() { echo "错误：$*" >&2; exit 1; }
say() { printf '\033[1;36m==\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --code)     CODE="${2:-}"; shift 2 ;;
    --server)   SERVER="${2:-}"; shift 2 ;;
    --tunnel)   TUNNEL="${2:-}"; shift 2 ;;
    --routes)   ROUTES="${2:-}"; shift 2 ;;
    --docker)   MODE="docker"; shift ;;
    --image)    IMAGE="${2:-}"; shift 2 ;;
    --dir)      DIR="${2:-}"; shift 2 ;;
    --keypass)  KEYPASS="${2:-}"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)  sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
    *)          die "未知参数 $1（--help 看用法）" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "需要 root 权限（sudo bash -s -- --code ...）"
SERVER="${SERVER%/}"

CONF="$DIR/agent.json"
UNIT=/etc/systemd/system/selfremote-agent.service

if [ "$UNINSTALL" = "1" ]; then
  say "卸载 selfremote agent"
  systemctl disable --now selfremote-agent 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload 2>/dev/null || true
  docker rm -f selfremote-agent 2>/dev/null || true
  echo "配置文件保留在 $CONF（要彻底删除：rm -rf $DIR）"
  exit 0
fi

[ -n "$CODE" ] || die "缺少 --code（在控制面「站点 Agent」页生成安装码）"
command -v curl >/dev/null 2>&1 || die "需要 curl"

# ---- 平台识别 ---------------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64|amd64)   arch=amd64 ;;
  aarch64|arm64)  arch=arm64 ;;
  *) die "不支持的架构 $(uname -m)" ;;
esac
case "$os" in
  linux|darwin) ;;
  *) die "不支持的系统 $os（Windows 请用部署包方式）" ;;
esac
BIN="agent-${os}-${arch}"
[ "$os" = "darwin" ] && MODE="binary"  # macOS 没有 systemd，走前台/launchd 说明

say "selfremote agent 安装：$os/$arch，方式=$MODE，控制面=$SERVER，安装目录=$DIR"
mkdir -p "$DIR" && chmod 700 "$DIR"

# ---- 拿二进制 ---------------------------------------------------------------
if [ "$MODE" = "binary" ]; then
  say "下载 agent 二进制（$BIN）"
  curl -fsSL "$SERVER/agent-dist/$BIN" -o "$DIR/sr" || die "下载失败：$SERVER/agent-dist/$BIN"
  chmod 755 "$DIR/sr"
fi

# ---- 用安装码换注册（生成密钥对 + 写配置） ----------------------------------
enroll_args=(agent enroll --server "$SERVER" --code "$CODE" -o "$CONF" --force)
[ -n "$TUNNEL" ]  && enroll_args+=(--tunnel "$TUNNEL")
[ -n "$ROUTES" ]  && enroll_args+=(--routes "$ROUTES")
[ -n "$KEYPASS" ] && enroll_args+=(--keypass "$KEYPASS")

if [ "$MODE" = "binary" ]; then
  say "用安装码接入控制面"
  "$DIR/sr" "${enroll_args[@]}"
else
  command -v docker >/dev/null 2>&1 || die "docker 模式需要 docker"
  say "拉取镜像 $IMAGE"
  docker pull "$IMAGE" >/dev/null || die "镜像拉取失败（离线环境请改用二进制方式）"
  say "用安装码接入控制面（容器内执行）"
  docker run --rm --entrypoint /usr/local/bin/sr -v "$DIR:/etc/selfremote" "$IMAGE" \
    agent enroll --server "$SERVER" --code "$CODE" -o /etc/selfremote/agent.json --force \
    ${TUNNEL:+--tunnel "$TUNNEL"} ${ROUTES:+--routes "$ROUTES"}
  CONF="$DIR/agent.json"
fi
[ -f "$CONF" ] || die "接入失败：配置文件没有生成"

# ---- 装成服务 ---------------------------------------------------------------
if [ "$NO_SERVICE" = "1" ]; then
  say "已按要求只接入、不安装服务。手动运行："
  echo "  sudo $DIR/sr agent -c $CONF"
elif [ "$MODE" = "docker" ]; then
  say "启动容器 selfremote-agent"
  docker rm -f selfremote-agent >/dev/null 2>&1 || true
  docker run -d --name selfremote-agent --restart unless-stopped \
    --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
    -v "$DIR:/etc/selfremote" "$IMAGE" agent -c /etc/selfremote/agent.json >/dev/null
  sleep 2
  docker logs --tail 12 selfremote-agent || true
elif [ "$os" = "linux" ]; then
  say "写入 systemd 服务"
  cat >"$UNIT" <<EOF
[Unit]
Description=selfremote 站点 Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$DIR/sr agent -c $CONF
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  chmod 600 "$CONF" 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable --now selfremote-agent
  sleep 2
  systemctl --no-pager --lines=12 status selfremote-agent || true
else
  cat <<EOF

macOS 已装好（$DIR/sr 与 $CONF）。前台运行：
  sudo $DIR/sr agent -c $CONF
开机自启可自建 launchd（/Library/LaunchDaemons/com.selfremote.agent.plist），
或直接把它加入你的启动项。
EOF
fi

cat <<EOF

$(say "完成")
  站点配置：$CONF
  查看状态：$( [ "$MODE" = docker ] && echo "docker logs -f selfremote-agent" || echo "systemctl status selfremote-agent / journalctl -fu selfremote-agent" )
  回到控制面「站点 Agent」页，状态应变为「在线」。
EOF
