#!/usr/bin/env bash
# 检查两套 selfremote 栈之间有没有共享资源（只读，不启停任何容器）。
#
# 用法：bash scripts/check-dev-isolation.sh [旧项目名] [新项目名]
#       默认 selfremote / selfremote-dev
#
# 检查项：
#   1. 容器名前缀是否各自独立（compose 项目隔离）
#   2. 宿主发布端口是否重叠（含 host 网络容器的隐式占用）
#   3. 新版是否有容器使用 host 网络（会与旧版的 host 端口/TUN 冲突）
#   4. 新版镜像是否误用了 ghcr :latest（会跟生产共用同一镜像层与后续 pull）
#   5. 两套栈是否挂载了同一个宿主目录（数据目录共用）
#
# 退出码：0 全部通过；1 有 FAIL；2 环境不可用（没有 docker）。
set -uo pipefail

OLD=${1:-selfremote}
NEW=${2:-selfremote-dev}
FAIL=0
WARN=0

ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }
warn() { printf '  WARN  %s\n' "$1"; WARN=$((WARN+1)); }

command -v docker >/dev/null 2>&1 || { echo "docker 不可用"; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker 未运行（需要能连上 daemon）"; exit 2; }

names() { docker ps -a --format '{{.Names}}' | grep -E "^${1}-" | sort; }

OLD_C=$(names "$OLD")
NEW_C=$(names "$NEW")

echo "== 1. 容器隔离（compose 项目名）=="
printf '  %s: %s\n' "$OLD" "$(printf '%s' "$OLD_C" | tr '\n' ' ')"
printf '  %s: %s\n' "$NEW" "$(printf '%s' "$NEW_C" | tr '\n' ' ')"
OVERLAP=$(comm -12 <(printf '%s\n' "$OLD_C") <(printf '%s\n' "$NEW_C") | sed '/^$/d')
if [ -n "$OVERLAP" ]; then
  bad "两套栈存在同名容器：$(printf '%s' "$OVERLAP" | tr '\n' ' ')"
else
  ok "没有同名容器（项目名隔离生效）"
fi
[ -z "$NEW_C" ] && warn "新版还没有容器在跑（先 up 再复检）"

# 取每个容器的宿主发布端口（host 网络容器没有发布端口，单独检查）
host_ports() {
  local c
  for c in $1; do
    docker port "$c" 2>/dev/null
  done | awk '{print $3}' | sed 's/.*://' | sed '/^$/d' | sort -un
}
OLD_P=$(host_ports "$OLD_C")
NEW_P=$(host_ports "$NEW_C")

echo "== 2. 宿主端口 =="
printf '  %s: %s\n' "$OLD" "$(printf '%s' "$OLD_P" | tr '\n' ' ')"
printf '  %s: %s\n' "$NEW" "$(printf '%s' "$NEW_P" | tr '\n' ' ')"
PORT_CLASH=$(comm -12 <(printf '%s\n' "$OLD_P") <(printf '%s\n' "$NEW_P") | sed '/^$/d')
if [ -n "$PORT_CLASH" ]; then
  bad "端口重叠：$(printf '%s' "$PORT_CLASH" | tr '\n' ' ')"
else
  ok "发布端口不重叠"
fi

echo "== 3. 新版是否使用 host 网络 =="
HOSTNET=""
for c in $NEW_C; do
  mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$c" 2>/dev/null)
  [ "$mode" = "host" ] && HOSTNET="$HOSTNET $c"
done
if [ -n "$HOSTNET" ]; then
  bad "新版有 host 网络容器（会占用宿主端口/TUN/iptables）：$HOSTNET"
else
  ok "新版没有 host 网络容器"
fi

echo "== 4. 新版镜像标签 =="
BAD_IMG=""
for c in $NEW_C; do
  img=$(docker inspect --format '{{.Config.Image}}' "$c" 2>/dev/null)
  case "$img" in
    *ghcr.io/zph0713/selfremote*:latest) BAD_IMG="$BAD_IMG $c($img)" ;;
  esac
done
if [ -n "$BAD_IMG" ]; then
  bad "新版在用生产镜像 :latest（会与生产共用镜像）：$BAD_IMG"
else
  ok "新版没有使用 ghcr :latest"
fi

echo "== 5. 挂载目录 =="
mounts_of() {
  local c
  for c in $1; do
    docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$c" 2>/dev/null
  done | tr ' ' '\n' | sed '/^$/d' | sort -u
}
OLD_SRC=$(mounts_of "$OLD_C")
NEW_SRC=$(mounts_of "$NEW_C")
printf '  %s: %s\n' "$OLD" "$(printf '%s' "$OLD_SRC" | tr '\n' ' ')"
printf '  %s: %s\n' "$NEW" "$(printf '%s' "$NEW_SRC" | tr '\n' ' ')"
SRC_CLASH=$(comm -12 <(printf '%s\n' "$OLD_SRC") <(printf '%s\n' "$NEW_SRC") | sed '/^$/d')
if [ -n "$SRC_CLASH" ]; then
  bad "两套栈挂载了同一个宿主目录：$(printf '%s' "$SRC_CLASH" | tr '\n' ' ')"
else
  ok "挂载目录没有交集"
fi

echo "-----------------------------------------"
echo "FAIL=$FAIL WARN=$WARN"
[ "$FAIL" -eq 0 ]
