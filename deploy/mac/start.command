#!/bin/bash
# selfremote Mac 一键启动（双击运行；也可在终端: ./start.command [配置文件名]）
cd "$(dirname "$0")" || exit 1

echo "== selfremote 启动器 =="
echo "== 清理下载隔离标记…"
xattr -dr com.apple.quarantine . 2>/dev/null

ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then
  BIN="./selfremote-macos-arm64"
else
  BIN="./selfremote-macos-amd64"
fi
CFG="${1:-client.json}"

if [ ! -f "$BIN" ]; then
  echo "错误：找不到 $BIN（本文件夹里应该有）"
  read -n1 -p "按任意键关闭..."; exit 1
fi
if [ ! -f "$CFG" ]; then
  echo "错误：找不到配置文件 $CFG"
  echo "提示：把 client.json.example 复制为 client.json，按 README-使用说明 填写"
  read -n1 -p "按任意键关闭..."; exit 1
fi

chmod +x "$BIN" 2>/dev/null
echo "== 芯片: $ARCH   程序: $BIN   配置: $CFG"
echo "== 接下来会要求输入你的 Mac 密码（创建虚拟网卡需要管理员权限）"
echo
sudo "$BIN" client -c "$CFG"
RC=$?
echo
echo "== 客户端已退出 (exit=$RC)"
read -n1 -p "按任意键关闭此窗口..."
