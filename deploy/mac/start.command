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
echo
echo "== 接下来会依次出现三个提示（别搞混）："
echo "   ① sudo  → 输【你的 Mac 登录密码】（系统权限；报 Sorry, try again 说明输错了，3 次会退出）"
echo "   ② 程序  → 输【密钥文件密码】（生成密钥时你设的那个，至少 10 位）"
echo "   ③ 程序  → 输【Google Authenticator 动态码】（6 位；服务端启用 MFA 时）"
echo
sudo -p "▶ ① 请输入【Mac 登录密码】: " "$BIN" client -c "$CFG"
RC=$?
echo
echo "== 客户端已退出 (exit=$RC)"
read -n1 -p "按任意键关闭此窗口..."
