# selfremote 发布说明

自研远程接入隧道：让在外网的设备（Mac / 笔记本）直连**家庭内网的内网 IP** —— NAS、路由器、任意设备、任意端口。

## v0.2.2 修复

- **macOS 客户端崩溃修复**：utun 读取偏移错误，连接时会 `panic: slice bounds out of range [-4:]`
  （wireguard-go 的 darwin 契约要求读取偏移 ≥ 4 字节 utun 头；已加模拟测试锁死）

## v0.2.1 修复

- **macOS 客户端连接修复**：配置虚拟网卡的子网掩码格式错误（hex → 点分十进制），
  此前在 Mac 上会报 `ifconfig: ffffff00: bad value` 而无法建立连接
- macOS 路由注入改用全版本兼容的 `-net/-netmask` 语法
- 「双击启动.command」与文档明确区分连接时的三个提示（sudo 登录密码 / 文件密码 / 动态码）

## v0.2.0 亮点

**🛡 Web 控制面（新）**：注册 / 登录（密码 + Google Authenticator 动态码）、设备密钥管理、实时总览。
一套 `docker compose` 起全家桶：nginx + web + mariadb + 网关。

**🔐 动态码连接**：客户端连接时需要输入实时动态验证码（MFA 在加密隧道内验证，码不裸奔、防重放），
用错 3 次自动锁定并断开。

**🧾 加密密钥文件（.srkey）**：客户端配置在网页上生成后即以「文件密码」加密下载
（argon2id + ChaCha20-Poly1305）；运行时先解文件密码、再输动态码。服务器只保存公钥。

**📊 连接状态**：连接后打印状态块（服务端主机、隧道、MFA 状态、流量），Ctrl+C 即刻断开并通知服务端。

**♻️ 兼容**：纯命令行模式（不使用 Web 控制面、无 MFA）完全保留，见下方「服务端（命令行模式）」。

## 下载

| 我要… | 拿这个 |
|---|---|
| Mac 客户端 | `selfremote-macos-arm64`（Apple 芯片）/ `selfremote-macos-amd64`（Intel）/ `selfremote-macos.zip` 整包 |
| Windows 客户端 | `selfremote-windows-amd64.exe` |
| Linux 客户端 / 网关程序 | `selfremote-linux-amd64` / `selfremote-linux-arm64` |
| 服务端镜像（在线） | `ghcr.io/zph0713/selfremote:latest`（网关）、`ghcr.io/zph0713/selfremote-web:latest`（控制面） |
| 服务端镜像（离线） | `selfremote-image-linux-amd64.tar.gz`、`selfremote-web-image-linux-amd64.tar.gz`（`docker load -i`） |

## 快速开始

### 客户端（Mac）

用 Web 控制面生成的 `client-*.srkey`：

```sh
sudo ./selfremote-macos-arm64 client -c client-yourname.srkey
# 输入文件密码 → 输入 Google Authenticator 动态码 → 连上
```

（老式明文 `client.json` 同样支持；控制面未启用 MFA 时直接连接。）

### 服务端（Web 控制面 · 推荐）

```sh
git clone https://github.com/zph0713/selfremote && cd selfremote/deploy/stack
cp .env.example .env && vi .env        # 改数据库密码；可选 SERVER_ADDR / LAN_CIDRS
bash init.sh                           # 生成网关密钥（一次）
docker compose up -d                   # nginx + web + mariadb + gateway
# 打开 http://<主机>:8080 → 注册管理员 → 绑定 Google Authenticator → 生成客户端密钥
```

### 服务端（命令行模式 · 无 Web 也可）

```sh
docker run -d --name selfremote-gw --restart unless-stopped \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v /etc/selfremote:/etc/selfremote \
  ghcr.io/zph0713/selfremote:latest gateway -c /etc/selfremote/gateway.json
```

文档：仓库 `docs/` 目录（QUICKSTART-WEB / QUICKSTART-CLIENT / QUICKSTART-SERVER / DEPLOY-NAS / PROTOCOL）。
