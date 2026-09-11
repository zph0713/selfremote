# selfremote 发布说明

自研远程接入隧道：让在外网的设备（Mac / 笔记本）直连**家庭内网的内网 IP** —— NAS、路由器、任意设备、任意端口。

本版本：M1.0 完成 —— 协议核心（Noise IK 握手、会话、显式 nonce 帧）+ 20 项测试 + Docker 端到端冒烟通过。

---

## 🖥 服务端（网关）—— 部署在家里或任意 Docker 主机

**方式 A：在线拉取（任意 Docker 主机）**

```sh
docker pull ghcr.io/zph0713/selfremote:latest

docker run -d --name selfremote-gw --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v /etc/selfremote:/etc/selfremote \
  ghcr.io/zph0713/selfremote:latest gateway -c /etc/selfremote/gateway.json
```

> Docker Desktop（Windows/Mac）把 `--network host` 换成 `-p 28333:28333/udp`。
> 国内网络拉取慢 → 用方式 B。

**方式 B：离线镜像 tar（下载 `selfremote-image-linux-amd64.tar.gz`）**

```sh
docker load -i selfremote-image-linux-amd64.tar.gz
# 然后按方式 A 的 docker run 使用（去掉 pull）
```

**方式 C：Linux 裸机**：直接下载 `selfremote-linux-amd64`（/`-arm64`）运行 `./selfremote-linux-amd64 gateway -c gateway.json`

完整步骤（密钥生成、gateway.json、ip_forward/防火墙）：见仓库 `docs/QUICKSTART-SERVER.md`。

---

## 💻 客户端（在外网的设备）

| 平台 | 下载 |
|---|---|
| macOS Apple 芯片 | `selfremote-macos-arm64` |
| macOS Intel | `selfremote-macos-amd64` |
| macOS 整包（含说明+模板） | `selfremote-macos.zip` |
| Windows / Linux | `selfremote-windows-amd64.exe` / `selfremote-linux-amd64` |

```sh
chmod +x selfremote-macos-arm64
xattr -d com.apple.quarantine selfremote-macos-arm64 2>/dev/null   # macOS 去隔离标记
sudo ./selfremote-macos-arm64 client -c client.json
```

看到 `client: session established` 即连接成功；Ctrl+C 退出并自动清理路由。
完整步骤（密钥交换、配置、验证）：见仓库 `docs/QUICKSTART-CLIENT.md`。

---

## 一分钟理解

- **服务端**监听 UDP，另一端把隧道流量转发进内网（SNAT）——谁连上隧道，就"坐进"了家里内网；
- **客户端**只把家里内网网段（如 `192.168.1.0/24`）的流量送进隧道，其余上网流量不受影响；
- 端到端加密（Noise IK + ChaCha20-Poly1305），服务端用公钥白名单授权，未授权握手静默丢弃。
