# 服务端快速开始（Docker，任意主机）

> 服务端 = 家里的「网关」：监听加密隧道（UDP），把隧道里的流量转发进内网（SNAT）。
> 任何 Docker 主机都能跑：Linux 服务器、群晖 NAS、甚至临时借用的电脑。

## 0. 前置条件

- 主机能运行 Docker；内核有 `/dev/net/tun`（普通 Linux / 群晖都有）
- 客户端能连到它：公网 IPv6（推荐）或公网 IPv4
- UDP 端口（默认 `28333`）在防火墙放行

## 1. 获取镜像（三选一）

```sh
# A. 在线拉取（GitHub 容器仓库）
docker pull ghcr.io/zph0713/selfremote:latest

# B. 离线导入（Release 里下载 selfremote-image-linux-amd64.tar.gz）
docker load -i selfremote-image-linux-amd64.tar.gz

# C. 源码本地构建（仓库根目录）
docker build -f deploy/nas/Dockerfile -t selfremote:latest .
```

## 2. 生成服务端密钥

```sh
docker run --rm ghcr.io/zph0713/selfremote:latest genkey
# private_key = ...   ← 填进 gateway.json
# public_key  = ...   ← 提供给客户端
```

## 3. 写配置 gateway.json

（模板见 `deploy/examples/gateway.json.example`）

```json
{
  "listen": "[::]:28333",
  "private_key": "（第 2 步的 private_key）",
  "tunnel_cidr": "10.77.0.1/24",
  "peers": [
    { "name": "my-mac", "public_key": "（客户端 genkey 的 public_key）" }
  ]
}
```

## 4. 运行

**Linux / 群晖（推荐 host 网络）：**

```sh
docker run -d --name selfremote-gw --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v /etc/selfremote:/etc/selfremote \
  ghcr.io/zph0713/selfremote:latest gateway -c /etc/selfremote/gateway.json
```

**Docker Desktop（Windows / macOS 本机试验）**：把 `--network host` 换成 `-p 28333:28333/udp`。

## 5. 宿主上必须做的两件事

1. **开启 IPv4 转发**：`sysctl -w net.ipv4.ip_forward=1`
   （群晖：控制面板 → 任务计划 → 开机执行；容器启动时会尽力设置，但不保证）
2. **防火墙放行 UDP 28333**

转发 / NAT 规则由容器 entrypoint 自动配置（幂等），无需手动写 iptables。

## 6. 验证

```sh
docker logs selfremote-gw
# 客户端连上后应出现：gateway: session established with ...
```

客户端侧 `ping 内网IP` 应通。更多排错见 [DEPLOY-NAS.md](DEPLOY-NAS.md) 第 6 节。
