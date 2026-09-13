# 服务端 / 站点快速开始（命令行模式，无 Web 控制面）

> v0.3 起服务端分成两个角色：
> - **中转服务端 `sr server`**：监听一个 UDP 端口，把客户端与各站点汇总中转（用户态转发，
>   不需要 TUN / NET_ADMIN / 内核转发）；可跑在任意 VPS、容器、甚至笔记本上
> - **站点 Agent `sr agent`**：部署在能访问目标内网的机器上（NAS、服务器、软路由…），
>   主动拨号服务端，负责 tun + 转发 + SNAT + 地址翻译
>
> 用 Web 控制面（推荐）时这两个角色由控制面生成配置与部署包，见
> [QUICKSTART-WEB.md](QUICKSTART-WEB.md)；本页是手工/无控制面的用法。
> v0.2 的直连模式（`sr gateway`，客户端直连网关）仍然可用，见文末。

## 0. 前置条件

- 中转服务端：一个**公网可达**的 UDP 端口（IPv6 或 IPv4），不需要 TUN、不需要特权
- 站点机器：Linux/macOS，能访问目标内网；容器方式需要 `/dev/net/tun` 与 NET_ADMIN
- 客户端能连到服务端（域名或 IP）

## 1. 获取镜像 / 二进制

```sh
# 在线拉取（中转服务端与站点共用同一个镜像）
docker pull ghcr.io/zph0713/selfremote:latest

# 离线导入（Release 里的 selfremote-image-linux-amd64.tar.gz）
docker load -i selfremote-image-linux-amd64.tar.gz

# 或源码构建
docker build -f deploy/nas/Dockerfile -t selfremote:latest .
```

## 2. 生成密钥

```sh
docker run --rm ghcr.io/zph0713/selfremote:latest genkey
# private_key = ...   ← 填进 server.json
# public_key  = ...   ← 客户端/站点配置里的 server_public_key
```

## 3. 写配置 server.json 并启动

（模板见 `deploy/examples/server.json.example`）

```json
{
  "listen": "[::]:28333",
  "private_key": "（第 2 步的 private_key）",
  "tunnel_cidr": "10.77.0.1/24",
  "clients_file": "/etc/selfremote/clients.json",
  "agents_file": "/etc/selfremote/agents.json",
  "api_listen": "0.0.0.0:8770",
  "api_token": "（随机串；只给控制面用，不要暴露公网）",
  "status_file": "/etc/selfremote/server-status.json",
  "netinfo_file": "/etc/selfremote/netinfo.json"
}
```

```sh
docker run -d --name selfremote-server --restart unless-stopped \
  --network host \
  -v /etc/selfremote:/etc/selfremote \
  ghcr.io/zph0713/selfremote:latest server -c /etc/selfremote/server.json
```

> 服务端不用 `--cap-add`、不用 `/dev/net/tun`；`--network host` 只是为了拿到宿主 UDP 端口，
> 也可以改成 `-p 28333:28333/udp -p 127.0.0.1:8770:8770`。

## 4. 注册客户端与站点（手工写注册表）

`clients.json`（客户端设备：公钥 + 隧道地址 + 允许访问的站点 id）：

```json
{
  "clients": [
    { "name": "my-mac", "user": "me", "public_key": "（客户端 genkey 的 public_key）",
      "totp_secret": "（Base32 动态码密钥，留空则不要求 MFA）",
      "tunnel_ip": "10.77.0.2",
      "agents": ["home"] }
  ]
}
```

`agents.json`（站点：公钥 + 隧道地址 + 网段映射）：

```json
{
  "agents": [
    { "id": "home", "name": "家里 NAS", "public_key": "（站点 genkey 的 public_key）",
      "tunnel_ip": "10.77.0.100", "totp_secret": "（站点自动应答用的 Base32 密钥）",
      "enabled": true,
      "routes": [ { "real": "192.168.1.0/24", "virtual": "10.200.7.0/24" } ] }
  ]
}
```

- `virtual` 省略 = 原样呈现；两个站点真实网段相同时，给其中一个填虚拟网段即可共存
- 服务端每 250ms 检查文件变化，**无需重启**：新增/删除/停用立即生效

## 5. 站点端配置与启动

（模板见 `deploy/examples/agent.json.example`；用 Web 控制面时会下发加密的 `.srkey`）

### 5a. 推荐：用控制面的安装命令（v0.4）

```sh
# 控制面「站点 Agent」页创建站点后，页面会给出这条命令：
curl -fsSL http://<控制面>:8080/install.sh | sudo bash -s -- --code ABCD-EFGH
```

脚本流程：下载 agent 二进制（从控制面）→ `sr agent enroll`（本地生成密钥对，用安装码换
注册：隧道地址 / 服务端公钥 / 网段映射）→ 写配置（`/opt/selfremote/agent.json`，600）
→ 装 systemd 服务或 `--docker` 起容器。常用参数：`--docker`、`--routes 192.168.1.0/24,10.0.0.0/8`、
`--tunnel host:port`、`--no-service`（只接入）、`--uninstall`。

也可以手工等价地做：

```sh
sr agent enroll --server http://<控制面>:8080 --code ABCD-EFGH -o /etc/selfremote/agent.json
sr agent -c /etc/selfremote/agent.json
```

### 5b. 手工配置（无控制面）

```json
{
  "id": "home",
  "name": "家里 NAS",
  "server": "nas.example.com:28333",
  "private_key": "（站点自己的 genkey private_key）",
  "server_public_key": "（第 2 步的服务端 public_key）",
  "tunnel_cidr": "10.77.0.100/24",
  "routes": [ { "real": "192.168.1.0/24", "virtual": "10.200.7.0/24" } ]
}
```

> v0.4 起站点**不再需要** `mfa_secret`（认证靠密钥对）；`agents.json` 里对应站点也不要填
> `totp_secret`，否则服务端会要求动态码。

```sh
docker run -d --name selfremote-agent --restart unless-stopped \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  -v /etc/selfremote:/etc/selfremote \
  ghcr.io/zph0713/selfremote:latest agent -c /etc/selfremote/agent.json
```

站点宿主上必须开启 IPv4 转发（`sysctl -w net.ipv4.ip_forward=1`，群晖用「任务计划 → 开机」）；
Linux 上的转发与 SNAT 规则由 agent 自己幂等配置（`--no-net-setup` 可关掉自己配）。

## 6. 验证

```sh
docker logs selfremote-server   # 站点连上：session established with ... [agent]
docker logs selfremote-agent    # 出现 banner：═══ selfremote agent 已上线 ═══
```

客户端 `ping 10.200.7.50`（虚拟网段 + 主机号）应通；`ping 10.77.0.1` 能验证"服务端可达"。

## 附：v0.2 直连模式（`sr gateway`）

不想要中转、客户端能直连站点公网地址时，可用老模式：站点跑
`sr gateway -c gateway.json`（见 `deploy/examples/gateway.json.example`），
客户端配置的 `server` 直接填它、`server_public_key` 填网关公钥。功能等同 v0.2：
单站点、客户端直连、隧道内 MFA。**注意**：直连模式下没有多站点汇总与 ACL。
