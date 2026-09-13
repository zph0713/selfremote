# 群晖 NAS 部署

> 目标：DSM 7.2+（Container Manager）· v0.3 起 NAS 通常同时扮演
> **中转服务端（server）** 与 **本机站点（agent-home）**；远程站点各自在别的机器上跑 agent。

## 0. 部署形态（已决策：docker-first）

- 中转服务端（`sr server`）：**无特权**容器，`--network host` 只是为了让宿主的 UDP 端口
  直接可用；不需要 `NET_ADMIN`、不需要 `/dev/net/tun`、不需要内核转发
- 本机站点（`sr agent`）：`network_mode: host` + `NET_ADMIN` + `/dev/net/tun`
  —— 它要建 tun、改转发、做 SNAT，这些必须作用于 NAS 宿主网络栈（这是"内网 IP 直连"本身的要求）
- **Mac 客户端不容器化**：macOS 上 Docker 容器在虚拟机内，碰不到宿主网络栈
- 远程站点用同一个镜像（或部署包里的二进制），可在任意能出站 UDP 的机器上跑

## 1. 前置检查（NAS，SSH）

```sh
uname -m                 # x86_64 → amd64 镜像；aarch64 → arm64 镜像
ls -la /dev/net/tun      # 站点容器需要；只跑 server 的话不要求
iptables --version       # 看后端（legacy / nft）
```

DSM 控制面板 → 安全性 → 防火墙（若开启）：放行 **UDP 28333**（入站）、
`HTTP_PORT/tcp`（控制面，局域网访问可不放）。**不要**把管控 API 端口（8770）暴露到公网。

## 2. 获取镜像（二选一）

### 方式 A：预编译镜像（推荐，不用从 Docker Hub 拉构建镜像）

```sh
# Windows 开发机（项目根目录）
GOOS=linux GOARCH=amd64 go build -o dist/sr-linux-amd64 ./cmd/sr
docker build -f deploy/nas/Dockerfile.prebuilt -t selfremote:latest .
docker save selfremote:latest -o dist/selfremote-image.tar

# NAS SSH
cd /volume1/docker/selfremote && docker load -i selfremote-image.tar
```

（Web 控制面镜像同理：`docker build -f deploy/stack/web.Dockerfile -t selfremote-web:latest .`，
或用 Release 里的 `selfremote-web-image-linux-amd64.tar.gz`。）

### 方式 B：NAS 上从源码构建（需要能访问 Docker Hub）

```sh
docker build -f deploy/nas/Dockerfile -t selfremote:latest .
docker build -f deploy/stack/web.Dockerfile -t selfremote-web:latest .
```

## 3. 推荐：全套 compose（中转 + 控制面 + 本机站点）

```sh
cd /volume1/docker/selfremote           # 从仓库复制 deploy/stack/ 到这里的目录
cp .env.example .env
vi .env                                 # 数据库密码、SR_AGENT_KEYPASS、SR_CONFIG_DIR=/volume1/docker/selfremote/data
bash init.sh                            # 生成 server.json 与控制面令牌（幂等）
docker compose up -d                    # nginx + web + mariadb + server
```

浏览器打开 `http://<NAS内网IP>:8080` → 注册管理员 → 绑定 Google Authenticator →
「站点 Agent」添加站点（id 用 `home`，网段填 NAS 所在内网，例如 `192.168.1.0/24`）→
下载部署包 → 把包里的 `home.srkey` 放到 `/volume1/docker/selfremote/data/agent-home.srkey` →
`.env` 里 `SR_AGENT_KEYPASS` 填下载时设的文件密码 → `docker compose up -d agent-home`。

之后：状态应显示「在线」；在 Mac 上用网页生成的 `client-*.srkey` 连接即可访问内网。

> 只要中转（不要 NAS 本机站点）：`docker compose up -d nginx web db server`，
> 其余站点用部署包在各自机器上运行。

## 4. 只有一个容器也行（纯命令行模式）

不用控制面时，NAS 可以只跑 **server + 一个站点 agent**（都是同一个镜像）：

```sh
# 中转服务端（无特权）
docker run -d --name selfremote-server --restart unless-stopped \
  --network host -v /volume1/docker/selfremote/config:/etc/selfremote \
  selfremote:latest server -c /etc/selfremote/server.json

# 本机站点（需要 tun 与 NET_ADMIN）
docker run -d --name selfremote-agent --restart unless-stopped \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  -v /volume1/docker/selfremote/config:/etc/selfremote \
  selfremote:latest agent -c /etc/selfremote/home.json
```

配置写法见 [QUICKSTART-SERVER.md](QUICKSTART-SERVER.md)（`server.json` / `agents.json` / `clients.json`）。
**注意**：手工模式下 `clients.json` / `agents.json` 由你自己维护（控制面会自动维护它们）。

v0.2 的直连模式（`selfremote:latest gateway -c gateway.json`）仍然可用，见本文档附录。

## 5. 转发开关（站点容器必须）

站点容器 entrypoint 会尽力设置 `net.ipv4.ip_forward=1`，但群晖宿主重启后**以开机任务为准**：

> DSM 控制面板 → 任务计划 → 新增 → 触发的任务 → **开机** → 用户 `root` →
> 命令：`sysctl -w net.ipv4.ip_forward=1`

## 6. 验证

- `docker logs selfremote-server`：站点连上应出现 `session established with ... [agent]`
- `docker logs selfremote-agent`：应出现 `═══ selfremote agent 已上线 ═══` 横幅
- 网页「站点 Agent」：状态「在线」，网段与流量正常刷新
- 在外的 Mac：`ping 10.200.7.50`（虚拟网段+主机号）、`ping 10.77.0.1`（服务端可达）
- 吞吐（可选）：`iperf3` 隧道内外对比

## 7. 排查备忘

| 现象 | 排查 |
|---|---|
| 站点容器起不来，报 tun 错误 | `/dev/net/tun` 未映射或宿主无该设备 |
| 站点容器日志停在"找不到配置文件" | 正常：先在网页创建站点并下载 `.srkey` 放到数据目录，容器会自动继续 |
| iptables 报错 | 换后端：compose 里设 `SR_IPT: iptables`（或 `iptables-legacy`）；DSM 内核多为 legacy |
| 内网设备不通但 NAS 通 | 站点容器 `ip_forward` 未开（见第 5 节）；或站点上报名段与实际不符（重新下载部署包） |
| 小包通、大文件卡死 | 典型 MTU 问题：确认客户端 MTU 1360；必要时加 TCP MSS clamp |
| 外部完全连不上 | DSM 防火墙未放行 UDP；DDNS 解析的 v6 不是 NAS 当前地址 |
| 网页看不到站点状态 | 控制面容器能否访问 `SRV_API_URL`（默认 `http://server:8770`）；`docker logs <项目>-web-1` |
| 重启 NAS 后失效 | Docker `restart: unless-stopped` + entrypoint 幂等规则应能自愈；不一致时检查开机任务 |

## 附录：v0.2 直连模式（`sr gateway`）

客户端能直连 NAS 公网地址时可用（单站点、无汇总/ACL）：

```sh
docker run -d --name selfremote-gw --restart unless-stopped \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v /volume1/docker/selfremote/config:/etc/selfremote \
  selfremote:latest gateway -c /etc/selfremote/gateway.json
```

客户端配置里的 `server` 直接填 NAS 的公网地址，`server_public_key` 填网关公钥；
`deploy/examples/gateway.json.example` 有模板。
