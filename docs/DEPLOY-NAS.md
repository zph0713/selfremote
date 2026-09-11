# 群晖 NAS 部署（Docker 容器）

> 状态：**未验证**（M1.1 联调时执行）· 目标：DSM 7.2+（Container Manager）

## 0. 部署形态（已决策：docker-first）

- 网关以 **Docker 容器**运行：`network_mode: host` + `NET_ADMIN` + `/dev/net/tun`
- 容器化 ≠ 零主机改动：host 网络、IPv4 转发开关本质上要作用于 NAS 宿主网络栈——这是「内网 IP 直连」功能本身的要求（转发/NAT 规则必须生效在宿主的网络栈上），隧道类容器（WireGuard/Tailscale 的 NAS 版）都是这个形态
- **Mac 客户端不容器化**：macOS 上 Docker 容器在 Linux 虚拟机内，碰不到宿主网络栈；utun 创建与路由注入必须由原生进程完成（见 docs/DESIGN.md 决策记录）
- 未来 M2 的中继（relay）沿用同一镜像、同一容器套路

## 1. 前置检查（NAS，SSH）

```sh
uname -m                 # x86_64 → amd64 镜像；aarch64 → 需 arm64 镜像（重新构建）
ls -la /dev/net/tun      # 应存在；没有则需确认内核 tun 模块
iptables --version       # 看后端（legacy / nft）
```

DSM 控制面板 → 安全性 → 防火墙（若开启）：放行 **UDP 28333**（入站）。
控制面板 → 终端机和 SNMP：开启 SSH（部署时用）。

## 2. 构建镜像（二选一）

### 方式 A（推荐：不用从 Docker Hub 拉大镜像）

在 Windows 开发机（项目根目录）：

```sh
GOOS=linux GOARCH=amd64 go build -o dist/sr-linux-amd64 ./cmd/sr
docker build -f deploy/nas/Dockerfile.prebuilt -t selfremote:latest .
docker save selfremote:latest -o dist/selfremote-image.tar
```

把 `dist/selfremote-image.tar` 传到 NAS（例如 File Station 上传到 `/volume1/docker/selfremote/`），然后：

```sh
# NAS SSH
cd /volume1/docker/selfremote
docker load -i selfremote-image.tar
```

### 方式 B：NAS 上从源码构建（需要能访问 Docker Hub）

```sh
# 仓库源码放到 NAS 后（或 git clone）
docker build -f deploy/nas/Dockerfile -t selfremote:latest .
```

## 3. 准备配置与启动

目录结构（示例）：

```
/volume1/docker/selfremote/
├── selfremote-image.tar      # 方式 A 的镜像
├── docker-compose.yml        # 从 deploy/nas/ 复制
└── config/
    └── gateway.json
```

`gateway.json` 用 `sr genkey` 生成密钥后填写（见 docs/PROTOCOL.md 第 6 节）。

启动（二选一）：

- **Container Manager → 项目 → 新增**：选择 `docker-compose.yml` 所在目录，构建启动
- **SSH**：`cd /volume1/docker/selfremote && docker compose up -d`

备选（不用 compose 时）：

```sh
docker run -d --name selfremote-gw \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v /volume1/docker/selfremote/config:/etc/selfremote \
  selfremote:latest gateway -c /etc/selfremote/gateway.json
```

## 4. 转发开关（必须，二选一）

容器 entrypoint 会尽力设置 `net.ipv4.ip_forward=1`，但群晖宿主重启后**以开机任务为准**：

> DSM 控制面板 → 任务计划 → 新增 → 触发的任务 → **开机** → 用户 `root` →
> 命令：`sysctl -w net.ipv4.ip_forward=1`

## 5. 验证

- 容器日志：`docker logs selfremote-gw`（应看到 network setup 与 gateway 启动输出）
- NAS 本机：`ping -c3 10.77.0.2`（客户端连上后）
- 在外的 Mac：`ping 192.168.1.x`、打开 `http://192.168.1.x:5000`
- 吞吐（可选）：`iperf3` 隧道内外对比

## 6. 排查备忘

| 现象 | 排查 |
|---|---|
| 容器起不来，报 tun 错误 | `/dev/net/tun` 未映射或宿主无该设备 |
| iptables 报错 | 换后端：compose 里设 `SR_IPT: iptables`（或 `iptables-legacy`）；DSM 内核多为 legacy |
| 内网设备不通但 NAS 通 | `SR_LAN_IF` 写错（Open vSwitch 机型是 `ovs_eth0`）；或 ip_forward 未开 |
| 小包通、大文件卡死 | 典型 MTU 问题：确认客户端 MTU 1360；必要时加 TCP MSS clamp |
| 外部完全连不上 | DSM 防火墙未放行 UDP；DDNS 域名解析的 v6 不是 NAS 当前地址 |
| 重启 NAS 后失效 | Docker `restart: unless-stopped` + entrypoint 幂等规则应能自愈；不一致时检查开机任务 |
