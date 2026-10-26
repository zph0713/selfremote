# 开发栈部署：在另一台机器上验证新代码，不影响生产

目标：把分支上的新功能（当前是 M5.0 可观测）在**另一台机器**的 Docker 里跑起来看效果，
同时保证**正在运行的 server 端一个字节都不变**。

> 交给另一台机器上的 AI 执行：直接给它 [AGENT-DEPLOY.md](AGENT-DEPLOY.md)（含硬约束、一键脚本、验收与汇报格式）。
> 一条命令搞定：`bash scripts/deploy-dev.sh --check` 预检 → `bash scripts/deploy-dev.sh --yes` 部署。

## 1. 隔离原则（两套栈没有任何共享）

| 项目 | 生产栈 | 开发栈（本文） |
|---|---|---|
| compose 项目名 | `selfremote` | **`selfremote-dev`** |
| 镜像 | `ghcr.io/zph0713/selfremote(-web):latest` | **本地 `:dev` 标签** |
| 数据目录 | `deploy/stack/data` | **`deploy/stack/data-dev`** |
| 数据库 | `selfremote` 项目的 `db-data` 卷 | **`selfremote-dev` 项目的 `db-data` 卷** |
| HTTP / 备用端口 | 8080 / 28080 | **18080 / 18081** |
| 隧道 UDP 端口 | 28333 | **28334** |
| 管控 API 端口 | 8770（仅环回） | **8771（开发机）** |
| hub 密钥 / 注册表 | `data/` 下的 `server.json`、`clients.json`、`agents.json` | **`data-dev/` 下另一套** |

结论：容器、网络、卷、密钥、数据库、端口全部另起一套；生产栈不重启、不换镜像、不迁移数据。

## 1.1 与旧版同机并行的两条硬规则

旧版正在跑，新版必须**同时**满足这两条，否则会在运行时互相踩：

1. **新版建议先不要起 `agent-home`（本机站点）**。在基础 compose 里它是 `host` 网络 +
   `NET_ADMIN` + `/dev/net/tun`，会在宿主机上建 `sr0` 并对 `10.77.0.0/24` 写 iptables
   MASQUERADE/FORWARD 规则——和旧版的本机站点用同一个网卡名与网段，规则会互相覆盖。
   （如果走的是 desktop 覆盖，agent-home 被改成 bridge 网络、规则关在容器自己的 netns 里，
   风险小很多；但为了少一个变量，第一轮仍然建议不起。）
   → 起栈时显式只起四个服务：`db web nginx server`（见 §7）。
   要在新版里验证「站点」功能，用**另一台 LAN 机器**做站点（新版网页生成安装码 → 那台机器装 agent）。
2. **测试客户端用 `sr socks`，不要同时开两个 TUN**。两套 hub 的隧道地址都从 `10.77.0.2` 起，
   同一台 Mac 同时连两个栈会抢同一个 TUN 地址/路由。`sr socks` 是用户态代理，不建 TUN、
   不改路由，适合并行验证。
3. **新版站点 agent 不要装在已经跑着旧 agent 的机器上**。agent 在宿主机上建 `sr0` 并对
   `10.77.0.0/24` 写 iptables 规则，同一台机器跑两个 agent（哪怕连的是不同 hub）会互相覆盖。
   → 新版的第一个站点请用**另一台机器**；如果只有一台，先停旧 agent 再装新的。

> 旧版彻底下线之后（见 §13），这三条限制自动解除：那时可以起 agent-home，也可以正常用 TUN 客户端。

## 2. 前提

- **另一台机器**（推荐）：Linux + Docker Engine + compose v2；Windows/macOS 的 Docker Desktop 也可以
- 磁盘 ~2 GB（两个镜像 + MariaDB 卷）
- 不要在跑着生产栈的那台 NAS 上加一套（虽然项目名隔离，但没必要冒险）

## 3. 拉代码（只切分支，不动 main）

```sh
git clone https://github.com/zph0713/selfremote.git
cd selfremote
git checkout feat/m5.0-observability
git log -1 --oneline        # 应看到 v0.5.0: 可观测 …
```

## 4. 构建 dev 镜像（tag 用 `:dev`，绝不产出 `:latest`）

```sh
# 在仓库根目录
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/sr-linux-amd64 ./cmd/sr
docker build -f deploy/nas/Dockerfile.prebuilt -t selfremote:dev .
docker build -f deploy/stack/web.Dockerfile  -t selfremote-web:dev .
```

> 想在站点页用「下载部署包」功能，先跑 `bash scripts/build-agent-dist.sh` 再构建 web 镜像
> （否则镜像里没有各平台 agent 二进制，页面会提示自行编译，不影响本批功能）。

## 5. 环境文件

```sh
cd deploy/stack
cp .env.dev.example .env.dev
vi .env.dev
```

必改两项：

- `DB_ROOT_PASSWORD` / `DB_PASSWORD`：随便设，**不要和生产相同**
- `SERVER_ADDR`：改成这台机器可达的地址，例如 `192.168.1.50:28334`

## 6. 生成独立的密钥与注册表（关键：用 `data-dev`）

```sh
cd deploy/stack
set -a; . ./.env.dev; set +a
TUNNEL_PORT="$TUNNEL_PORT" API_PORT="$API_PORT" API_BIND=0.0.0.0 \
  SR_IMAGE=selfremote:dev bash init.sh ./data-dev
cat data-dev/bootstrap-token      # 注册第一个管理员要用
```

- `API_BIND=0.0.0.0` 只用于开发栈：server 跑在桥接网络里，控制面容器要跨容器访问管控 API。
  生产保持默认 `127.0.0.1`。
- 这一步会新建一套 hub 密钥：**开发栈的客户端密钥必须由开发栈签发**，生产 `.srkey` 连不上它（反之亦然）。

## 7. 起栈

**与旧版同机并行时，只起这四个服务**（不要 `agent-home`，原因见 §1.1）：

```sh
cd deploy/stack
docker compose -p selfremote-dev --env-file .env.dev \
  -f docker-compose.yml \
  -f docker-compose.desktop.yml \
  -f docker-compose.dev.yml up -d db web nginx server
docker compose -p selfremote-dev ps
```

浏览器打开 `http://<机器>:18080` → 用 `bootstrap-token` 注册管理员 → 绑定动态码 → 进入控制面。

## 8. 验收清单（M5.0）

- [ ] 导航栏出现「客户端连接」；页脚版本显示 v0.5.0
- [ ] `/clients` 能打开（空列表也有说明文案）
- [ ] `/agents` 列表有「当前速率 ↓ / ↑」列
- [ ] 站点详情出现「活跃端口与流量」表（无流量时是空表提示）
- [ ] 管控 API 可用（在开发机上）：
      ```sh
      TOKEN=$(cat data-dev/api-token)
      curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8771/api/v1/overview
      ```
- [ ] 想看真实端口数据：用开发栈签发的 `.srkey` 跑 `sr socks` 连上，访问本机站点网段，
      然后刷新站点详情页（端口表每 2 秒自动刷新）

## 9. 确认没影响生产

一条命令跑完全部隔离检查（只读，不启停容器）：

```sh
bash scripts/check-dev-isolation.sh selfremote selfremote-dev
```

它检查五件事，任何一项 FAIL 就说明两套栈有共享：

1. 容器名前缀是否独立（compose 项目隔离）
2. 宿主发布端口是否重叠
3. 新版是否有容器用了 `host` 网络（会占宿主端口/TUN/iptables）
4. 新版镜像是否误用了 `ghcr.io/zph0713/selfremote:latest`
5. 新版挂载的数据目录是否指向生产 `data`

人工复核（可选）：

```sh
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}' | grep -E 'selfremote'
docker volume ls | grep selfremote
ss -lunp 2>/dev/null | grep -E '28333|28334'    # 两套各自监听
```

生产栈应保持：容器**重启时间不变**、镜像仍是 `ghcr.io/...:latest`、`deploy/stack/data` 未被改动。

## 10. 收尾

```sh
cd deploy/stack
# 停（保留数据，方便下次继续）
docker compose -p selfremote-dev --env-file .env.dev -f docker-compose.yml -f docker-compose.desktop.yml down
# 或彻底删掉（含数据库卷与开发密钥）
docker compose -p selfremote-dev --env-file .env.dev -f docker-compose.yml -f docker-compose.desktop.yml down -v
rm -rf data-dev
```

**清理必须带 `-p selfremote-dev`**：不带项目名时 compose 会用文件里的 `name: selfremote`，
那就是生产栈的项目名。

## 11. 禁止事项

- ❌ `git tag`、push `main`、更新 ghcr `:latest`（会让 NAS 的 `docker compose pull` 拉到新镜像）
- ❌ 复用生产的 `deploy/stack/data`（会改到生产密钥与注册表）
- ❌ 开发栈沿用 28333/8080/28080/8770（同机时会和 host 网络的生产 server 撞端口）
- ❌ 用生产 `.srkey` 连开发栈（hub 公钥不同，只会白折腾）

## 12. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 控制面提示「读不到中转服务端」 | `API_BIND` 没设 `0.0.0.0`，或 `SRV_API_URL` 不是 `http://host.docker.internal:8771` |
| 18080 打不开 | 端口被占或防火墙；看 `docker compose -p selfremote-dev logs nginx` |
| 本机站点一直离线 | Linux 上 `host.docker.internal` 需要 `extra_hosts`（dev 覆盖文件已加）；或 28334/UDP 未发布 |
| web 容器反复重启 | 数据库密码与卷里的不一致：改过密码要 `down -v` 重新初始化 |
| 客户端连上却访问不到内网 | `LAN_CIDRS` 要设成开发机真实能到的网段；或客户端密钥里没勾选站点 |
| IPv6 | 开发栈走桥接，只用 IPv4；生产 IPv6 直连不受影响 |

> 说明：这台 Mac 上 Docker 当前未运行，所以 `docker compose config` 没有实跑，
> 只做了 YAML/Shell 静态校验。第一次在目标机器上跑如果报错，把 `docker compose ... up` 的
> 输出贴回来即可定位。

## 13. 新版跑通后：切换并下线旧版

**前提**：新版验收通过——至少一台客户端（`sr socks` 或 TUN）和一个站点（另一台 LAN 机器）
在新版上跑通，端口流量能在页面看到。

### 13.1 先备份旧版（仓库外）

```sh
cd deploy/stack
tar czf ~/selfremote-old-data-$(date +%F).tar.gz data/
docker exec selfremote-db-1 mariadb-dump -usr -p"$DB_PASSWORD" selfremote > ~/selfremote-old-db-$(date +%F).sql
```

> 容器名以 `docker ps` 为准（`<项目名>-db-1`）。备份别放进仓库，避免误提交。

### 13.2 停旧版（保留数据，不要 `-v`）

```sh
cd deploy/stack
docker compose -p selfremote -f docker-compose.yml down
```

旧版用的是 `host` 网络，停掉后才会释放 28333/UDP 与 8080/28080。
**这一步会中断生产服务几十秒到几分钟**，安排在没人用的时候做。

### 13.3 新版二选一

- **只在局域网用**：保持现在的 18080 / 28334 不动，直接开始逐台切换客户端。
- **接管生产入口**（公网 IPv6 + 28333/UDP + 28080）：把新版按生产形态再起一遍——
  server 改回 `host` 网络（去掉 desktop 覆盖）、`server.json` 的 `listen` 用 28333、
  `api_listen` 用 `127.0.0.1:8770`。数据目录仍用 `data-dev`（独立），确认稳定后再谈迁移。

### 13.4 客户端与站点重新接入

新版 hub 是**新密钥**，旧 `.srkey` / 旧 agent 配置连不上（这是隔离的代价，也是安全的保证）：

1. 新版网页「站点 Agent」→ 建站点 → 复制安装命令 → 在目标机器执行；
2. 「客户端密钥」→ 建设备 → 下载 `.srkey` → 导入客户端（或走 M5.3 之后的注册码流程）；
3. 一台一台切，旧版停着但数据仍在，出问题可以立刻回退。

### 13.5 回退

```sh
# 停新版（保留 data-dev）
docker compose -p selfremote-dev --env-file .env.dev -f docker-compose.yml -f docker-compose.desktop.yml down
# 起旧版（数据和卷都还在）
cd deploy/stack && docker compose -p selfremote -f docker-compose.yml up -d
```

两套栈**不能同时**占用 28333/8080/28080，所以回退一定是"先停新的、再起旧的"。

### 13.6 确认稳定后再删旧版

稳定运行 3–7 天后再执行（备份在手、新版可用）：

```sh
docker compose -p selfremote -f docker-compose.yml down -v
rm -rf data/            # 旧密钥与注册表；先确认备份可用
```

删掉之后，新版可以正式接管端口与公网入口，`§1.1` 的两条并行限制也随之解除。
