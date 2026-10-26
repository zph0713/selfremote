# 开发栈部署：在另一台机器上验证新代码，不影响生产

目标：把分支上的新功能（当前是 M5.0 可观测）在**另一台机器**的 Docker 里跑起来看效果，
同时保证**正在运行的 server 端一个字节都不变**。

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

```sh
cd deploy/stack
docker compose -p selfremote-dev --env-file .env.dev \
  -f docker-compose.yml \
  -f docker-compose.desktop.yml \
  -f docker-compose.dev.yml up -d
docker compose -p selfremote-dev ps
```

浏览器打开 `http://<机器>:18080` → 用 `bootstrap-token` 注册管理员 → 绑定动态码 → 进入控制面。

## 8. 验收清单（M5.0）

- [ ] 导航栏出现「客户端连接」；页脚版本显示 v0.5.0
- [ ] `/clients` 能打开（空列表也有说明文案）
- [ ] `/agents` 列表有「当前速率 ↓ / ↑」列
- [ ] 站点详情出现「活跃端口与流量」表（无流量时是空表提示）
- [ ] 管控 API 可用（在开发机上）：
      `curl -s -H "Authorization: Bearer $(cat data-dev/api-token)" http://127.0.0.1:8771/api/v1/overview`
- [ ] 想看真实端口数据：用开发栈签发的 `.srkey` 跑 `sr socks` 连上，访问本机站点网段，
      然后刷新站点详情页（端口表每 2 秒自动刷新）

## 9. 确认没影响生产

```sh
docker ps --format '{{.Names}}' | grep selfremote          # 两套容器名各自带项目前缀
docker volume ls | grep selfremote                         # 两套 db-data 卷
ss -lunp | grep -E '28333|28334'                            # 端口各自监听
```

生产栈（如果在同机）应保持：`selfremote-server-1` 等容器**没有重启时间变化**、
镜像仍是 `ghcr.io/...:latest`、`deploy/stack/data` 目录未被改动。

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
