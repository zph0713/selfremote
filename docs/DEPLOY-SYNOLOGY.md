# 群晖 NAS 部署（Container Manager 图形界面）

> 目标：在群晖上用 **Container Manager → 项目** 起完整一套（nginx + web 控制面 +
> MariaDB + 中转服务端 + 本机站点），起完即在线：
> 网页注册管理员 → 本机站点自动挂上 → 生成客户端密钥 → Mac 上连回来。
>
> 全程只需要一次 SSH（跑 `init.sh` 生成密钥），其余都在图形界面点。
> 命令行版的部署说明见 [DEPLOY-NAS.md](DEPLOY-NAS.md)。

---

## 0. 先决条件（三分钟检查）

| 项 | 怎么确认 | 备注 |
|---|---|---|
| DSM 版本 | 控制面板 → 信息中心 | 需要 **DSM 7.2 或更新**（才有 Container Manager 的「项目」） |
| Container Manager | 套件中心 → 已安装 | DSM 6 叫 Docker，界面不同，本手册不适用 |
| SSH | 控制面板 → 终端机和 SNMP → 勾选「启动 SSH 功能」 | 只用来跑一次 `init.sh`，跑完可以关掉 |
| 共享文件夹 | File Station | 建议 `/volume1/docker/selfremote`（下面统称**项目目录**） |
| NAS 架构 | 控制面板 → 信息中心 → 处理器 | 绝大部分机型 x86_64；ARM 机型（如 DS223）也能用，镜像有多架构 |
| 内网网段 | 控制面板 → 网络 → 网络界面 | 本手册以 `192.168.2.0/24` 为例，按你的实际值改 |
| 外网怎么进 | 见第 8 步 | 有公网 IPv6 最省事；只有 IPv4 需要路由器做端口转发 |

---

## 1. 把部署文件放进 NAS

下载 **selfremote-stack-v0.4.zip**（本文档同目录），用 File Station 上传到 `/volume1/docker/`，
右键解压到 `/volume1/docker/selfremote`。解压后应该是：

```
/volume1/docker/selfremote/
├── docker-compose.yml      ← 五件套定义
├── .env.example            ← 配置模板（下一步复制成 .env）
├── init.sh                 ← 生成密钥/令牌/预置本机站点
└── nginx.conf              ← 控制面反代
```

> 目录里必须同时有这几样：compose 里的 `./nginx.conf` 是相对路径，
> 相对的是 compose 文件所在的目录。

## 2. 准备镜像（三选一）

| 方式 | 适用 | 做法 |
|---|---|---|
| **A. 从 ghcr.io 直接拉**（最省事） | NAS 能访问 ghcr.io | 第 5 步启动项目时自动拉；也可以 SSH `sudo docker pull ghcr.io/zph0713/selfremote:v0.4.0 && sudo docker pull ghcr.io/zph0713/selfremote-web:v0.4.0` |
| **B. 离线镜像包**（网络不通/很慢） | 国内网络拉不动 ghcr | 在开发机下载 Release 里的 `selfremote-image-linux-amd64.tar.gz` 与 `selfremote-web-image-linux-amd64.tar.gz` → 上传 NAS → Container Manager → **映像 → 新增 → 从文件添加**（或 SSH `gunzip -c x.tar.gz \| sudo docker load`） |
| **C. 自建镜像** | 你自己改了代码 | 开发机 `bash scripts/build-agent-dist.sh` + `docker build` 两个 Dockerfile → `docker save` → 上传 → 导入（同 B） |

镜像名要对得上 `.env` 里的 `SR_IMAGE` / `SR_WEB_IMAGE`（默认就是官方镜像名）。

## 3. 写配置 `.env`

File Station → 右键 `.env.example` → **复制** → 改名为 `.env` → 右键「用文本编辑器打开」，按下面改：

```ini
# 数据库口令：随便生成两个强口令（30 位随机串最好，别用中文/特殊符号）
DB_ROOT_PASSWORD=换成一串随机口令
DB_PASSWORD=换成另一串随机口令

# 数据目录：绝对路径（server 私钥、注册表、令牌都在这里）
SR_CONFIG_DIR=/volume1/docker/selfremote/data

# 端口
HTTP_PORT=8080                 # 被占用就换（见排查）
HTTP_ALT_PORT=28080            # 家宽拦 8080 时的备用入口
TUNNEL_PORT=28333              # 隧道 UDP 端口

# 服务端对外地址：先留空，起完在第 7 步核对
SERVER_ADDR=

# 本机站点（NAS 自己所在的内网）——【必改】成你家网段
LAN_CIDRS=192.168.2.0/24
HOME_SITE_ID=home
HOME_SITE_NAME=本机站点
```

## 4. SSH 跑一次初始化

```bash
# SSH 登录 NAS（账号是管理员）
sudo -i
cd /volume1/docker/selfremote

# 关键：把网段传进去（要和 .env 的 LAN_CIDRS 一致）
TUNNEL_PORT=28333 API_PORT=8770 LAN_CIDRS=192.168.2.0/24 \
  HOME_SITE_ID=home HOME_SITE_NAME=本机站点 \
  bash init.sh /volume1/docker/selfremote/data
```

成功会打印三样东西：`server.json` + `api-token`、`bootstrap-token`（**注册管理员要用，记下来**）、
`agent-home.json` + 预置站点文件。这三步都幂等，重复跑不会覆盖已有密钥。

> 这一步用的是 `docker run --rm <镜像> genkey`，所以要先有第 2 步的镜像。
> 若拉镜像慢，可以先 `sudo docker pull` 再跑 init。

## 5. Container Manager 开项目

1. Container Manager → 左侧 **项目** → **新增**
2. **项目名称**：`selfremote`
3. **路径**：选 `/volume1/docker/selfremote`
4. **来源**：选 **「使用现有的 docker-compose.yml」**（DSM 检测到该目录已有文件时会出现这个选项；
   不同 DSM 小版本措辞略有差异）。**不要**加 `docker-compose.desktop.yml` —— 那是 Docker Desktop 专用
5. 「下一步」→ 会列出 5 个服务 → **完成**（首次会自动拉镜像，坐着等）
6. 启动后项目详情里能看到 5 个容器：`db` / `web` / `nginx` / `server` / `agent-home`

> `server` 与 `agent-home` 用的是 **host 网络**（直接占用 NAS 的 UDP 28333 与 8770），
> 所以不需要在「端口设置」里映射它们；只有 nginx 映射了 8080/28080。

## 6. 验证（四个都过才算好）

```bash
# ① 容器状态：五个 Up（db 是 healthy）
sudo docker ps --format '{{.Names}}\t{{.Status}}'

# ② 控制面活着（返回 303/200 都算通）
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthz

# ③ 中转服务端在监听 UDP 28333（能看到 LISTEN 即可）
sudo netstat -anp | grep 28333

# ④ 本机站点已预置（应该能看到 agent-home 的配置）
sudo ls -l /volume1/docker/selfremote/data/
```

浏览器打开 `http://192.168.2.243:8080` → 出现登录页 = 成功一半。

## 7. 注册管理员 + 挂上本机站点

1. 登录页点「注册」→ 填用户名/口令/**部署令牌**（第 4 步的 `bootstrap-token`）
2. 绑定 Google Authenticator（扫码 → 输 6 位码确认）
3. 进入首页 → **站点 Agent** 页应看到 `home`（本机站点）状态 **在线**
4. 「客户端密钥」→ 生成密钥（勾选 `home`、设文件口令）→ 下载 `.srkey`
5. 打开刚下载的密钥看看 `server` 字段对不对（`cat` 出来是一段 JSON 的话已经加密了，
   改看网页上「服务端地址」显示值）——**不对就回第 3 步写死 `SERVER_ADDR`**
   （如 `nas.example.com:28333` 或 `[公网IPv6]:28333`），改完 `docker compose up -d web` 重建 web，
   然后**重新生成密钥**（密钥会把地址快照进去）。

## 8. 外网可达（决定能不能在外面连回来）

在**手机流量**（不要用家里 WiFi）上测：

- 有公网 IPv6（推荐）：直接访问 `http://[NAS的IPv6]:8080`。群晖「控制面板 → 外部访问 → DDNS」
  建议加一条（Synology DDNS 免费），顺手在同一页申请 **Let's Encrypt 证书**，
  之后就能用 `https://xxx.synology.me:8443` 这种带证书的入口（控制面建议开 HTTPS：
  上了证书后在 `.env` 里设 `COOKIE_SECURE=1` 并重建 web 容器）。
- 只有公网 IPv4：路由器上把 **TCP 8080** 和 **UDP 28333** 转发到 NAS（28333 必须转，
  不然客户端和外部站点都连不上）。
- 开启 DSM 防火墙的话，放行：`8080/tcp`、`28080/tcp`、`28333/udp`。
- 家用宽带常见拦截：运营商封入站 80/8080 → 换 `HTTP_ALT_PORT`（28080）试。

> 安全提醒：控制面是明文 HTTP，**不要裸奔公网**。要么只在内网/隧道内访问，
> 要么按上面配好证书走 HTTPS。

## 9. 之后的日常运维

```bash
cd /volume1/docker/selfremote

# 升级（最新镜像 + 重建容器；数据都在 data 目录和 db 卷里，不会丢）
sudo docker compose pull && sudo docker compose up -d

# 看日志（排查用）
sudo docker compose logs --tail=50 web server agent-home

# 停 / 起（也可以直接在 Container Manager 项目页点）
sudo docker compose stop
sudo docker compose start
```

**备份**（重要：`data/` 里有服务端私钥和全部注册表，丢了要重建整栈）：

```bash
sudo tar czf /volume1/backup/selfremote-data-$(date +%F).tar.gz \
  -C /volume1/docker/selfremote data
sudo docker exec selfremote-db-1 sh -c \
  'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" selfremote' > /volume1/backup/selfremote-db.sql
```

**再加一个远程站点**：网页「站点 Agent」→ 新建站点 → 拿安装码 →
在目标机器上执行一行命令（Linux）：

```bash
curl -fsSL http://192.168.2.243:8080/install.sh | sudo bash -s -- --code XXXX-XXXX
```

（目标机器要能访问控制面地址；跨网段的话用 DDNS 域名或公网地址）

## 10. 群晖特有的坑

| 现象 | 原因 / 处理 |
|---|---|
| 项目起不来，报端口被占用 | DSM 里别的套件占了 8080（下载器/监控常见）→ 改 `.env` 的 `HTTP_PORT` |
| 拉镜像超时 / TLS handshake timeout | 国内直连 ghcr 不稳 → 走第 2 步的**离线镜像包**；或在 DSM 控制面板 → 网络 → 代理服务器里配代理后重启 Container Manager |
| 「项目」里看不到「使用现有的 docker-compose.yml」 | 路径选错了（要选到 `/volume1/docker/selfremote` 这一层，里面有 docker-compose.yml） |
| `agent-home` 一直重启 | 看日志：多半是 `data/agent-home.json` 不存在（init.sh 没跑成，或 `SR_CONFIG_DIR` 与 init.sh 的路径不一致） |
| 站点显示离线 | `sudo docker compose logs --tail=50 agent-home`；它在容器里连 `127.0.0.1:28333`（host 网络），server 没起来就起不来 |
| 开了 Open vSwitch 的机型 | 不用改配置：转发/SNAT 规则是按「除隧道口 sr0 外的任何出口」生效的，`SR_LAN_IF` 只影响日志提示 |
| 客户端连不上、但网页正常 | UDP 28333 没通：路由器转发 `/ DSM 防火墙 / 运营商`。先在家用手机流量测 `[公网IPv6]:28333` — UDP 没有握手包，直接看客户端日志有没有 `session established` |
| 重启 NAS 后要重新设置？ | 不需要。容器带 `restart: unless-stopped` 会自启；`agent-home` 启动时自己设置 `ip_forward`（host 网络=作用于宿主） |

## 11. 卸载 / 重装

```bash
# 停服务但留数据（推荐）
sudo docker compose down            # 加 -v 会删掉 db 数据卷，谨慎

# 彻底重来：删项目（Container Manager → 项目 → 停止 → 删除），
# 再删目录 /volume1/docker/selfremote（data 里的密钥一并没了）
```
