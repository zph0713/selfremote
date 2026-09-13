# selfremote

自研远程接入隧道（类 VPN）：让在外网的设备（Mac / 笔记本）直连**任意一个自己部署的站点的内网 IP**
—— 访问 NAS、路由器、其它设备，像在家一样。多个站点（家里、公司、朋友家）集中到一台中转服务端，
由 Web 控制面统一管理：站点状态、启停、踢线、部署包下载，客户端密钥与站点权限都在页面上配置。

## 现状

- 阶段：**M3.2** —— v0.3 已把系统拆成四个角色：**中转服务端 `sr server` / 站点 `sr agent` /
  客户端 `sr client` / Web 控制面**；两条链路都强制 MFA；站点网段冲突用虚拟网段 + 地址翻译解决
- 形态：`client ──隧道──▶ server（用户态中转，无 TUN 无特权）──隧道──▶ agent ──▶ 站点内网`
- 协议：全自研帧格式与会话管理；密码学使用成熟库（Noise IK / X25519 / ChaCha20-Poly1305 / BLAKE2s）
- 安全：客户端密钥与站点配置都在网页生成时以「文件密码」加密（`.srkey`）；两条隧道连接都需动态码
  （客户端人工输码、站点用配置里的密钥自动应答；隧道内校验、防重放、失败锁定）
- 兼容：v0.2 的直连模式（`sr gateway`）与老客户端配置继续可用

## 两条线

### 🖥 服务端（Docker，任意位置）

```sh
git clone https://github.com/zph0713/selfremote && cd selfremote/deploy/stack
cp .env.example .env    # 改数据库密码；可选 SERVER_ADDR / LAN_CIDRS
bash init.sh            # 生成 server.json 与控制面令牌（一次）
docker compose up -d    # nginx + web + mariadb + server
```

打开 `http://<主机>:8080` → 注册管理员 → 绑定 Google Authenticator → **站点 Agent 页添加站点**
（本机站点 id 用 `home`）→ 下载部署包 → 把包里的 `.srkey` 放到数据目录并 `docker compose up -d agent-home`。

详见 [docs/QUICKSTART-WEB.md](docs/QUICKSTART-WEB.md)；纯命令行模式（无 Web）见
[docs/QUICKSTART-SERVER.md](docs/QUICKSTART-SERVER.md)；群晖细节见 [docs/DEPLOY-NAS.md](docs/DEPLOY-NAS.md)

### 💻 客户端（在外网的设备）

1. 到 [Releases](https://github.com/zph0713/selfremote/releases) 下载对应平台文件
2. 在 Web 控制面「客户端密钥」里勾选可访问站点并生成 `client-*.srkey`
3. `sudo ./selfremote-macos-arm64 client -c client-yourname.srkey` → 输入文件密码 → 动态码

详见 [docs/QUICKSTART-CLIENT.md](docs/QUICKSTART-CLIENT.md)

### 🌐 站点（Agent，任意能访问目标内网的机器）

网页「站点 Agent」创建站点后，页面会给出一行安装命令 —— 在目标机器上（root）执行即可：

```sh
curl -fsSL http://<控制面>:8080/install.sh | sudo bash -s -- --code ABCD-EFGH   # 末尾加 --docker 走容器方式
```

脚本会下载 agent、用一次性安装码换注册（**密钥在目标机器上生成**）、装成开机自启的服务。
站点主动拨号接入，**可位于 NAT 后，不需要任何入站端口**。本机站点由初次部署的
`init.sh` + compose 自带，无需这一步。

> 完全不联网的目标机器：用站点详情页里的「离线部署包（zip）」，拷过去按 README 运行。

## 文档

- [Web 控制面：部署与使用（推荐）](docs/QUICKSTART-WEB.md)
- [客户端快速开始](docs/QUICKSTART-CLIENT.md) · [服务端 / 站点（命令行模式）](docs/QUICKSTART-SERVER.md)
- [架构设计](docs/DESIGN.md) · [协议规格](docs/PROTOCOL.md) · [群晖 NAS 部署](docs/DEPLOY-NAS.md)

## 开发

```sh
go build ./... && go test ./...            # 构建与全量测试
go run ./cmd/sr genkey                     # 生成密钥对（base64）
go run ./cmd/sr server -c server.json      # 本机跑中转服务端
go run ./cmd/web -dsn '<MariaDB DSN>' -data ./data   # 本机跑 Web 控制面

# Docker 端到端冒烟（真 TUN + 转发 + NAT，v0.2 直连模式）
bash scripts/e2e-docker.sh
# v0.3 三容器真内核全链路（双 MFA + 地址翻译 + 停用/启用 + 踢线）
bash scripts/e2e-hub.sh
# v0.3 控制面全链路（真库 + 真服务端 + 真网页流程 + 部署包下载）
bash scripts/e2e-control.sh
```

> 注：Go module 路径暂为 `selfremote`，将来发布模块时一并改名。

## 仓库结构

```
cmd/sr/            CLI（server / agent / gateway / client / genkey）
cmd/web/           Web 控制面入口
internal/tunnel/   协议核心：握手、会话、帧、MFA、注册表、TUN、用户态中转、地址翻译
internal/serverapp/ 中转服务端管控 API（状态 / 踢线 / 刷新）
internal/keyfile/  加密配置文件（argon2id + ChaCha20-Poly1305）
internal/webapp/   控制面：账号、站点、客户端密钥、部署包、hub API 客户端
internal/config/   配置加载
deploy/nas/        站点容器（Dockerfile / entrypoint，agent 与 gateway 共用）
deploy/stack/      全家桶 compose（nginx + web + mariadb + server + agent-home）
deploy/examples/   配置模板（client.json / gateway.json / server.json / agent.json）
docs/              设计、协议与使用文档
scripts/           e2e 与打包脚本
```
