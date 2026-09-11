# selfremote

自研远程接入隧道（类 VPN）：让在外网的设备（Mac / 笔记本）直连**家庭内网的内网 IP** —— 访问 NAS、路由器、其它设备，像在家一样。
可选用 Web 控制面管理（注册 / Google Authenticator 动态码 / 客户端密钥 / 实时总览）。

## 现状

- 阶段：**M1.1 进行中** —— 协议核心、分发流水线、**Web 控制面（v0.2）** 均已就绪并测试通过；待 NAS 实机部署
- 形态：L3 覆盖网（utun ← UDP/IPv6 → 网关容器 ← SNAT → 家庭内网）；优先 IPv6 直连
- 协议：全自研帧格式与会话管理；密码学使用成熟库（Noise IK / X25519 / ChaCha20-Poly1305 / BLAKE2s）
- 安全：客户端密钥文件在网页生成时即以「文件密码」加密（`.srkey`）；连接需实时动态码
  （MFA 在加密隧道内校验、防重放、失败锁定）

## 两条线

### 💻 客户端（在外网的设备）

1. 到 [Releases](https://github.com/zph0713/selfremote/releases) 下载对应平台文件
2. 用 Web 控制面生成 `client-*.srkey`（加密密钥文件）；没有控制面时手写 `client.json`
3. `sudo ./selfremote-macos-arm64 client -c client-yourname.srkey` → 输入文件密码 → 动态码

详见 [docs/QUICKSTART-CLIENT.md](docs/QUICKSTART-CLIENT.md)

### 🖥 服务端（Docker，任意位置）

```sh
git clone https://github.com/zph0713/selfremote && cd selfremote/deploy/stack
cp .env.example .env    # 改数据库密码；可选 SERVER_ADDR / LAN_CIDRS
bash init.sh            # 生成网关密钥（一次）
docker compose up -d    # nginx + web + mariadb + gateway
```

打开 `http://<主机>:8080` → 注册管理员 → 绑定 Google Authenticator → 生成客户端密钥。

详见 [docs/QUICKSTART-WEB.md](docs/QUICKSTART-WEB.md)；纯命令行模式（无 Web）见
[docs/QUICKSTART-SERVER.md](docs/QUICKSTART-SERVER.md)；群晖细节见 [docs/DEPLOY-NAS.md](docs/DEPLOY-NAS.md)

## 文档

- [Web 控制面：部署与使用（推荐）](docs/QUICKSTART-WEB.md)
- [客户端快速开始](docs/QUICKSTART-CLIENT.md) · [服务端（命令行模式）](docs/QUICKSTART-SERVER.md)
- [架构设计](docs/DESIGN.md) · [协议规格](docs/PROTOCOL.md) · [群晖 NAS 部署](docs/DEPLOY-NAS.md)

## 开发

```sh
go build ./... && go test ./...            # 构建与全量测试
go run ./cmd/sr genkey                     # 生成密钥对（base64）
go run ./cmd/web -dsn '<MariaDB DSN>' -data ./data   # 本机跑 Web 控制面

# Docker 端到端冒烟（真 TUN + 转发 + NAT）
bash scripts/e2e-docker.sh
# 全家桶 e2e（compose 栈 + Web 注册/绑码/下密钥 + 客户端 MFA 连接 + 吊销）
bash scripts/e2e-stack.sh
```

> 注：Go module 路径暂为 `selfremote`，将来发布模块时一并改名。

## 仓库结构

```
cmd/sr/            CLI（genkey / gateway / client）
cmd/web/           Web 控制面入口
internal/tunnel/   协议核心：握手、会话、帧、MFA 校验、客户端注册表热加载
internal/keyfile/  加密密钥文件（argon2id + ChaCha20-Poly1305）
internal/webapp/   控制面：注册/登录/TOTP/设备管理/仪表盘（内置模板与样式）
internal/config/   配置加载
deploy/nas/        网关容器（Dockerfile / entrypoint / compose）
deploy/stack/      全家桶 compose（nginx + web + mariadb + gateway + init.sh）
deploy/examples/   配置模板（client.json / gateway.json）
docs/              设计、协议与使用文档
scripts/           e2e 脚本
```
