# selfremote

自研远程接入隧道（类 VPN）：让在外网的设备（Mac / 笔记本）直连**家庭内网的内网 IP** —— 访问 NAS、路由器、其它设备，像在家一样。

## 现状

- 阶段：**M1.0 完成**（协议核心已实现，20 项测试全绿）；下一步 M1.1：NAS 部署 + Mac 真机联调
- 分发：**客户端**下载即用（GitHub Releases）；**服务端**任意 Docker 主机部署（ghcr.io / 离线 tar）
- 形态：L3 覆盖网（utun ← UDP/IPv6 → 网关容器 ← SNAT → 家庭内网）；优先 IPv6 直连
- 协议：全自研帧格式与会话管理；密码学使用成熟库（Noise IK / X25519 / ChaCha20-Poly1305 / BLAKE2s）

## 两条线

### 💻 客户端（在外网的设备）

1. 到 [Releases](https://github.com/zph0713/selfremote/releases) 下载对应平台文件
2. 生成密钥、填 `client.json`
3. `sudo ./selfremote-macos-arm64 client -c client.json`

详见 [docs/QUICKSTART-CLIENT.md](docs/QUICKSTART-CLIENT.md)

### 🖥 服务端（Docker，任意位置）

```sh
docker pull ghcr.io/zph0713/selfremote:latest   # 或离线 tar / 源码构建
# genkey → gateway.json → docker run（见文档）
```

详见 [docs/QUICKSTART-SERVER.md](docs/QUICKSTART-SERVER.md)；群晖细节见 [docs/DEPLOY-NAS.md](docs/DEPLOY-NAS.md)

## 文档

- [客户端快速开始](docs/QUICKSTART-CLIENT.md)
- [服务端快速开始](docs/QUICKSTART-SERVER.md)
- [架构设计](docs/DESIGN.md) · [协议规格 v0.1](docs/PROTOCOL.md) · [群晖 NAS 部署](docs/DEPLOY-NAS.md)

## 开发

```sh
go build ./cmd/sr          # 本机构建
./sr genkey                # 生成密钥对（base64 私钥/公钥）

# 交叉编译
GOOS=linux  GOARCH=amd64 go build -o dist/sr-linux-amd64  ./cmd/sr
GOOS=darwin GOARCH=arm64 go build -o dist/sr-darwin-arm64 ./cmd/sr

# Docker 端到端冒烟（真 TUN + 转发 + NAT，需本机有 Docker）
bash scripts/e2e-docker.sh
```

> 注：Go module 路径暂为 `selfremote`，将来发布模块时一并改名。

## 仓库结构

```
cmd/sr/           CLI 入口（genkey / gateway / client）
internal/tunnel/  协议核心：握手、会话、帧、UDP 传输、TUN 设备
internal/config/  配置加载
deploy/nas/       Docker 部署（Dockerfile×2 / docker-compose.yml / entrypoint.sh）
deploy/examples/  配置模板（client.json / gateway.json）
docs/             设计、协议、快速开始文档
scripts/          e2e 冒烟脚本
```
