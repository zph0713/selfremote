# selfremote

自研远程接入隧道（类 VPN）：让在外网的 Mac 随时随地直连家庭内网 —— 访问 NAS、路由器、其它设备的**内网 IP**，像在家一样。

## 现状

- 阶段：**M1.0**（协议核心开发中）
- 形态：L3 覆盖网（Mac utun ← UDP/IPv6 → 群晖 NAS 网关 ← SNAT → 家庭内网）
- 传输：优先 **IPv6 直连**（家里南京电信 v6 可入站，NAS 已绑定域名并验证过）；中转/打洞为后续里程碑
- 协议：全自研帧格式与会话管理；密码学使用成熟库（Noise IK / X25519 / ChaCha20-Poly1305 / BLAKE2s）

## 文档

- [架构设计](docs/DESIGN.md)
- [协议规格 v0.1](docs/PROTOCOL.md)
- [群晖 NAS 部署](docs/DEPLOY-NAS.md)

## 快速开始

```sh
go build ./cmd/sr          # 本机构建
./sr genkey                # 生成密钥对（base64 私钥/公钥）

# 交叉编译
GOOS=linux  GOARCH=amd64 go build -o dist/sr-linux-amd64  ./cmd/sr   # NAS
GOOS=darwin GOARCH=arm64 go build -o dist/sr-darwin-arm64 ./cmd/sr   # Mac (Apple Silicon)
GOOS=darwin GOARCH=amd64 go build -o dist/sr-darwin-amd64 ./cmd/sr   # Mac (Intel)
```

> 注：Go module 路径暂为 `selfremote`，将来发布到 GitHub 时一并改名。

## 仓库结构

```
cmd/sr/           CLI 入口（genkey / gateway / client）
internal/tunnel/  协议核心：握手、会话、帧、UDP 传输、TUN 设备
internal/config/  配置加载
deploy/nas/       群晖部署（Dockerfile / compose / 说明）
docs/             设计与部署文档
```
