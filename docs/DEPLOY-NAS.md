# 群晖 NAS 部署（草稿，待 M1.1 联调验证）

> 状态：**未验证** · 前置：Docker（Container Manager）、SSH 可用

## 0. 前置检查

在 NAS 上执行：

```sh
uname -m                 # x86_64 → sr-linux-amd64；aarch64 → sr-linux-arm64
ls -la /dev/net/tun      # 应存在，否则容器无法创建 tun 设备
sudo iptables --version  # DSM7 多为 iptables (legacy)，确认可用
```

DSM 控制面板 → 安全性 → 防火墙（若开启）：放行 **UDP 28333**。

## 1. 构建

方式 A（推荐）：Windows 上交叉编译，把二进制拷到 NAS

```sh
GOOS=linux GOARCH=amd64 go build -o dist/sr-linux-amd64 ./cmd/sr
```

方式 B：NAS 上 `docker build`（deploy/nas/Dockerfile，多阶段构建）

## 2. 运行

```sh
docker run -d --name selfremote-gw \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v /volume1/docker/selfremote:/etc/selfremote \
  selfremote:latest gateway -c /etc/selfremote/gateway.json
```

参数为什么必须这样：

- `--network host`：转发与 SNAT 规则要作用于宿主网络栈（容器与 NAS 共用一个网络命名空间）
- `--cap-add NET_ADMIN`：创建 tun、写 iptables
- `--device /dev/net/tun`：把宿主 tun 设备暴露给容器

## 3. 网络配置（由容器 entrypoint 自动执行，幂等）

```sh
sysctl -w net.ipv4.ip_forward=1

# 出 LAN 口做源地址改写（接口名按实际：eth0 / ovs_eth0）
iptables -t nat -C POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE

# 转发放行
iptables -C FORWARD -i sr0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i sr0 -o eth0 -j ACCEPT
iptables -C FORWARD -i eth0 -o sr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i eth0 -o sr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

## 4. 验证

- NAS 本机：`ping -c3 10.77.0.2`
- 在外的 Mac：连接后 `ping 192.168.1.x`（内网设备）、打开 `http://192.168.1.x:5000`
- 吞吐（可选）：`iperf3` 隧道内外对比

## 5. 排查备忘

| 现象 | 排查 |
|---|---|
| 容器内 iptables 报错 | DSM 的 iptables 版本/后端差异；确认 legacy vs nft |
| 小包通、大文件卡死 | 典型 MTU 问题：确认客户端 MTU 1360；兜底加 TCP MSS clamp 规则 |
| 内网设备不通但 NAS 通 | MASQUERADE 规则没生效 / 出接口名写错（ovs_eth0） |
| 外部完全连不上 | DSM 防火墙未放行 UDP；或 DDNS 域名解析的 v6 不是 NAS 当前地址 |
| 重启 NAS 后失效 | Docker `--restart unless-stopped` + entrypoint 幂等规则应能自愈；不一致时排查 |
