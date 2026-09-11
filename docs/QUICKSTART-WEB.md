# Web 控制面：部署与使用（推荐方式）

> 一套 `docker compose` 起四件套：**nginx（反代）+ web（控制面）+ mariadb + gateway（隧道网关）**。
> 在网页上注册账号、绑定 Google Authenticator、生成客户端密钥；客户端连接时需要
> **文件密码 + 实时动态码** 双重校验。

```
浏览器 ──▶ nginx :8080 ──▶ web ──▶ mariadb（注册/账号/设备）
                             │
                  写 clients.json（白名单+动态码密钥）
                  读 status.json / netinfo.json（实时状态）
                             ▼
             gateway（网关容器，host 网络）──▶ 家庭内网
                             ▲
     Mac: sr client -c client-xxx.srkey（文件密码 → 动态码）
```

## 0. 前置条件

- 一台能跑 Docker 的主机（群晖 NAS / Linux / 树莓派均可）
- 客户端能连到它：公网 IPv6（推荐）或公网 IPv4；UDP 端口默认 `28333`
- 主机上 `/dev/net/tun` 可用（群晖/普通 Linux 都满足）

## 1. 部署

```sh
# 拿到项目文件（任选其一）
git clone https://github.com/zph0713/selfremote && cd selfremote/deploy/stack
# 或者从 Releases 下载源码包后进入 deploy/stack

cp .env.example .env
vi .env                  # 至少要改两个数据库密码；建议确认 LAN_CIDRS
bash init.sh             # 生成网关密钥与 gateway.json（幂等，只做一次）
docker compose up -d
```

浏览器打开 `http://<主机IP>:8080`（端口由 `.env` 的 `HTTP_PORT` 控制）。

> **不需要公网暴露 8080**：可以在家里局域网直接访问；出门后可以先把隧道连上，
> 再通过隧道里的内网 IP 访问本页面。

### 群晖 NAS 特别注意

1. 数据目录建议绝对路径：`.env` 里 `SR_CONFIG_DIR=/volume1/docker/selfremote`
2. 开启 Open vSwitch 的群晖，`.env` 里设 `SR_LAN_IF=ovs_eth0`
3. IPv4 转发要宿主固定开启（一次性）：控制面板 → 任务计划 → 新增「触发的任务」→
   开机运行 `sysctl -w net.ipv4.ip_forward=1`
4. 防火墙放行 `HTTP_PORT/tcp`（局域网访问可不放）与 `TUNNEL_PORT/udp`

## 2. 首次使用

1. **注册管理员**：打开页面 → 「创建管理员账号」（仅第一个账号可自助注册，
   之后的新账号由管理员在「用户」页创建）
2. **绑定 Google Authenticator**：注册后自动进入绑定页 → 用 App 扫码 →
   输入 App 显示的 6 位码完成绑定 → **保存页面给出的 10 个恢复码**（手机丢失时用）
3. 之后登录 = 用户名 + 密码 + 动态码（或恢复码）

## 3. 生成客户端密钥

「客户端密钥」→ 「生成新客户端密钥」：

- **设备名称**：如 `mac-air`
- **密钥文件密码**：≥10 位；在 Mac 上运行时要输入它来解密文件。
  **服务器不保存私钥、也保存不了这个密码——忘记了只能重新生成**

点「生成并下载」→ 得到 `client-mac-air.srkey`（加密文件）。

> 也支持「导入已有公钥」：把以前配好的设备公钥登记进来继续用。

## 4. 在 Mac 上连接

```sh
sudo ./selfremote-macos-arm64 client -c client-mac-air.srkey
# 该密钥文件已加密，请输入文件密码: ********
# 请输入 Google Authenticator 动态验证码（6 位）: 123456
```

看到 `════ selfremote 已连接 ════` 状态块即成功（内含服务端主机、隧道 IP、流量），
`Control + C` 退出并自动清理路由；服务端会立即看到你下线。

## 5. 日常操作与排障

| 动作 | 位置 |
|---|---|
| 看谁在线、流量多少 | 「总览」页（自动刷新） |
| 吊销某台设备 | 「客户端密钥」→ 吊销（在线会话数秒内被断开） |
| 加新账号 | 「用户」页（管理员）；新账号首次登录需自行绑定 MFA |
| 换手机 / 重装 App | 「设置」→ 重新绑定 |

常见问题：

- **动态码错误**：确认手机时间自动同步；连续错 3 次会锁定 30 秒
- **「暂时无法生成」**：网关刚启动还没写 `netinfo.json`，等 30 秒刷新重试；
  或 `.env` 里显式设置 `SERVER_ADDR`
- **改了 .env 里的数据库密码后 web 起不来（Access denied）**：MariaDB 只在**空数据卷**时
  初始化密码。要么 `docker compose down -v` 删卷重建（会清空账号数据），要么进 db 容器用
  root 改密码
- **客户端连不上**：先 `docker logs <项目名>-gateway-1` 看网关日志；
  确认 UDP `TUNNEL_PORT` 可达（IPv6 需路由器放行；部分光猫需关防火墙）
- **网页打不开**：`docker compose ps` 检查容器；`docker logs <项目名>-web-1`

## 6. 安全模型（简述）

- 私钥只存在于你下载的 `.srkey` 文件里（文件密码加密：argon2id + ChaCha20-Poly1305）；
  服务器只保存公钥
- 动态码在**加密隧道内**验证（网络上抓不到），有防重放（同一码不能用两次）与
  连续失败锁定；数据流量在通过动态码校验前一律丢弃
- 登录密码 argon2id 哈希存储；会话 Cookie HttpOnly + SameSite；登录失败限速
- 数据（账号、设备、会话）只保存在你自己的 mariadb 容器里
