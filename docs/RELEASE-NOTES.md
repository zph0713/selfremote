# v0.3.0 — 服务端 / 站点（Agent）/ 客户端 / 控制面 四角色拆离

这一版把原来的「网关」一分为二：**中转服务端**只做汇总与转发，**站点 Agent** 负责某个内网的
接入；客户端与 Web 控制面延续 v0.2 的能力，并新增站点管理与部署分发。

## 新增

### 🛰 中转服务端（`sr server`）

- 一个 UDP 端口同时接受**客户端**与**站点 Agent**，在用户态完成中转：
  **不需要 TUN、NET_ADMIN、ip_forward** —— 任意 VPS / 容器 / 笔记本都能跑
- 按站点申报的网段选路；逐包校验源地址（防伪造）、目标站点、在线状态与
  **客户端→站点 ACL**；站点之间、客户端之间默认不可互访
- 自答 `10.77.0.1` 的 ICMP echo（"服务端可达"诊断）
- 热加载 `clients.json` + `agents.json`（控制面写入，删除条目 = 立即吊销）
- 管控 API：`GET /api/v1/status|agents`、`POST /api/v1/agents/{id}/kick|refresh`（Bearer 令牌）

### 🌐 站点 Agent（`sr agent`）

- **主动拨号**服务端：可部署在 NAT/防火墙之后，不需要任何入站端口
- 本地网络承接：tun + `ip_forward` + 源地址改写（多网卡无需指定接口名）
- **每站点虚拟网段 + 无状态地址翻译**：两个站点都跑 `192.168.1.0/24` 也能同时接入
  （站点侧改写 real ↔ virtual，校验和/分片/IPv6 全覆盖）
- **无人值守 MFA**：配置文件携带独立动态码密钥，自动应答服务端的挑战；断电重启自动续连
- 上报心跳（主机名/版本/网段/流量），执行管控指令：停用 / 启用 / 立即重连 / 立刻上报
- 配置文件支持 `.srkey` 加密（文件密码），支持 `SR_KEYPASS` / `SR_AGENT_SERVER` 环境覆盖

### 🖥 Web 控制面

- **站点 Agent 页**：实时状态（在线/认证中/离线/已停用）、流量、最后心跳、网段冲突告警；
  启停、踢线重连、轮换动态码密钥、删除站点
- **一键部署包**：下载 zip = 平台对应的 agent 二进制 + 加密配置（含站点私钥与动态码密钥）
  + 中文部署说明（Linux systemd/容器、macOS）；每次下载换新密钥（旧包随即失效）
- **客户端密钥**：勾选可访问站点 → 路由与服务端 ACL 同时落地；隧道地址自动分配；
  设备列表可在线调整站点权限（立即生效）
- 总览页展示服务端状态、站点与连接的汇总；控制面与中转服务端通过管控 API 解耦

### 🧰 部署与分发

- 全家桶 compose：`nginx + web + mariadb + server + agent-home`（本机站点）
- `init.sh` 生成 `server.json` 与控制面令牌；`agent-home` 首次启动会等待配置文件
- web 镜像内置各平台 agent 二进制（CI 构建），部署包页面直接下载
- 新增 e2e：`scripts/e2e-hub.sh`（三容器真内核全链路）、`scripts/e2e-control.sh`（控制面全流程）

## 兼容性

- `sr gateway`（v0.2 直连模式）与老 `.srkey` 客户端配置**继续可用**（协议帧向后兼容）
- MFA 校验规则微调：**同一时间步内允许重连复用同一动态码**（无人值守站点需要），
  跨时间步仍然拒绝重放
- 旧的 `gateway.json` 无需改动；新安装用 `server.json`

## 升级步骤（v0.2 → v0.3）

1. 拉新镜像：`docker pull ghcr.io/zph0713/selfremote:latest` 与 `...-web:latest`
2. `deploy/stack`：`cp .env.example .env`（新增 `SR_AGENT_KEYPASS`）→ `bash init.sh`（生成 `server.json`）
3. `docker compose up -d`（服务名 `gateway` → `server`，compose 文件已更新）
4. 网页：添加站点（本机站点 id=home，网段填你的内网）→ 下载部署包 → 把 `.srkey` 放到数据目录
   → `docker compose up -d agent-home`
5. 客户端：到「客户端密钥」重新生成 `.srkey`（勾选站点），替换 Mac 上的旧文件即可

## 验证

- `go test ./...` 全绿（含中转/翻译/注册表/管控新测试）
- `bash scripts/e2e-hub.sh` → `E2E_HUB_PASS`：客户端→服务端→站点→内网全链路，双 MFA、
  地址翻译（ping + TCP）、停用/启用、踢线
- `bash scripts/e2e-control.sh` → `E2E_CONTROL_PASS`：真数据库 + 真服务端 + 真页面流程，
  站点创建、部署包结构校验、客户端站点权限、启停写入注册表
