# selfremote M5 设计：可观测 · 站点可配置 · 客户端注册与桌面端

状态：**设计已定稿，待开工**
前置：[DESIGN.md](DESIGN.md)（架构）、[PROTOCOL.md](PROTOCOL.md)（协议）、[SECURITY.md](SECURITY.md)（安全）
版本线：v0.5.0 – v0.5.4（M4.0/M4.1 已被站点接入与打洞占用，本批顺延为 M5）

## 1. 目标

| 目标 | 内容 | 归属 |
|---|---|---|
| **观测** | 服务端两个表格页（站点 / 客户端）+ 明细：网段、活跃端口、端口级实时流量 | M5.0 |
| **站点可配置** | agent 运行时可改：服务端地址/密钥方式、暴露网段、暴露端口策略；本地配置页 + 服务端远程配置（红标 + 二次确认） | M5.1–M5.2 |
| **客户端注册** | 客户端本地生成密钥 → 凭一次性安装码注册 → 双向密钥指纹核对 → 设备级 TOTP | M5.3 |
| **客户端救援通道** | 服务端可推送配置到客户端，**必须客户端交互确认**才生效 | M5.3 |
| **桌面客户端** | PySide6 薄壳：注册 / 连接 / 站点网段与连通性 / 救援确认；**macOS + Windows 双平台** | M5.4 |

非目标（本批不做）：站点直连打洞、流量伪装、客户端实时站点状态 API、历史流量落库、Windows TUN 全隧道（见 §8）。

## 2. 决策记录（续 DESIGN.md 第 8 节）

| # | 决策 | 结论 |
|---|---|---|
| 16 | 活跃端口口径 | **隧道内实际观测到的目的端口**。不做主动扫描（会触发站点侧告警，等于把扫描器装进内网） |
| 17 | agent 远程配置授权 | **服务端全权**：同一信任域（agent 密钥本就由控制面签发），不设 agent 端审批 |
| 18 | agent 改地址的安全提示 | **红色警示 + 点击确认才生效**；死手开关保留为默认开启、可关闭的选项 |
| 19 | 客户端运行模式 | **默认 `sr socks`（免 root）**；TUN 为可选（macOS 已支持，Windows 本批不支持，见 §8） |
| 20 | 客户端站点列表数据源 | **密钥文件内的 routes + 本机真实探活**，本轮不新增客户端状态 API |
| 21 | 客户端技术栈 | **PySide6 薄壳 + Go 二进制子进程**；协议逻辑只在 Go 侧一份 |
| 22 | 端口策略执行位置 | **agent 侧主执行**（站点边界）+ hub 侧同修订号快速失败（可观测） |
| 23 | **客户端密钥归属** | **客户端本地生成密钥对**，服务端只见公钥（对齐 v0.4 agent 接入模型；消除"服务端知道所有客户端私钥"） |
| 24 | **注册时的密钥验证** | 双向：服务端侧"持有私钥"由首次 Noise IK 握手证实（`pending → verified`）；客户端侧核对 **hub 公钥指纹**（TOFU + 人工比对，支持 `--expect-fingerprint`） |
| 25 | **客户端 MFA** | **设备级 TOTP**（每设备独立密钥，注册后在网页端扫码绑定）；旧设备回落用户级密钥保持兼容 |
| 26 | **客户端重连宽限** | MFA 通过后发 15 分钟"重连票"（绑定该密钥），网络抖动不反复要码；可按设备关闭 |
| 27 | **客户端救援通道** | 服务端可推送 server 地址 / routes / tunnel_ip 等，**必须客户端弹窗确认**（超时 5 分钟即拒绝）；改地址后 60 s 连不上自动回滚 |
| 28 | 双平台 | Go 侧已能编 Windows（本机实测 15.9 MB exe）；GUI 需按平台各自打包（PyInstaller 不能交叉编译） |

## 3. M5.0 观测：数据面采集

### 3.1 采集什么

在 hub 的 `relayFromClient` / `relayFromAgent` 里，除现有 `parseIPHeader` 外多读 4 字节端口，写入**方向性四元组流表**：

```
key = (agentID, clientID, proto, dstIP, dstPort)
value = { pktsToSite, bytesToSite, pktsFromSite, bytesFromSite, firstSeen, lastSeen }
```

为什么不是全 5 元组也不是纯端口聚合：

- 纯端口聚合（peer × port）分不清"哪台站点机被谁打"，客户端页也拿不到目标机；
- 全 5 元组（含源端口）条目量随连接数爆，需求用不上；
- 四元组同时满足两侧视图（站点：谁在打我的哪个端口；客户端：我在打谁的哪个端口），且 key 是定长结构体，**热路径零字符串分配**。

容量：默认 4096 条上限，满时按 `lastSeen` 淘汰；条目约 48 B，峰值内存 < 300 KB。

### 3.2 计数与速率

- 计数：每个 key 两个方向的原子累加（`atomic.Uint64` 对），分片 map 或每 peer 一把锁，禁止全局锁。
- 速率：**hub 侧采样**（≥1 s 一次，EMA 窗口 5 s）输出 `rx_bps`/`tx_bps`；前端只读 bps，不自己算时间差。
- 归零：纯内存，hub 重启归零；UI 标注"自 hub 启动以来"。不写数据库（高频写会把 MariaDB 拖死）。

### 3.3 边角情况（必须处理）

| 情况 | 处理 |
|---|---|
| ICMP（proto 1 / 58） | 无端口，`port=0`，UI 单独一行标 "ICMP" |
| 分片非首片 | `l4Off=-1`，无端口，归 `port=0` 桶并按 proto 标注"碎片" |
| IPv6 扩展头 | `parseIPHeader` 已走链，端口偏移复用其 `l4Off` |
| 表满 | 淘汰最久未见；计数不丢，仅失去明细 |

### 3.4 API（internal/serverapp）

| 端点 | 说明 |
|---|---|
| `GET /api/v1/status` | 扩展：peer 增加 `rx_bps`、`tx_bps`、`caps`、`config_rev` |
| `GET /api/v1/peers/{id}/ports?limit=50` | 端口聚合：`{proto, dst_ip, port, clients, rx_bps, tx_bps, pkts, last_seen}` |
| `GET /api/v1/flows?limit=100` | 四元组明细（钻取用） |
| `GET /api/v1/overview` | 列表页一次拿全：totals + agents + clients + relay |

serverapp 侧加 1 s 快照缓存，多标签页轮询只打一次 hub。

### 3.5 页面（internal/webapp）

- 新增 `GET /agents`（列表）、`GET /clients`（列表）、`GET /clients/{id}`（详情）；`/agents/{id}` 补区块。全部 `authMFA`，普通用户只见自己的设备。
- 站点表：名称 / 状态 / 隧道 IP / 网段（real=virtual）/ 当前速率 / 累计 / 最近上报 / 操作（启停、踢线）。
- 站点详情：网段明细、端口表（协议 / 端口 / 客户端数 / 速率 / 累计 / 最近）、relay 丢弃计数（已有）。
- 客户端表：设备名 / 归属用户 / 状态 / 隧道 IP / **注册详情**（主机名、系统/架构、客户端版本、公钥指纹、注册时间、验证时间）/ 允许站点 / 速率 / 最近活跃。
- 刷新：2 s 轮询 JSON（`/api/ui/overview`、`/api/ui/peer/{id}`，web 侧 1 s 缓存，session 鉴权），不整页刷新。SSE 留后续（需改 nginx 反代）。
- 导航加"站点 / 客户端"两项。

### 3.6 验收

- 单测：聚合正确性、双向计数、表满淘汰、ICMP/分片归类、速率采样。
- 实测：100 Mbps 混合流量下，改造前后 hub CPU 增幅 ≤ 2%，客户端 p99 延迟增幅 ≤ 5%。
- 页面：三态与 `sr server` 日志一致；端口流量与 `tcpdump` 抽样对得上。

## 4. M5.1–M5.2：站点可配置

### 4.1 文件布局

```
agent-home.json        # 服务端签发（含密钥）：server, private_key, server_public_key, tunnel_cidr, id, name
agent-home.local.json  # 本机运行时配置（无密钥）：routes, ports, allow_dangerous, last_good, revision
agent-home.audit.log   # 追加写 JSONL 审计
```

旧部署兼容：`.local.json` 缺失时由主配置 `routes` 生成并落盘；此后以本地文件为准。主配置新增字段一律 `omitempty`。

### 4.2 运行时配置模型

```json
{
  "revision": 7,
  "routes": [{"real": "192.168.2.0/24", "virtual": ""}],
  "ports": {
    "mode": "allow-list",
    "tcp": ["445", "3389", "5000-5100"],
    "udp": ["53", "123"],
    "icmp_echo": false
  },
  "allow_dangerous": false
}
```

- `ports.mode`：`allow-all`（缺省，保持老行为）/ `allow-list`。
- 匹配用**站点侧端口**：隧道→内网看目的端口，内网→隧道看源端口（同一连接端口号相同，无需连接状态）。
- **ICMP 错误必须永远放行**（v4 type 3/11/12、v6 type 1/2/3），否则砸掉 PMTU 发现；只有 echo request/reply 受 `icmp_echo` 控制。

### 4.3 热应用与原子性

- `ConfigStore.Apply(next)`：全量校验 → temp 文件 + rename（保留权限）→ 原子替换运行时状态 → 生效。
- `Translator` 在 `sendFromTun` 热路径被读：改为 `atomic.Pointer[Translator]` 整体替换，避免加锁。
- 改网段/端口 = **不断线**；改服务端地址/密钥 = "应用并重连"（显式按钮，提示会断几秒）。

### 4.4 远程配置通道（服务端全权 + 红标确认）

复用已有 server→agent 密封帧通道（`frameAgentCmd`），新增：

| 帧 | 方向 | 载荷 |
|---|---|---|
| `0x0D frameConfigPush` | server → agent | `{rev, routes, ports, operator, reason, ts}` |
| `0x0E frameConfigAck` | agent → server | `{rev, ok, err, applied_at, rolled_back}` |

- **能力协商**：`AgentInfo` 增加 `caps:["obs","portpolicy","remoteconfig"]` 与 `config_rev`；老 agent 不下发，UI 灰显"请先升级站点"。
- **幂等**：`rev` 单调递增（agent 侧生成并持久化），重复 rev 直接 ack 成功不重放。
- **改 `server` 地址（按用户要求）**：网页上该字段红色警示 + before/after 摘要弹窗 + **点击确认才提交**；文案直白写"改错会导致站点失联，只能到机器上恢复"。
- **死手开关（默认开启，可关）**：应用前落 `pending.json`、保留 `last_good.json`；90 s 内未完成握手+认证则自动回滚并重连，审计记 `rolled_back`。
- **灾难值保险丝（本地，防手滑）**：拒 `0.0.0.0/0`、`::/0`、`10.77.0.0/24`、前缀 < /8、以及"网段 > /16 且端口全开"。`allow_dangerous: true` 可关。
- **审计**：agent 侧 JSONL `{ts, actor, operator, source_ip, action, before, after, rev, result}`；web → hub 透传 `X-SR-Operator` / `X-SR-Request-ID`（控制 API 本身无用户身份）。
- **回滚入口**：服务端站点详情页 + agent 本地页面各一个按钮。

### 4.5 本地配置页（internal/agentui）

- `sr agent -c ... -ui 127.0.0.1:28443`（默认开，`-ui off` 关闭）。
- 页面：状态 / 网络与暴露（网卡网段自动探测 + 勾选）/ 端口策略 / 服务端（地址、密钥方式、重连）/ 审计 / 日志尾部。
- 认证：仅 loopback 免密（仍带 session + CSRF）；绑非 loopback 时首访强制设管理密码（argon2id）+ 登录限速 + 同源校验。
- 顶部横幅常驻"最近一次由服务端（operator）修改于 …"。

### 4.6 验收

- 端口策略：allow-list 拒绝未列端口并计数；ICMP 错误仍放行；SOCKS/TUN 两种客户端均验证。
- 远程配置：push → ack → rev 递增 → 重启保持；错地址 90 s 自动回滚。
- 本地页面：非 loopback 无密码不可访问；审计含 operator。

## 5. M5.3：客户端注册、密钥验证与 MFA

### 5.1 现状与问题

今天客户端密钥是**服务端生成**的（`devices.go:304` 生成密钥对，私钥写进下载的 `.srkey`），意味着服务端知道所有客户端私钥；客户端 MFA 用的是**用户级** TOTP（`db.go:458` 取 `u.totp_secret`，与网页登录共用同一个密钥）。本阶段改成与 v0.4 站点接入同构的模型。

### 5.2 注册流程（对齐 `sr agent enroll`）

1. **网页**：新建设备 → 勾选可访问站点、填名称 → 得到一次性安装码 `XXXX-XXXX`（60 分钟、一次性、按 IP 限速）+ 一行注册命令。
2. **客户端**：`sr client enroll --server https://host:28080 --code XXXX-XXXX -o client.srkey`
   - 本地生成 X25519 密钥对（私钥永不离开本机）；
   - `POST /api/v1/client/enroll`：`{code, public_key, hostname, os, arch, client_version}`；
   - 服务端校验：安装码有效/未用/未过期、公钥 base64 32 字节、公钥未被其它设备占用；分配隧道 IP；按勾选站点展开 routes；写设备行（含注册详情）；返回 `{device_id, name, tunnel_ip, routes, server_addr, server_public_key}`；
   - 客户端用用户设置的文件密码 `keyfile.Seal` 封装，写盘（已存在则备份 `.bak` + 原子 rename）。
3. **密钥验证（两个方向）**
   - **服务端侧**：注册后设备状态 `pending`；**首次 Noise IK 握手成功才置 `verified`**（X25519 不能签名，握手是唯一可信的"持有私钥"证明）；hub 报告该 peer 上线时网页侧写 `verified_at`。
   - **客户端侧**：注册响应里的 `server_public_key` 是 TOFU，必须能核对——网页端展示 hub 公钥指纹（SHA-256 前 16 hex），客户端注册后打印同一指纹；支持 `--expect-fingerprint <hex>` 强制匹配；GUI 展示指纹并要求用户首次比对，本地记住，之后不符即拒绝连接。
4. **旧路径**：网页"生成并下载 .srkey"保留为"旧方式"（老设备重下用），新建设备默认走注册码。

### 5.3 设备级 MFA

- 注册完成后网页端显示**待绑定动态码**：生成设备专属 TOTP 密钥 + `otpauth://` 二维码（**密钥只在网页端显示，绝不经客户端通道传输**）。
- 隧道连接沿用现有 `frameAuthChallenge`：客户端提示输入 6 位码。
- **重连宽限（15 分钟）**：MFA 通过后 hub 发一枚绑定该设备密钥的短期"重连票"；网络抖动重连免再输码，可按设备关闭。
- 迁移：现有设备 `devices.totp_secret` 为空时回落用户级密钥（行为不变）；网页提供"绑定设备动态码 / 轮换 / 关闭"。
- 注册详情（网页可见）：主机名、系统/架构、客户端版本、公钥指纹、注册时间、验证时间、最近活跃、MFA 状态。

### 5.4 数据与协议改动

```sql
ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS arch VARCHAR(16) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS client_version VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS enroll_code VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS enroll_expires DATETIME NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS enrolled_at DATETIME NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS verified_at DATETIME NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_seen DATETIME NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS config_rev BIGINT NOT NULL DEFAULT 0;
```

- `clients.json`：`RegistryClient` 增加 `id`（稳定设备标识，如 `dev-12`，供 hub 状态与网页对齐，避免仅靠名字匹配）与 `config_rev`（救援通道用）。
- `PeerConfig.ID` 对客户端也生效（`PeerStats.ID` 立刻稳定）。
- 新增公开端点 `POST /api/v1/client/enroll`（复用 `enrollLimiter` 限速、`normalizeInstallCode`、`clientIP`）。

## 6. M5.3：客户端救援通道（必须交互确认）

新帧：`0x0F frameClientConfigPush`（server→client）、`0x10 frameClientConfigAck`（client→server），仅在认证通过后可用。

- 可改字段：`server`（服务端地址）、`routes`（会话内覆盖，不改密钥文件语义）、`tunnel_ip`（改后需重握手）、`mfa_reconnect_minutes`、`idle_disconnect_minutes`。**永不下发密钥**。
- 载荷：`{rev, changes:[{field, before, after}], reason, operator, expires_at}`。
- **确认机制（用户明确要求）**：
  - GUI：模态弹窗列出 before → after 差异，`server` 地址改动**红色高亮**，显示原因 / 操作员 / 倒计时（默认 5 分钟）；「接受」「拒绝」；超时视为拒绝并记审计。
  - CLI：TTY 内 `y/N` 提示；**无 TTY 一律拒绝**（不静默接受）。
- 生效与持久化：接受后先内存生效并重连；密钥文件当前已解锁时（GUI 会话持有密码 / CLI 有 `usedPass`）可选"写回密钥文件"（`.bak` + 原子 rename + 同密码重封）。
- **自动回滚**：改 `server` 地址后 60 s 内未重新握手 → 回滚旧地址并提示。
- 服务端页面：客户端详情页"推送配置"（必填原因），显示 pending / accepted / rejected / rolled_back 时间线。

## 7. M5.4：Qt 客户端（PySide6，macOS + Windows）

### 7.1 进程模型

- 单进程 PySide6 + `QProcess` 托管随包分发的 `selfremote` 二进制。
- **协议逻辑只在 Go 侧**：GUI 不解析密钥、不实现握手，只做参数、输出解析、状态展示。
- 配置目录：macOS `~/Library/Application Support/SelfRemote/`；Windows `%APPDATA%\SelfRemote\`。

### 7.2 界面与流程

1. **注册页**：服务端地址 + 安装码 + 文件密码 → 调 `sr client enroll` → 显示 hub 公钥指纹供核对 → 写 `.srkey`。
2. **登录**：选择/导入 `.srkey` → 输入文件密码（仅内存，经 `SR_KEYPASS` 传子进程，不落盘）→ 显示服务端地址 / 隧道 IP / 可访问网段。
3. **连接**：默认 `sr socks -l 127.0.0.1:1080`（自动选空闲端口）；状态机 认证中 → 需要动态码 → 已就绪 / 失败。
4. **MFA**：连接时弹窗输入 6 位码；**CLI 需新增 `-auth-stdin`**（从 stdin 读 `{"mfa":"123456"}` 行，无 TTY 时代替交互提示）——现有 `-mfa` 只对首次尝试有效，重试走终端交互，GUI 无法喂第二轮码。
5. **救援确认**：见 §6 的模态弹窗。
6. **TUN 模式（macOS 可选）**：osascript 提权；退出后自检默认网关直连路由，异常给"修复网络"（关开 Wi-Fi，免 root）。
7. **空闲断开**（可选，默认关闭）：N 分钟无流量自动断开并清空 MFA 宽限。

### 7.3 站点列表与连通性

- 列表来源：密钥里的 `routes`（签发时快照）。hub 的 ACL 才是权威，密钥可能滞后（`devices.go:352`）；UI 标注"来自密钥文件（重新注册/重下密钥可更新）"。
- 每行：网段 CIDR / 探活状态 / RTT / 最近探测 / 自定义目标（主机:端口，可保存）。
- 探活（SOCKS 模式仅 TCP）：
  1. 未指定目标时探该网段第一个可用地址的 80/443/22，任一可连即"站点可达"；
  2. 三态：**成功**（含 RTT）/ **拒绝**（主机在但端口关）/ **超时**（不可达）；
  3. **阴性对照（必须）**：同时探同一主机 `9/tcp`；对照也"成功"→ 标记"探针结果不可信"（经隧道的假阳性是实测过的真问题）；
  4. 并发 ≤ 4、超时 3 s。
- TUN 模式额外支持 ICMP 探活；SOCKS 模式不承诺 ICMP，UI 明确区分。

## 8. 双平台构建（macOS + Windows）

### 8.1 现状（本机已实测）

- `GOOS=windows GOARCH=amd64 go build ./cmd/sr` **通过**（15.9 MB exe）；`release.yml` 已在分发 `selfremote-windows-amd64.exe`。
- `sr socks` 是纯用户态（netstack + UDP），Windows 无特权依赖，预期可用（**需在 Windows 机上实测**，本机无法验证）。
- **Windows TUN 未实现**：`device.go` 的 `ifaceCommands` 对 `windows` 返回 `not implemented`，`device_test.go:94` 还专门断言了这一点；实现还需 `wintun.dll` + `netsh` 配置。

### 8.2 本批做法

| 平台 | SOCKS 模式 | TUN 模式 | GUI |
|---|---|---|---|
| macOS | ✅ 现有 | ✅ 现有 | PyInstaller `.app` |
| Windows | ✅ 预期可用（需实测） | ❌ 本批不做，GUI 灰显 + 说明 | PyInstaller `.exe`（onedir） |

- GUI 在**各平台本机/对应 runner** 打包（PyInstaller 不能交叉编译）：GitHub Actions 加 `macos-latest` + `windows-latest` 矩阵，产出 `selfremote-client-macos.zip` / `selfremote-client-windows.zip`；也可在 Windows 机上手工构建。
- Windows TUN 列为后续里程碑（M5.5）：内嵌 wintun.dll + `netsh interface ipv4 set address/add route` + 管理员清单；注意 wintun 的 GPLv2 分发条款。

## 9. 兼容性与迁移

| 项 | 影响 | 处理 |
|---|---|---|
| 新帧号 | 老 agent/客户端静默丢弃未知帧（`engine.go` 分发 default） | 能力协商（`caps`）后再下发 |
| 新配置字段 | `DisallowUnknownFields` 会让缺字段结构体解析失败 | 一律 optional + `omitempty`；本地文件独立 schema |
| 老客户端 | 协议只增帧，不受影响 | 无需升级；旧密钥文件继续可用 |
| 老设备 MFA | 无设备级密钥 | 回落用户级 TOTP，行为不变 |
| 网页"下载 .srkey" | 与新注册流程并存 | 标记为"旧方式"，仅用于老设备重下 |
| 观测数据 | hub 重启归零 | UI 标注"自 hub 启动以来" |
| 网段漂移告警 | 本地/远程改过会与注册表不一致 | 文案改"本机配置与注册表不一致（可能已被本地或远程修改）" |

## 10. 测试计划

- **单测**：流表聚合/淘汰/分片/ICMP；端口策略（含 ICMP 错误放行）；`ConfigStore` 热应用与回滚；`rev` 幂等；客户端注册校验（重复公钥、过期码、超限）。
- **回环冒烟**（扩展 `scripts/loopback-smoke.sh`）：端口策略放行/拒绝；agent 远程 push → ack → rev；agent 死手开关（地址指死端口 → 90 s 回滚）；客户端注册 → 首次握手置 verified；客户端救援 push → 拒绝不生效 / 接受生效。
- **性能**：`iperf3` 混合 100 Mbps，改造前后 CPU / p99 基线；门槛 CPU 增幅 ≤ 2%。
- **安全**：本地页面仅 loopback；非 loopback 强制密码；灾难值被拒；审计含 operator；MFA 密钥不经客户端通道。
- **GUI 走查**：阴性对照触发"探针不可信"；密码不落盘；救援弹窗超时拒绝；指纹核对流程。

## 11. 里程碑

| 阶段 | 内容 | 验收 |
|---|---|---|
| **M5.0**（v0.5.0） | 四元组流表 + 速率采样 + 控制 API + `/agents` `/clients` 两页与明细 | 100 Mbps 下 CPU 增幅 ≤ 2%；三态与日志一致；单测全绿 |
| **M5.1**（v0.5.1） | ConfigStore 热配置 + 端口策略（agent 侧执行 + hub 快速失败）+ 网段探测 | 策略放行/拒绝实测通过；热应用不断线 |
| **M5.2**（v0.5.2） | agent 本地配置页 + 审计 + 远程配置帧（红标确认）+ 死手开关 + 回滚 | 远程 push 生效；错地址 90 s 自动回滚；审计可追 |
| **M5.3**（v0.5.3） | 客户端注册 + 双向密钥验证 + 设备级 MFA + 客户端救援通道（协议 / CLI / 网页） | 注册→验证→MFA 连接全链路；救援必须确认；拒绝不生效 |
| **M5.4**（v0.5.4） | PySide6 客户端 + 探活 + 双平台打包 | macOS/Windows 均可注册连接；探活三态正确；救援弹窗可用 |

## 12. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 端口采集拖慢热路径 | 吞吐/延迟下降 | 定长 key 无分配、分片锁、压测门槛 ≤ 2%，超了退化为纯端口聚合 |
| agent 远程改地址失联 | 需 SSH 抢救 | 红标 + 二次确认 + 死手开关默认开启可关 |
| server 被攻破后改写 agent 暴露面 | 内网被放大暴露 | 灾难值保险丝、页面 MFA、双端审计、可回滚（同一信任域，残余风险已接受） |
| 注册走 HTTP 泄露安装码 | 设备被抢先注册 | 安装码 60 分钟一次性 + IP 限速；建议开 HTTPS（`COOKIE_SECURE` 已说明 nginx 支持 TLS） |
| 救援通道被滥用改地址 | 客户端连不上 | 必须人工确认 + 60 s 自动回滚 + 审计 |
| 端口策略砸 PMTU/分片 | 大包不通且难查 | ICMP 错误永远放行；策略只作用于 TCP/UDP 端口 |
| 探测假阳性 | 界面全绿但实际不通 | 强制阴性对照 + 三态展示，禁止 ping/`nc -z` 作唯一判据 |
| Windows 无 TUN | 全隧道模式缺失 | 本批 Windows 限定 SOCKS（GUI 明示）；TUN 列 M5.5 |
| PyInstaller 体积/签名 | 分发麻烦 | `--onedir` + 内附二进制；签名后置 |
