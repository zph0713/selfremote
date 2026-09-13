# selfremote 隧道协议规格 v0.3

> 状态：**已实现**（v0.3，2026-09-13）· 与 `internal/tunnel` 代码一致
> v0.2 新增：密封控制帧（MFA 认证、服务器信息、再见）、客户端注册表热加载、数据门控
> v0.3 新增：中转服务端（被动接受）与站点 Agent（主动拨号）两种角色、站点网段上报与
> 管控指令帧、源地址防伪造与客户端→站点 ACL、每站点虚拟网段与无状态地址翻译

## 1. 设计原则

1. **密码学全部来自成熟库**，绝不自创算法；协议"骨架"（消息编排、会话、帧格式）自研
2. UDP 承载，面向 IP 包（L3 隧道）
3. 版本化帧头，为后续演进（中继、封装层）留空间
4. 传输层可插拔：协议核心不感知"包是怎么到对端的"
5. **角色对称**：同一个引擎实现四种模式——直连网关（v0.2 遗留）、客户端、站点 Agent、
   中转服务端；两条链路（客户端↔服务端、站点↔服务端）走完全相同的握手、MFA 与帧规则

## 2. 密码套件

**Noise_IK_25519_ChaChaPoly_BLAKE2s**，使用 Go 库 `github.com/flynn/noise` 实现。

- 双方各持一对 X25519 静态密钥（`sr genkey` 生成，base64 存于配置）
- 拨号方预置对端公钥（防中间人）；接受方持有对端公钥白名单（未授权握手静默丢弃）
- IK 模式：两轮完成，双向认证 + 前向保密；`Split()` 得到两个方向的 `CipherState`
- 数据加密：ChaCha20-Poly1305（Noise 传输模式）；nonce 由发送方**显式携带**于数据帧头（见 §3），接收方按包解密 + 64 位滑动窗口防重放

## 3. 帧格式

两种帧布局：

**握手帧**（HS_INIT / HS_RESP）：

```
[ver:1 = 0x01][type:1] + Noise IK 握手消息
```

**数据帧**（DATA / KEEPALIVE / CTRL）：

```
[ver:1][type:1][nonce:8 = 大端][AEAD 密文]
```

- 明文 = 一个完整 IP 包（KEEPALIVE 为空明文）
- **nonce 由发送方显式携带**，接收方按包设置 nonce 解密：丢包 / 乱序只影响该包本身，不会使会话失步（v0.1 草案原为隐式计数器，实现时发现丢任一包都会令会话永久失步，已修正并加测试覆盖）
- AEAD 关联数据（AD）= 完整帧头（ver + type + nonce），绑定帧类型与序号

| type | 名称 | 载荷 |
|---|---|---|
| `0x01` | HS_INIT | Noise IK 消息 1 |
| `0x02` | HS_RESP | Noise IK 消息 2 |
| `0x03` | DATA | 明文 = IP 包 |
| `0x04` | KEEPALIVE | 空明文 |
| `0x05` | CTRL | 预留：中继协商、端点更新 |
| `0x06` | AUTH_CHALLENGE | `{"required":bool}`（网关 → 客户端） |
| `0x07` | AUTH_RESP | `{"code":"123456"}`（客户端 → 网关） |
| `0x08` | AUTH_RESULT | `{"ok":bool,"msg":"…"}`（网关 → 客户端） |
| `0x09` | INFO | 服务器信息 JSON（主机名 / 监听地址 / 隧道网段 / MFA 标记 / 角色 / 站点网段列表） |
| `0x0A` | BYE | 空载荷；客户端退出时通知网关立即清理会话 |
| `0x0B` | AGENT_INFO | 站点 Agent → 服务端：`{id,hostname,version,tunnel_ip,serving,uptime_s,routes[],rx_bytes,tx_bytes,ts}`（上线即发 + 30s 心跳） |
| `0x0C` | AGENT_CMD | 服务端 → 站点 Agent：`{"cmd":"disable\|enable\|kick\|stat","reason":"…"}` |

`0x06–0x0C` 与 DATA/KEEPALIVE 相同，都走**密封数据帧**格式（加密 + 显式 nonce）；
旧版客户端会忽略未知帧类型（天然兼容）。

开销核算：IPv6 40 + UDP 8 + 数据帧头 10 + AEAD tag 16 = **74B**；tun MTU `1360` → 线路上限 `1434B` < 1500，无需分片。

## 4. 会话管理

- **握手重传**：客户端 2s 间隔重试，失败后退避到 10s 循环；服务器对每个 init 都回复（幂等）
- **重密钥**：120s 或 2^20（≈104 万）个包，先到者触发；先建新会话、短暂并行收包、再拆旧
- **保活**：双向空闲 10s 发 KEEPALIVE；25s 未收到任何合法包 → 判定断线 → 重新握手
- **丢包 / 乱序 / 重放**：接收方维护 64 位滑动窗口——窗口内任何未见过的 nonce 均可解密（容忍乱序与丢包，代价只是丢失的那一个包）；重复或过旧的 nonce 直接丢弃（重放防护）。解密失败不改动会话状态
- **端点学习**（网关侧）：从通过认证的包的来源地址学习/更新客户端地址，支持客户端网络切换

## 5. MFA（动态码）与注册表（v0.2+，v0.3 扩展）

**数据门控**：对启用 MFA 的对端（客户端**或站点 Agent**），动态码校验通过之前，
DATA 帧双向一律丢弃（认证帧与保活正常通行）。

**认证流程**（全部在已加密会话内）：

1. 会话建立后，接受方（服务端）立即发 `AUTH_CHALLENGE{required}` + `INFO`；
2. **客户端**（有人值守）：被要求时提示用户输入 Google Authenticator 6 位码，发 `AUTH_RESP{code}`。
   **站点 Agent**（无人值守）：用配置文件里的 `mfa_secret`（base32）现场算出当前动态码自动应答，
   不需要人工介入，断电重启后自动续连；
3. 接受方校验：±1 时间步（30s）漂移窗口；匹配到的时间步必须**不小于**该对端上次通过的步
   （同一时间步内允许复用——Agent 秒级重连需要；**跨时间步一律拒绝**，捕获到的旧码无法重放）；
   失败 3 次 → 断开会话并锁定 30 秒（锁定期间拒绝握手）；
4. 通过后服务端发 `AUTH_RESULT{ok}` + `INFO`，放行数据；5 秒未收到码则重发挑战，
   2 分钟未通过则丢弃会话；
5. 客户端兼容旧服务端：3 秒内未收到挑战即视为就绪；换密钥（rekey）保留认证状态
   （无需重新输码），会话掉线重连则必须重新认证。

**注册表（热加载）**：服务端可配置 `clients_file` 与 `agents_file`；每 250ms 检查 mtime，
变更即原子重载——新增对端即时生效，被移除/禁用的对端立即吊销（在线会话直接断开）。
条目见 §7。MFA 密钥在服务端侧：客户端的取自账号（`totp_secret`），站点的独立生成。

## 5b. 站点 Agent 与中转服务端（v0.3）

**角色与方向**：站点 Agent **主动拨号**服务端（因此可部署在 NAT/防火墙之后，不需要任何
入站端口）；服务端是被动接受方。客户端同样只连服务端。服务端在用户态把两边的数据包
互相转发（没有 TUN 设备、不需要 NET_ADMIN、不需要内核转发）。

```
client ──隧道1──▶ server（用户态中转：按站点网段选路 + ACL）──隧道2──▶ agent ──▶ 站点内网
```

**中转规则**（服务端，逐包判定，计数可观测）：

| 来源 | 校验 | 目标 |
|---|---|---|
| 客户端 | 源地址**必须**等于它的隧道地址（防伪造）；目标网段必须被某个启用的站点声明；该站点必须在客户端的 ACL 里；站点在线且已认证 | 转发给对应站点 Agent |
| 站点 Agent | 源地址**必须**在它上报的（虚拟）网段内，或等于它自己的隧道地址（防伪造） | 转发给目标隧道地址对应的客户端 |

- 目标为服务端自己的隧道地址（`10.77.0.1`）：直接回 ICMP echo（"服务端可达"诊断）；
- 站点之间、客户端之间**默认不可互访**（只允许 client↔agent 两个方向）；
- 站点向服务端上报 `AGENT_INFO`（身份/版本/网段/流量/是否在转发），服务端据此展示状态；
  上报网段与注册表不一致时标记 `config_mismatch` 告警；
- 服务端用 `AGENT_CMD` 下达管控：`disable`（站点暂停转发，进程继续心跳）、`enable`、
  `kick`（立即重连）、`stat`（立刻上报一次）。

**每站点虚拟网段与地址翻译**：站点把「真实网段」映射为「虚拟网段」（前缀长度必须相同），
客户端只使用虚拟网段，翻译在**站点侧**完成、逐包无状态：

- 隧道 → 内网：目的地址 虚拟→真实（`ToLocal`）
- 内网 → 隧道：源地址 真实→虚拟（`ToTunnel`）
- 改写后修正 IPv4 头校验和、以及 TCP/UDP/ICMPv6 校验和中的伪首部贡献
  （RFC 1624 增量更新）；分片场景只在含传输层头的分片里更新一次；IPv6 的 ICMPv6
  echo 校验和覆盖伪首部因此一并修正
- 不匹配任何映射的包一律丢弃（防伪造/防误路由）；站点自己的隧道地址原样放行

这样两个站点即使都跑 `192.168.1.0/24` 也能同时接入（其中一个映射为 `10.200.7.0/24`）。

## 6. 寻址与路由

- 隧道网段 `10.77.0.0/24`（单网段，所有角色共享）：
  - `10.77.0.1` = 服务端自己的虚拟地址（客户端 ping 它验证"服务端可达"；它没有 TUN）
  - `10.77.0.2–99` = 客户端设备（控制面自动分配）
  - `10.77.0.100–254` = 站点 Agent（控制面自动分配；站点用它自己的地址报诊断）
- 站点侧：`net.ipv4.ip_forward=1` + `POSTROUTING MASQUERADE -s 10.77.0.0/24 ! -o sr0`
  + `FORWARD -i sr0 ! -o sr0 ACCEPT`（容器 entrypoint 幂等配置；多网卡无需指定接口名）
- 客户端注入路由：**站点对内呈现的网段**（虚拟网段，如 `192.168.1.0/24` 或映射后的
  `10.200.7.0/24`）→ tun；
- DNS：不转发内网 DNS；直接用内网 IP 访问（M3 再议 mDNS / 内网 DNS）

## 7. 配置格式

`server.json`（中转服务端）：

```json
{
  "listen": "[::]:28333",
  "private_key": "<base64, 32B>",
  "tunnel_cidr": "10.77.0.1/24",
  "clients_file": "/etc/selfremote/clients.json",
  "agents_file": "/etc/selfremote/agents.json",
  "api_listen": "0.0.0.0:8770",
  "api_token": "<控制面令牌>",
  "status_file": "/etc/selfremote/server-status.json",
  "netinfo_file": "/etc/selfremote/netinfo.json"
}
```

`gateway.json`（v0.2 直连模式，仍受支持）：同上但无 `agents_file` / `api_*`。

`clients.json`（控制面写入，服务端热加载）：

```json
{
  "clients": [
    { "name": "mac-air", "user": "hope", "public_key": "<base64,32B>",
      "totp_secret": "<base32>", "tunnel_ip": "10.77.0.2",
      "agents": ["home", "office"] }
  ]
}
```

`agents.json`（控制面写入，服务端热加载；**不含私钥**）：

```json
{
  "agents": [
    { "id": "home", "name": "家里 NAS", "public_key": "<base64,32B>",
      "tunnel_ip": "10.77.0.100", "totp_secret": "<base32>", "enabled": true,
      "routes": [ { "real": "192.168.1.0/24", "virtual": "10.200.7.0/24" } ] }
  ]
}
```

`virtual` 省略 = 原样呈现；`enabled:false` = 软停用（服务端拒绝其流量并下发 `disable`，
站点进程继续心跳；删掉条目才是硬吊销）。

`status.json` / `netinfo.json`：服务端写给控制面的实时状态与主机网络信息（原子写，
3s / 30s 刷新），仅供展示；控制面另有 `GET /api/v1/status|agents` 与
`POST /api/v1/agents/{id}/kick|refresh` 管控接口（Bearer 令牌）。

`client.json`：

```json
{
  "server": "nas.example.com:28333",
  "private_key": "<base64, 32B>",
  "server_public_key": "<base64, 32B>",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["10.200.7.0/24"]
}
```

`agent.json`（站点；通常以加密 `.srkey` 下发）：

```json
{
  "id": "home",
  "name": "家里 NAS",
  "server": "nas.example.com:28333",
  "private_key": "<base64, 32B>",
  "server_public_key": "<base64, 32B>",
  "tunnel_cidr": "10.77.0.100/24",
  "mfa_secret": "<base32>",
  "routes": [ { "real": "192.168.1.0/24", "virtual": "10.200.7.0/24" } ]
}
```

`client-*.srkey` / `agent-*.srkey`（加密配置文件）：其明文就是上面的
`client.json` / `agent.json`。外层信封：

```json
{
  "srkey": 1,
  "kdf":    { "name": "argon2id", "salt": "…", "time": 3, "memory": 65536, "threads": 4, "keylen": 32 },
  "cipher": { "name": "chacha20poly1305", "nonce": "…" },
  "ct": "…base64（密文，AD = \"selfremote-keyfile-v1\"）…"
}
```

`sr client -c xxx.srkey` 时提示输入文件密码，在内存中解密使用，不落盘明文。

约定：私钥文件权限 600；配置里绝不出现私钥明文以外的秘密。

## 8. 未来扩展（已预留的演进点）

- **多站点互访 / 客户端互访**：中转表放宽即可（当前刻意只允许 client↔agent）
- **站点直连升级（打洞）**：服务端把站点的可达端点告知客户端，CTRL 帧做端点重协商
- **封装层（抗 QoS）**：在 UDP 之下/之外再套 TCP / QUIC 外形，协议核心不变
- **Windows / Linux 客户端**：同一代码库，交叉编译即可
- **站点端的独立 MFA 复核**：当前客户端 MFA 由服务端校验（服务端是信任边界）；
  将来可让站点也校验一遍（端到端防御）
