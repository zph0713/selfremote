# selfremote 隧道协议规格 v0.2

> 状态：**已实现**（v0.2，2026-09-12）· 与 `internal/tunnel` 代码一致
> v0.2 新增：密封控制帧（MFA 认证、服务器信息、再见）、客户端注册表热加载、数据门控

## 1. 设计原则

1. **密码学全部来自成熟库**，绝不自创算法；协议"骨架"（消息编排、会话、帧格式）自研
2. UDP 承载，面向 IP 包（L3 隧道）
3. 版本化帧头，为后续演进（中继、封装层）留空间
4. 传输层可插拔：协议核心不感知"包是怎么到对端的"

## 2. 密码套件

**Noise_IK_25519_ChaChaPoly_BLAKE2s**，使用 Go 库 `github.com/flynn/noise` 实现。

- 双方各持一对 X25519 静态密钥（`sr genkey` 生成，base64 存于配置）
- 客户端预置网关公钥（防中间人）；网关持有客户端公钥白名单（未授权握手静默丢弃）
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
| `0x09` | INFO | 服务器信息 JSON（主机名 / 监听地址 / 隧道网段 / MFA 标记） |
| `0x0A` | BYE | 空载荷；客户端退出时通知网关立即清理会话 |

`0x06–0x0A` 与 DATA/KEEPALIVE 相同，都走**密封数据帧**格式（加密 + 显式 nonce）；
旧版客户端会忽略未知帧类型（天然兼容）。

开销核算：IPv6 40 + UDP 8 + 数据帧头 10 + AEAD tag 16 = **74B**；tun MTU `1360` → 线路上限 `1434B` < 1500，无需分片。

## 4. 会话管理

- **握手重传**：客户端 2s 间隔重试，失败后退避到 10s 循环；服务器对每个 init 都回复（幂等）
- **重密钥**：120s 或 2^20（≈104 万）个包，先到者触发；先建新会话、短暂并行收包、再拆旧
- **保活**：双向空闲 10s 发 KEEPALIVE；25s 未收到任何合法包 → 判定断线 → 重新握手
- **丢包 / 乱序 / 重放**：接收方维护 64 位滑动窗口——窗口内任何未见过的 nonce 均可解密（容忍乱序与丢包，代价只是丢失的那一个包）；重复或过旧的 nonce 直接丢弃（重放防护）。解密失败不改动会话状态
- **端点学习**（网关侧）：从通过认证的包的来源地址学习/更新客户端地址，支持客户端网络切换

## 5. MFA（动态码）与客户端注册表（v0.2）

**数据门控**：对启用 MFA 的客户端，动态码校验通过之前，DATA 帧双向一律丢弃
（认证帧与保活正常通行）。

**认证流程**（全部在已加密会话内）：

1. 会话建立后，网关立即发 `AUTH_CHALLENGE{required}` + `INFO`；
2. 客户端被要求时提示用户输入 Google Authenticator 6 位码，发 `AUTH_RESP{code}`；
3. 网关校验：±1 时间步（30s）漂移窗口；匹配到的时间步必须**严格大于**该客户端
   上次通过的步（同一动态码无法重放，即使会话重建）；失败 3 次 → 断开会话并
   锁定 30 秒（锁定期间拒绝握手）；
4. 通过后网关发 `AUTH_RESULT{ok}` + `INFO`，放行数据；网关 5 秒未收到码则重发
   挑战，2 分钟未通过则丢弃会话；
5. 客户端兼容旧网关：3 秒内未收到挑战即视为就绪；网关侧换密钥（rekey）保留认证
   状态（无需重新输码），会话掉线重连则必须重新输码。

**客户端注册表（clients.json，热加载）**：网关可配置 `clients_file`；每 250ms 检查
mtime，变更即原子重载——新增客户端即时生效，被移除/禁用的客户端立即吊销（在线
会话直接断开）。条目：

```json
{ "name": "mac-air", "user": "hope", "public_key": "<base64,32B>", "totp_secret": "<base32>" }
```

`totp_secret` 存在即该客户端启用 MFA。Web 控制面（`cmd/web`）是唯一写入者。

## 6. 寻址与路由

- 隧道网段 `10.77.0.0/24`：网关 `10.77.0.1/24`，客户端 `10.77.0.2/24`（客户端用 /24，内核自动生成隧道网段直连路由，`10.77.0.1` 才可达）
- 客户端注入路由：家庭 LAN 网段（如 `192.168.1.0/24`）→ tun
- 网关：`net.ipv4.ip_forward=1` + `POSTROUTING MASQUERADE -s 10.77.0.0/24`
- DNS：MVP 不转发内网 DNS；直接用内网 IP 访问（M3 再议 mDNS / 内网 DNS）

## 7. 配置格式

`gateway.json`（`clients_file` 设置后静态 `peers` 可为空）：

```json
{
  "listen": "[::]:28333",
  "private_key": "<base64, 32B>",
  "tunnel_cidr": "10.77.0.1/24",
  "peers": [],
  "clients_file": "/etc/selfremote/clients.json",
  "status_file": "/etc/selfremote/status.json",
  "netinfo_file": "/etc/selfremote/netinfo.json"
}
```

`clients.json`（可选；Web 控制面维护，见 §5）：

```json
{
  "clients": [
    { "name": "mac-air", "user": "hope", "public_key": "<base64,32B>", "totp_secret": "<base32>" }
  ]
}
```

`status.json` / `netinfo.json`：网关写给控制面的实时状态与主机网络信息（原子写，
3s / 30s 刷新），仅供展示。

`client.json`：

```json
{
  "server": "nas.example.com:28333",
  "private_key": "<base64, 32B>",
  "server_public_key": "<base64, 32B>",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["192.168.1.0/24"]
}
```

`client-*.srkey`（加密客户端密钥文件）：其明文就是上面的 `client.json`。外层信封：

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

- **中继模式**：CTRL 帧做端点重协商；帧结构不变
- **封装层（抗 QoS）**：在 UDP 之下/之外再套 TCP / QUIC 外形，协议核心不变
- **UDP 打洞**：需要会合服务器时，新增 CTRL 消息类型即可
- **多客户端**：v0.2 已支持（注册表热加载 + 逐客户端 MFA）；逐客户端路由留待将来
- **Windows / Linux 客户端**：同一代码库，交叉编译即可
- **Web 控制面**：v0.2 已上线（注册/登录/MFA/设备密钥/仪表盘），见 `cmd/web`
