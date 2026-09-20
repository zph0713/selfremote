# v0.4.1 — 热修：站点不再卡在「认证中」（会话重建后自动恢复）

一个**线上症状明确、修复很小**的热修版：站点 agent 重启（或掉线、被踢线、机器休眠）之后，
面板一直显示「认证中」，而且这个站点**实际用不了**——客户端到该站点的流量被中转端拒绝。
过去只能靠「删掉站点重装」（重新接入 = 换公钥 = 注册表里新增一条记录）绕过。

## 修的是什么

中转服务端（`sr server`）对每个站点维护一个「已认证」标记。v0.4 起站点不再使用动态码，
这个标记本来只应在**注册表新增该站点的那一刻**置位——于是任何一次会话终止
（agent 重启后的静默超时、BYE、管理员踢线、注册表里 MFA 字段变化）都会把它清成 false，
而**再也没有任何路径会把它恢复**：

- 面板状态机：`已连接 + 未认证` → 显示「认证中」
- 中转判活：客户端 → 该站点的数据一律按「站点不可用」丢弃（计数器记 `dropped_offline`）

结果是 agent 侧日志一切正常（`session established`、两分钟一次 rekey 都在），
面板却永远「认证中」、站点用不了。重新接入之所以"能治好"，只是因为换公钥等于新增一条注册表记录。

修复（`internal/tunnel`）：

- 新增 `peerState.resetAuth()`：会话丢失后按「该站点是否需要动态码」重新置位——
  **需要动态码的站点仍然必须重新验证**（安全语义不变），不需要的站点由密钥握手本身完成认证
- 会话终止的四条路径（静默掉线 / BYE / 踢线 / 注册表密钥变化）统一走 `resetAuth()`
- tick 循环加一条兜底：只要会话在线且该站点不需要动态码，就当已认证（防止将来再漏掉某条路径）

## 影响与恢复

- **不需要重新接入、不需要重新生成安装码**。升级中转服务端后，仍在线的站点会在 1 秒内
  自动从「认证中」变回「在线」，被拒绝的流量立即恢复
- 真正使用动态码的站点（v0.3 时代配置）行为不变：会话重建后依旧要重新通过一次动态码
- 新增两条回归测试：无动态码站点重启后必须可用；有动态码站点重启后必须重新验证

## 升级（只换中转服务端即可）

```bash
cd <项目目录>
sudo docker compose pull && sudo docker compose up -d server
```

离线环境：用 Release 里的 `selfremote-image-linux-amd64.tar.gz`
（注意包里的镜像名是 `selfremote:release`，导入后要重新打成 compose 认的名字）：

```bash
sudo gunzip -c selfremote-image-linux-amd64.tar.gz | sudo docker load
sudo docker tag selfremote:release ghcr.io/zph0713/selfremote:v0.4.1
sudo docker tag selfremote:release ghcr.io/zph0713/selfremote:latest
sudo docker compose up -d server
```

## 兼容性

- 协议、注册表格式、客户端 `.srkey`、站点配置**全部不变**，可以只升级中转服务端
- 站点与客户端二进制无需更换（本修复只在中转服务端一侧生效）

## v0.4.0 亮点（摘要）

- 站点接入 = 一行命令：网页建站拿一次性安装码 → 目标机器 `curl … /install.sh | sudo bash -s -- --code XXXX-XXXX`
- 初次部署自带本机站点（`init.sh` 预置 + 控制面自动导入），起完 compose 就能用
- 路由模式开关（auto/real/virtual）：站点网段冲突时自动分配虚拟网段并做地址翻译
- `sr socks`：免 root 的本地 SOCKS5/HTTP 代理，走隧道但不建 TUN、不改系统路由
- 安全加固：安装码一次性 + 限速、站点密钥现场生成、控制面会话语义收紧

更早的版本说明见 [Releases](https://github.com/zph0713/selfremote/releases)。
