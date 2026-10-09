# v0.4.2 — 客户端目标地址可修改：服务端地址变了，不用重新生成密钥文件

## 场景

中转服务端的公网地址一变（换运营商、动态 IPv6 前缀刷新等），客户端密钥文件（`.srkey`）里
记的还是旧地址，连接一直失败；过去只能去 Web 控制面重新生成、重新下载一份密钥文件——
而控制面往往正因为同一个地址问题连不上。

v0.4.2 起，「去哪找服务端」随时可查、可改，全程只在客户端本机完成：

## 怎么用

```sh
# 查看密钥文件里当前记的服务端地址
./selfremote-macos-arm64 keyedit -c client-xxx.srkey -show

# 改成新地址：先验证格式 → 再写回文件 → 原文件自动备份为 client-xxx.srkey.bak
./selfremote-macos-arm64 keyedit -c client-xxx.srkey -server '[240e:1:2::3]:28333'

# 不带 -server 为交互式输入；-kpass / 环境变量 SR_KEYPASS 供自动化使用（如启动脚本）
```

只想临时用新地址、不动文件：`sr client` 支持一次性的 `-server` 覆盖
（`sr socks` 同样支持）：

```sh
sudo ./selfremote-macos-arm64 client -c client-xxx.srkey -server '[240e:1:2::3]:28333'
```

## 说明

- 地址只决定「去哪找服务端」。服务端身份仍由密钥文件里的 `server_public_key` 在握手时
  验证（改地址本就连不上真正的服务端）——不降低安全性，也不影响站点权限（权限在服务端侧）
- `keyedit` 全程本地操作、不联网；加密文件用同一个文件密码重新封装（换新随机盐），
  其余字段原样保留
- IPv6 必须带方括号（如 `[240e:1:2::3]:28333`），格式不对会被提前拦下并给出中文提示
- 明文 `client.json` 同样适用（不加密封回，直接改）

## 升级（只需换客户端二进制）

- 中转服务端、站点、Web 控制面**不需要升级**：协议与密钥文件格式均未变化
- 已有密钥文件直接可用，不需要重新生成；`-server` 覆盖与 `keyedit` 都是新增能力

## v0.4.1 亮点（摘要）

- 热修：站点 agent 重启 / 掉线 / 被踢线后不再卡「认证中」，站点会话自动恢复；
  只需升级中转服务端（`docker compose pull && docker compose up -d server`）

更早的版本说明见 [Releases](https://github.com/zph0713/selfremote/releases)。
