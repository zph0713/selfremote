# 客户端快速开始（Mac / Windows / Linux）

> 客户端运行在**在外网的设备**上。它只把「家里内网网段」的流量送进加密隧道，
> 其余上网流量不受影响（分流）。

## 0. 先准备三样东西（向服务端要）

| 项 | 说明 | 示例 |
|---|---|---|
| 服务端地址 | 公网地址 + 端口 | `[240e:xxxx::1]:28333` 或 `nas.example.com:28333`（IPv6 必须带方括号） |
| 服务端公钥 | 服务端 `genkey` 输出的 `public_key` | `G4KvynS6LpB.../yo=` |
| 家里内网网段 | 需要走隧道的内网 IP 段 | `192.168.1.0/24` |

自建自用：两端都是你自己 —— 各跑一次 `genkey`，互换 `public_key` 即可。

## 1. 下载

到 [Releases](https://github.com/zph0713/selfremote/releases) 下载：

| 平台 | 文件 |
|---|---|
| macOS Apple 芯片 | `selfremote-macos-arm64` |
| macOS Intel | `selfremote-macos-amd64` |
| macOS 整包 | `selfremote-macos.zip`（含两种二进制 + 本说明 + 配置模板） |
| Windows | `selfremote-windows-amd64.exe` |
| Linux | `selfremote-linux-amd64` |

## 2. 生成本机密钥

```sh
./selfremote-macos-arm64 genkey
# private_key = ...   ← 填进 client.json（私钥，不要外传）
# public_key  = ...   ← 发给服务端，加入它的白名单
```

## 3. 写配置 client.json

（模板见 `client.json.example`）

```json
{
  "server": "[240e:xxxx::1]:28333",
  "private_key": "（第 2 步的 private_key）",
  "server_public_key": "（服务端的 public_key）",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["192.168.1.0/24"]
}
```

字段说明：

- `server`：服务端地址；IPv6 带方括号，如 `[240e:1:2::3]:28333`
- `tunnel_cidr`：本机在隧道内的地址，保持 `10.77.0.2/24` 即可
- `routes`：要走隧道的网段（填家里的内网网段，可多条）

## 4. 运行（需要管理员权限：要创建虚拟网卡）

**macOS：**

```sh
chmod +x selfremote-macos-arm64
xattr -d com.apple.quarantine selfremote-macos-arm64 2>/dev/null   # 去掉下载隔离标记
sudo ./selfremote-macos-arm64 client -c client.json
```

**Linux：**

```sh
chmod +x selfremote-linux-amd64
sudo ./selfremote-linux-amd64 client -c client.json
```

**Windows**（需要把 `wintun.dll` 放在同目录，管理员 PowerShell）：

```powershell
.\selfremote-windows-amd64.exe client -c client.json
```

看到 `client: session established` 即连接成功。

## 5. 验证

```sh
ping 192.168.1.1                    # 家里路由器
curl -I http://192.168.1.50:5000    # 内网服务（按实际填）
```

## 6. 退出

`Ctrl+C` —— 会自动清理系统路由。

## 常见问题

| 现象 | 处理 |
|---|---|
| `Operation not permitted` | 忘了 `sudo` |
| macOS 提示"身份不明的开发者" | 系统设置 → 隐私与安全性 → "仍要打开" |
| 一直重连 / 握手超时 | ① 服务端离线 ② 服务端地址变了 ③ 你所在网络没有 IPv6（用手机热点验证） |
| 能连上但网页打不开 | 把终端输出发回来排查 |

> 后续版本计划：macOS launchd 开机自启（M1.2）。
