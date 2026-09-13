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

## 2. 两条路径：密钥文件从哪来？

- **路径 A（推荐）**：用 Web 控制面 → 「客户端密钥」页 → 生成并下载 `client-<名字>.srkey`
  （加密文件，含该设备专属密钥与站点路由；生成时勾选可访问站点）。
  可直接跳到**第 4 步运行**——启动时会先要**文件密码**、再要 **Google Authenticator 动态码**。
  下面第 2、3 步（手工 genkey / 写 client.json）不用做。
- **路径 B**：没有 Web 控制面时，按下面第 2、3 步手工配置（明文 `client.json`，无 MFA）。

## 3. 生成本机密钥

```sh
./selfremote-macos-arm64 genkey
# private_key = ...   ← 填进 client.json（私钥，不要外传）
# public_key  = ...   ← 发给服务端/站点，加入它的白名单
```

## 3. 写配置 client.json

（模板见 `client.json.example`）

```json
{
  "server": "[240e:xxxx::1]:28333",
  "private_key": "（第 2 步的 private_key）",
  "server_public_key": "（服务端/网关的 public_key）",
  "tunnel_cidr": "10.77.0.2/24",
  "routes": ["192.168.1.0/24"]
}
```

字段说明：

- `server`：服务端地址；v0.3 下指向**中转服务端**（不再是网关）；IPv6 带方括号，如 `[240e:1:2::3]:28333`
- `tunnel_cidr`：本机在隧道内的地址；v0.3 由控制面自动分配（`10.77.0.2–99`），
  手工配置时用 `10.77.0.2/24` 并保证不与其它设备重复
- `routes`：要走隧道的网段 = **站点对内呈现的网段**（虚拟网段）。站点网段没冲突时就是站点
  内网本身（如 `192.168.1.0/24`）；冲突时控制面会给站点分配虚拟网段（如 `10.200.7.0/24`），
  这里就要填虚拟的那个
- 只访问单个站点、且用直连模式（`sr gateway`）时，`server_public_key` 填网关公钥

## 4. 运行（需要管理员权限：要创建虚拟网卡）

> 从 [Releases](https://github.com/zph0713/selfremote/releases) 下载的**整包 zip 里带「双击启动.command」**：
> 在 Mac 上双击它即可（自动识别芯片、修权限、运行）。首次被 macOS 拦截时，
> 对文件点【右键】→【打开】。
>
> ⚠️ 不要双击 `selfremote-macos-arm64` 本体——它是程序不是文档，
> 直接双击会被 macOS 当文本打开，报「文本编码 Unicode（UTF-8）不适用」。

**使用加密密钥文件（.srkey）时，把命令里的 `client.json` 换成 `client-你起的名字.srkey` 即可。**

> ⚠️ 会有 **三个** 密码类提示，千万别搞混：
> 1. `Password:` —— **sudo 要的是你的 Mac 登录密码**（系统权限）。输错会报英文 `Sorry, try again`，
>    连错 3 次命令直接退出（此时我们的程序还没启动）。
> 2. `该密钥文件已加密，请输入文件密码:` —— **10 位密钥文件密码**（网页生成密钥时你自己设的）。
> 3. `请输入 Google Authenticator 动态验证码:` —— **6 位动态码**（服务端启用 MFA 时）。

**macOS：**

```sh
chmod +x selfremote-macos-arm64
xattr -d com.apple.quarantine selfremote-macos-arm64 2>/dev/null   # 去掉下载隔离标记
# 推荐用 -p 把 sudo 的提示文字改成中文，避免和文件密码混淆：
sudo -p "▶ ① Mac 登录密码: " ./selfremote-macos-arm64 client -c client.json
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
| 第一个提示处报 `Sorry, try again` | 那是 **sudo 在要 Mac 登录密码**（不是你设的文件密码/动态码）——输开机密码 |
| macOS 提示"身份不明的开发者" | 系统设置 → 隐私与安全性 → "仍要打开" |
| 一直重连 / 握手超时 | ① 服务端离线 ② 服务端地址变了 ③ 你所在网络没有 IPv6（用手机热点验证） |
| `密码错误，请重试（1/3）` | 文件密码输错了（就是生成密钥时你设的那个 ≥10 位密码） |
| 动态码不对 | 确认手机时间自动同步；连错 3 次会被服务端锁定 30 秒 |
| 服务端要求动态码但一直不提示 | 客户端版本太旧，去 Releases 下载 v0.2.0+ |
| 能连上但打不开网页 | 把终端输出发回来排查 |

> 后续版本计划：macOS launchd 开机自启（M1.2）。
