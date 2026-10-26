# 给 AI / 运维的部署作业指导：部署 selfremote 开发栈

> 这份文件就是**执行说明书**。另一台机器上的 AI 请从头按顺序执行，不要跳步、不要"优化"。
> 目标：把 `feat/m5.0-observability` 分支跑起来做验证，**同时不碰正在运行的旧版 selfremote**。

- 仓库：`https://github.com/zph0713/selfremote`
- 分支：`feat/m5.0-observability`
- 本批内容：v0.5.0 可观测（站点/客户端两张表 + 活跃端口与实时流量）
- 详细背景：`docs/DESIGN-M5.md`、`docs/RELEASE-NOTES.md`、`docs/DEPLOY-DEV.md`

---

## 0. 硬约束（违反任何一条都算失败）

1. **不要动旧版**：旧版是 compose 项目名 `selfremote`（容器 `selfremote-*`，端口 28333/8080/28080）。
   不许 `down`、`restart`、`rm`、`pull`、`up` 它，也不许改它的 `deploy/stack/data`。
2. **不要起 `agent-home`**：本机站点会在宿主机建 `sr0` 并写 iptables，和旧版本机站点冲突。
   只起 `db web nginx server` 四个服务。
3. **不要打 tag、不要 push main、不要更新 ghcr `:latest`**（会影响生产）。
4. **镜像只用本地 `:dev` 标签**，不许用 `ghcr.io/zph0713/selfremote:latest`。
5. **端口只用 18080 / 18081 / 28334 / 8771**（旧版用 8080/28080/28333/8770）。
6. **数据目录只用 `deploy/stack/data-dev`**（旧版是 `deploy/stack/data`）。
7. 任何一步失败：**停下来贴日志**，不要自己改代码或改生产。

---

## 1. 拉代码并确认版本

```sh
git clone -b feat/m5.0-observability https://github.com/zph0713/selfremote.git
cd selfremote
git log -1 --oneline
git status --short          # 应为空
```

记下 `git log -1` 的短哈希，最后要写进汇报。

## 2. 环境预检（只读，不改任何东西）

```sh
bash scripts/deploy-dev.sh --check
```

预期输出包含：docker/compose 版本、仓库与分支、四个端口空闲、磁盘 > 3 GB，
以及（如果旧版在同机）`检测到旧版栈（项目 selfremote）：本脚本不会触碰它`。

任一项失败 → 按提示修（端口占用/磁盘不足/没装 docker compose v2），**不要绕过**。

## 3. 部署

```sh
bash scripts/deploy-dev.sh --yes
```

脚本会依次：构建 `selfremote:dev` / `selfremote-web:dev` → 生成 `deploy/stack/.env.dev`
（随机数据库密码；已存在则复用）→ `init.sh ./data-dev` 生成独立密钥 → 
`docker compose -p selfremote-dev up -d db web nginx server` → 健康检查。

成功时末尾会打印：

```
== 完成
   控制面   http://<这台机器IP>:18080
   隧道     UDP 28334
   令牌     .../deploy/stack/data-dev/bootstrap-token
```

各阶段预期：

| 阶段 | 预期 |
|---|---|
| 1. 构建镜像 | 出现 `镜像 selfremote:dev` 与 `镜像 selfremote-web:dev` |
| 2. 环境文件 | 首次 `已生成`；重复执行 `已存在，复用` |
| 3. 生成密钥 | `data-dev/server.json`、`data-dev/agent-home.json` 存在 |
| 4. 启动 | `容器已启动` |
| 5. 健康检查 | `控制面可访问（HTTP 200）` + `管控 API 正常（无令牌 401）` |

## 4. 验收

```sh
# 4.1 页面
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/login          # 期望 200

# 4.2 管控 API（无令牌应 401）
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8771/api/v1/overview

# 4.3 带令牌 → 应返回 JSON，version 为 0.5.0
set -a; . deploy/stack/.env.dev; set +a
TOKEN=$(cat deploy/stack/data-dev/api-token)
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8771/api/v1/overview \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("version:", d["status"]["version"], "peers:", len(d["status"]["peers"]), "flows:", d["flow_entries"])'

# 4.4 容器与端口
docker compose -p selfremote-dev ps

# 4.5 隔离自检（必须全 PASS）
bash scripts/check-dev-isolation.sh selfremote selfremote-dev
```

**全部通过的标准**：4.1 = 200，4.2 = 401，4.3 打印 `version: 0.5.0`，4.5 `FAIL=0`。

## 5. 需要人（你）继续做的两件事（AI 无法代做）

1. 浏览器打开 `http://<机器IP>:18080`，用 `deploy/stack/data-dev/bootstrap-token` 里的字符串
   注册管理员，然后按页面提示绑定动态码（Google Authenticator）。
2. 登录后确认导航栏有「客户端连接」，页脚版本 `v0.5.0`，`/agents` 列表有「当前速率」列。

## 6. 常见失败与处理

| 现象 | 原因 | 处理 |
|---|---|---|
| `docker 守护进程没运行` | 没启动 Docker | `sudo systemctl start docker`，或 Docker Desktop 启动后重试 |
| `缺少 docker compose v2` | 只有 `docker-compose` v1 | 装 compose v2 插件（`docker compose version` 要能跑） |
| `端口被占用：18080` | 有别的东西占着 | `ss -lntp \| grep 18080` 查是谁；换端口要同时改 `.env.dev` 与脚本变量 |
| 构建时拉 `golang:1.27-alpine` 很慢 | 本机无 Go | 正常现象，等；或先在本机装 Go |
| `控制面 120 s 内没起来` | 数据库没初始化/密码不一致 | `cd deploy/stack && docker compose -p selfremote-dev logs --tail=80 web nginx db` |
| 页面能开但提示「读不到中转服务端」 | 管控 API 绑定/地址不对 | 确认 `API_BIND=0.0.0.0` 且 `SRV_API_URL=http://host.docker.internal:8771` |
| `check-dev-isolation.sh` 有 FAIL | 两套栈有共享 | **不要继续**，把输出贴回来 |

## 7. 汇报格式（部署完请原样贴回）

```
分支/提交：feat/m5.0-observability @ <短哈希>
机器：<uname -a 前两项> / docker <版本> / compose <版本>
--check：PASS
部署：PASS（镜像自建 / 复用，首次生成密钥 / 复用）
4.1 login：200
4.2 overview 无令牌：401
4.3 overview 带令牌：version=... peers=... flows=...
4.5 隔离自检：FAIL=0
异常与处理：<有就写，没有写"无">
```

## 8. 收尾（验证结束后，可选）

```sh
# 停栈（保留数据和密钥，下次接着用）
cd deploy/stack
docker compose -p selfremote-dev --env-file .env.dev -f docker-compose.yml -f docker-compose.desktop.yml down

# 彻底删除（含数据库卷与开发密钥）
docker compose -p selfremote-dev --env-file .env.dev -f docker-compose.yml -f docker-compose.desktop.yml down -v
rm -rf data-dev
```

**项目名必须带 `-p selfremote-dev`**：不带的话 compose 会用文件里的 `name: selfremote`，那是生产项目名。

---

## 附：给另一台机器 AI 的一句话指令（可直接复制）

```
在 https://github.com/zph0713/selfremote 的 feat/m5.0-observability 分支上部署开发栈做验证。
先读仓库里的 docs/AGENT-DEPLOY.md，按它的硬约束和步骤执行（不要起 agent-home、不要碰项目
selfremote、只用 18080/18081/28334/8771 与 data-dev）。先跑 scripts/deploy-dev.sh --check，
通过后跑 scripts/deploy-dev.sh --yes，然后按文档第 4 节验收、第 7 节格式汇报。
失败就停下贴日志，不要改代码也不要动旧版。
```
