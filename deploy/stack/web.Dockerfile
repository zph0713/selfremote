# selfremote web 控制面镜像（多阶段：源码 → 静态二进制 + agent 部署包二进制）
#
# 镜像里除控制面本身，还带上各平台 agent 二进制（/agent-dist），
# 这样"站点 Agent"页面可以直接下载「二进制 + 加密配置 + 说明」的部署包。
#
# 构建（项目根目录执行）：
#   docker build -f deploy/stack/web.Dockerfile -t selfremote-web:latest .
# 本地不装 Go/docker 交叉编译也可用 release 流水线（CI 会先构建好二进制）；
# AGENT_DIST 为空时镜像里就没有二进制，页面会提示"需要自行编译"。
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/selfremote-web ./cmd/web

# 预编译的 agent 二进制（可选；CI 会先跑 make 生成再构建镜像）。
# 单独用 `docker build` 时这一层是空的，部署页会提示自行编译。
FROM scratch AS agentdist
COPY dist/agent-dist/ /agent-dist/

FROM alpine:3.20
# 以 root 运行：/data 卷在群晖上通常归 root，避免权限摩擦
COPY --from=build /out/selfremote-web /usr/local/bin/selfremote-web
COPY --from=agentdist /agent-dist/ /agent-dist/
ENV AGENT_DIST_DIR=/agent-dist
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/selfremote-web"]
