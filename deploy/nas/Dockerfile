# selfremote gateway — 规范构建（多阶段，从源码构建；需要能访问 Docker Hub 拉取基础镜像）
#
# 构建：docker build -f deploy/nas/Dockerfile -t selfremote:latest .
FROM golang:1.27-alpine AS build

ARG GOPROXY=https://goproxy.cn,direct
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/sr ./cmd/sr

FROM alpine:3

# iptables 用于容器 entrypoint 配置转发/NAT（作用于宿主网络栈）
# iptables-legacy 一并安装：老内核（如 DSM 7 的 4.4）大概率用 legacy 后端
RUN apk add --no-cache iptables iptables-legacy

COPY --from=build /out/sr /usr/local/bin/sr
COPY deploy/nas/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["gateway", "-c", "/etc/selfremote/gateway.json"]
