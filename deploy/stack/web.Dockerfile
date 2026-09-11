# selfremote web 控制面镜像（多阶段：源码 → 静态二进制）
# 构建（项目根目录执行）：
#   docker build -f deploy/stack/web.Dockerfile -t selfremote-web:latest .
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/selfremote-web ./cmd/web

FROM alpine:3.20
# 以 root 运行：/data 卷在群晖上通常归 root，避免权限摩擦
COPY --from=build /out/selfremote-web /usr/local/bin/selfremote-web
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/selfremote-web"]
