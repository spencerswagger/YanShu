# yanshu-server 镜像（多阶段）
#
# 构建：docker build -f server/Dockerfile -t yanshu-server:dev server
# 注意：冻结内核必须一起进镜像——启动路径上有 sha256 白名单校验，缺了会直接拒启。

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" \
      -o /out/yanshu-server ./cmd/yanshu-server

FROM alpine:3.20
RUN addgroup -g 10001 -S yanshu \
 && adduser -u 10001 -S -G yanshu -H -h /app yanshu \
 && apk add --no-cache ca-certificates wget su-exec

WORKDIR /app
COPY --from=build /out/yanshu-server /app/yanshu-server
COPY kernel/yanshu_sm.wasm /app/kernel/yanshu_sm.wasm
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0444 /app/kernel/yanshu_sm.wasm && chmod 0755 /app/docker-entrypoint.sh

ENV YANSHU_KERNEL_WASM=/app/kernel/yanshu_sm.wasm \
    YANSHU_ADDR=0.0.0.0:8080 \
    YANSHU_BLOB_DIR=/app/data/blobs \
    YANSHU_VERIFIER=sm2

RUN mkdir -p /app/data/blobs /app/data/logs && chown -R 10001:10001 /app

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

# 入口以 root 启动只为修正卷权限，随后 su-exec 降权到 10001 运行（业务进程始终非 root）。
ENTRYPOINT ["/app/docker-entrypoint.sh"]
