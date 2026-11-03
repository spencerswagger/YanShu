# 雁书前端镜像：Vite 构建 → nginx 提供静态页并把 /v1、/healthz 反代到服务端。
#
# 构建上下文是**仓库根目录**（不是 web/）：前端运行需要端侧内核 ys_kernel.wasm，
# 它随仓库在 server/kernel/yanshu_sm.wasm，构建时复制到站点根。
#
#   docker build -f web/Dockerfile -t yanshu-web:local .

FROM swr.cn-east-5.myhuaweicloud.com/spencerswagger/library-node:22-alpine AS build
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# 直接跑 vite build：跳过 prebuild 脚本（它会去仓库其他目录找内核，容器内不可用）
RUN npx vite build

FROM swr.cn-east-5.myhuaweicloud.com/spencerswagger/library-nginx:alpine
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY server/kernel/yanshu_sm.wasm /usr/share/nginx/html/ys_kernel.wasm

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz >/dev/null || exit 1
