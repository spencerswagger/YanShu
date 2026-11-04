# 雁书 前端镜像（单端口：nginx 同时发静态站点 + 反代 API）
#
# 只用国内 SWR 源，不从 Docker Hub 拉任何东西：
#   NODE_IMAGE  = swr.cn-east-5.myhuaweicloud.com/spencerswagger/library-node:<tag>
#   NGINX_IMAGE = swr.cn-east-5.myhuaweicloud.com/spencerswagger/library-nginx:<tag>
# 若 SWR 上的 tag 不同（例如 `22-alpine` 不存在），构建时用 --build-arg 覆盖即可，无需改文件：
#   docker build -f web/Dockerfile --build-arg NODE_IMAGE=...:22.20-alpine --build-arg NGINX_IMAGE=...:1.27-alpine .
#
# 构建上下文必须是**仓库根**（需要同时拿到 web/ 与 server/kernel/yanshu_sm.wasm）：
#   docker build -f web/Dockerfile -t yanshu-web:dev .
#
# 端侧内核产物不入库（根 .gitignore 忽略 *.wasm），但 `server/kernel/yanshu_sm.wasm`
# 是入库的冻结产物；这里把它拷进 web/public 并**校验 sha256 等于冻结值**，
# 再写 `ys_kernel.build.json`，供 `prebuild`（scripts/ensure-wasm.mjs）核验。
# 冻结值一变（内核升级）→ 构建直接失败，不会悄悄把旧/新内核混进镜像。

ARG NODE_IMAGE=swr.cn-east-5.myhuaweicloud.com/spencerswagger/library-node:22-alpine
ARG NGINX_IMAGE=swr.cn-east-5.myhuaweicloud.com/spencerswagger/library-nginx:alpine

# ---------- 构建阶段 ----------
FROM ${NODE_IMAGE} AS build

WORKDIR /app

# 依赖层单独缓存：只有 lock 变了才重装
COPY web/package.json web/package-lock.json ./
RUN npm config set registry https://repo.huaweicloud.com/repository/npm/ \
 && npm config set fetch-retries 5 \
 && npm ci --no-audit --no-fund

# 源码（web/ 全部内容，含 public/_headers、scripts/）
COPY web/ ./

# 冻结内核：内核由 server/kernel/ 决定，**勿写死 sha / 导出数**（历史值见 v0.1.1）。
# 下面从实际 COPY 进来的字节现算 sha256 / 导出数 / 版本 / 头长；`YS_KERNEL_SHA` 只作**可选断言**
# （CI 想固定值时可 --build-arg 传入，传入就必须一致，否则构建失败）。
ARG YS_KERNEL_COMMIT=unknown
# 兜底值 = 当前冻结内核（daa94926… / 140,762 B / 43 导出）；实际校验已改为构建时现算，
# 这里的默认值只防"忘了传 build-arg"时无参考。历史值见 v0.1.1（c1b87d0a… / 127,313 / 34 导出）。
ARG YS_KERNEL_SHA=daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de
COPY server/kernel/yanshu_sm.wasm ./public/ys_kernel.wasm
RUN node -e "\
const fs=require('fs'),crypto=require('crypto');\
const buf=fs.readFileSync('public/ys_kernel.wasm');\
const sha=crypto.createHash('sha256').update(buf).digest('hex');\
const want=(process.env.YS_KERNEL_SHA||'').trim();\
if(want && sha!==want){console.error('[kernel] sha256 与传入的 YS_KERNEL_SHA 不一致：实际 '+sha+'，期望 '+want);process.exit(1);}\
const mod=new WebAssembly.Module(buf);\
const inst=new WebAssembly.Instance(mod,{});\
const ex=inst.exports||{};\
const fnNames=Object.keys(ex).filter(function(k){return typeof ex[k]==='function';});\
const ver=fnNames.indexOf('ys_version')>=0?(ex.ys_version()>>>0):0;\
const hdr=fnNames.indexOf('ys_header_len')>=0?ex.ys_header_len():0;\
const commit=process.env.YS_KERNEL_COMMIT||'unknown';\
fs.writeFileSync('public/ys_kernel.build.json',JSON.stringify({\
commit,ref:commit.slice(0,7),builtAt:new Date().toISOString(),\
sha256:sha,bytes:buf.length,imports:WebAssembly.Module.imports(mod).length,\
exports:fnNames.length,hasMemory:!!ex.memory,\
ysVersion:'0x'+ver.toString(16),headerLen:hdr,\
unpackV1Arity:(fnNames.indexOf('ys_unpack_v1')>=0?ex.ys_unpack_v1.length:0),\
hasSignDer:fnNames.indexOf('ys_sm2_sign_der')>=0,hasPackV1:fnNames.indexOf('ys_pack_v1')>=0\
},null,2)+'\\n');\
console.log('[kernel] sha256='+sha+' bytes='+buf.length+' exports='+fnNames.length+' version=0x'+ver.toString(16)+' header='+hdr);" \
 && node scripts/ensure-wasm.mjs

# 构建期环境变量（默认同源反代 /v1，通常无需覆盖；只有前端直连外部 API 时才传）
ARG VITE_YS_API_BASE=/v1
ARG VITE_YS_WASM_URL=/ys_kernel.wasm
ARG VITE_YS_CRYPTO=auto
ENV VITE_YS_API_BASE=${VITE_YS_API_BASE} \
    VITE_YS_WASM_URL=${VITE_YS_WASM_URL} \
    VITE_YS_CRYPTO=${VITE_YS_CRYPTO}

RUN npm run build

# ---------- 运行阶段 ----------
FROM ${NGINX_IMAGE} AS runtime

# 用我们的站点配置替换默认站点（默认站点只发静态、不反代 API）
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# 说明：这里保留 nginx 默认的 root master（绑 80 需要特权端口），
# 只有 worker 以 nginx 用户跑；要强制非 root 就把 listen 改成 8080 并加 CAP_NET_BIND_SERVICE。
EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1/healthz-static >/dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]
