# 证据 B · **Core 真实服务 + 契约布局内核**（跨浏览器链路 + 契约布局）

> **限定（写死在文件头）**
> - 中转 = **Core 真实 HTTP 服务**（`feat/server-skeleton` @ `9065eb8`，`/v1` 路径，PG 持久化 + 磁盘密文块）。
>   服务端签名校验当前为 `YANSHU_VERIFIER=stub-allow`（不验签），因此本证据**只覆盖传输与端侧密码学**，
>   不覆盖服务端验签；换真实 SM2 验签后需再跑一次同流程。
> - 内核 = **契约布局** `YSPK/1.0`（`ys_header_len()` = 112、`SENDER_PUB` 入包、公钥 65 字节、DER 签名、
>   解包来源由包内公钥自证）。

| 项 | 值 |
|---|---|
| 运行标签 | `B-core-contract-kernel` |
| 日期 | 2026-11-02 |
| 前端 | `web/`（Vue 3 + Vite，dev server，`/v1` 反代到 Core） |
| 中转 | Core `yanshu-server`（`9065eb8`，`127.0.0.1:8080`，`search_path=yanshu_web`，`YANSHU_BLOB_DIR` 独立目录，`YANSHU_LOG_FILE` 落盘） |
| 内核 | 契约布局 wasm（HEADER 112），`npm run wasm:rebuild` 构建自 `feat/endcrypto-wasm` `e9f8254`（`ys_version()=0x00010000`、30 导出、0 import、`ys_unpack_v1` 6 参自证；构建溯源 `sha256=a657b33948b7…` 写在 `public/ys_kernel.build.json`，页面与测试都会显示/校验） |
| 界面标签 | `真实加密 · 契约布局内核（YSPK/1.0）` |
| 样本 | 与证据 A **同一份**：2 506 889 字节，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 客户端 | 两个独立 Chrome profile |

## 流程

A 端：注册（真码）→ 建包（`ys_pack_v1`，清单写实 `ext`/`created_at`）→ prelude + 3 块 PUT → complete → 界面「已发送」。
B 端：待收（`GET /v1/inbox`）→ 取 prelude（开租约）→ 逐块 GET → 端侧验签解密（`ys_unpack_v1` 只给私钥，来源由包内 `SENDER_PUB` 自证）→ 落盘 → `ack`。

## 结果

- 发送 `state: READY`；接收成功；`ack` 后服务端物理删除密文（再取即 `410 TRANSFER_CONSUMED`，Node 侧同流程已验证）。
- 落盘 `ys-e2e-input.bin`：**2 506 889 字节**，sha256 与源文件**完全相同**（`bytesEqual: true`）。
- 结果 JSON：`results/web/2026-11-02-B-core-contract-kernel.json`
- Core 服务端日志只记方法/路由/状态/字节数（无文件名、无明文）。

## 这份证据能说明 / 不能说明

**能**：契约布局的端侧加解密（SM4-GCM 分块、SM2 封装/签名、SM3 摘要）与 Core 的真实 HTTP 接口
（注册 / 建包 / prelude / 分块 / complete / inbox / 取件 / ack）在浏览器里走通，字节一致。

**不能**：不能替代 Gate 的篡改用例（那属证据二）；服务端仍是 `stub-allow` 不验签，验签路径未覆盖；
大文件上限（整包接口）见 PR 的「v1 已知限制」。

## 复跑命令（摘要）

```bash
# Core
cd server && go build -o bin/yanshu-server ./cmd/yanshu-server
set -a; . /.keys/pg.env; set +a
YANSHU_DATABASE_URL="${PG_DEV_DSN}&search_path=yanshu_web" \
YANSHU_BLOB_DIR=<blob 目录> YANSHU_ADDR=127.0.0.1:8080 \
YANSHU_LOG_FILE=<日志文件> \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET=<≥16 字节> ./bin/yanshu-server   # 新版缺/短会直接 fatal 退出
# Web
cd web && npm run wasm:rebuild  # 一条命令：fetch → archive → cargo build → 核验 → 写 public/ys_kernel.wasm + build.json
VITE_YS_RELAY_ORIGIN=http://127.0.0.1:8080 npx vite --port 5173
```
