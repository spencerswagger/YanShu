# 证据 D · **真认证链路**（Core `sm2` 验签 + 契约布局内核）

> **限定**
> - 中转 = 本地起的 Core `feat/server-skeleton@caf00ac`，`YANSHU_VERIFIER=sm2`：**wazero 加载端侧内核 `ys_sm2_verify_der` 做真验签**（不是 `stub-allow`）。
> - 内核 = 契约布局，构建自 `feat/endcrypto-wasm@80400ec`（`ys_version()=0x00010000`、HEADER 112、34 函数 / 0 import）。
> - 数据库 = `yanshu_web` schema；blob 与日志为本次独立目录。

| 项 | 值 |
|---|---|
| 运行标签 | `D-core-sm2-real-auth` |
| 日期 | 2026-11-02 |
| 前端 | `web/`（Vue 3 + Vite dev server，`/v1` 反代到 18090） |
| 服务端 | Core `caf00ac`，`YANSHU_VERIFIER=sm2`，监听 `127.0.0.1:18090` |
| 内核（客户端） | `80400ec`，sha256 `c1b87d0ad9a8…`，`ys_version()=0x00010000` |
| 内核（服务端验签） | 同一 crate 的 `f1ef9f9` 构建产物（wazero 加载，日志 `sm2 verifier loaded … version=0x00010000`） |
| 样本 | `ys-e2e-input.bin`，2 506 889 字节，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 分块 | 服务端 `chunk_size=1048576` → **3 块**（2×1 MiB + 409 601 B；HTTP 上的切片为 1 048 592 / 1 048 592 / 409 753 字节含 tag） |
| 客户端 | 两个独立 Chrome profile（两个身份） |

## 流程（每一步都过真验签）

1. `POST /v1/codes`：客户端用 `ys_sm2_sign_der` 签 `YSAUTH1` 挑战输入（`CODE(4)` 覆盖在 `SIG_INPUT` 里），**Core 用 wazero 调内核验签**。
2. `POST /v1/transfers`、`GET /v1/inbox`、`POST /v1/ack` 同理（`TRANSFER_CREATE` / `INBOX_LIST` / `TRANSFER_ACK`）。
3. B 端取 prelude → `ys_unpack_meta_prelude` 先显示「来自 `sender_code` / 文件名 / 大小 / 块数」（标**未校验**）→ 逐块 GET → `ys_unpack_v1` 验签解密 → 落盘（切**已校验**）→ `ack`。

## 结果

- 注册、建包、分块、complete、取件、ack 全部 2xx；ack 后状态终结（再取 410，Node 链路另测）。
- 落盘 `ys-e2e-input.bin`：**2 506 889 字节**，sha256 与源文件**完全相同**。
- 服务端日志只有方法/路由/状态/字节数（无文件名、无明文）。
- 结果 JSON：`results/web/2026-11-02-D-core-sm2-real-auth.json`

## 能说明 / 不能说明

**能**：`SIG_INPUT` 的 `CODE(4)` 覆盖、DER 签名、`ZA`/userID 口径在**真实服务端验签**下成立（否则 `POST /v1/codes` 会 401）；
契约布局内核 + 真实 HTTP 服务端 + 分块传输 + 端侧解密在浏览器两端跑通，落盘逐字节一致。

**不能**：不能替代 Gate 的篡改/零明文证据；大文件上限见 PR「v1 已知限制」；TURN/直传未做。

## 一处环境发现（值得记）

Core 的 `server/kernel/README.md` 把内核固定为 `feat/endcrypto-wasm@f1ef9f9`、sha256 `8b89dd7f…`（130 653 B）；
在本沙盒用同一 commit 重建得到的是 **`c1b87d0a…`（127 313 B）**——**wasm 产物跨环境不可复现**（工具链/路径差异）。
所以"产物 ↔ 源码同源"不能只靠比 sha256，得同时记录 commit + `ys_version()` + 导出数（本仓库的
`npm run wasm:rebuild` 就是这么做的）；服务端要固定产物时，应以**自己构建并记录**的 sha 为准。
