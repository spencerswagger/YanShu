# 收口 · Web 真认证端到端（服务端 = 真 sm2，地址 `http://127.0.0.1:18080`）

> **锚 sha256，不锚 head 号。** 内核产物 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127 313 B）。
> **本文件是 Web 侧今晚唯一收口证据**；其它散文件（A/B/C/D）只作附件。

| 项 | 值 |
|---|---|
| 跑批 | 2026-11-02（夜班收口轮） |
| 服务端 | 宿主 `http://127.0.0.1:18080`，**`YANSHU_VERIFIER=sm2`（真验签）**、`YANSHU_TOKEN_EPOCH=1` |
| 服务端产物 | 宿主当前二进制（spencer 启动，`healthz` = `{"status":"ok","api_version":"v1","contract":"v1"}`） |
| 内核 | `c1b87d0a…` / 127 313 B / 34 函数 + `memory` / 0 import / `ys_version()=0x00010000` / HEADER 112 |
| 样本 | `ys-e2e-input.bin` **2 506 889 字节**，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 客户端 | 两个独立 Chrome profile（两个身份），前端 `web/` 经 vite 反代直连 18080 |
| 原始数据 | `results/web/c1b87d0a-closure-browser.json`（浏览器）、`results/web/c1b87d0a-closure-node.json`（Node 分支） |

## ④d 宿主实例真认证端到端（浏览器双端）

A 端：注册（真签名）→ 选 2.4 MiB 文件 → `ys_pack_v1` 打包 → prelude + **3 块**（`chunk_size=1048576`）→ complete → 「已发送」。
B 端：待收 → 取 prelude（`ys_unpack_meta_prelude` 先显示「来自谁/文件名/大小/块数」，标**未校验**）→ 逐块 GET →
`ys_unpack_v1` 验签解密 → 落盘（切**已校验**）→ `ack`。

- 落盘 `ys-e2e-input.bin`：**2 506 889 字节**，sha256 与源文件**完全相同**（`bytesEqual: true`）。
- 界面标签：`真实加密 · 契约布局内核（YSPK/1.0）`；内核自检「§2.3 四条」全过（版本 / HEADER / V1 样例真解 / 版本闸门）。
- `ack` 之后：`GET /v1/transfers/{id}` → `state=CONSUMED / terminal_reason=CONSUMED`；
  再取 prelude → **HTTP 410**，原始响应体：
  `{"error":{"code":"TRANSFER_CONSUMED","message":"transfer has been consumed","request_id":"…"}}`

## ④e 三条只有真认证才会暴露的行为（原始响应）

| 场景 | 实测 | 原始响应（节选） |
|---|---|---|
| 昵称签名 `NICKNAME_UPDATE`（真挑战 + 真 DER 签名） | **200** | `{"code":"…","nickname":"阿雁·真认证",…}` |
| 改 `SIG_INPUT` 一字节（DER 末字节取反） | **401** | `{"error":{"code":"AUTH_SIGNATURE_INVALID","message":"signature verification failed","request_id":"b55a2dcf24652b21"}}` |
| 复用已用挑战 | **401** | `{"error":{"code":"AUTH_CHALLENGE_INVALID",…}}`（未误报成签名错） |
| 请求路径码 ≠ 头里的码（签名对头码有效） | **401 `AUTH_CODE_MISMATCH`** | `{"error":{"code":"AUTH_CODE_MISMATCH","message":"X-YS-Code does not match the signed code","request_id":"req_732b4a4470d592b7"}}` |

> **更正（撤回一条假偏差）**：此前本文件记过“宿主返回 `AUTH_SIGNATURE_INVALID`”，那是**我构造错了**
> （签名与头码不对应，服务端按头码重建 `SIG_INPUT` 时验签先失败）。用最小复现
> `web/scripts/repro-code-mismatch.mjs`（只让路径码 ≠ 头码、签名严格按头码构造）在**同一宿主**复跑：
> **401 `AUTH_CODE_MISMATCH`**，与契约一致。该条偏差**撤回**，偏差清单以 Gate 的证伪结论为准。

## 401 凭证自愈（宿主 `EPOCH=1` 无法构造，用交付二进制本地真演练）

1. 上传到第 2 块人为中断（留下 `pending` 与旧 `upload_token`）；
2. `YANSHU_TOKEN_EPOCH` 1→2 重启（**同一交付二进制**）→ 旧 token 打 `GET /status`：
   **HTTP 401**，`{"error":{"code":"AUTH_TOKEN_STALE","message":"upload token was revoked by a key version rotation; create a new transfer","request_id":"…"}}`；
3. 客户端 `resumeSend` → **自动重建传输并重传**（用户无感）→ `state=READY`；
4. B 端取回 `heal.bin` **12 000 字节，逐字节一致**。

结果：`results/web/c1b87d0a-sm2-token-heal.json`。**标注：这一节是本地演练（非宿主实例）**，
因为宿主 `TOKEN_EPOCH=1` 未递增；宿主递增后同一脚本可直接复跑（`notes/c2-token-heal.mjs`）。
客户端按 `err.authFailed`（任意 401 / `AUTH_*`）触发，不依赖具体错误名。

## 结论与残留

- **端到端在真 sm2 下成立**：浏览器双端、分块、解密、落盘逐字节一致；`ack` 后 410。
- **真签名链路成立**：注册/昵称/建包全走真签名，篡改签名被拒，挑战复用被单独识别。
- **无残留偏差**：此前记的“路径码≠头码返回 `AUTH_SIGNATURE_INVALID`”已查明是我方构造错误（签名与头码不对应），
  用 `web/scripts/repro-code-mismatch.mjs` 正确构造后同宿主实测 **401 `AUTH_CODE_MISMATCH`**，与契约一致；该条已撤回。
- 未在宿主构造 `AUTH_TOKEN_STALE`（需递增 EPOCH，属运维动作）；自愈逻辑已在交付二进制上真演练通过。
