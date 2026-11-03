# 证据 C · **宿主常驻实例 + 契约布局内核**（跨浏览器端到端）

> **限定（写死在文件头）**
> - 中转 = **宿主常驻实例** `http://127.0.0.1:18080`（`yanshu_dev`，`YANSHU_VERIFIER=stub-allow` 仅联调）。
>   服务端**尚未接真实 SM2 验签**，所以本证据覆盖端侧密码学 + 传输链路，不覆盖服务端验签；验签落地后需再跑一份。
> - 内核 = **契约布局** `YSPK/1.0`，构建自 **验收冻结 head** `feat/endcrypto-wasm@80400ec`（`ys_version()=0x00010000`、
>   `ys_header_len()=112`、30 函数 + `memory`、0 import、`ys_unpack_v1`/`_meta_v1` 6 参自证）。

| 项 | 值 |
|---|---|
| 运行标签 | `C-host-instance-contract-kernel` |
| 日期 | 2026-11-02 |
| 前端 | `web/`（Vue 3 + Vite dev server，`/v1` 反代到宿主实例） |
| 中转 | 宿主 `127.0.0.1:18080`（`yanshu-server-980fc44`，契约 `v1` / `YSPK/1.0`，chunk 1 MiB） |
| 内核（锚 sha256） | **127 313 B / `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`**（= 冻结产物，head `80400ec` 仅作溯源）；34 函数 / 0 import；`PB_S → AWQW`（64B）/ `X2EH`（误传 65B）均已打印 |
| 样本 | `ys-e2e-input.bin`，2 506 889 字节，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 分块 | 服务端 `chunk_size=1048576` → **3 块**（2×1 MiB + 409 601 B） |
| 客户端 | 两个独立 Chrome profile（两个身份） |

## 流程

A：注册（真码）→ `ys_pack_v1` 打包（清单写实 `ext`/`created_at`）→ prelude + 3 块 PUT → complete → 「已发送」。
B：待收 → `GET /v1/inbox` → 取 prelude（开租约）→ **`ys_unpack_meta_prelude` 立刻显示「来自谁 / 文件名 / 大小 / 块数」，并标 `未校验`** →
逐块 GET → `ys_unpack_v1` 验签解密（只给私钥）→ 落盘（此时切 `已校验`）→ `ack`。

## 结果

- 落盘 `ys-e2e-input.bin`：**2 506 889 字节**，sha256 与源文件**完全相同**（`bytesEqual: true`）。
- 结果 JSON：`results/web/2026-11-02-C-host-instance-contract-kernel.json`
- 两态标注：prelude 阶段 `scope=prelude` / `data_verified=false`（块未到齐），落盘前 `ys_unpack_v1` 成功后才标 `已校验`；
  整包 `ys_unpack_meta(_v1)` 对 prelude-only 返回 `CRYPTO_TRUNCATED`（有测试钉住，两个入口不混用）。
- 截图：`outbound/screenshots/C-host-instance-contract-kernel-*.png`（工作区，不入库）

## 后续

真认证版本见 `2026-11-02-D-core-sm2-real-auth.md`（服务端切 `YANSHU_VERIFIER=sm2` 后同一套流程复跑）。

## 能说明 / 不能说明

**能**：契约布局内核 + 真实服务端（契约 `/v1` 路径、1 MiB 分块、租约、ack 终结）在浏览器两端跑通，落盘逐字节一致。
**不能**：不能替代服务端认证验收（`stub-allow`）；不能替代 Gate 的篡改证据；大文件上限见 PR 的「v1 已知限制」。
