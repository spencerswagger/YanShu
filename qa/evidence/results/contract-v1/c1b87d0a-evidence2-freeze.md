# 验收冻结 head `80400ec` · 证据二（生产路径）与用户码一致性

- 日期：
> **验收锚点：锚 sha256，不锚 head 号** —— 本份对应产物 sha256 `c1b87d0a-d9a847fa-…`（完整值见正文），head 号仅作溯源；sha256 一变则全部重跑。
2026-11-02
- **冻结 head**：`feat/endcrypto-wasm@80400ec`
- wasm 产物：**127,313 字节**，sha256 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`
- `ys_version()`：`0x00010000`（0.1.0）
- 入口类型：**`wasm-production`**（`--entry-kind production`，走 `ys_pack_v1` / `ys_unpack_v1`）

同一份 head 上的两件事，都跑在这个产物上：

## 1) 证据二（篡改必报错）全量

| 组 | 结果 |
|---|---|
| 单块包（6 条，含版本闸门） | **PASS 6 / FAIL 0** |
| 多块包（11 条，含版本闸门） | **PASS 11 / FAIL 0** |
| 补充变体（18 种） | **PASS 18 / FAIL 0** |
| 未报错 | **0** |

基线（未篡改包）解出的明文与原文逐字节一致。
版��闸门用例：旧 `rune-v1` 格式包 → `CRYPTO_VERSION_UNSUPPORTED`。

复跑：`qa/evidence/run_evidence2_wasm.sh <rune-crate@80400ec> <workdir>`。

## 2) 跨实现一致性（用户码派生 + 归一化）

| 组 | 结果 |
|---|---|
| 用户码派生：5 组公钥 × 4 入口（wasm 64/65、原生 64/65） | **全部逐字符一致** |
| `PB_S` | 四处均 **`AWQW`**（契约 §15.1 值，校验位 `X`） |
| 归一化：14 组输入（接受 7 / 拒绝 7） | wasm 与期望全一致；含 `AWQWX`/`AWQW-X` 5 位整体拒绝 |

复跑：`qa/evidence/check_code_consistency.py --wasm … --ys-tool … [--base-url …]`。

## 3) 与更早 head 的对照（为什么必须钉住 head）

| head | wasm 字节 | sha256 前 16 | 用户码（`PB_S`） | 说明 |
|---|---:|---|---|---|
| `3c546c0` | 124,360 | `f0c7681f0ea3e0fe` | `AWQW`（wasm 64 / native 65 两入口） | `_wire` 与 ys-tool-64 尚不存在 → 脚本按"能力缺口"SKIP |
| `f1ef9f9` | 127,313 | — | 四入口 `AWQW` | 新增 `_wire` 显式入口 |
| **`80400ec`（冻结）** | **127,313** | `c1b87d0ad9a847fa` | 四入口 `AWQW` | 一致性锁进 `cargo test`（`tests/ffi_user_code.rs` + `tests/wasm_user_code.rs`） |

> "结果对、产物旧"是这类跨端验证最常见的坑：文件名与报告里必须同时写 **head + 产物 sha256**，
> 否则下一个人无法判断手里的 wasm 是哪版。

## 4) 边界

认证为 `stub-allow` 之外的 sm2 那份单列在 `2026-11-02-evidence1-core-run5-sm2.md`；
本文件不涉及存储/DB/日志扫描。
