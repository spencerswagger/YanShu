# 验收冻结 head `80400ec` · 证据二（生产路径）与用户码一致性


> 复核：在 `80400ec` 上由 `git archive` + 独立 target 重新构建并复跑，产物 127,313B / sha256 `c1b87d0a…7259f`，单块 6/6、多块 11/11。

> **验收锚点：锚 sha256，不锚 head 号** —— 冻结产物 sha256 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313B）；head 号仅作溯源，sha256 一变则全部重跑。


- 日期：2026-11-02
- **冻结 head（正式）**：`feat/endcrypto-wasm@**031e95b**`；本份实际构建自 `80400ec`，两者 `crypto/sm/src` 与 `Cargo.toml` **零改动**、产物**同字节**（127,313B / 同一 sha256）
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

## 最终重跑（宿主重启后，`check_all.sh` 一条命令）

```
wasm 127,313 B / sha256=c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f
自测 11/11、14/14 → 用户码一致性 26/26 → prelude 元数据 6/6 → 证据二 6/6 + 11/11
服务端内嵌内核（/worktrees/YS-CORE）sha 白名单 + 向量套件：exit=0
```

宿主实例（`yanshu-server-980fc44`）端到端冒烟：`/healthz` 200；3 块包（3072B→3738B），
绕开 `deliver` 自行 GET prelude + 3 块，**逐字节一致**（transfer `e3d6cc8e…`）。
