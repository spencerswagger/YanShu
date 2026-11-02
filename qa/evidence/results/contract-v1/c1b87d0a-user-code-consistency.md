# 用户码跨实现一致性 · 冻结 head `233805a`（含"根因"的实测证据）

> **验收锚点：锚 sha256，不锚 head 号** —— 冻结产物 sha256 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313B）；head 号仅作溯源，sha256 一变则全部重跑。


- 日期：2026-11-02
- **冻结/最新 head**：`feat/endcrypto-wasm@233805a`（与 `80400ec`/`031e95b` **同一份产物**）
- wasm：**127,313 字节**，sha256 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`
- 脚本：`qa/evidence/check_code_consistency.py`
- 结论：**20/20 通过**（5 组公钥 × 4 入口逐字符一致；`PB_S = AWQW`；归一化 14 组一致）

## 1. 五组公钥 × 四入口（全部相等）

| 公钥 | wasm(64B) | wasm_wire(65B) | native(64B) | native(65B) |
|---|---|---|---|---|
| **契约 `PB_S`** | **AWQW** | **AWQW** | **AWQW** | **AWQW** |
| `b9bd344a…` | C5M6 | C5M6 | C5M6 | C5M6 |
| `639a4ce3…` | M5KA | M5KA | M5KA | M5KA |
| `049edc59…` | 9B2T | 9B2T | 9B2T | 9B2T |
| `7159249e…` | 52KB | 52KB | 52KB | 52KB |

退出码 0。

## 2. 归一化（wasm 侧 + 期望；给 `--base-url` 时再对 Core）

14 组：`AWQW` / `awqw` / `a-w-q-w` / ` AWQW ` / `AW\tQW` / `AWQW\r\n` / `0WQW` 接受；
`OI` / `AWQ` / **`AWQWX`** / **`AWQW-X`** / `AWQU` / `AWQ!` / 中文 / 空串拒绝。
wasm 与期望全一致；对 Core 服务端能判的用例（400 `CODE_FORMAT_INVALID` vs 404）同判，
被码查询限速打成 423 的记"判不了"，不计入一致。

## 3. "是代码修了，还是重建产物就对了" —— 三头实测（不依赖任何自述）

同一把 `PB_S`，三个 head 各构建一次 wasm 与 `ys-tool`，四种调用组合：

| head | wasm(64B) | wasm(65B `_wire`) | native(64B) | native(65B) | 说明 |
|---|---|---|---|---|---|
| `12b3d94`（契约对齐前） | **GPNV** | 无该导出 | **GPNV** | 只收 64B | 两侧都按 **64 字节**做 SM3 → 与契约不符 |
| `86fde3c`（契约对齐） | `CRYPTO_CURVE_INVALID` | 无该导出 | 只收 65B | **AWQW** | 入口改成收 **65 字节**（0x04），64B 调用会报错 |
| `233805a`（当前） | **AWQW** | **AWQW** | **AWQW** | **AWQW** | 两个宽度都正确（显式 `_wire` 入口） |

结论：**是代码真的改过**（`12b3d94` 上用同样的 64 字节输入算出 `GPNV`，与 `AWQW` 不同），
不是"重建产物碰巧就好了"；此后 64/65 混用导致的 `X2EH` 是**调用宽度**问题，
由 `f1ef9f9` 加 `_wire` 入口、`80400ec`/`95a24ac` 锁进 `cargo test` 解决。

> 我早前报 `X2EH` 时用的是**自己的驱动**，当时给 64 字节入口喂了 65 字节缓冲区——
> 那是我的调用 bug，已在 `adapters/README` 归档更正。

## 4. 已并入常规项

`qa/evidence/check_all.sh` 第 2 步（构建 → 自测 → **用户码一致性** → prelude 元数据 → 证据二），
任一失败整体非 0，末尾打印产物字节数与 sha256。内核 head 一变，一条命令重跑。

## 5. 产物与 run #5 进度（同日）

- 宿主二进制：`980fc44` 编好，`yanshu-server-980fc44` sha256
  `168ef3afa0b82142ff2ba717c5da100ac646b3b6173f5d76aefb3d984153b9ab`；
  `deliver-980fc44` sha256 `62daeb60045dbb058f94c505bd626b010860bd7ea863e2add8fe2833166c6ac4`。
  该二进制**没有 `--version`**，版本看 `/healthz`（`api_version=v1` / `contract=v1`）。
- run #5（真 `sm2`）已在 `980fc44` 上跑通：三处零命中、对照 1/1/1/0，
  详见 `2026-11-02-host-binary-980fc44.md`。
