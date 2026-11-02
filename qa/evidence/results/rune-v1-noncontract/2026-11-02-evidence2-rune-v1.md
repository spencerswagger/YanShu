# 证据二实测结果：密文篡改必报错（**非契约实现的临时验证**）

> ⚠️ **这份结果不是对契约实现的验收。**
> 被测对象是端侧内核按 `pack.rs::layout`（HEADER 40B / 块头 9B / raw R‖S / 密文摘要）
> 产出的包，与已冻结的 `docs/CRYPTO-PACK.md`（HEADER 112B / 块头 16B / DER 签名 / 明文摘要）
> **不是同一套格式**。按裁定：**契约权威，端侧按契约重写**。
> 本文件保留，仅用于记录"旧布局下的解密入口是严格拒绝篡改的"这一事实，
> 以及给重写提供对照。契约实现就绪后，会用默认布局（`--layout contract-v1`）
> 重跑全量，结果另存为 `YYYY-MM-DD-evidence2-contract-v1.md`。
>
> 跑这份结果时需要显式 `--layout rune-v1`；工具默认已经是契约布局，并会在
> 非契约布局时打印「不作验收」横幅。
>
> 判定口径：**解密失败即 PASS，与具体错误码无关**。下文表格里的
> `BLOCK_SEQUENCE` / `MANIFEST_MISMATCH` / `TRUNCATED` / `MISSING_BLOCK` 是这一版实现的
> 错误名，仅作诊断与对照；返工后这些名字会变，不算回归。

- 日期：2026-11-02
- 对象：`crypto/sm`（分支 `feat/endcrypto-wasm`，commit `12b3d94`）
- 后端：`--backend cmd` → `qa/evidence/adapters/ys_pack_probe`（真实 `yanshu_sm::pack`
  打包 / `yanshu_sm::pack::unpack` 解包，**不是测试替身**）
- 判定：baseline（未篡改包）必须解出与原文**逐字节一致**的明文；每条篡改必须返回
  明确错误；任何一条返回成功即整体 FAIL
- 结论：**真 PASS**（旧实现）。10/10 篡改全部被明确拒绝，附加 16 种变体无一漏网

## 复跑

```sh
# 取端侧源码（任意目录，不进仓库）
git -C <YanShu> archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune

# 一条命令跑完：构建探针 → 生成密钥 → 打包（单块 + 三块 + donor）→ 篡改检查
# 注意：跑非契约布局必须显式指定 rune-v1（脚本里已带），否则默认按契约解析、直接报错
qa/evidence/run_evidence2_rune.sh /tmp/rune/crypto/sm /tmp/ys-ev2
```

产物（`.yspk`、密钥、`result-*.json`）全部落在 workdir，不入仓库。

## 结果

单块包（444B，`BLOCK_COUNT=1`，明文 68B）：

| 用例 | 结果 | 实际错误名 |
|---|---|---|
| baseline | PASS | 解密成功，明文逐字节一致 |
| flip-envelope-header | PASS | `MANIFEST_MISMATCH` |
| flip-chunk-header | PASS | `BLOCK_SEQUENCE` |
| flip-chunk-data | PASS | `MANIFEST_MISMATCH` |
| flip-chunk-tag | PASS | `MANIFEST_MISMATCH` |
| drop/swap/splice/half/truncate | SKIP | 只有 1 块，用例不适用（不记 FAIL） |

多块包（2558B，`BLOCK_COUNT=3`，`BLOCK_SIZE=1024`，明文 2061B）：

| 用例 | 结果 | 实际错误名 |
|---|---|---|
| baseline | PASS | 解密成功，明文逐字节一致 |
| flip-envelope-header（`HEADER[8]`，FILE_ID） | PASS | `MANIFEST_MISMATCH` |
| flip-chunk-header（块号末字节） | PASS | `BLOCK_SEQUENCE` |
| flip-chunk-data（密文中段 1 字节） | PASS | `MANIFEST_MISMATCH` |
| drop-middle-chunk（删整条块记录） | PASS | `BLOCK_SEQUENCE` |
| swap-chunks（交换块 0/1） | PASS | `BLOCK_SEQUENCE` |
| splice-donor-chunk（换入另一包的合法块） | PASS | `MANIFEST_MISMATCH` |
| flip-chunk-tag（GCM tag 1 字节） | PASS | `MANIFEST_MISMATCH` |
| drop-chunk-slice（只删密文+tag） | PASS | `TRUNCATED` |
| truncate-tail（截尾块） | PASS | `MISSING_BLOCK` |

合计 PASS 10 / FAIL 0 / SKIP 0，退出码 0。失败路径**不写任何输出文件**
（探针在 `unpack` 返回 Err 时不落盘，实测 0 字节残留），不存在"返回部分明文"。

## 补充探针（16 种，找漏网）

| 篡改 | 错误名 |
|---|---|
| 块头 `flags` 字节 | `LAST_FLAG_MISMATCH` |
| 块头 `ct_len` 字节 | `MANIFEST_MISMATCH` |
| 包头 `block_count` / `plain_size` / `block_size` | `MANIFEST_MISMATCH` |
| 包头 `magic` | `BAD_MAGIC` |
| 包头 `version` / `suite` | `UNSUPPORTED_VERSION` |
| 包头 `flags` / `reserved` | `BAD_FLAGS` |
| 签名末字节 | `SIGNATURE_MISMATCH` |
| DK 封装 C1 字节 | `BAD_KEY_RECORD` |
| 清单密文字节 | `MANIFEST_MISMATCH` |
| 尾部追加 1 字节 | `TRAILING_BYTES` |
| 交换两块密文+tag（保留各自块头） | `MANIFEST_MISMATCH` |
| 块 0 换成块 1 的密文 | `MANIFEST_MISMATCH` |

未报错 0 种。

## 两点观察（不是缺陷，但要写进契约口径）

1. **`TAG_MISMATCH` 在端到端篡改下取不到**。解包顺序是"清单摘要（`SM3(ct‖tag)`）→ GCM"，
   而清单本身被加密+签名保护，攻击者改不了摘要表，所以任何密文/tag 改动都先被
   `MANIFEST_MISMATCH` 拦下。GCM tag 校验依然在（`gcm::decrypt` 失败映射 `TAG_MISMATCH`），
   只是外部攻击路径打不到。报告引用错误名时不要写死 `TAG_MISMATCH`。
2. **块号与密文在 AEAD 里并没有直接绑定**（nonce 只由块序号派生，AAD 是包头）。
   "交换两块密文+tag 但保留块头" 之所以被拒，靠的是清单里的 `SM3(ct‖tag)` 摘要，
   不是 GCM。若将来允许"无清单"模式，这条会退化 —— 建议在契约里写明摘要表是必需项。

## 契约与实现的差异（需要拍板）

`docs/CRYPTO-PACK.md`（Ark，v1 冻结稿）与 `crypto/sm/src/pack.rs::layout`（Rune 现实现）
**是两套格式**，逐项不同：

| 项 | CRYPTO-PACK v1 | 端侧实现 |
|---|---|---|
| HEADER | 112 字节（含 HEADER_LEN/算法 ID/各段长度/KDF_SALT/RESERVED） | 40 字节（magic/version/suite/flags/reserved/file_id/block_size/block_count/plain_size） |
| 块记录头 | 16 字节（index/pt_len/ct_len/last/reserved） | 9 字节（index u32/flags u8/ct_len u32） |
| prelude 段 | HEADER+SENDER_PUB(65)+WRAPPED_KEY(129)+MANIFEST_SEC+SIG_SEC(DER 70..72) | HEADER+KEY_REC(kind+len+128)+SIG_REC(kind+len+64)+MANIFEST_REC(len+ct+tag) |
| 块 nonce | `u64be(i)‖000000‖last` | `u32be(i)‖00000000‖flag‖000000` |
| 清单 nonce | `ff…ff‖000000‖01` | `ff…ff‖80‖000000` |
| 每块摘要 | `SM3(明文块)` | `SM3(密文‖tag)` |
| 清单明文 | `YSM1` 魔数 + 文件名/MIME/EXT/时间/摘要表 | 无魔数：name/mime/block_size/count/size/摘要表 |
| SM2 封装 | 129B（`0x04` 前缀 + C1C3C2） | 128B（C1 = X‖Y 无前缀） |
| 签名 | DER（70..72B），输入 `YSSIG1‖ver‖HDR_CORE‖SENDER_PUB‖MANIFEST_SEC` | raw `R‖S`（64B），输入 `HEADER‖MANIFEST_PLAINTEXT` |
| AAD | `AAD_CHUNK(32)` / `AAD_MANIFEST(31)` 结构化 | 直接是 40 字节包头 |

本脚本因此做成**可插拔布局**，但**默认是契约布局**：不显式给 `--layout` 时按
`contract-v1` 解析，跑旧实现的包会直接报 `CRYPTO_VERSION_UNSUPPORTED` 并提示用
`--layout auto` 先判别；显式 `--layout rune-v1` 时输出会打「非契约实现、不作验收」横幅，
JSON 里也会带 `contract_compliant: false`。本文件的所有结果均属 `rune-v1`。
`contract-v1` 目前只由契约里的公开测试向量覆盖，等端侧按契约重写后再跑全量。

## 复跑时的两个坑（已修）

1. **共享 `CARGO_TARGET_DIR` 会串版本**：沙盒全局 `CARGO_TARGET_DIR=/.cache/rust`，
   多人共用时出现过"用旧源码构建、却复用别人新版本的 `libyanshu_sm`"。已改成构建产物
   落在临时目录（`adapters/build_probe.sh` 不再继承该变量）。上表结果已在隔离构建下复跑确认。
2. **默认布局已切到契约**：不带 `--layout` 时按 `contract-v1` 解析，拿旧包会直接
   `CRYPTO_VERSION_UNSUPPORTED`；跑本文件的结果必须显式 `--layout rune-v1`。

## 本次没做的

- 没有验证 wasm 侧（`cdylib` + raw C ABI）路径；本次走的是同一个 crate 的原生 API。
  等 Web 接上适配层后，可用 `--backend cmd` 指向浏览器/Node 侧的解密入口再跑一遍。
- 没有覆盖"服务器把包换掉"这类元数据层攻击（不在证据二范围）。
