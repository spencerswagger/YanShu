# 证据二实测结果：密文篡改必报错（契约布局 `YSPK/1.0`）

- 日期：2026-11-02
- 对象：`crypto/sm`，分支 `feat/endcrypto-wasm`，commit `de6d6e1`
- 包布局：**`contract-v1`（默认，`YSPK/1.0`）** —— 112B 头、`SENDER_PUB` 入包、C1 带 `0x04`、
  DER 签名、`u64be(index)` nonce、结构化 32B AAD
- 解密入口：**Rust 原生 API（`pack::unpack`）**，即 `--entry-kind native-api`
  → **属"测试入口"，不是 wasm C ABI 生产导出路径**；结论需在 wasm 生产路径上复跑一次
  才作为最终验收（Web 的适配层就绪后做）
- 判定：**解密失败即 PASS（清单层 / AEAD 层 / 结构层任一道拒绝都算）**；
  判 FAIL 的唯一条件是"解密成功或返回部分明文"。错误名只作诊断，不参与判定
- 基线：未篡改包解出的明文与原文**逐字节一致**（`--expect-plaintext` 比对通过）

## 复跑

```sh
git -C <YanShu> archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune
qa/evidence/run_evidence2_contract.sh /tmp/rune/crypto/sm /tmp/ys-ev2
```

一键脚本做的事：构建探针 → 生成两对密钥 → 打包（单块 1 MiB 块 + 三块 1 KiB 块 + donor）
→ 默认契约布局跑篡改检查。产物（包、密钥、JSON）落在 workdir，不入仓库。

## 结果

单块包（603B，`BLOCK_COUNT=1`，明文 68B）：

| 用例 | 结果 | 实际错误名（诊断） |
|---|---|---|
| baseline | PASS | 解密成功，明文逐字节一致 |
| flip-envelope-header | PASS | `CRYPTO_MANIFEST_AUTH_FAILED` |
| flip-chunk-header | PASS | `CRYPTO_CHUNK_MISSING` |
| flip-chunk-data | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |
| flip-chunk-tag | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |
| drop / swap / splice / 半块 / 截尾 | SKIP | 只有 1 块，用例不适用（不记 FAIL） |

多块包（2732B，`BLOCK_COUNT=3`，`BLOCK_SIZE=1024`，明文 2061B）：

| 用例 | 结果 | 实际错误名（诊断） |
|---|---|---|
| baseline | PASS | 解密成功，明文逐字节一致 |
| flip-envelope-header（`HEADER[56]` KDF_SALT） | PASS | `CRYPTO_MANIFEST_AUTH_FAILED` |
| flip-chunk-header（块号末字节） | PASS | `CRYPTO_CHUNK_MISSING` |
| flip-chunk-data（密文中段 1 字节） | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |
| drop-middle-chunk（删整条块记录） | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| swap-chunks（交换块 0/1） | PASS | `CRYPTO_CHUNK_MISSING` |
| splice-donor-chunk（换入另一包的合法块） | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |
| flip-chunk-tag（GCM tag 1 字节） | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |
| drop-chunk-slice（只删密文+tag） | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| truncate-tail（截尾块） | PASS | `CRYPTO_LENGTH_INCONSISTENT` |

合计 **PASS 10 / FAIL 0 / SKIP 0**，退出码 0。
错误名分布（仅诊断）：`CRYPTO_CHUNK_AUTH_FAILED×3`、`CRYPTO_LENGTH_INCONSISTENT×3`、
`CRYPTO_CHUNK_MISSING×2`、`CRYPTO_MANIFEST_AUTH_FAILED×1`。
失败路径**不写任何输出文件**（`unpack` 返回 Err 时不落盘，实测 0 字节残留）。

## 补充变体（18 种，找漏网）

| 篡改 | 结果 | 错误名 |
|---|---|---|
| 包头 FLAGS | PASS | `CRYPTO_FLAGS_UNKNOWN` |
| 包头 AEAD_ID | PASS | `CRYPTO_ALG_UNSUPPORTED` |
| 包头 KDF_SALT | PASS | `CRYPTO_MANIFEST_AUTH_FAILED` |
| 包头 CHUNK_SIZE | PASS | `CRYPTO_MANIFEST_AUTH_FAILED` |
| 包头 CHUNK_COUNT | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| 包头 PLAINTEXT_SIZE | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| 包头 RESERVED | PASS | `CRYPTO_HEADER_INVALID` |
| 发送方公钥首字节 | PASS | `CRYPTO_CURVE_INVALID` |
| DK 封装 C1 字节 | PASS | `CRYPTO_KEY_UNWRAP_FAILED` |
| 签名 DER 末字节 | PASS | `CRYPTO_SIGNATURE_INVALID` |
| 清单密文字节 | PASS | `CRYPTO_MANIFEST_AUTH_FAILED` |
| 块头 PT_LEN | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| 块头 CT_LEN | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| 块头 LAST_FLAG | PASS | `CRYPTO_CHUNK_ORDER` |
| 块头 RESERVED | PASS | `CRYPTO_HEADER_INVALID` |
| 尾部追加 1 字节 | PASS | `CRYPTO_LENGTH_INCONSISTENT` |
| 交换两块密文+tag（保留各自块头） | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |
| 块 0 换成块 1 的密文 | PASS | `CRYPTO_CHUNK_AUTH_FAILED` |

**未报错 0 种**。没有发现"某类篡改居然没报错"。

## 结论与边界

1. **契约布局下全量通过**：单块 5/5、多块 10/10、补充变体 18/18，没有任何一条返回明文
   或"尽力恢复"。
2. **两层防线都能观测到**：清单层（`CRYPTO_MANIFEST_AUTH_FAILED`）与 AEAD 层
   （`CRYPTO_CHUNK_AUTH_FAILED`）在本次都有实际触发，说明两层不是纸面上的。
   旧实现的"端到端取不到 tag 类错误"在契约版已不再成立——因为摘要口径改为明文块，
   密文改动先撞 AEAD。这条差异属预期，不是回归。
3. **AAD 里的块号绑定无法从外部单独验证**：nonce 也随块序号变化，任何"换块/换位"都会
   同时踩到 nonce 与 AAD，外部构造无法把它们分开。直接验证 AAD 绑定要依赖实现方的
   单元级反例（Rune 已补 `check_01…check_22`），Gate 只记录这个边界，不据此判分。
4. **入口性质**：本次走 Rust 原生 API（native-api），不是 wasm C ABI 生产导出路径；
   等 Web 的 wasm 适配层接好，用 `--entry-kind production` 再跑一遍，才算最终验收。
5. **没有覆盖**：服务器替换整包/替换元数据（元数据层攻击）、并发/断点续传下的篡改、
   跨版本包（v2 预留位）。

## 附：本次没做的

- wasm 生产路径复跑（等 Web）。
- 证据一（服务端无明文）仍是 PENDING：等 Core 的投递驱动命令与五项参数。
