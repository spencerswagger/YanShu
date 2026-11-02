# 证据二实测结果：密文篡改必报错（**生产导出路径**：wasm32 raw C ABI）

- 日期：2026-11-02
- 对象：`crypto/sm`，分支 `feat/endcrypto-wasm` @ **`e9f8254`**（Rune 已删除 rune-v1 旧布局，
  仓库只剩 `YSPK/1.0`；解密调用走 6 参 `ys_unpack_v1`，没有则回退 7 参 `ys_unpack` 传 NULL）
- **入口类型：`wasm-production`**（`--entry-kind production`）
- `ys_version()`：`0x00010000` → **0.1.0**；wasm 文件 sha256
  `a657b33948b7299bd282e2c4a6b4774906afa8c61d3a0e6a7fa279d2c2b57b19`（124,976 字节）
- 包布局：`contract-v1`（默认）
- 解密入口：**`yanshu_sm.wasm` 的 `ys_unpack`**（`--entry-kind production`）——
  就是 Web 将来要调的同一批导出，不是 Rust 原生 API、也不是测试替身
- 打包同样走 wasm：`ys_pack_v1`（同一个 `.wasm`，见上面的 sha256）
- 判定：解密失败即 PASS（任一道防线拒绝都算）；错误名只作诊断
- 基线：未篡改包解出的明文与原文**逐字节一致**（`--expect-plaintext`）

## 复跑

```sh
git -C <YanShu> archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune
qa/evidence/run_evidence2_wasm.sh /tmp/rune/crypto/sm /tmp/ys-ev2-wasm
```

脚本做的事：构建 `wasm32-unknown-unknown` → 用 wasm 的 `ys_sm2_keygen` / `ys_pack_v1`
产密钥与包（单块 + 三块等长 + donor）→ 用 `ys_unpack` 跑全套篡改检查。

## 结果

单块包（569B / 1 块 / 明文 35B）：**PASS 5 / FAIL 0 / SKIP 5**
（删块、换序、换包块、半块、截尾对单块包不适用，记 SKIP 不记 FAIL）

多块包（3742B / 3 等长块 1024B / 明文 3072B）：**PASS 10 / FAIL 0 / SKIP 0**

| 用例 | 结果 | 实际错误名（诊断） |
|---|---|---|
| baseline | PASS | 解密成功，明文逐字节一致 |
| flip-envelope-header（`HEADER[56]` KDF_SALT） | PASS | `MANIFEST_MISMATCH` |
| flip-chunk-header（块号末字节） | PASS | `MISSING_BLOCK` |
| flip-chunk-data（密文中段 1 字节） | PASS | `TAG_MISMATCH` |
| drop-middle-chunk | PASS | `TRUNCATED` |
| swap-chunks | PASS | `MISSING_BLOCK` |
| splice-donor-chunk（换入另一包合法块） | PASS | `TAG_MISMATCH` |
| flip-chunk-tag | PASS | `TAG_MISMATCH` |
| drop-chunk-slice | PASS | `TRUNCATED` |
| truncate-tail | PASS | `TRUNCATED` |

错误名分布（仅诊断）：`TAG_MISMATCH×3`、`TRUNCATED×3`、`MISSING_BLOCK×2`、`MANIFEST_MISMATCH×1`。

## 补充变体（18 种，生产路径同一入口）

| 篡改 | 结果 | 错误名 |
|---|---|---|
| 包头 FLAGS | PASS | `BAD_FLAGS` |
| 包头 AEAD_ID | PASS | `UNSUPPORTED_VERSION` |
| 包头 KDF_SALT | PASS | `MANIFEST_MISMATCH` |
| 包头 CHUNK_SIZE | PASS | `MANIFEST_MISMATCH` |
| 包头 CHUNK_COUNT | PASS | `TRUNCATED` |
| 包头 PLAINTEXT_SIZE | PASS | `TRUNCATED` |
| 包头 RESERVED | PASS | `BAD_FLAGS` |
| 发送方公钥首字节 | PASS | `BAD_POINT` |
| DK 封装 C1 字节 | PASS | `BAD_KEY_RECORD` |
| 签名 DER 末字节 | PASS | `SIGNATURE_MISMATCH` |
| 清单密文字节 | PASS | `MANIFEST_MISMATCH` |
| 块头 PT_LEN | PASS | `TRUNCATED` |
| 块头 CT_LEN | PASS | `TRUNCATED` |
| 块头 LAST_FLAG | PASS | `BLOCK_SEQUENCE` |
| 块头 RESERVED | PASS | `BAD_FLAGS` |
| 尾部追加 1 字节 | PASS | `TRUNCATED` |
| 交换两块密文+tag（保留块头） | PASS | `TAG_MISMATCH` |
| 块 0 换成块 1 的密文 | PASS | `TAG_MISMATCH` |

**未报错 0 种**。

（本次 head `e9f8254` 复跑：单块 5/5、多块 10/10、补充变体 18/18，与上一版结论一致。）

## 与 native-api 那份（`2026-11-02-evidence2-contract-v1.md`）的差别

| 项 | native-api 那份 | 本份 |
|---|---|---|
| 解密入口 | Rust 原生 `pack::unpack` | **wasm `ys_unpack`（生产导出）** |
| 打包 | Rust 原生 `pack::pack` | **wasm `ys_pack_v1`** |
| 结果 | 5/5、10/10、18/18 | 5/5、10/10、18/18 |
| 结论效力 | 测试入口，不算最终验收 | **可作为 v1 的验收证据**（入口即生产路径） |

两份都留在 `results/contract-v1/`，因为一个证明"算法与格式正确"，一个证明"Web 真正调的那条路也正确"。

## 发现的问题（不影响结论，但要让实现方知道）

1. **头文件注释与实现不一致**：`crypto/include/yanshu_sm.h` 里 `ys_pack_v1` 的
   `recipient_public` 注释写 `/* 64 */`，但实现（`ffi.rs`）读 **65 字节**并强制 `0x04` 前缀，
   传 64 字节会得到 `BAD_POINT`。驱动里已按 65 处理并做了 64→65 自动补前缀。
   （本轮复查 `73e4b2a` 的头文件，注释仍未改；`ys_unpack` 的 7 参/`_v2` 6 参说明已补齐。）
2. **wasm 的 `ys_error_name` 返回不带 `CRYPTO_` 前缀**（如 `TAG_MISMATCH`），而 native/Rust
   侧错误名是 `CRYPTO_*`。两边不一致会让"按错误名做前端映射"时踩坑；本次用
   `--error-regex 'ERR [A-Z_]+'` 兼容，但建议统一。
3. `RUSTFLAGS=-C linker=gcc` 这类全局设置会把 wasm 目标也带偏（rust-lld 被替换成 gcc
   直接报错）。已改成按 host target 变量设置，脚本里留了注释。

## 待补：Web 集成后的 C 份

本份是 Gate 直接用 Rune 构建出的 `.wasm` 跑的（入口就是生产 ABI，但**不是** Web 适配层
实际加载的那个产物）。等 Web 用同一份内核接好并通过它自己的页面链路跑通，再用
`--entry-kind production` 复跑一份（C 份）存到同目录，才算"浏览器里那条路"的验收。
在那之前本份定位是"生产 ABI 已验"，不是"Web 已验"。

## 边界

- 只验解密与篡改拒绝，不验 Web 的 JS 适配层（那层是 Web 的事）。
- 未覆盖并发、断点续传中途篡改、跨版本包。
