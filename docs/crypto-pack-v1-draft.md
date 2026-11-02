# 加密包格式 v1（草案 · 待 Ark 冻结稿替换）

> 状态：**临时锚点**。`docs/CRYPTO-PACK.md` 尚未落盘，本文件按 `docs/REQUIREMENTS.md` §4
> 的包格式基线实现，字段布局集中写在代码里的 `crypto/sm/src/pack.rs` 的 `layout` 模块。
> Ark 的定稿字段落盘后，**只改 `layout` 与 `Header`/`Manifest` 的序列化**，其余调用方不动。
>
> 已与 GmSSL 逐字节交叉验证（`scripts/crosscheck/`，77 项全 PASS）。

## 1. 总布局

```text
HEADER(40) | KEY_REC | SIG_REC | MANIFEST_REC | BLOCK(0) | BLOCK(1) | ... | BLOCK(n-1)
```

所有整数**大端**。没有任何字段依赖"尽力恢复"，解析严格。

## 2. HEADER（40 字节，同时是每个块与清单的 AAD）

| 偏移 | 长度 | 字段 | 值 / 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | `YSPK`（`59 53 50 4B`） |
| 4 | 1 | `version` | `1`；其它值 → `UNSUPPORTED_VERSION` |
| 5 | 1 | `suite` | `1` = SM4-GCM-128 + SM3 + SM2(C1C3C2) |
| 6 | 1 | `flags` | bit0 = 1（含加密清单）；其余位必须为 0 |
| 7 | 1 | `reserved` | `0`，非 0 → `BAD_FLAGS` |
| 8 | 16 | `file_id` | CSPRNG；HKDF 的 info，用于区分同 DK 的不同文件 |
| 24 | 4 | `block_size` | 明文块大小（默认 1 MiB = `1048576`）；`1..=64 MiB` |
| 28 | 4 | `block_count` | 必须等于 `max(1, ceil(plain_size/block_size))` |
| 32 | 8 | `plain_size` | 明文总字节数 |

块数规则：**空文件也算 1 个空块**（`ct_len = 0`），保证"末块标志"机制永远有末块。

## 3. KEY_REC（DK 封装）

```text
u8  kind = 1
u32 len  = 128
u8  payload[128]   # SM2(C1C3C2) 加密的 32 字节文件密钥 DK
```

`payload` = `C1(64) = x1||y1`（不带 0x04 前缀）`|| C3(32) || C2(32)`。
kind/len 不符或 SM2 解密失败 → `BAD_KEY_RECORD`。

## 4. SIG_REC（来源签名）

```text
u8  kind = 2
u32 len  = 64
u8  payload[64]    # SM2 签名 r||s（非 DER）
```

签名对象：`SM3(ZA || HEADER || MANIFEST_PLAINTEXT)`，ID 固定 `1234567812345678`（GB/T 32918.2 默认）。
验签失败 → `SIGNATURE_MISMATCH`。收件人需从"用户码 → 公钥"拿到 `sender_public` 才能验签。

## 5. MANIFEST_REC（加密清单）

```text
u32 ct_len
u8  ct[ct_len]
u8  tag[16]
```

* 清单密钥：`K_man = HKDF-SM3(salt="YanShu/v1/manifest", ikm=DK, info=file_id, 16B)`
* 清单 nonce（固定 12 字节）：`ff ff ff ff ff ff ff ff 80 00 00 00`
* AAD = HEADER 40 字节
* tag 校验失败或清单自解析失败 → `MANIFEST_MISMATCH` / `BAD_MANIFEST_RECORD`

清单明文（大端）：

| 长度 | 字段 |
|---:|---|
| 2 | `name_len`（1..=512） |
| name_len | 文件名 UTF-8（**服务端不可见**） |
| 2 | `mime_len`（0..=128） |
| mime_len | MIME UTF-8 |
| 4 | `block_size` |
| 4 | `block_count` |
| 8 | `plain_size` |
| 4 | `digest_count`（必须 = `block_count`） |
| 32 × n | 每块 `SM3(ct || tag)` |

清单里的 `block_size/block_count/plain_size` 必须与 HEADER 完全一致，否则 `MANIFEST_MISMATCH`。
每块摘要对**密文块字节（ct||tag）**计算：这样断点续传时无需解密即可校验已收块。

## 6. BLOCK

```text
u32 index        # 块号，必须 0,1,2,... 连续
u8  flags        # bit0 = 1 表示末块，其余位必须 0
u32 ct_len       # 明文长度（GCM 不改变长度）
u8  ct[ct_len]
u8  tag[16]
```

* 块密钥：`K_blk = HKDF-SM3(salt="YanShu/v1/block", ikm=DK, info=file_id, 16B)`
* 块 nonce（12 字节，STREAM 构造）：`index_be32 || 00 00 00 00 || flag || 00 00 00`
  - `flag = 0x01` 仅末块，其余 `0x00`
* AAD = HEADER 40 字节
* 长度规则：非末块 `ct_len = block_size`；末块 `ct_len = plain_size - (n-1)*block_size`

## 7. 严格拒绝规则（解包）

| 情况 | 错误 |
|---|---|
| 魔数不对 | `BAD_MAGIC` (-4) |
| version / suite 不是 1 | `UNSUPPORTED_VERSION` (-5) |
| flags / reserved / block_size 越界 | `BAD_FLAGS` (-6) |
| 任何字段读越界 | `TRUNCATED` (-7) |
| DK 封装 kind/len/解密失败 | `BAD_KEY_RECORD` (-8) |
| 签名记录 kind/len 不对 | `BAD_SIGNATURE_RECORD` (-9) |
| 清单记录解析失败 | `BAD_MANIFEST_RECORD` (-10) |
| 块号重复（index < 期望） | `DUPLICATE_BLOCK` (-12) |
| 块号跳号（index > 期望） | `BLOCK_SEQUENCE` (-11) |
| 缺块 / 末尾不足 | `MISSING_BLOCK` (-13) |
| 末块标志与块位置不符 | `LAST_FLAG_MISMATCH` (-14) |
| GCM tag 校验失败（改 1 字节） | `TAG_MISMATCH` (-15) |
| 清单与包头 / 块长度 / 块摘要不一致 | `MANIFEST_MISMATCH` (-16) |
| 签名验签失败 | `SIGNATURE_MISMATCH` (-17) |
| 末块之后还有字节 | `TRAILING_BYTES` (-18) |

换序（交换两个块）会先命中 `DUPLICATE_BLOCK`/`MISSING_BLOCK`；删块命中 `MISSING_BLOCK`；
改块内任意字节命中 `MANIFEST_MISMATCH`（摘要）或 `TAG_MISMATCH`。

## 8. 已知取舍

* 块号 + 末块标志进 nonce，且块记录里冗余一份 `index/flags`：任何重排/截断都会在
  解析或 tag 校验阶段被拒，代价是每块 9 字节开销。
* 清单每块 32 字节摘要，1 GiB 文件约 32 KiB 清单（1 MiB 块）——可接受。
* 单包一次性放在内存里（`ys_pack`/`ys_unpack`），流式接口留给下一轮（Web 侧大文件要配合）。
