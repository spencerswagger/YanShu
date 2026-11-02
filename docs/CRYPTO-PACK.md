# 雁书 YanShu · 加密包格式契约（CRYPTO-PACK）

> **本契约版本：v1**（版本字符串 `YSPK/1.0`）
> **冻结日期：2026-11-02**
> **变更需走 ADR**：本文件冻结后，任何字段、偏移、长度、算法 ID、KDF info 串、样例值的改动都必须先落 `docs/ADR.md` 的 ADR 记录并经评审；不得在实现里"顺手改一下"。
>
> 适用对象：**Rune**（端侧 WASM，生产与消费本格式）、**Core**（只做不透明字节的存储与转发，不解析）、**Web**（只透传 `prelude` / 块切片与元数据）。
>
> 本文中的 **MUST / MUST NOT / SHOULD** 按 RFC 2119 语义解读。凡本文没有写死的字节，实现 MUST NOT 自行发明。

---

## 0. 这份文档解决什么问题

目标是"两个互不通信的实现方，各自照本文实现，产物**逐字节相同**"。因此本文：

- 所有字段给出 **offset / length / 类型 / 字节序**；
- 所有非确定性的东西（nonce、AAD、KDF info、签名输入）都写成**可复现的字节拼接公式**；
- 每个关键结构配 **hex 样例**（第 15 章），样例本身自洽、可手算核对，Rune 可直接拿它做测试向量锚点。

本文不讨论"为什么选国密"（决策已锁死，见 §1.4 一句话取舍），也不含密评内容。

### 0.1 术语

| 术语 | 含义 |
|---|---|
| **包 / envelope** | 一个完整的 `.yspk` 字节串，从第 0 字节到最后一字节，结构见 §4 |
| **prelude** | 包内 `HEADER + SENDER_PUB + WRAPPED_KEY + MANIFEST_SEC + SIG_SEC` 的连续字节段（不含块区），见 §12 |
| **块 / chunk** | 明文按 `CHUNK_SIZE` 切出的定长片段；末块可短 |
| **块记录 / chunk record** | 包内的一个块单元：16 字节块头 + 密文 + 16 字节 tag |
| **DK** | Data Key，256 位文件内容密钥，随机生成，只以 SM2 密文形式入包 |
| **KEK_CHUNK / KEK_MANIFEST** | 由 DK 经 HKDF-SM3 派生的两把 SM4 密钥（各 128 位） |
| **清单 / manifest** | 加密的文件元信息（文件名、MIME、大小、每块 SM3） |

---

## 1. 范围与已锁死前提

### 1.1 本文定义

1. 包版本号与向前兼容规则（§2）
2. 全局编码与字节序约定（§3）
3. 整体结构与段表（§4）
4. HEADER 字段级定义（§5）
5. 分块模型、块头、nonce 构造（§6）
6. SM4-GCM 参数与 AAD 构成（§7）
7. 加密清单明文结构（§8）
8. SM2 封装（C1C3C2）（§9）
9. SM2 签名与签名输入（§10）
10. 密钥派生 HKDF-SM3（§11）
11. 包与 HTTP 传输的映射（§12）
12. 接收方校验清单与拒绝矩阵（§13）
13. 限值与边界（§14）
14. 样例字节串（§15）
15. 模块分工锚点（§16）

### 1.2 本文不定义（非目标）

- 传输协议本身（见 `docs/API.md`）
- 前端展现、UI 交互
- P2P 打洞的 SDP/ICE 细节（只在 `docs/API.md` 里定义信令封装）
- 密钥在本机的存储格式（IndexedDB schema 属 Rune 内部实现，不入契约）
- 任何密评相关内容

### 1.3 算法族（已锁死，不再论证）

`SM4-GCM` 数据加密 · `SM3` 摘要/派生 · `SM2` 封装与签名。完全自研实现，不套用现成加密库封装业务包。

### 1.4 设计取舍（一句话点到，不展开论证）

- **SM4-GCM 而非自拼 CTR+MAC**：AEAD 一次成型，tag 覆盖 AAD，减少自研实现的组合错误面。
- **16 字节 chunk 头放在密文外**：块序/末块标志需要能被 AAD 绑定，放在密文外才能在不破坏 AEAD 的前提下被读取与校验。
- **1 MiB 块**：单块解密延迟与 WASM 内存抖动在移动端可接受，同时把 1 GB 文件的 tag 开销压在 0.0016% 量级。
- **nonce 只由块序号派生（STREAM 型）**：随机 nonce 在"续传/重传"场景容易重复，序号派生天然唯一且可复现。
- **SM2 只封 32 字节 DK**：SM2 加密的 KDF 与点运算只跑一次，不随文件大小增长。
- **C1C3C2 平文拼接 + 未压缩点**：跨语言（Rust/Go/JS）解析最省事，无 ASN.1 歧义；签名值则选 DER，便于与 GmSSL 命令行交叉验证。
- **清单整体加密**：文件名/MIME 对服务器零知识，服务端连"这是个 PDF"都看不到。

---

## 2. 版本策略

### 2.1 版本字段位置

| 位置 | 字段 | 长度 | v1 取值 |
|---|---|---|---|
| `HEADER[0..4)` | `MAGIC` | 4 | `59 53 50 4B`（ASCII `YSPK`） |
| `HEADER[4]` | `VERSION_MAJOR` | 1 | `0x01` |
| `HEADER[5]` | `VERSION_MINOR` | 1 | `0x00` |

**版本字符串**（用于 API、日志、UI、错误提示的唯一规范写法）：`YSPK/1.0`，即 `MAGIC` 的 ASCII + `/` + `VERSION_MAJOR` 十进制 + `.` + `VERSION_MINOR` 十进制。

**只有一种布局**：`YSPK/1.0`。本文任何出现"历史布局 / 其他布局 / 可选布局"的地方，都只用于描述"必须拒绝"的行为，不构成可选项；实现里也不存在运行时选择布局的开关（见 §2.2 第 7 条）。

### 2.2 向前兼容规则（硬规则）

1. **未知大版本 MUST 拒绝**。接收方读到 `VERSION_MAJOR != 0x01` 时，MUST 立即以 `CRYPTO_VERSION_UNSUPPORTED` 失败，**不得**尝试按 v1 解析、不得"尽力而为"。
2. **未知小版本 MUST 拒绝**。v1 的接收方读到 `VERSION_MINOR != 0x00` 时 MUST 以 `CRYPTO_VERSION_UNSUPPORTED` 失败。理由：小版本尚未定义兼容语义，猜测就是漏洞。
3. **前 8 字节布局永久冻结**：`MAGIC(4) | VERSION_MAJOR(1) | VERSION_MINOR(1) | HEADER_LEN(2, u16be)`。任何未来版本都必须保持这 8 字节的位置与语义，好让老实现能读出"这是哪个版本"并干净地拒绝。
4. **算法 ID 双门控**：`AEAD_ID / KDF_ID / SM2_WRAP_ID / SIG_ID`（`HEADER[12..16)`）各自独立。未知值 MUST 拒绝（`CRYPTO_ALG_UNSUPPORTED`）。未来加算法 = 抬 `VERSION_MINOR` 并新增 ID 值，老实现按第 2 条拒绝。
5. **保留位 MUST 为 0**：`HEADER` 的 `RESERVED` 区、`FLAGS` 的保留位、块头的 `RESERVED` 字节，写方 MUST 写 0；读方 MUST 校验为 0，否则拒绝（`CRYPTO_HEADER_INVALID` / `CRYPTO_FLAGS_UNKNOWN`）。这是为了防止"老实现静默忽略新语义"。
6. **不做版本协商**。不存在"探测对方支持哪个版本"的握手，包自己声明版本，不匹配就失败。
7. **可发布构建不得带"运行时切换布局"**：能产出非 `YSPK/1.0` 包字节的构建（历史临时布局等）MUST 只存在于测试/开发环境；发布构建里唯一的包布局就是 `YSPK/1.0`，且版本以包内版本字段为准，不由符号名决定。

### 2.3 端侧内核"是否符合契约"的判定写法（推荐）

前端与门禁要用内核自报的信息判断"这颗 wasm 是不是契约实现"，**不能只凭"它不是桩"**。推荐下面四条全中才算合规：

| # | 判据 | 期望 |
|---:|---|---|
| 1 | `ys_version()` | `0x00010000`（高 16 位 = `VERSION_MAJOR`，低 16 位 = `VERSION_MINOR`） |
| 2 | `ys_header_len()` | `112` |
| 3 | 冒烟：解包 §15.2 的 V1 样例（522 字节） | 成功，且解密结果 == `hello` |
| 4 | 冒烟：把该样例 `HEADER[4]` 改成 `0x02` 后再解包 | `CRYPTO_VERSION_UNSUPPORTED` |

补充：wasm 模块 MUST 无 import（纯计算），导出集 MUST 含契约必需符号；界面上的"契约内核"标签，显示条件应是**上面四条全过**，而不是"不是桩就显示合规"。

`ys_version()` 只说明"这颗内核对哪个版本实现"，**包版本判定的唯一权威仍是包内的 `VERSION_MAJOR/MINOR`**（§2.2）：运行时不得用 `ys_version()` 代替解包时的版本校验。

---

## 3. 全局编码与字节序约定

### 3.1 字节序与整数

- **所有整数字段一律大端（网络序，big-endian）**，文中 `u16be / u32be / u64be`。
- 所有整数**无符号**，定长，无 varint、无长度省略、无对齐填充。
- 布尔量用 `u8`：`0x00` = 假，`0x01` = 真；**其他值 MUST 拒绝**。

### 3.2 二进制在外部世界的表示

| 场景 | 表示 | 规则 |
|---|---|---|
| 包本身（`.yspk` 文件） | 原始字节 | 无任何外层封装、无压缩、无 base64 |
| HTTP 请求/响应体（prelude、块切片） | `application/octet-stream` 原始字节 | 见 `docs/API.md` |
| JSON 里的二进制字段 | **base64url（RFC 4648 §5）** | **不带 `=` 填充**；解码方 MUST 拒绝含 `=` 的输入、MUST 拒绝 `len % 4 == 1` 的输入 |
| 摘要/指纹的展示 | 小写 hex | 仅用于日志/UI/样例，**不上 wire** |
| 测试向量 | 小写 hex | 本文第 15 章一律小写、无分隔、无 `0x` 前缀 |

### 3.3 字符串

- 一律 UTF-8，NFC 规范化，无 BOM。
- 长度前缀为**字节数**，不是字符数。
- 文件名：只允许 basename（不含 `/`、`\`、NUL、0x00–0x1F 控制字符），≤ 255 字节。
- MIME：ASCII 小写，字符集 `[a-z0-9!#$&^_.+-]` 与单个 `/`，≤ 127 字节；未知类型写 `application/octet-stream`。
- 扩展名：ASCII 小写 `[a-z0-9]`，≤ 16 字节，**不含点**；无扩展名则长度 0。

### 3.4 用户码（Crockford Base32）

- 字母表：`0123456789ABCDEFGHJKMNPQRSTVWXYZ`（32 个符号，剔除 `I L O U`）。
- **码生成**：`PUB = 未压缩公钥 65 字节` → `D = SM3(PUB)`（32 字节）→ 取 `D` 的**前 20 个 bit（大端 bit 序，即 `D[0]` 的 bit7..bit0、`D[1]` 的 bit7..bit0、`D[2]` 的高 4 bit）**，按 5 bit 一组切成 4 组（MSB 在前），逐组映射字母表 → 4 字符码。等价说法：`Crockford32(D)` 的左对齐编码取前 4 个字符。
- **校验字符（v1 不启用）**：码**固定 4 位**——线上传的、服务端存的、别人输入的、包里与签名里参与运算的，都只有这 4 位，**码本身不含校验位**。实现可本地计算 `check_symbol()`：把上述 20 bit 当无符号整数 `V`，取 `CHECK_ALPHA[V mod 37]`（`CHECK_ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"`）——它**只**用于输入框前置防误输提示，不上行、不参与派生、不改变码长度。将来若要升 5 位展示，属契约变更，需 ADR。
- **输入归一化**（客户端 MUST 做；服务端 MAY 执行同一套，归一化结果必须正好 4 个合法符号，完整判定口径见 `docs/API.md` §1.6）：转大写 → 去所有 `-` 与空白 → `O→0`、`I→1`、`L→1` → 长度必须为 4 → 每个字符必须在字母表内（`U` 一律拒绝）。**禁止**猜测性纠错，**禁止**把 5 位 `CODE-CHECK` 截成 4 位。
- 码**不是密钥、不是口令**；服务端只把它当索引键。

### 3.5 签名与封装的编码

- SM2 封装密文：**C1C3C2 顺序、未压缩点、纯字节拼接**，无 ASN.1 包装（详见 §9）。
- SM2 签名值：**ASN.1 DER**（`SEQUENCE { r INTEGER, s INTEGER }`），详见 §10.4。

---

## 4. 整体包结构

### 4.1 段表

一个包 = 5 个连续段，中间无填充、无分隔符：

```
偏移 0
┌───────────────────────────────────────────────────────────────┐
│ HEADER            112 字节（固定）                             │
├───────────────────────────────────────────────────────────────┤
│ SENDER_PUB         65 字节（0x04 ‖ X32 ‖ Y32，未压缩公钥）       │
├───────────────────────────────────────────────────────────────┤
│ WRAPPED_KEY       129 字节（SM2 C1C3C2 封装 DK）                │
├───────────────────────────────────────────────────────────────┤
│ MANIFEST_SEC      MANIFEST_LEN 字节（= MANIFEST_PT_LEN + 16）   │
├───────────────────────────────────────────────────────────────┤
│ SIG_SEC           SIG_LEN 字节（DER，70..72）                   │
├───────────────────────────────────────────────────────────────┤
│ CHUNK_SEC         Σ(32 + PT_LEN(i))，i = 0 .. CHUNK_COUNT-1     │
└───────────────────────────────────────────────────────────────┘
```

### 4.2 派生量与公式

设 `n = CHUNK_COUNT`，`S = PLAINTEXT_SIZE`，`C = CHUNK_SIZE`：

```
PT_LEN(i)        = C                              , 若 i < n-1
                 = S - C * (n - 1)                , 若 i = n-1
PRELUDE_LEN      = 112 + 65 + 129 + MANIFEST_LEN + SIG_LEN
                 = 306 + MANIFEST_LEN + SIG_LEN
CHUNK_REC_LEN(i) = 32 + PT_LEN(i)
CHUNK_REC_OFF(i) = PRELUDE_LEN + Σ_{j<i} (32 + PT_LEN(j))
ENVELOPE_LEN     = PRELUDE_LEN + Σ_{i<n} (32 + PT_LEN(i))
```

**一致性硬约束**（写方 MUST 满足，读方 MUST 校验）：

- `n == ceil(S / C)`；当 `S == 0` 时 `n == 1`、`PT_LEN(0) == 0`。
- `CHUNK_COUNT ∈ [1, 1048576]`，`C ∈ [16, 1048576]`。
- 包尾**不得有多余字节**：`ENVELOPE_LEN` 必须与实际字节数严格相等。

### 4.3 prelude 与块区（给传输层看的切法）

`prelude` = `HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC`，即偏移 `[0, PRELUDE_LEN)` 的连续字节。
块区 = `[PRELUDE_LEN, ENVELOPE_LEN)`，按 §6.2 的块记录逐条排列。

传输时 **prelude 整段上传一次，块区按块切片上传**（每片 = `CHUNK_CT ‖ TAG`，**不含 16 字节块头**，块头由接收方按 §6.3 规则本地重建）。映射细节见 §12。

**块序绑在 AEAD 里**（硬要求）：块记录的完整性不靠"事后比对"，而靠块级 AEAD 的 AAD 逐字节绑定 `CHUNK_INDEX`（块序号）、`CHUNK_COUNT`（总块数）、`LAST_FLAG`（末块标志）、`CHUNK_SIZE`、`PLAINTEXT_SIZE` 与 `PT_LEN`（§7.2）。因此"删中间块 / 交换两块顺序 / 把别的包的合法块搬进来"在**块层就失败**，不是只靠清单摘要兜底；两道防线的分工与预期错误码见 §7.5。

---

## 5. HEADER（112 字节）

### 5.1 字段表

| offset | length | 字段 | 类型 | v1 取值 / 说明 |
|---:|---:|---|---|---|
| 0 | 4 | `MAGIC` | bytes | `59 53 50 4B`（`YSPK`） |
| 4 | 1 | `VERSION_MAJOR` | u8 | `0x01` |
| 5 | 1 | `VERSION_MINOR` | u8 | `0x00` |
| 6 | 2 | `HEADER_LEN` | u16be | `0x0070`（= 112） |
| 8 | 4 | `FLAGS` | u32be | 见 §5.2 |
| 12 | 1 | `AEAD_ID` | u8 | `0x01` = SM4-GCM（96-bit nonce，128-bit tag） |
| 13 | 1 | `KDF_ID` | u8 | `0x01` = HKDF-SM3（RFC 5869 结构，SM3 作 HMAC 原语） |
| 14 | 1 | `SM2_WRAP_ID` | u8 | `0x01` = C1C3C2 ‖ 未压缩点 ‖ 平文拼接 |
| 15 | 1 | `SIG_ID` | u8 | `0x01` = SM2-SM3，DER 编码，默认 ZA |
| 16 | 4 | `CHUNK_SIZE` | u32be | 明文块大小，v1 生产值 `0x00100000`（1 MiB） |
| 20 | 4 | `CHUNK_COUNT` | u32be | 块数 `n ≥ 1` |
| 24 | 8 | `PLAINTEXT_SIZE` | u64be | 明文总字节数 `S` |
| 32 | 8 | `WRAPPED_KEY_LEN` | u64be | v1 恒 `129` |
| 40 | 8 | `MANIFEST_LEN` | u64be | `MANIFEST_PT_LEN + 16` |
| 48 | 4 | `MANIFEST_PT_LEN` | u32be | 清单明文长度 |
| 52 | 4 | `SENDER_PUB_LEN` | u32be | v1 恒 `65` |
| 56 | 16 | `KDF_SALT` | bytes | CSPRNG 随机盐，每个包重新生成 |
| 72 | 8 | `SIG_LEN` | u64be | 签名 DER 字节数（70..72） |
| 80 | 32 | `RESERVED` | bytes | 全 `0x00`；非零即拒绝 |

### 5.2 `FLAGS` 位定义

| bit | 名称 | 含义 | v1 |
|---:|---|---|---|
| 0 | `NAME_OBFUSCATED` | 清单内文件名为客户端打码后的标签（`NAME_MODE = 0x01`），非真实文件名。**MUST 与清单 `NAME_MODE` 相等**；不等即整包非法（`CRYPTO_MANIFEST_INVALID`，校验位置见 §13 #15） | 生产恒 `0` |
| 1 | `SENDER_SIGNED` | 包内含有效 `SIG_SEC`。v1 **MUST 为 1**；为 0 时接收方 MUST 拒绝（`CRYPTO_UNSIGNED`） | 恒 `1` |
| 2..31 | `RESERVED` | MUST 为 0 | 全 0 |

> 「服务端是否知道文件名」这一点由**架构建模**保证，而不是由 `NAME_OBFUSCATED` 位保证：清单整体在 `MANIFEST_SEC` 密文里，服务端从未见过明文文件名。该位只是给"发送方主动把文件名换成 `file-<随机>`"这一可选交互留的口子。

### 5.3 `HEADER` 的两段切分

- **`HDR_CORE = HEADER[0..72)`**：参与 SM2 签名（§10.2），因为它在签名前已完全确定。
- **`HEADER[72..80) = SIG_LEN`**：不参与签名（签名长度是签名运算的结果，鸡生蛋问题）。
- **`HEADER[80..112) = RESERVED`**：不参与签名（必须为 0，读方强校验，等价于被保护）。

---

## 6. 分块模型

### 6.1 为什么是 1 MiB

1 MiB 明文块（`CHUNK_SIZE = 0x00100000`）是推荐生产值：单块解密耗时在移动端 < 20 ms，WASM 线性内存压力小，且与 HTTP 分片上传的重试粒度天然合拍。

`CHUNK_SIZE` 写在头里，**接收方 MUST 按头里的值处理，MUST NOT 硬编码 1 MiB**。允许区间 `[16, 1048576]`（样例用 32 来减少篇幅）。

### 6.2 块记录结构

```
块记录 i:
┌───────────────────────────────────────────────┐
│ offset 0   len 4   CHUNK_INDEX   u32be        │
│ offset 4   len 4   PT_LEN        u32be        │
│ offset 8   len 4   CT_LEN        u32be        │
│ offset 12  len 1   LAST_FLAG     u8 (0/1)     │
│ offset 13  len 1   RESERVED      u8  = 0x00   │
│ offset 14  len 2   RESERVED      u16be = 0    │
├───────────────────────────────────────────────┤
│ offset 16  len CT_LEN   CHUNK_CT（密文，与明文等长）│
├───────────────────────────────────────────────┤
│ offset 16+CT_LEN  len 16  TAG（GCM tag）        │
└───────────────────────────────────────────────┘
```

| 字段 | 规则 |
|---|---|
| `CHUNK_INDEX` | `0..n-1`，必须等于记录在块区里的序号 |
| `PT_LEN` | 该块明文字节数；`i < n-1` 时必须等于 `CHUNK_SIZE`，`i == n-1` 时必须等于 `S - C*(n-1)` |
| `CT_LEN` | v1 必须等于 `PT_LEN`（GCM 长度保持）；不等即拒绝（`CRYPTO_LENGTH_INCONSISTENT`） |
| `LAST_FLAG` | 仅 `i == n-1` 时为 `0x01`，其余 `0x00`；与 `CHUNK_INDEX` 不一致即拒绝 |
| `RESERVED` | 必须为 0，否则拒绝 |

### 6.3 传输切片与块头重建

上传/下载的块切片**只含 `CHUNK_CT ‖ TAG`**，长度 = `PT_LEN + 16`。接收方本地重建 16 字节块头：

```
CHUNK_INDEX = 路径里的 index（已由接收方核对 0 <= index < CHUNK_COUNT）
PT_LEN      = len(切片) - 16
CT_LEN      = PT_LEN
LAST_FLAG   = 0x01 if index == CHUNK_COUNT - 1 else 0x00
RESERVED    = 0x00 / 0x0000
```

（`CHUNK_COUNT` 来自 prelude 的头，因此在收齐 prelude 之后重建绝对是确定的。）

### 6.4 nonce 构造（唯一可复现）

`NONCE` 固定 12 字节，**只由块序号派生，不使用随机数**：

```
NONCE(chunk i) = u64be(i) ‖ 0x00 0x00 0x00 ‖ (LAST_FLAG ? 0x01 : 0x00)
                 └─8 字节──┘ └──3 字节─┘  └──────1 字节──────┘
```

- 第 0..7 字节：块序号，大端。
- 第 8..10 字节：保留，固定 `00 00 00`（这一区间是为未来"每块多段/多流"预留的扩展位，v1 必须为 0，参与 nonce 即等于参与加密）。
- 第 11 字节：末块标志，`0x01` 仅末块。

示例：`i = 0` 非末块 → `0000000000000000 000000 00`；`i = 2` 且为末块 → `0000000000000002 000000 01`。

**清单的 nonce**（不与任何块冲突，且清单用独立的 `KEK_MANIFEST`）：

```
NONCE(manifest) = FF FF FF FF FF FF FF FF 00 00 00 01
```

为什么要 `LAST_FLAG` 进 nonce（STREAM 构造的价值）：攻击者把"末块"伪装成"中间块"会改变 nonce → tag 校验失败；截断尾块 → 接收方找不到 `LAST_FLAG=1` 的块 → 明确报错。nonce 唯一性由"每包 `KDF_SALT` 新鲜 + `DK` 新鲜"保证：同一 `KEK` 绝不会跨包复用。

---

## 7. SM4-GCM 参数与 AAD

### 7.1 参数

| 参数 | 值 |
|---|---|
| 算法 | SM4，128 位分组，`AEAD_ID = 0x01` |
| key 长度 | **16 字节**（SM4 密钥只支持 128 位；`KEK` 由 32 字节 `DK` 派生后截取 16 字节，见 §11） |
| nonce 长度 | **12 字节**（96 位），构造见 §6.4 |
| tag 长度 | **16 字节**（128 位），附在密文之后 |
| 模式 | GCM（GHASH 认证，密文与明文等长） |
| AAD | 见 §7.2 / §7.3，固定长度，**不得为空** |

### 7.2 块 AAD：`AAD_CHUNK`（32 字节）

```
offset len 字段
0      1   AAD_LABEL = 0x01（域分隔，块）
1      4   MAGIC = "YSPK"
5      1   VERSION_MAJOR
6      1   VERSION_MINOR
7      4   CHUNK_SIZE      u32be
11     4   CHUNK_COUNT     u32be
15     8   PLAINTEXT_SIZE  u64be
23     4   CHUNK_INDEX     u32be
27     1   LAST_FLAG       u8
28     4   PT_LEN          u32be
                        = 32 字节
```

逐字节拼接（全部大端、无填充、定长 32 字节，可手算复现）：

```
AAD_CHUNK = 0x01                      // 域分隔，块
          ‖ "YSPK"                    // 4 字节
          ‖ VERSION_MAJOR ‖ VERSION_MINOR
          ‖ u32be(CHUNK_SIZE)
          ‖ u32be(CHUNK_COUNT)
          ‖ u64be(PLAINTEXT_SIZE)
          ‖ u32be(CHUNK_INDEX)        // 块序号：第 0 块从 0 起
          ‖ u8(LAST_FLAG)             // 末块 0x01，其余 0x00
          ‖ u32be(PT_LEN)
```

`CHUNK_INDEX` **同时**进 nonce（§6.4）与 AAD：nonce 让"用错密钥流"解不出，AAD 让"位置被换过"认证失败——两步都在 AEAD 内部完成，不依赖任何后置校验。

**这 32 字节绑定了什么**（每一条都对应一种攻击）：

| 被绑定字段 | 拦住的攻击 |
|---|---|
| `CHUNK_INDEX` | 块重排（换序后 AAD 与原 AAD 不符） |
| `LAST_FLAG` + `CHUNK_COUNT` + `CHUNK_SIZE` + `PLAINTEXT_SIZE` | 删中间块、截断尾块、谎报块数 |
| `MAGIC/版本` | 跨版本/跨格式混淆 |
| `PT_LEN` | 长度篡改（截短密文） |

`AAD_LABEL` 让块 AAD 与清单 AAD 处于不同域，杜绝把清单密文当块塞回块区的混淆攻击。

**跨包搬运为什么也失败**：AAD 里不含"包标识"字段，包身份由密钥承担——`KEK_CHUNK` 由每包独立的 `DK`（32 字节 CSPRNG）与 `KDF_SALT`（16 字节 CSPRNG）派生（§11），别的包的同序号块在本包密钥下必然认证失败。这也是"`DK` 与 `KDF_SALT` 每包必须重新取"是硬约束的原因。

### 7.3 清单 AAD：`AAD_MANIFEST`（31 字节）

```
offset len 字段
0      1   AAD_LABEL = 0x02（域分隔，清单）
1      4   MAGIC = "YSPK"
5      1   VERSION_MAJOR
6      1   VERSION_MINOR
7      4   FLAGS           u32be
11     4   CHUNK_SIZE      u32be
15     4   CHUNK_COUNT     u32be
19     8   PLAINTEXT_SIZE  u64be
27     4   MANIFEST_PT_LEN u32be
                        = 31 字节
```

清单 AAD 把 `FLAGS` 也绑进去：这样"把 `SENDER_SIGNED` 掀掉"这类头部篡改会让清单认证先失败，而不是靠后面的签名校验去兜。

### 7.4 一点补充

- 认证失败（tag 不符）时**一律**报 `CRYPTO_CHUNK_AUTH_FAILED` / `CRYPTO_MANIFEST_AUTH_FAILED`，**不得**区分"tag 错"与"解密后内容不对"，避免给攻击者 oracle。
- 明文校验顺序：先 GCM 认证，再比 SM3 摘要（§8.4）。GCM 已保证完整性，SM3 是给"分块续传/部分重组"留的第二把锁，也是 Gate 的交叉验证点。

### 7.5 篡改检测语义（两道防线，别把 tag 当唯一防线）

校验顺序固定为**先清单层、再块层**（完整次序见 §13）：

| 层 | 防线 | 主要覆盖的篡改 | 典型错误码 |
|---|---|---|---|
| 第 1 道（清单层） | `MANIFEST_SEC` 的 GCM tag + 清单内每块明文 `SM3` 摘要表 | 头字段被改、清单被改、块数/块长/总长被谎报、块内容被替换 | `CRYPTO_MANIFEST_AUTH_FAILED` / `CRYPTO_DIGEST_MISMATCH` |
| 第 2 道（块层） | 块头自洽（序号/末块标志/块长，§6.2）+ 块级 AEAD（`AAD_CHUNK`，§7.2）+ GCM tag | 块重排、删中间块、截断尾块、密文单字节篡改、跨包搬运 | `CRYPTO_CHUNK_ORDER` / `CRYPTO_CHUNK_MISSING` / `CRYPTO_CHUNK_AUTH_FAILED` |

**为什么两道都要有**：清单层保护"整包声明"（块数、总长、摘要表本身），块层保护"每一块的位置与字节"。少了第 1 道，头里的块数/总长可被谎报；少了第 2 道，块级重排/搬运只能靠摘要表兜底，而摘要表本身也只是一个 GCM 保护的声明。

**预期现象（不是缺陷，写清以免误判）**：凡是同时破坏清单或块数的用例（删块、换序、搬入别包块、改头字段），第 1 道往往先拦下，端到端因此**可能取不到块级 tag 失败**（实现内部常叫 `TAG_MISMATCH`）。本契约 §13 规定块级 GCM（第 20 条）先于摘要比对（第 21 条），所以"只翻转某块密文 1 个字节"这类用例应得 `CRYPTO_CHUNK_AUTH_FAILED`；若某实现把摘要比对提前，同一用例会得 `CRYPTO_DIGEST_MISMATCH`。

**测试判定口径**：篡改用例只要被**任一**防线拒绝即算通过，**不得**要求特定错误码或特定防线；反之，任何篡改被接受（解出明文、或静默截短）即 FAIL。

**不利情形**：逐块比对意味着"边收边解"时必须先拿到清单；清单在 `prelude` 里，所以 §12 的顺序（先 prelude、后块）是强制的。

---

## 8. 加密清单（MANIFEST）

### 8.1 加密方式

`MANIFEST_SEC = SM4-GCM(KEK_MANIFEST, NONCE(manifest), MANIFEST_PT, AAD_MANIFEST) ‖ TAG(16)`

即 `MANIFEST_SEC` 长度 = `MANIFEST_PT_LEN + 16`，与头里的 `MANIFEST_LEN` 严格相等。

### 8.2 明文结构 `MANIFEST_PT`

| offset | length | 字段 | 类型 | 说明 |
|---:|---:|---|---|---|
| 0 | 4 | `MAGIC` | bytes | `59 53 4D 31`（`YSM1`） |
| 4 | 1 | `MANIFEST_VERSION` | u8 | `0x01` |
| 5 | 1 | `NAME_MODE` | u8 | `0x00` = 清单内是真文件名；`0x01` = 打码标签。**MUST 等于 `FLAGS.NAME_OBFUSCATED`**，不等即整包非法（§13 #15） |
| 6 | 1 | `DIGEST_ALG` | u8 | `0x01` = SM3 |
| 7 | 1 | `DIGEST_LEN` | u8 | `0x20`（32） |
| 8 | 8 | `FILE_SIZE` | u64be | 必须等于头里的 `PLAINTEXT_SIZE` |
| 16 | 4 | `CHUNK_SIZE` | u32be | 必须等于头里的 `CHUNK_SIZE` |
| 20 | 4 | `CHUNK_COUNT` | u32be | 必须等于头里的 `CHUNK_COUNT` |
| 24 | 8 | `CREATED_AT` | u64be | Unix 毫秒（UTC），发送方本地时间 |
| 32 | 2 | `NAME_LEN` | u16be | 0..255；**`0` 合法**（空文件名，规则见 §8.5） |
| 34 | `NAME_LEN` | `NAME` | utf8 | §3.3 规则 |
| 34+N | 2 | `MIME_LEN`（记 `M`） | u16be | 1..127 |
| 36+N | `M` | `MIME` | ascii | §3.3 规则 |
| 36+N+M | 2 | `EXT_LEN`（记 `E`） | u16be | 0..16 |
| 38+N+M | `E` | `EXT` | ascii | 不含点 |
| 38+N+M+E | 4 | `DIGEST_TABLE_LEN` | u32be | 必须等于 `CHUNK_COUNT * 32` |
| 42+N+M+E | `CHUNK_COUNT*32` | `DIGEST[0..n-1]` | bytes | 每块明文的 SM3，按块序拼接 |

`MANIFEST_PT_LEN = 42 + N + M + E + CHUNK_COUNT*32`（V1 样例：`42+6+10+3+32 = 93`）。

### 8.3 清单里放什么 / 不放什么

**放**：文件名、MIME、扩展名、总大小、块大小、块数、创建时间、每块明文 SM3（给断点续传与二次校验）。
**不放**：任何密钥、DK、公钥、码、IP、路径、缩略图、预览文本 —— 清单体积小、语义干净，减少"顺手多塞点东西"导致的泄露面。

### 8.4 摘要口径

`DIGEST[i] = SM3( 第 i 块明文 )`，明文即切片后的原始字节（不含任何头、不含长度前缀）。接收方在 GCM 认证通过后 MUST 复算并比对，不符报 `CRYPTO_DIGEST_MISMATCH`。

**易错点（写死）**：摘要取**明文块**——不是 `CHUNK_CT`、不是 `CHUNK_CT ‖ TAG`、不是整条块记录。这三种口径算出来的值完全不同，跨实现对照时以本文为准。

### 8.5 空文件名（`NAME_LEN = 0`）

**协议层允许空文件名**：`NAME_LEN = 0` 是合法值，`NAME` 字段占 0 字节，后续偏移照常（`MIME_LEN` 落在 offset 34）。

| 角色 | 要求 |
|---|---|
| 写方 | `NAME_LEN == 0` 时 `NAME_MODE` MUST 为 `0x00`，且 `FLAGS.NAME_OBFUSCATED` MUST 为 0（空名没有"打码"语义，禁止用该组合制造口径分歧） |
| 读方 | MUST 接受空名并正常解包；**不得**因文件名为空而拒绝（`CRYPTO_MANIFEST_INVALID` 只用于结构/长度/一致性非法） |
| 客户端展示 | 空名显示"未命名"；`EXT` 仍可非空，按扩展名做降级展示（图标/类型提示） |
| 落盘命名 | 落盘文件名完全由接收端本地决定（含去重），不来自清单、不参与寻址 |

**安全说明（为什么允许空名）**：文件名只是展示信息，既不参与加密也不参与寻址，服务端也从未见过明文名（清单在 `MANIFEST_SEC` 密文内）。`MANIFEST_PT_LEN` 被清单 AAD（§7.3）覆盖，长度本身是被认证的——因此"空名"不构成混淆通道；反过来，禁止空名只会逼客户端编造假名字（如 `unnamed.bin`），把展示问题变成假数据问题。

---

## 9. SM2 封装（DK）

### 9.1 输入输出

- 输入：接收方 SM2 公钥 `PB`（未压缩点 65 字节）+ 32 字节 `DK`。
- 输出：`WRAPPED_KEY` = **129 字节** = `C1(65) ‖ C3(32) ‖ C2(32)`。
- `SM2_WRAP_ID = 0x01` 固定表示：C1C3C2 顺序、未压缩点、无 ASN.1 包装、KDF 为 SM3 计数器 KDF。

### 9.2 生成步骤（逐字节可复现）

```
1. k ← CSPRNG，1 <= k <= n-1（n 为 SM2 曲线阶）
2. (x1,y1) = [k]G
   C1 = 0x04 ‖ x1(32, be) ‖ y1(32, be)             // 65 字节，未压缩
3. (x2,y2) = [k]PB
4. t = SM3-KDF(x2 ‖ y2, 32)                        // 见 9.3；若 t 全零则重取 k
5. C2 = DK XOR t                                    // 32 字节
6. C3 = SM3(x2 ‖ DK ‖ y2)                           // 32 字节（注意是明文 DK 参与）
7. 输出 C1 ‖ C3 ‖ C2
```

### 9.3 SM3-KDF（计数器模式）

```
输入：Z（字节串，此处 = x2‖y2，共 64 字节），klen（字节数）
ct = 1, 2, 3, ...
K[c] = SM3( Z ‖ u32be(ct) )
输出 = (K[1] ‖ K[2] ‖ … ) 截断到 klen
```

即每 32 字节一段、计数器从 1 开始、大端 32 位。

### 9.4 硬规则

- **禁止** `C1C2C3` 顺序；**禁止** ASN.1/DER 包装封装结果；**禁止**压缩点（`0x02/0x03`）。
- 随机数 `k` **MUST** 来自 CSPRNG，且**每次封装必须新取**；`WRAPPED_KEY` 只出现一次，不得跨包复制。
- 解封失败（点不在曲线上、C3 不符）一律报 `CRYPTO_KEY_UNWRAP_FAILED`，不区分原因。
- 里层明文长度只允许 32 字节（即 `DK`）；`C2` 长度必须是 32。

---

## 10. SM2 签名（来源证明）

### 10.1 签什么、由谁签

- 签名者：**发送方** SM2 私钥。
- 被签对象：**`HDR_CORE` + 发送方公钥 + 清单密文**（即"这个包的头部声明 + 我是谁 + 我声明的内容"），公式见 §10.2。
- 位置：`SIG_SEC`，长度写回 `HEADER[72..80)`。
- `SIG_ID = 0x01`：SM2 + SM3 + 默认用户标识 `1234567812345678` + DER 编码。

### 10.2 签名输入 `SIG_INPUT`

```
SIG_INPUT = "YSSIG1"            (6 字节 ASCII)
          ‖ VERSION_MAJOR        (1)
          ‖ VERSION_MINOR        (1)
          ‖ HDR_CORE             (72，即 HEADER[0..72))
          ‖ SENDER_PUB           (65，未压缩点)
          ‖ MANIFEST_SEC         (MANIFEST_LEN，含 16 字节 tag)
```

长度 = `6 + 1 + 1 + 72 + 65 + MANIFEST_LEN` = `145 + MANIFEST_LEN`。

**签名算法（写死，两端必须完全一致）**

```
ZA = SM3( ENTL(2, u16be) ‖ ID ‖ a(32) ‖ b(32) ‖ xG(32) ‖ yG(32) ‖ xA(32) ‖ yA(32) )
e  = SM3( ZA ‖ SIG_INPUT )
SIG_SEC = SM2-Sign(e)，DER 编码
```

| 参数 | 值 |
|---|---|
| `ID`（userID） | **`1234567812345678`**，16 字节 ASCII —— 默认值，**不许自定、不许为空** |
| `ENTL` | `0x0080`（= `ID` 的比特数 128），`u16be` |
| `a` / `b` | SM2 曲线参数，32 字节大端 |
| `xG` / `yG` | 基点坐标，32 字节大端 |
| `xA` / `yA` | **签名者**公钥坐标（`SENDER_PUB` 去掉首字节 `0x04` 后的 64 字节） |

三条易错点：

1. **`ZA` 不是 `SIG_INPUT` 的一部分**：`ZA` 由 SM2 算法内部喂给哈希，`SIG_INPUT` 是 `ZA` 之后的**消息 M**。把 `ZA` 再拼进 `SIG_INPUT` 会得到另一套签名，两端永远验不过。
2. **`ID` 必须是默认值**：换成别的（含空串）等价于换算法；`ENTL` 随 `ID` 比特数变化，`ID` 为空时是 `0x0000`，本契约**禁止**空 `ID`。
3. **`xA/yA` 是签名者公钥**，不是验证者（接收方）公钥；用错一方验签必失败。

**为什么这样签**：

- 绑定 `HDR_CORE` → 头里的块数/大小/盐/算法 ID 不可被改；
- 绑定 `SENDER_PUB` → 公钥不可被替换成别人的（防止"同一份清单换个署名"）；
- 绑定 `MANIFEST_SEC`（含 tag）→ 清单密文不可被换；
- 不绑定块区 → 签名只需在发送开始时算一次，1 GB 文件的签名成本恒定；块的完整性由 GCM tag + AAD 保证。

### 10.3 发送方公钥放哪

`SENDER_PUB` 明文放在 `HEADER` 之后（§4.1），因此**接收方可以离线校验**：解包 → 验签 → 用 §3.4 由 `SENDER_PUB` 派生 4 位码 → 与 API 元数据里的发送方码比对（不符报 `CRYPTO_SENDER_MISMATCH`）。这条比对挡住了"服务器把发送方换成别人"的低成本冒充（服务器仍可信，见 `docs/API.md` 的威胁边界）。

### 10.4 DER 编码规则（写死）

```
SIG = SEQUENCE { r INTEGER, s INTEGER }
```

- 严格 DER：最短长度编码、INTEGER 最短补码表示（高位为 1 时补 `0x00`）、无前后多余字节。
- 长度范围：**70..72 字节**（r、s 各 32 字节，各自最多补 1 个 `0x00`）。`SIG_LEN` 必须等于实际 DER 长度，否则 `CRYPTO_HEADER_INVALID`。
- 校验方 MUST 做严格 DER 解析并拒绝非规范编码（不给签名延展性留空间）。

### 10.5 校验失败语义

- DER 解析失败 / r,s 越界 / 验签不过 → `CRYPTO_SIGNATURE_INVALID`。
- `FLAGS.SENDER_SIGNED == 0` → `CRYPTO_UNSIGNED`（v1 一律拒绝）。

---

## 11. 密钥派生（HKDF-SM3）

### 11.1 参数

| 项 | 值 |
|---|---|
| 结构 | RFC 5869（extract-then-expand），HMAC 原语换成 SM3 |
| HMAC-SM3 | RFC 2104，block size 64 字节，输出 32 字节 |
| `IKM` | `DK`（32 字节，CSPRNG） |
| `salt` | `HEADER[56..72)` 的 `KDF_SALT`（16 字节） |
| `L` | 16 字节（SM4 密钥长度） |
| info（块） | `YANSHU/v1/chunk-key`（19 字节 ASCII） |
| info（清单） | `YANSHU/v1/manifest-key`（22 字节 ASCII） |

### 11.2 公式

```
PRK        = HMAC-SM3(key = KDF_SALT, msg = DK)                  // 32 字节
T(1)       = HMAC-SM3(key = PRK, msg = info ‖ 0x01)              // 32 字节
KEK        = T(1)[0..16)                                          // 取前 16 字节
```

（`L = 16 ≤ 32`，因此只用 `T(1)`，不产生多轮拼接。）

```
KEK_CHUNK    = HKDF-SM3(DK, KDF_SALT, "YANSHU/v1/chunk-key",    16)
KEK_MANIFEST = HKDF-SM3(DK, KDF_SALT, "YANSHU/v1/manifest-key", 16)
```

### 11.3 首版不做的东西（明确写死）

- **首版不做"口令/分享码 → 密钥"的 KDF**。雁书没有账号、没有口令、没有分享码加密：用户码只是索引，不是密钥材料。将来若引入"带口令的分享链接"，必须新开 ADR 并抬 `VERSION_MINOR`。
- **不做 PBKDF2/Argon2/scrypt 等慢哈希**（无口令场景），也**不做**把用户码混进 `DK` 的派生（会让"码打错"变成"解密失败"，语义更差）。
- `DK` 与 `KDF_SALT` **只用一次**：一个包一套，绝不复用；断点续传/重传沿用同一个包，因此不变。

---

## 12. 包 ↔ HTTP 传输映射

> 传输协议的完整定义见 `docs/API.md`；这里只写"包的哪段字节对应哪个请求体"，保证 Core 与 Web 不需要理解密码学。

| 包内段 | 上传/下载方式 | 字节 |
|---|---|---|
| `HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC` | 一次性 `prelude`（`application/octet-stream`） | 长度 `PRELUDE_LEN`，服务端另存 `SM3(prelude)` 做完整性核对 |
| 块记录 i 的 `CHUNK_CT ‖ TAG` | 按 `index = i` 单独上传/下载 | 长度 `PT_LEN(i) + 16`，即 `CHUNK_REC_LEN(i) - 16` |

**重建规则**（接收方按顺序拼接，得到与发送方**逐字节相同**的包）：

1. 收齐 `prelude` → 解析 `HEADER` → 得到 `CHUNK_SIZE / CHUNK_COUNT / PLAINTEXT_SIZE / MANIFEST_LEN / SIG_LEN`，按 §4.2 算出 `PT_LEN(i)` 与全部偏移。
2. 按任意顺序收块切片（索引自带，乱序不影响），每片校验长度 `== PT_LEN(i) + 16`。
3. 拼接：`prelude` 后按 `i = 0..n-1` 顺序写"重建的 16 字节块头 + 切片"，得到 `ENVELOPE_LEN` 字节的包。
4. 校验 `ENVELOPE_LEN` 与实际长度一致，然后进入 §13 的校验清单。

**因此**：传输层的乱序、重试、切换路径（中转 ↔ 直传）都不影响最终包字节；块序号就是唯一坐标。

---

## 13. 接收方校验清单（MUST，按顺序）

| # | 校验 | 失败错误码 |
|---:|---|---|
| 1 | 总长度 ≥ `112 + 65 + 129 + 16 + 70`（最小包） | `CRYPTO_TRUNCATED` |
| 2 | `MAGIC == "YSPK"` | `CRYPTO_MAGIC_MISMATCH` |
| 3 | `VERSION_MAJOR == 1 && VERSION_MINOR == 0` | `CRYPTO_VERSION_UNSUPPORTED` |
| 4 | `HEADER_LEN == 112` | `CRYPTO_HEADER_INVALID` |
| 5 | `AEAD_ID == 1 && KDF_ID == 1 && SM2_WRAP_ID == 1 && SIG_ID == 1` | `CRYPTO_ALG_UNSUPPORTED` |
| 6 | `FLAGS` 仅 bit0(任意)/bit1(必须 1) 有效，其余为 0 | `CRYPTO_FLAGS_UNKNOWN` / `CRYPTO_UNSIGNED` |
| 7 | `RESERVED[80..112)` 全 0 | `CRYPTO_HEADER_INVALID` |
| 8 | `16 ≤ CHUNK_SIZE ≤ 1048576` | `CRYPTO_HEADER_INVALID` |
| 9 | `CHUNK_COUNT == ceil(PLAINTEXT_SIZE / CHUNK_SIZE)`，且 `1 ≤ CHUNK_COUNT ≤ 1048576` | `CRYPTO_LENGTH_INCONSISTENT` |
| 10 | `WRAPPED_KEY_LEN == 129`、`SENDER_PUB_LEN == 65`、`MANIFEST_LEN == MANIFEST_PT_LEN + 16` | `CRYPTO_LENGTH_INCONSISTENT` |
| 11 | `SIG_LEN ∈ [70,72]` 且与实际 DER 长度一致 | `CRYPTO_HEADER_INVALID` |
| 12 | `ENVELOPE_LEN` 等于 §4.2 计算值：**不足** → `CRYPTO_TRUNCATED`；**多出**（尾随字节）→ `CRYPTO_TRAILING_BYTES`；计算所用字段自相矛盾 → `CRYPTO_LENGTH_INCONSISTENT` | 见左列 |
| 13 | SM2 解封 `WRAPPED_KEY` → 得 32 字节 `DK` | `CRYPTO_KEY_UNWRAP_FAILED` |
| 14 | HKDF 派生 `KEK_MANIFEST`，解 `MANIFEST_SEC`（AAD 见 §7.3） | `CRYPTO_MANIFEST_AUTH_FAILED` |
| 15 | `MANIFEST_PT` 的 `MAGIC=="YSM1"`、`MANIFEST_VERSION==1`、`DIGEST_ALG==1`、`DIGEST_LEN==32`、`NAME_MODE ∈ {0x00,0x01}` 且**与 `FLAGS.NAME_OBFUSCATED` 相等**（`NAME_LEN==0` 时 `NAME_MODE` MUST 为 `0x00`，§8.5） | `CRYPTO_MANIFEST_INVALID` |
| 16 | 清单内 `FILE_SIZE / CHUNK_SIZE / CHUNK_COUNT` 与头一致；`DIGEST_TABLE_LEN == CHUNK_COUNT*32`；字符串长度前缀不越界 | `CRYPTO_LENGTH_INCONSISTENT` |
| 17 | SM2 验签 `SIG_SEC` over `SIG_INPUT`（§10.2） | `CRYPTO_SIGNATURE_INVALID` |
| 18 | `Crockford(SM3(SENDER_PUB))[0..4)` == 元数据中的发送方码 | `CRYPTO_SENDER_MISMATCH` |
| 19 | 逐块：块头自洽（`INDEX/PT_LEN/CT_LEN/LAST_FLAG/RESERVED`，§6.2）；同一序号出现两次 = 重复块 | `CRYPTO_CHUNK_ORDER` / `CRYPTO_CHUNK_DUPLICATE` / `CRYPTO_LENGTH_INCONSISTENT` |
| 20 | 逐块：GCM 认证（nonce §6.4、AAD §7.2） | `CRYPTO_CHUNK_AUTH_FAILED` |
| 21 | 逐块：`SM3(明文块) == DIGEST[i]` | `CRYPTO_DIGEST_MISMATCH` |
| 22 | 存在且仅存在一个 `LAST_FLAG=1` 的块，且其 `INDEX == CHUNK_COUNT-1`；缺块报明确索引 | `CRYPTO_CHUNK_MISSING` / `CRYPTO_CHUNK_ORDER` |

### 13.1 错误名 ↔ 数值对照（唯一权威）

端侧 C ABI 用整数返回错误（`0` 成功、负数为错误）。**名字是唯一权威**：断言、日志、UI 文案、门禁判定一律用 `CRYPTO_*` 名字；数值只用于 ABI 传输，不进 wire、不进 HTTP。

| 数值 | C ABI 常量 | 契约错误名 | 触发时机 / 备注 |
|---:|---|---|---|
| 0 | `YS_OK` | —（成功） | — |
| -1 | `YS_ERR_BAD_ARGUMENT` | `CRYPTO_BAD_ARGUMENT` | 入参非法：NULL、名字/MIME/扩展名不合 §3.3、块大小越界 |
| -2 | `YS_ERR_BUFFER_TOO_SMALL` | —（ABI 专用） | 输出缓冲不足：写入所需长度后由调用方重试，**不是**数据错误 |
| -3 | `YS_ERR_RNG` | `CRYPTO_RNG` | 随机源失败，或同一 `seed` 被二次使用 |
| -4 | `YS_ERR_BAD_MAGIC` | `CRYPTO_MAGIC_MISMATCH` | §13 #2 |
| -5 | `YS_ERR_UNSUPPORTED_VERSION` | `CRYPTO_VERSION_UNSUPPORTED` | §13 #3 |
| -6 | `YS_ERR_BAD_FLAGS` | `CRYPTO_FLAGS_UNKNOWN` | §13 #6 保留位非 0 |
| -7 | `YS_ERR_TRUNCATED` | **`CRYPTO_TRUNCATED`** | 实际字节不足：包/段/块记录读到一半 EOF |
| -8 | `YS_ERR_BAD_KEY_RECORD` | `CRYPTO_KEY_RECORD_INVALID` | `WRAPPED_KEY` 记录不合法（长度 ≠ 129、首字节 ≠ `0x04`） |
| -9 | `YS_ERR_BAD_SIGNATURE_RECORD` | `CRYPTO_SIGNATURE_RECORD_INVALID` | DER 结构非法，或自述长度与 `SIG_LEN` 不符 |
| -10 | `YS_ERR_BAD_MANIFEST_RECORD` | `CRYPTO_MANIFEST_INVALID` | 清单 `MAGIC`/版本/摘要算法/长度前缀非法 |
| -11 | `YS_ERR_BLOCK_SEQUENCE` | `CRYPTO_CHUNK_ORDER` | **别名**（规范值 -28） |
| -12 | `YS_ERR_DUPLICATE_BLOCK` | `CRYPTO_CHUNK_DUPLICATE` | 同一 `CHUNK_INDEX` 出现两次 |
| -13 | `YS_ERR_MISSING_BLOCK` | `CRYPTO_CHUNK_MISSING` | **别名**（规范值 -30） |
| -14 | `YS_ERR_LAST_FLAG_MISMATCH` | `CRYPTO_LAST_FLAG_MISMATCH` | `LAST_FLAG` 与位置不符，或出现多个末块 |
| -15 | `YS_ERR_TAG_MISMATCH` | `CRYPTO_CHUNK_AUTH_FAILED` | **别名**（规范值 -29） |
| -16 | `YS_ERR_MANIFEST_MISMATCH` | `CRYPTO_MANIFEST_AUTH_FAILED` | **别名**（规范值 -31） |
| -17 | `YS_ERR_SIGNATURE_MISMATCH` | `CRYPTO_SIGNATURE_INVALID` | §13 #17 |
| -18 | `YS_ERR_TRAILING_BYTES` | `CRYPTO_TRAILING_BYTES` | 包尾有多余字节 |
| -19 | `YS_ERR_BAD_POINT` | `CRYPTO_KEY_UNWRAP_FAILED` | C1 点不在曲线上（**规范值**） |
| -20 | `YS_ERR_BAD_KDF` | `CRYPTO_KEY_UNWRAP_FAILED` | **别名**（KDF 输出全零等） |
| -21 | `YS_ERR_BAD_CODE` | `CRYPTO_BAD_CODE` | 码派生不符，或归一化后不是 4 个合法符号 |
| -22 | `YS_ERR_CODE_EXHAUSTED` | `CRYPTO_CODE_EXHAUSTED` | 撞码重生成次数用尽 |
| -23 | `YS_ERR_BAD_CIPHERTEXT` | `CRYPTO_KEY_UNWRAP_FAILED` | **别名**（C3 不符） |
| -24 | `YS_ERR_HEADER_INVALID` | `CRYPTO_HEADER_INVALID` | §13 #4 / #7 / #8 / #11 |
| -25 | `YS_ERR_ALG_UNSUPPORTED` | `CRYPTO_ALG_UNSUPPORTED` | §13 #5 |
| -26 | `YS_ERR_UNSIGNED` | `CRYPTO_UNSIGNED` | `FLAGS.SENDER_SIGNED == 0` |
| -27 | `YS_ERR_LENGTH_INCONSISTENT` | `CRYPTO_LENGTH_INCONSISTENT` | 长度字段互相矛盾（`MANIFEST_LEN ≠ MANIFEST_PT_LEN+16`、`CT_LEN ≠ PT_LEN`） |
| -28 | `YS_ERR_CHUNK_ORDER` | `CRYPTO_CHUNK_ORDER` | 块序/位置错（**规范值**） |
| -29 | `YS_ERR_CHUNK_AUTH_FAILED` | `CRYPTO_CHUNK_AUTH_FAILED` | 块级 GCM tag 不符（**规范值**） |
| -30 | `YS_ERR_CHUNK_MISSING` | `CRYPTO_CHUNK_MISSING` | 缺块（**规范值**） |
| -31 | `YS_ERR_MANIFEST_AUTH_FAILED` | `CRYPTO_MANIFEST_AUTH_FAILED` | 清单 GCM tag 不符（**规范值**） |
| -32 | `YS_ERR_DIGEST_MISMATCH` | `CRYPTO_DIGEST_MISMATCH` | 明文块 SM3 与清单不符 |
| -33 | `YS_ERR_SENDER_MISMATCH` | `CRYPTO_SENDER_MISMATCH` | §13 #18 |
| -99 | `YS_ERR_INTERNAL` | `CRYPTO_INTERNAL` | 内部错误（panic 捕获等） |

**规则（写死）**

1. **数值冻结、不得复用**：已占用的数值不得改含义；新增语义取**未被占用的最小值**（当前从 `-34` 起；`-99` 已保留给 `CRYPTO_INTERNAL`）。数值不进 wire、不进 HTTP。
2. **别名只为兼容**：`-11 / -13 / -15 / -16 / -20 / -23` 是首版遗留的重复值，语义已并入对应契约名；实现的新路径 SHOULD 返回规范值，但判定与日志一律按**名字**，返回别名不算失败。
3. **多对一允许、一对多禁止**：一个契约名可以对应多个数值（别名），任何数值只对应一个契约名。
4. **判定口径**：单测与门禁断言 `CRYPTO_*` 名字；只有 ABI 边界（JS ↔ wasm）用数值。
5. **`-2` 不是数据错误**：缓冲区不足只表示"调用方给的空间不够"，按返回的所需长度重试，**不得**计入失败用例或篡改用例。

**`CRYPTO_TRUNCATED` 与 `CRYPTO_LENGTH_INCONSISTENT` 的分界（写死）**

| 情形 | 错误名 |
|---|---|
| 实际字节比结构所需少（读一半没了） | `CRYPTO_TRUNCATED`（-7） |
| 长度字段互相矛盾（声明 vs 声明） | `CRYPTO_LENGTH_INCONSISTENT`（-27） |
| 字节数比声明多（有尾随字节） | `CRYPTO_TRAILING_BYTES`（-18） |

> 本节新增的名字（`CRYPTO_TRUNCATED`、`CRYPTO_TRAILING_BYTES`、`CRYPTO_CHUNK_DUPLICATE`、`CRYPTO_LAST_FLAG_MISMATCH`、`CRYPTO_KEY_RECORD_INVALID`、`CRYPTO_SIGNATURE_RECORD_INVALID`、`CRYPTO_BAD_ARGUMENT`、`CRYPTO_RNG`、`CRYPTO_INTERNAL` 等）此前只在实现内部存在；**一律不改变任何字段布局与样例字节**。

> 上述错误码是**端侧错误码**（端侧产出、Web 展示），不经 HTTP 上行。服务端错误码见 `docs/API.md` §10，两套命名不混用。

---

## 14. 限值与边界

| 项 | v1 限值 | 说明 |
|---|---|---|
| `PLAINTEXT_SIZE` | ≤ `4 294 967 296`（4 GiB） | 产品策略上限，格式本身支持 u64 |
| `CHUNK_SIZE` | `[16, 1048576]`，生产默认 `1048576` | 读方按头取值 |
| `CHUNK_COUNT` | `[1, 1048576]` | 与 `PLAINTEXT_SIZE` 交叉校验 |
| 文件名 | ≤ 255 字节 | UTF-8 NFC |
| MIME | ≤ 127 字节 | 必须非空 |
| 扩展名 | ≤ 16 字节 | 可为空 |
| `MANIFEST_PT_LEN` | ≤ 4 MiB | 由 `CHUNK_COUNT*32 + 字符串` 天然满足 |
| 空文件 | `S=0, n=1, PT_LEN(0)=0` | 唯一一块，密文 0 字节、tag 16 字节 |

---

## 15. 样例（测试向量锚点）

> **样例的定位**：所有**结构性字节**（头、AAD、清单明文、块头、长度、偏移）都是确定的，可以手算核对；**密码学输出**（`C2/C3`、`TAG`、`SIG`、`DIGEST`）由下列固定输入算出。
>
> 真实实现里 `DK / KDF_SALT / k / k_sig` 必须每次随机；下表把它们**钉死**只是为了可复现。Rune 的测试钩子（test-only RNG）应当能注入这些固定值，从而逐字节复现本文所有 hex。**生产代码 MUST NOT 出现这些常量**。

### 15.1 公共测试夹具

| 名称 | 值（hex） |
|---|---|
| 接收方私钥 `d_R` | `3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8` |
| 接收方公钥 `PB_R` | `0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13` |
| 发送方私钥 `d_S` | `00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f` |
| 发送方公钥 `PB_S` | `04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d` |
| `DK` | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `KDF_SALT` | `000102030405060708090a0b0c0d0e0f` |
| 封装临时标量 `k_enc` | `59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21` |
| 签名临时标量 `k_sig` | `6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f` |

派生结果（可直接核对 HKDF-SM3 实现）：

```
KEK_CHUNK    = f8a4b7977b28e093f1bbc91f62089400
KEK_MANIFEST = e05971b0c4e3a8f648d9854a064cb648
```

由 `PB_S` 派生的用户码：`SM3(PB_S) = 572fcd0bf0efa3d2e0795a54408138ac5b4c4c0f43f8a219631b14b014428562` → **`AWQW`**（4 位，即契约里唯一的码形态）。若实现自带 `check_symbol()`，这 20 bit 算出的本地提示值为 `X`，仅用于输入框防误输，**不进入码、不上行**。

### 15.2 样例 V1：最小单块包

**明文输入**

| 项 | 值 |
|---|---|
| 文件内容 | `hello`（`68 65 6c 6c 6f`，5 字节） |
| 文件名 | `hi.txt`（`68692e747874`，6 字节） |
| MIME | `text/plain`（10 字节） |
| 扩展名 | `txt`（3 字节） |
| `CREATED_AT` | `1767225600000`（2026-01-01T00:00:00Z，hex `0000019b76daa800`） |
| `CHUNK_SIZE` | `1048576`（`00100000`） |
| `PLAINTEXT_SIZE` | `5` |
| `CHUNK_COUNT` | `1` |
| `FLAGS` | `0x00000002`（仅 `SENDER_SIGNED`） |

**HEADER（112 字节）**

```
5953504b 0100 0070 00000002 01 01 01 01
00100000 00000001 0000000000000005
0000000000000081  000000000000006d  0000005d  00000041
000102030405060708090a0b0c0d0e0f
0000000000000046
0000000000000000000000000000000000000000000000000000000000000000
```

连续写（便于 diff）：`5953504b010000700000000201010101001000000000000100000000000000050000000000000081000000000000006d0000005d00000041000102030405060708090a0b0c0d0e0f00000000000000460000000000000000000000000000000000000000000000000000000000000000`

逐字段核对：

| offset | 字段 | 值 |
|---:|---|---|
| 0 | `MAGIC` | `5953504b` |
| 4 | `VERSION_MAJOR/MINOR` | `01 00` |
| 6 | `HEADER_LEN` | `0070` |
| 8 | `FLAGS` | `00000002` |
| 12 | `AEAD/KDF/WRAP/SIG_ID` | `01 01 01 01` |
| 16 | `CHUNK_SIZE` | `00100000` |
| 20 | `CHUNK_COUNT` | `00000001` |
| 24 | `PLAINTEXT_SIZE` | `0000000000000005` |
| 32 | `WRAPPED_KEY_LEN` | `0000000000000081`（129） |
| 40 | `MANIFEST_LEN` | `000000000000006d`（109） |
| 48 | `MANIFEST_PT_LEN` | `0000005d`（93） |
| 52 | `SENDER_PUB_LEN` | `00000041`（65） |
| 56 | `KDF_SALT` | `000102…0e0f` |
| 72 | `SIG_LEN` | `0000000000000046`（70） |
| 80 | `RESERVED` | 32 × `00` |

**V1 全包段偏移地图**（与 §4.2 公式一致，可逐项相加核对）

| 段 | offset | 长度 | 构成 |
|---|---:|---:|---|
| `HEADER` | 0 | 112 | 定长 |
| `SENDER_PUB` | 112 | 65 | `04‖X32‖Y32` |
| `WRAPPED_KEY` | 177 | 129 | `C1(65)‖C3(32)‖C2(32)` |
| `MANIFEST_SEC` | 306 | 109 | 密文 93 + tag 16 |
| `SIG_SEC` | 415 | 70 | DER |
| `CHUNK_REC(0)` | 485 | 37 | 块头 16 + 密文 5 + tag 16 |
| **合计** | — | **522** | `PRELUDE_LEN = 485` |

**SENDER_PUB（65 字节，位于 offset 112）**

```
04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1
16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d
```

**WRAPPED_KEY（129 字节，位于 offset 177 = 112+65）**

```
C1(65) = 0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a
         73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0
C3(32) = f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a4673
C2(32) = 44e70dd8f4bfee133f6f597fb2ff6946147d8c1092763f5d3ceaf6d74f234985
```

连续写：`0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a467344e70dd8f4bfee133f6f597fb2ff6946147d8c1092763f5d3ceaf6d74f234985`

自检：用 `d_R` 解封应得 `DK`；`C2` 应等于 `DK XOR SM3-KDF(x2‖y2, 32)`。

**MANIFEST_PT（93 字节）**

| offset | len | hex | 字段 / 取值 |
|---:|---:|---|---|
| 0 | 4 | `59534d31` | `MAGIC` = `YSM1` |
| 4 | 1 | `01` | `MANIFEST_VERSION` |
| 5 | 1 | `00` | `NAME_MODE` |
| 6 | 1 | `01` | `DIGEST_ALG` = SM3 |
| 7 | 1 | `20` | `DIGEST_LEN` = 32 |
| 8 | 8 | `0000000000000005` | `FILE_SIZE` = 5 |
| 16 | 4 | `00100000` | `CHUNK_SIZE` = 1048576 |
| 20 | 4 | `00000001` | `CHUNK_COUNT` = 1 |
| 24 | 8 | `0000019b76daa800` | `CREATED_AT`（Unix ms） |
| 32 | 2 | `0006` | `NAME_LEN` |
| 34 | 6 | `68692e747874` | `NAME` = `hi.txt` |
| 40 | 2 | `000a` | `MIME_LEN` |
| 42 | 10 | `746578742f706c61696e` | `MIME` = `text/plain` |
| 52 | 2 | `0003` | `EXT_LEN` |
| 54 | 3 | `747874` | `EXT` = `txt` |
| 57 | 4 | `00000020` | `DIGEST_TABLE_LEN` = 32 |
| 61 | 32 | `becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268` | `DIGEST[0]` = SM3(`hello`) |
| 93 | — | — | （结束，正好 93 字节） |

连续写：`59534d3101000120000000000000000500100000000000010000019b76daa800000668692e747874000a746578742f706c61696e000374787400000020becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268`

**AAD_MANIFEST（31 字节）**

```
025953504b010000000002001000000000000100000000000000050000005d
```

| offset | len | hex | 字段 |
|---:|---:|---|---|
| 0 | 1 | `02` | `AAD_LABEL`（清单域） |
| 1 | 4 | `5953504b` | `MAGIC` |
| 5 | 1 | `01` | `VERSION_MAJOR` |
| 6 | 1 | `00` | `VERSION_MINOR` |
| 7 | 4 | `00000002` | `FLAGS` |
| 11 | 4 | `00100000` | `CHUNK_SIZE` |
| 15 | 4 | `00000001` | `CHUNK_COUNT` |
| 19 | 8 | `0000000000000005` | `PLAINTEXT_SIZE` |
| 27 | 4 | `0000005d` | `MANIFEST_PT_LEN` = 93 |

**MANIFEST_SEC（109 字节 = 93 密文 + 16 tag，位于包内 offset 306）**，nonce = `ffffffffffffffff00000001`

密文（93 字节）：

```
186874ecd599472da43a0d5a866014eeb5b072e634f2b72b67ec329825dafbb48343ff0ba9b0063b
1fe02070b21d20c6b3e86781a5e9a5463f72040e925397a7cb97e6b8d25f6065aede90354b013789
ecbe2c6662730b6faa60bdd0f1
```

tag（16 字节）：`578349057322670a37cac504041ce16f`

连续写：`186874ecd599472da43a0d5a866014eeb5b072e634f2b72b67ec329825dafbb48343ff0ba9b0063b1fe02070b21d20c6b3e86781a5e9a5463f72040e925397a7cb97e6b8d25f6065aede90354b013789ecbe2c6662730b6faa60bdd0f1578349057322670a37cac504041ce16f`

**块 0 的 AAD（`AAD_CHUNK`，32 字节）**

```
015953504b010000100000000000010000000000000005000000000100000005
```

| offset | len | hex | 字段 |
|---:|---:|---|---|
| 0 | 1 | `01` | `AAD_LABEL`（块域） |
| 1 | 4 | `5953504b` | `MAGIC` |
| 5 | 1 | `01` | `VERSION_MAJOR` |
| 6 | 1 | `00` | `VERSION_MINOR` |
| 7 | 4 | `00100000` | `CHUNK_SIZE` |
| 11 | 4 | `00000001` | `CHUNK_COUNT` |
| 15 | 8 | `0000000000000005` | `PLAINTEXT_SIZE` |
| 23 | 4 | `00000000` | `CHUNK_INDEX`（块序号） |
| 27 | 1 | `01` | `LAST_FLAG`（末块） |
| 28 | 4 | `00000005` | `PT_LEN` |

**块 0 的 nonce（12 字节）**：`000000000000000000000001`（`i=0` 且为末块 → 末块位 `01`）

**块记录 0（37 字节 = 16 + 5 + 16）**

| 段 | offset（块内） | offset（包内） | 字节数 | hex |
|---|---:|---:|---:|---|
| 块头 | 0 | 485 | 16 | `00000000 00000005 00000005 01 00 0000` |
| 密文 `CHUNK_CT` | 16 | 501 | 5 | `84bf7e96d2` |
| tag | 21 | 506 | 16 | `590df9b1343a6dd6ea84c381578472ef` |

连续写（建议直接比对这个）：`0000000000000005000000050100000084bf7e96d2590df9b1343a6dd6ea84c381578472ef`

**SIG_INPUT = "YSSIG1" ‖ 0100 ‖ HDR_CORE(72) ‖ SENDER_PUB(65) ‖ MANIFEST_SEC(109)，共 254 字节**

```
5953534947310100
5953504b010000700000000201010101001000000000000100000000000000050000000000000081000000000000006d0000005d00000041000102030405060708090a0b0c0d0e0f
04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d
186874ecd599472da43a0d5a866014eeb5b072e634f2b72b67ec329825dafbb48343ff0ba9b0063b1fe02070b21d20c6b3e86781a5e9a5463f72040e925397a7cb97e6b8d25f6065aede90354b013789ecbe2c6662730b6faa60bdd0f1578349057322670a37cac504041ce16f
```

**SIG_SEC（70 字节 DER，位于包内 offset 415）**

```
3044022063287a23c4ed9288dd091ad23495200bf98ed1e89cf1ffaf6ecba6013ec5b413022035654a55f88a4a5960318fbebdf6c0585354f2d471c15a7a0b48b1df91f3c567
```

结构：`30 44`（SEQUENCE，长度 68） ‖ `02 20` ‖ r(32) ‖ `02 20` ‖ s(32)。

**完整包（522 字节）**

```
5953504b010000700000000201010101001000000000000100000000000000050000000000000081000000000000006d0000005d00000041000102030405060708090a0b0c0d0e0f00000000000000460000000000000000000000000000000000000000000000000000000000000000
04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d
0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a467344e70dd8f4bfee133f6f597fb2ff6946147d8c1092763f5d3ceaf6d74f234985
186874ecd599472da43a0d5a866014eeb5b072e634f2b72b67ec329825dafbb48343ff0ba9b0063b1fe02070b21d20c6b3e86781a5e9a5463f72040e925397a7cb97e6b8d25f6065aede90354b013789ecbe2c6662730b6faa60bdd0f1578349057322670a37cac504041ce16f
3044022063287a23c4ed9288dd091ad23495200bf98ed1e89cf1ffaf6ecba6013ec5b413022035654a55f88a4a5960318fbebdf6c0585354f2d471c15a7a0b48b1df91f3c567
0000000000000005000000050100000084bf7e96d2590df9b1343a6dd6ea84c381578472ef
```

长度核对：`112 + 65 + 129 + 109 + 70 + 37 = 522`；`PRELUDE_LEN = 485 = 112+65+129+109+70`。

### 15.3 样例 V2：多块包（`CHUNK_SIZE = 32`，3 块）

**输入**：明文 = `00 01 02 … 4f`（80 字节）；文件名 `multi.bin`；MIME `application/octet-stream`；扩展名 `bin`；`CHUNK_SIZE = 32`；`CHUNK_COUNT = 3`；`PLAINTEXT_SIZE = 80`。其余夹具同 §15.1。

**HEADER**

```
5953504b01000070000000020101010100000020000000030000000000000050000000000000008100000000000000be000000ae00000041000102030405060708090a0b0c0d0e0f00000000000000470000000000000000000000000000000000000000000000000000000000000000
```

对照：`CHUNK_SIZE=00000020`、`CHUNK_COUNT=00000003`、`PLAINTEXT_SIZE=0000000000000050`、`MANIFEST_LEN=00000000000000be`（190）、`MANIFEST_PT_LEN=000000ae`（174）、`SIG_LEN=47`（71）。

段偏移：`HEADER` 0/112、`SENDER_PUB` 112/65、`WRAPPED_KEY` 177/129、`MANIFEST_SEC` 306/190、`SIG_SEC` 496/71、`CHUNK_SEC` 567，三个块记录分别在 **567 / 631 / 695**（长度 64 / 64 / 48），合计 **743**。

**MANIFEST_PT（174 字节）**

```
59534d3101000120000000000000005000000020000000030000019b76daa80000096d756c74692e62696e00186170706c69636174696f6e2f6f637465742d73747265616d000362696e00000060
fa34635f1d3ac2729ac5987eb59e01928457f325b4b51ca85a177813c5c5ddf7
778cfd21a404c276d1efdf3137c41b3b89d7f003b192efde1fb0c053b7028e9a
20c717e09714e6191630c4b93a398e49346f3e69a862f38c609e92a0f0f2676d
```

（`00000060` = `DIGEST_TABLE_LEN` = 96；随后是 3 个 32 字节摘要。）

**AAD_MANIFEST（31 字节）**

```
025953504b01000000000200000020000000030000000000000050000000ae
```

**MANIFEST_SEC（190 字节）**

```
186874ecd599472da43a0d5a866014bbb5a072c634f2b72967ec329825dafbb4834cfa17ebb017617d833a15d2087fc6b3e06d8ed183be50641d677ad799716b1503d75234afaccd1212e1b6867a2bb4b4fdff906302486c2f146c1c9898816f22debef0423bae283565b1f763b192d1254bcb70b3008aaf6bfc2a26ad3b016215dbcf159736e366bf9feac2e3f009ab893e622ef3fd102d93a43c4a497b6a0fdc05a78b558d89b1b69e75953ee9ba8c48a50b71f6f8f061bde469085bc4
```

**块（3 条记录）**

| i | nonce | AAD_CHUNK | PT_LEN | 块记录（hex） |
|---:|---|---|---:|---|
| 0 | `000000000000000000000000` | `015953504b010000000020000000030000000000000050000000000000000020` | 32 | `00000000000000200000002000000000` + `e53cc98b73ce1316f88b40d72eb4ad007de4c4eb3b998e61423fa7375862a128ccfc7d2ea872b6d68cba78bdf0d49c5c` |
| 1 | `000000000000000100000000` | `015953504b010000000020000000030000000000000050000000010000000020` | 32 | `00000001000000200000002000000000` + `7f6eac8eb153c5a03bda573764795c7106e16c370c917266d7e6aacda5776ac17eae13a1a8abf32f27d4986b385173df` |
| 2 | `000000000000000200000001` | `015953504b010000000020000000030000000000000050000000020100000010` | 16 | `00000002000000100000001001000000` + `a06a9b48c7f97001d12c94ce07507a0864c4c34b507721fe15c9c7cae50f0811` |

逐块摘要：`DIGEST0=fa34635f…ddf7`、`DIGEST1=778cfd21…8e9a`、`DIGEST2=20c717e0…676d`（全文见上）。

**SIG_SEC（71 字节）**

```
3045022100f88983fb66ae091af5f9ffddc01036ea454f7fdd76c6122ea4869a3a774ddc03022027348d7ac905dffde6ba2ed6fb8916503629560c23aa24e93580dbe3e0e5e311
```

**包长**：`112+65+129+190+71 + 64+64+48 = 743` 字节。

### 15.4 样例 V3：SM2 封装样例（最小自洽）

| 项 | 值 |
|---|---|
| 接收方公钥 | `0409f9df…2da9ad13`（§15.1） |
| 明文 | `DK` = `000102…1e1f`（32 字节） |
| 临时标量 `k_enc` | `59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21` |
| 输出 | 129 字节，见 §15.2 的 `WRAPPED_KEY` |

拆解：

- `C1 = [k_enc]G`（65 字节）→ `0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0`
- `C3 = SM3(x2 ‖ DK ‖ y2)`（32 字节）→ `f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a4673`
- `C2 = DK XOR SM3-KDF(x2 ‖ y2, 32)`（32 字节）→ `44e70dd8f4bfee133f6f597fb2ff6946147d8c1092763f5d3ceaf6d74f234985`

校验路径（任一实现都可独立复核）：`SM3( x2 ‖ DK ‖ y2 ) == C3`；`C2 XOR SM3-KDF(x2‖y2,32) == DK`；`(x1,y1)` 在 SM2 曲线上。

### 15.5 样例 V4：签名样例

| 项 | 值 |
|---|---|
| 签名私钥 | `d_S`（§15.1） |
| 签名输入 | V1 的 `SIG_INPUT`（254 字节，见 §15.2） |
| 临时标量 `k_sig` | `6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f` |
| 输出（DER） | `3044022063287a23c4ed9288dd091ad23495200bf98ed1e89cf1ffaf6ecba6013ec5b413022035654a55f88a4a5960318fbebdf6c0585354f2d471c15a7a0b48b1df91f3c567` |

用 `PB_S` + 默认 ZA 验签必须通过。若把 `MANIFEST_SEC` 里任意一个字节取反，验签 MUST 失败。

### 15.6 复现这些样例的办法（给 Rune）

1. 注入固定 `DK`、`KDF_SALT`、`k_enc`、`k_sig`（只在 `#[cfg(test)]` 可见）。
2. 按 §6.4 / §7.2 / §7.3 生成 nonce 与 AAD（纯字节拼接，无需随机）。
3. 用 GmSSL 命令行交叉验证：`sm3` 对 `DIGEST` / `C3`、`sm4-gcm` 对 `MANIFEST_SEC` 与块密文、`sm2` 对 `WRAPPED_KEY` 解封与 `SIG` 验签。
4. 逐字节 diff 本文所有 hex；不一致时先查字节序、再查 AAD 字段顺序、最后查 KDF info 串（三处是最常见的偏差来源）。

---

## 16. 模块分工锚点

| 章节 | Core（Go） | Rune（Rust/WASM） | Web（Vue） | Gate |
|---|---|---|---|---|
| §2 版本策略 | 只透传，不解析 | **实现拒绝规则** | 展示 `YSPK/1.0` 错误文案 | 构造未知版本包做拒绝用例 |
| §4 段表 / §12 映射 | **prelude ↔ 块切片的存储边界** | 组装/拆解 | 上传编排、续传 | 逐字节重组校验 |
| §5 HEADER | 不解析 | **字段级读写** | 不碰 | 偏移/长度核对 |
| §6 分块 + nonce | 只认 `index` 与长度 | **nonce 派生** | 分片调度 | 乱序/截断用例 |
| §7 AAD | 不解析 | **AAD 拼接** | 不碰 | 改 1 字节必须报错 |
| §8 清单 | 不解析 | **结构读写** | 用清单渲染文件卡 | 文件名 grep 不到 |
| §9 SM2 封装 | 不解析 | **C1C3C2** | 不碰 | 与 GmSSL 对照 |
| §10 签名 | 不解析 | **SIG_INPUT + DER** | 展示"已验证来源" | 篡改必失败 |
| §11 KDF | 不解析 | **HKDF-SM3** | 不碰 | GmSSL 对照 |
| §13 校验清单 | — | **整表实现** | 错误文案映射 | 每条一个负例 |
| §15 样例 | — | **测试向量** | — | 复用为验收基线 |

---

## 17. v2 预留（仅记录，不实现）

以下位置已留好扩展位，**v1 一律写 0 并强校验**，改动需 ADR：

- `HEADER[80..112)` 32 字节 `RESERVED`（可放新算法参数、KDF 版本、包级策略位）。
- nonce 的 `[8..11)` 3 字节保留区（可支撑"每块多流"或"多段加密"）。
- `FLAGS` 的 bit2..bit31。
- `MANIFEST_PT` 尾部追加字段（靠 `DIGEST_TABLE_LEN` 之后的位置检查 + 版本号门控；v1 读到尾部多余字节即拒绝）。
- `NAME_MODE = 0x01`（打码文件名）的正式交互。
