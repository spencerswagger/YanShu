# 契约裁决记录 · 2026-11-03

对接过程中提出的 13 项契约问题（3 项有意偏离 + 10 项缺口）的裁决与落点。

- 契约版本：`docs/API.md` v1 / `docs/CRYPTO-PACK.md` `YSPK/1.0`（基线 commit `376c5b5`，分支 `feat/contracts-v1`）
- **影响面：全部 13 项均为澄清、错误码与元数据口径，不改包字段、不改样例字节**（V1 522 B / V2 743 B / 封装 129 B / 签名 70 B 均不变）。
- 唯一"会改变包字节"的候选（把包身份显式绑进 AAD）不在此列，单独见 `docs/adr/0001-aad-chunk-binding.md`，结论是 v1 不改、留待版本升级。

| # | 问题 | 裁决 | 落点 | 改字节 |
|---:|---|---|---|---|
| D1 | WebSocket（信令与在线表）未实现 | **补定义降级语义 + 排期**：v1 `GET /v1/ws` 返回 `503 SERVICE_UNAVAILABLE`；客户端视为直传不可用、静默走中转、收件通知改轮询 `inbox`（≥30 s，退避到 ≤5 min）；功能不受影响 | API §9.6、§4.1、§10.2、§15 | 否 |
| D2 | 审计 `path` 记路由模板而非实际路径 | **采纳（并写进白名单）**：审计字段改为 `route_template`，明确不记实际路径参数，避免 `transfer_id`（能力凭证）落日志；追溯改用 `request_id` + 元数据表 | API §2.1、§12 | 否 |
| D3 | 服务端对码做容错归一化 | **允许，但有硬约束**：规则必须与端侧逐字节一致、幂等、在一切判定之前完成；限速/锁定按归一化后的码计数；**禁止**猜测性纠错与 5 位截断。归一化不扩大撞码面（码空间仍是 2^20 个规范值），只归并同一码的不同写法 | API §1.6、§1.1、§4.3；CRYPTO-PACK §3.4 | 否 |
| G1 | 非当事人调 `ack` / `revoke` 无专用错误码 | **补定义**：新增 `403 NOT_TRANSFER_PARTY`（已认证但非当事人），不再复用 `409 TRANSFER_STATE_CONFLICT` | API §10.1 | 否 |
| G2 | `CHUNKS_MISSING` 的 `missing` 无槽位 | **补定义**：错误信封新增可选 `details` 对象，v1 **只允许**键 `missing`；新增键须走 ADR | API §0.2、§6.6、§10.1 | 否 |
| G3 | 白名单未含服务端必需的派生状态 | **补定义**：新增「派生状态（服务端内部，无业务内容）」一组：`prelude_received`、`received_chunks`、`upload_token_sm3`、`uploaded_bytes`、租约/取件记录、幂等键映射；并加两条硬规矩（新增列必须先改本节；任何列不得含用户内容） | API §2.1 | 否 |
| G4 | 按 IP 配额需要上传者 IP | **补定义**：`transfers.uploader_ip` 作为派生列列入白名单，仅用于配额与反滥用，不对外返回、不用于画像 | API §2.1 | 否 |
| G5 | 幂等重放要返回同一 `upload_token`，与"只存 `SM3`"冲突 | **认可并写死构造**：`upload_token = base64url(HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ TRANSFER_ID_ASCII))`；库内只存 `SM3(upload_token)`；`TOKEN_SECRET` 只来自部署密钥、不入库不落日志；轮换令存量 token 失效（≤ TTL 24 h） | API §1.5 | 否 |
| G6 | 码归一化与 `CRYPTO-PACK §3.4` 的"服务端只接受归一化后 4 字符"表述冲突 | **补定义（同 D3）**：CRYPTO-PACK 改为"服务端 MAY 执行同一套归一化，结果必须正好 4 个合法符号"，判定口径指向 API §1.6 | CRYPTO-PACK §3.4 | 否 |
| G7 | 重复注册（同码同公钥）语义未定义 | **补定义**：`200` 幂等，返回与首次相同的 body（`registered_at` 不变），**不覆盖昵称**；改昵称只能走 `NICKNAME_UPDATE` | API §4.3 | 否 |
| G8 | 终态 `GET /transfers/{id}` 字段集不明确 | **补定义**：给出固定字段清单（16 项），并明确**不再返回** `prelude_sm3` 与 `lease_expires_at` | API §7.2 | 否 |
| G9 | 块/prelude 响应未定义密文摘要头 | **明确拒绝纳入 v1**：完整性已由 AEAD tag + 清单摘要保证；实现可保留 `X-YS-Ciphertext-Sm3` 作**非契约扩展**，客户端 MUST NOT 依赖 | API §7.4 | 否 |
| G10 | `/v1/config` 的 `stun_urls` / `ws_url` 未给默认值 | **补定义约束而不给默认值**：`stun_urls` ≥1 条且禁 `turn:`；`ws_url` 可为 `null`（走 §9.6）；`config` 不得含密钥/TURN 凭据/内部地址 | API §4.1 | 否 |

## 补充裁决（错误码与 ABI，同日）

| # | 问题 | 裁决 | 落点 | 改字节 |
|---:|---|---|---|---|
| R1 | 错误名与首版数值对不上 | **名字为唯一权威，数值冻结**：契约给一张「错误名 ↔ 数值」唯一对照表；首版重复值降为**别名**（-11/-13/-15/-16/-20/-23），规范值固定为 -28/-30/-29/-31/-19；新语义取未占用最小值（当前从 -34 起，-99 保留）；一个名字可有多值、一个值只能属于一个名字；断言与日志只用名字 | CRYPTO-PACK §13.1 | 否 |
| R2 | 「截断」与「长度不符」是否拆开 | **拆开，但不新增数值**：首版已有 `-7`，正名为 `CRYPTO_TRUNCATED`；与 `CRYPTO_LENGTH_INCONSISTENT`（-27，声明互相矛盾）、`CRYPTO_TRAILING_BYTES`（-18，尾随字节）三分，写死分界表 | CRYPTO-PACK §13（#1/#12/#19）、§13.1 | 否 |
| R3 | §15 样例是否要随契约重生成 | **不重算**：AAD 的六个字段 `YSPK/1.0` 本来就有（`CHUNK_INDEX`/`CHUNK_COUNT`/`LAST_FLAG`/`CHUNK_SIZE`/`PLAINTEXT_SIZE`/`PT_LEN`），本期未改契约字段；样例 V1 522 B / V2 743 B / V3 129 B / V4 70 B 保持原样，测试常量按现样例断言即可 | CRYPTO-PACK §15（正文未变） | 否 |
| R4 | 新增导出命名与"运行时布局切换" | **命名不冲突**（契约管字节，不管符号名），但有两条约束：① `*_v1` 的 `v1` 只能指契约大版本 `YSPK/1.0`，不得指 ABI 代数（同族里 `_v1` 与 `_v2` 混用建议统一）；② 运行时切换布局（`ys_set_layout` 等）MUST 只存在于测试/开发构建，发布构建只允许 `YSPK/1.0`，未知布局值必须报错 | CRYPTO-PACK §2.2 规则 7 | 否 |

| R5 | `FLAGS.NAME_OBFUSCATED` 与清单 `NAME_MODE` 无一致性规则 | **写成硬规则**：两者 MUST 相等，不等即整包非法 `CRYPTO_MANIFEST_INVALID`；**以清单 `NAME_MODE` 为准**（它描述文件名字节的实际语义，header 位只是对外提示）；校验位置**并入 §13 #15**（清单字段合法性那一步），**不新增编号**，以免既有 `§13 #20/#21` 等引用漂移；另补：`NAME_LEN==0` 时 `NAME_MODE` MUST 为 0 | CRYPTO-PACK §5.2、§8.2、§8.5、§13 #15 | 否 |
| R6 | `NAME_LEN = 0`（空文件名）是否合法 | **采纳"允许空名"**：`NAME_LEN=0` 为合法值，`NAME` 占 0 字节、后续偏移照常；读方 MUST 接受、不得因空名拒绝；客户端显示"未命名"并保留扩展名降级展示；落盘名由接收端本地决定。安全上不构成混淆通道（名字不参与加密/寻址，`MANIFEST_PT_LEN` 受清单 AAD 覆盖，服务端本就看不到明文名）；禁止空名只会逼客户端编造假名 | CRYPTO-PACK §8.2、§8.5、§13 #15 | 否 |
| R7 | "布局/版本可并存"的残留措辞与内核合规判定 | **清理并写死**：契约声明只有一种布局 `YSPK/1.0`，凡"历史布局/其他布局"只用于描述拒绝行为；新增 §2.3 给出内核合规判定的四条判据（`ys_version()==0x00010000`、`ys_header_len()==112`、§15 V1 样例解包成功、改版本字节后必须 `CRYPTO_VERSION_UNSUPPORTED`），并明确"不是桩 ≠ 合规"；`ys_version()` 不参与运行时版本判定，包内版本字段才是权威 | CRYPTO-PACK §2.1、§2.3 | 否 |

| R8 | token 生命周期与应急吊销缺口（实测：换 `TOKEN_SECRET` 后旧 token 仍 201） | **补定义**：新增 API §1.7——三凭证定位与寿命（`transfer_id` / `upload_token` ≤6h / `download_id` 30min）；只存哈希导致"换 secret 不吊销"是数据模型必然结果；引入单调递增 `EPOCH`（`/v1/config` 暴露 `token_epoch`），递增即一键吊销；错误名三分（`AUTH_TOKEN_INVALID`/`EXPIRED`/`STALE`），判定先凭据后状态；`upload_token` 构造把 `EPOCH` 纳入派生输入，否则重签发得到同一字符串、吊销失效；给出可复跑用例（见上节，6 步） | API §1.5、§1.3、§1.7、§3、§4.1、§7.4、§10.1、§11.1、§14 | 否 |
| R9 | 重签发端点是否保留 | **保留并写严**（API §1.7.5 五条）：① 只认发件人 `PURPOSE 0x08` 签名，禁止凭 `transfer_id`/旧 token 换取；② 幂等（同 `(transfer_id, EPOCH)` 返回逐字节相同 token）+ 双向限速；③ 新 token 携当前 `EPOCH`，旧 token 永久 `STALE`、不得复活；④ 已传块不重传（先 `GET /status` 取 `missing`）；⑤ 标注为 **v1 追加载荷**，部署方可配置关闭（`501 FEATURE_DISABLED`，代价是吊销后重建传输） | API §1.7.5、§3、§10.1、§11.1 | 否 |

## 凭证吊销 · 可复跑用例（验收集直接抄）

前置：同一二进制 + 同一份冻结内核产物；`token_epoch` 可从不鉴权的 `GET /v1/config` 读到。

| 步 | 动作 | 期望 |
|---:|---|---|
| 1 | 建传输，记 `tokenA`；`PUT /prelude`（带 `tokenA`） | `201` |
| 2 | 运维递增 `EPOCH`（改 `YANSHU_TOKEN_KID` 后重启，或等价热载） | `/v1/config` 的 `token_epoch` 变化 |
| 3 | 再用 `tokenA` 打 `PUT /prelude` | **`401 AUTH_TOKEN_STALE`** |
| 4 | `POST /v1/transfers/{id}/token`（`PURPOSE 0x08` 签名）换 `tokenB` | `200`，且 `tokenB ≠ tokenA` |
| 5 | 用 `tokenB` 打 `PUT /prelude` | `201` 或 `204`（已传块不重传） |
| 6 | 同 `EPOCH` 下重复第 4 步 | `200`，返回**与 `tokenB` 逐字节相同**（幂等） |

判据：第 3 步必须 401（不许 201/410），第 5 步不许要求重传已完成块，第 6 步必须逐字节相同；任一步不符即 FAIL。

## 实现现状与偏离登记

契约不因实现现状改口，但把"已知偏离"记在这里，避免被当成"契约允许"。

| # | 现状 | 契约要求 | 状态 |
|---:|---|---|---|
| K1 | 服务端内嵌内核产物 `8b89dd7f…`（130,653 B）与冻结产物 `c1b87d0a…`（127,313 B）不同字节 | 内嵌内核 MUST 与冻结构建产物同 sha256；同一 commit 跨环境重建可能不同字节，因此**以冻结产物 sha256 为准**，不以 commit 号为准 | 待 Core 换产物后由验收集复跑 |
| K2 | 上传 token 的过期目前由传输 TTL（≤24 h）承担，`AUTH_TOKEN_EXPIRED` 实际不会触发 | 上传 token 寿命上限 6 h（§1.7.4 脚注）；未实现即暴露窗口放大到 24 h | 偏离，待修 |

## 易错点（自查清单）

落到实现里最容易走样、症状又最难查的几处，按"一处定义"逐条列：

| # | 易错点 | 正确做法 | 走样后的症状 |
|---:|---|---|---|
| 1 | `upload_token` 的派生串被加了分隔符 | `HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1" ‖ TRANSFER_ID_ASCII)` 是**原样拼接**：不加 `:`、不加 `\0`、不加长度前缀 | 幂等重放返回的 token 与首次不同，表现为 prelude/chunk 上传报冲突或身份不符 |
| 2 | 服务端把 5 位 `CODE-CHECK` 截成 4 位 | 归一化后**必须正好 4 位**，否则 `400 CODE_FORMAT_INVALID`；不截断、不猜测纠错 | 输错一位仍能命中别人的码；锁定计数被绕过 |
| 3 | 把 `X-YS-Ciphertext-Sm3` 当契约必选项 | 它是**非契约扩展**，可返回；客户端 MUST NOT 依赖它做完整性判断 | 换实现后客户端校验失败，误判为"数据被改" |
| 4 | 码派生用 64 字节 `X‖Y` 而不是 65 字节公钥 | `SM3` 覆盖 **65 字节 `0x04‖X‖Y`**，再取前 20 bit | 同一公钥在不同实现算出不同码（`AWQW` vs `X2EH` 这类分叉） |
| 5 | 把 `ZA` 拼进 `SIG_INPUT`，或换 userID | `ID = "1234567812345678"`、`ENTL = 0x0080`；`ZA` 只由 SM2 内部参与 | 验签永远不过，且两端各自"自测通过" |
| 6 | 两套签名域混用 | 挑战用 `YSAUTH1`，包签名用 `YSSIG1`；M 的拼接不同，不可互借 | 注册/建传输报 `AUTH_SIGNATURE_INVALID` |
| 7 | 先判定后归一化 | 归一化在**一切判定之前**：撞码、限速、锁定、`SIG_INPUT` 比对、审计 | 同一码的大小写变体绕过限速与失败锁定 |
| 8 | 把 `-2`（缓冲区不足）当失败用例 | 按返回的所需长度重试一次；不计入失败/篡改用例 | 门禁出现假阴性/假阳性 |

## 统计

- **补定义**：20 项（D1、D2、D3、G1–G8、G10、R1–R3、R5–R9）
- **明确拒绝**：2 项（G9 密文摘要头不纳入 v1；R4 的"运行时布局切换"不得进入发布构建）
- **排期下一轮**：1 项（D1 的 WS 实现；其降级语义已在 v1 补定义）
- **需要抬版本号**：0 项（唯一候选见 `docs/adr/0001-aad-chunk-binding.md`，结论为 v1 不改）
- **新增错误名**：9 个（`CRYPTO_TRUNCATED`、`CRYPTO_TRAILING_BYTES`、`CRYPTO_CHUNK_DUPLICATE`、`CRYPTO_LAST_FLAG_MISMATCH`、`CRYPTO_KEY_RECORD_INVALID`、`CRYPTO_SIGNATURE_RECORD_INVALID`、`CRYPTO_BAD_ARGUMENT`、`CRYPTO_RNG`、`CRYPTO_INTERNAL`），**不改任何字段布局与样例字节**

## 一致性校核

- 全部 `§` 交叉引用可解析；表格列数与代码围栏配对通过。
- `CRYPTO-PACK` 四组样例字节零变化（V1 522 B / V2 743 B / V3 129 B / V4 70 B），逐字节复核脚本 0 失败。
