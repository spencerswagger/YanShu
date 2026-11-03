# 宿主口径实测：`4eda665` 上「只换 secret」与「超期」到底返回什么

- 日期：2026-11-02
- 对象：`4eda665` 产物（`cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9`），
  内核 `c1b87d0a…`；因改 secret/库属运维动作，**在自建实例上做，产物与宿主同一份**（同二进制、同内核）。
- 用途：契约该写"两个码"还是"三个码"，只认这里的实测。

## 一、只换 `TOKEN_SECRET`（同一库、同一 token、同一 EPOCH=1）

```
起实例 A（secret=secret-A-…）→ 投递拿到 token → GET /v1/transfers/{id}/status → 200
停 A，起实例 B（secret=secret-B-…，EPOCH 仍 1）→ 同一 token 再打 → 401
```

**原始响应体（逐字）**：

```json
{"error":{"code":"AUTH_TOKEN_INVALID","message":"upload token is invalid for this transfer","request_id":"req_986d401ff721c30a"}}
```

→ **只换 secret 会吊销**，返回 `AUTH_TOKEN_INVALID`。
（`06c9f56` 上同一实验是 **200 不吊销**——两版行为不同，不能混写。）

## 二、超期：返回 410 `TRANSFER_EXPIRED`，**没有** `AUTH_TOKEN_EXPIRED`

构造与结果（同一进程内改库，不改代码、不重启）：

| 构造 | 端点 | 实测 |
|---|---|---|
| 正常 | `/status` | **200** |
| `created_at` 推到 **7 小时前**（模拟上传凭据 6h 窗口） | `/status` | **仍然 200** —— 该版**没有凭据超期检查**（与 `grep AUTH_TOKEN_EXPIRED` = 0 一致） |
| `expires_at` 推到 **1 小时前** + `YANSHU_SWEEP_INTERVAL=1s` 让 sweeper 跑一轮 | 库内状态 | `state=EXPIRED`、`terminal_reason=EXPIRED` |
| 同上 | `GET /prelude` | **410 `TRANSFER_EXPIRED`**（`transfer has expired`） |
| 同上 | `GET /chunks/0` | **410 `TRANSFER_EXPIRED`** |

原始响应体：

```json
{"error":{"code":"TRANSFER_EXPIRED","message":"transfer has expired","request_id":"req_ab966310354c669e"}}
```

→ **超期在这版是"传输级 410"**，不是"凭据级 401 EXPIRED"；6h 上传凭据窗口**未被实现**。

## 三、结论：契约该写几个码

**取决于要描述哪个产物**，两者只能选一个：

| 口径 | 凭据类码 | 超期 | "只换 secret" |
|---|---|---|---|
| **对齐在跑的 `4eda665`** | **两个**：`STALE` / `INVALID` | `410 TRANSFER_EXPIRED`（无 `AUTH_TOKEN_EXPIRED`） | **吊销**（401 `INVALID`） |
| **对齐交付版 `06c9f56`** | **三个**：`STALE` / `INVALID` / `EXPIRED` | 401 `EXPIRED`（6h / 30min） | **不吊销**（200） |

**建议**：契约按 **`06c9f56`（三个码）** 写，宿主 `4eda665` 的差异（无 `EXPIRED`、secret 即 401）作为**已知偏差**登记，
因为 `06c9f56` 是唯一六项全 PASS、且修了 `uploader_ip NULL` P0 的产物；换产物后契约自动成立。
若决定长期留在 `4eda665`，则必须把契约改成**两个码 + secret 吊销**，并删掉 `EXPIRED` 相关条文（否则双向核对会判
"契约描述了不存在的行为"）。

## 四、补充核对：`4eda665` 与 `dfd3e82` 的派生里有没有 KID（只读）

| head | 派生前缀 | KID 编码 | 是否进派生 | 校验路径 |
|---|---|---|---|---|
| `4eda665` | `"yanshu/upload-token/**v2**"` | **`u64be(KID)`**（8 字节大端） | **有** | HTTP 层调 `Derives()`：**用当前 secret+KID 重算**再比库内哈希（`handlers_transfers.go:571`） |
| `dfd3e82` | `"yanshu/upload-token/**v1**"` | **`u32be(KID)`**（4 字节大端） | **有** | 同样 `Derives()` 重算（另有 `ValidateHash` 辅助函数，注释写"不重算"，但线上路径不走它） |

结论：

1. **两个版本 KID 都进派生**——"重签发后旧凭据复活（`T1 == T2`）"的风险**不存在**：
   KID 一变，同一 `transfer_id` 派生出的是不同字符串；库内哈希也被新值覆盖，旧 token 过不了值校验。
2. 差别在**编码与前缀**（`u64be`+`v2` vs `u32be`+`v1`），所以**跨版本 token 不兼容**：
   `4eda665` 签的 token 拿到 `06c9f56`/`dfd3e82` 上会 401 `AUTH_TOKEN_INVALID`（数据无损）。
3. `4eda665` 的实际校验是**重算**，所以"只换 secret 不吊销"在这版**不成立**（实测 401 `INVALID`）；
   源码里 `ValidateHash` 的注释"不重算"是**过时注释**，线上路径未使用它——建议 Core 顺手修掉这句，
   否则后来人会照注释以为 secret 不参与校验。

## 五、`dfd3e82`（`83a99ffc…`，拟部署版本）的三个 grep

```
AUTH_TOKEN_EXPIRED = 0        （无任何文件命中）
AUTH_TOKEN_REVOKED = 0
AUTH_TOKEN_STALE   = 7        （README / api_test / handlers_transfers / spec/errors / spec_test / token-rotation-check.sh）
```

- **`EXPIRED` 触发点：不存在**（`git grep -n` 无输出，也没有 `6*time.Hour` / `30*time.Minute` 这类凭据时效判定；
  只有 `handlers_blobs.go` 的下载租约 `leaseExpiry`，那是租约期限而非 `AUTH_TOKEN_EXPIRED` 错误码）。
- 该 head 的 secret 语义此前已实测：**只改 secret → 401 `AUTH_TOKEN_INVALID`**（见 `83a99ffc-core-three-steps.md` 第 ② 行）。

**因此：若部署 `dfd3e82`，契约必须退回"两个凭据码"**（`STALE` / `INVALID`），
`AUTH_TOKEN_EXPIRED` 退回 **K2 预留名**（v1 不实现），超期走 **410 `TRANSFER_EXPIRED`**；
同时必须把"只换 secret 不吊销"改回"**只换 secret 即吊销**（401 `INVALID`）"。
只有部署 `06c9f56` 才成立"三码 + secret 不吊销"。
