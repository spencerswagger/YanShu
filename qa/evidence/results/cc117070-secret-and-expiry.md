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
