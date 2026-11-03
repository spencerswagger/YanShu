# `4eda665` 真认证验收 + 六项复核（收口）

- 日期：2026-11-02
- 宿主：`http://127.0.0.1:18080`，`YANSHU_VERIFIER=sm2`、`YANSHU_TOKEN_EPOCH=1`，
  `yanshu-server` = `cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9`（spencer 独立核过）
- 内核：`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B）；日志 `sm2 verifier loaded … version=0x00010000`
- 入口类型：**native-api**（HTTP，真 `sm2`）；与 `stub-allow` 各份**分开留档**

## 一、产物三件套（可复跑）

| 文件 | sha256 |
|---|---|
| `yanshu-server` | `cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9` |
| `deliver` | `16e919fbc678081345ac217be5628fcf0a96a5a8567f72ca2c040d462d04a990` |
| `yanshu_sm.wasm` | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f` |

编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`

## 二、token 六步（真 `sm2` + 真 KID）

| 步 | 场景 | 结果 | 备注 |
|---|---|---|---|
| ① | 基线（`EPOCH=1`） | **200** | 宿主实测（`GET /prelude` 571B） |
| ② | **只换 `TOKEN_SECRET`** | **401 `AUTH_TOKEN_INVALID`** | `4eda665` 自建实例实测；**旧语义**（终值应为"不吊销 → 200"） |
| ③ | **EPOCH+1**（改库，不重启） | **401 `AUTH_TOKEN_STALE`** | 同一进程、**PID 不变**（脚本 `check_epoch_online_revoke.py` 5/5 PASS） |
| ④ | 换 EPOCH 后新签发 | **200** | |
| ⑤ | 旧 token 复打 | **401 `AUTH_TOKEN_STALE`** | 不复活 |
| ⑥ | KID 调小 | **exit 1** | `config: YANSHU_TOKEN_KID must increase (current=3, provided=2); refusing to start` |
| 附 | 畸形 token（宿主只读） | 401 `AUTH_TOKEN_INVALID` | `upload token is invalid for this transfer` |
| 附 | 无 token（宿主只读） | 401 `AUTH_MISSING` | |
| 附 | `token_epoch` | 1 → 2 | 同进程内即变 |

## 三、六项复核

| # | 项 | 结果 |
|---|---|---|
| 1 | 内核入库 sha | **PASS**：`git cat-file blob 4eda665:server/kernel/yanshu_sm.wasm` == `c1b87d0a…`，**不是空 blob**（127,313 B）；工作区同值；启动日志 `kernel=./kernel/yanshu_sm.wasm` |
| 2 | 错误名 grep | **部分 PASS**：`REVOKED`=0、`STALE`=7、`INVALID`=8；**`EXPIRED`=0**（契约若按现网对齐则一致，按交付版则缺一码） |
| 3 | 迁移清单 | **PASS**：`0001_init / 0002_upload_token_kid / 0004_token_kid_state / 0005_restore_token_kid`，**无 `0004_drop_token_epoch`** |
| 4 | 升级路径（连跑两次） | **PASS 10/10**：老库补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → `rows 1→1` |
| 5 | 冻结向量套件 | **PASS**：26/26（四形态）、prelude 6/6、证据二 6/6 + 11/11；sm2 14 可执行 / user-code 5 / normalize 20 |
| 6 | KID 矩阵 + `SIG_INPUT` 四条 | **矩阵部分 FAIL（②旧语义）+ SIG_INPUT 3/4**：109 走进验签、110 → `BAD_REQUEST`、昵称 33 → `NICKNAME_INVALID`、513 → `NICKNAME_INVALID`（`SIG_INPUT_TOO_LONG` HTTP 不可达，码本身库层已实现且有单测） |

## 四、生产路径端到端（宿主真 `sm2`）

2,506,889 B → 3 块（1 MiB）→ 投递 `LEASED`；`GET /prelude` 571B **逐字节一致**；
三块 1,048,592 / 1,048,592 / 409,753 B **与本地密文逐字节一致**；解密落盘 sha256 `bb17026f…79dc9` **等于源文件**；
**ack 后再取 prelude 与 chunks 均为 410 `TRANSFER_CONSUMED`**。

## 五、结论与已知偏差

**结论：宿主 `4eda665` 在真 `sm2` 下可用**（投递/取回/解密/逐字节一致/ack 后 410 全部实测通过），
但**不是六项全 PASS**：第 2、6 项各有一处与"交付版契约"不符。

已知偏差（如实，不美化）：

1. **只换 `TOKEN_SECRET` → 401 `AUTH_TOKEN_INVALID`**（终值应为"不吊销 → 200"）；`06c9f56` 已修。
2. **`AUTH_TOKEN_EXPIRED` 未实现**（grep 0 处）；`06c9f56` 已实现（6h / 30min）。
3. **`SIG_INPUT_TOO_LONG` 在 HTTP 不可达**（昵称 33 / 513 都先被 `NICKNAME_INVALID` 拦下）；码本身已实现。
4. **token 六步里 ②③⑥ 是在自建实例上做的**（与宿主同二进制 `cc117070…`、同内核）；
   宿主只做了只读的三条（基线、畸形、缺失）——因为改宿主 `TOKEN_SECRET`/库属运维动作。
5. 宿主与 `06c9f56` **不等价**（派生格式变了）：换产物会使在传 token 失效（数据无损）。
