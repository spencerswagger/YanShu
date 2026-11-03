# 最终六项复核：`4eda665`（`cc117070…`）

- 日期：2026-11-02
- head：`feat/server-skeleton@**4eda665**`；产物由 Gate 自建，sha 与 Core 报的逐字节一致
  - `yanshu-server`：`cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9`
  - `deliver`：`16e919fbc678081345ac217be5628fcf0a96a5a8567f72ca2c040d462d04a990`
  - 内核：`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B）

## 六项结果

| # | 项 | 结果 | 证据 |
|---|---|---|---|
| 1 | 内核入库 sha | **PASS** | `git cat-file blob 4eda665:server/kernel/yanshu_sm.wasm` = `c1b87d0a…7259f`（127,313 B）；工作区同值；启动日志 `sm2 verifier loaded kernel=./kernel/yanshu_sm.wasm version=0x00010000` |
| 2 | 错误名 grep | **PASS**（附一处偏差） | `REVOKED=0`、`EXPIRED=0`、`STALE=7`、`INVALID=8`。**偏差**：契约 v1 已把 `AUTH_TOKEN_EXPIRED` 列为生效码（上传 6h / 租约 30min），而本 head 为 0 处 |
| 3 | 迁移清单 | **PASS** | `0001_init` / `0002_upload_token_kid` / `0004_token_kid_state` / `0005_restore_token_kid`，**无 `0004_drop_token_epoch`** |
| 4 | 升级路径 | **PASS 10/10** | 老 `08d40e7` 库缺列 → 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → **连跑两次 `rows 1→1`** |
| 5 | 冻结向量套件 | **PASS** | 一致性 26/26、prelude 6/6、证据二 6/6 + 11/11；sm2 14 条可执行（1 条 `executable:false` 跳过）、user-code 5、normalize 20 |
| 6 | KID 矩阵 + `SIG_INPUT` 四条 | **部分 FAIL** | KID：基线 200 → **只换 secret → 401 `AUTH_TOKEN_INVALID`（旧语义，终值是"不吊销"→ 200）** → KID+1 → 401 `AUTH_TOKEN_STALE` → 新签发 200 → 不复活；`SIG_INPUT`：109 通过、110 字段级、昵称 33 → `NICKNAME_INVALID`、**513 的专属码已实现（`spec/errors.go:32` + `TestSIGInputTooLong` PASS）但 HTTP 路径不可达**（昵称先被字段级拒） |

## `SIG_INPUT_TOO_LONG` 的准确表述（更新此前的 N/A）

- **码已实现**：`server/internal/spec/errors.go:32 → ErrSIGInputTooLong = "SIG_INPUT_TOO_LONG"`（400）；
  `MaxLegitSIGInputLen = 109`；四条单测我在该 head 树上跑过：`TestPerPurposeSIGInputLengths`、
  `TestSIGInputTooLong`、`TestRegisterSIGInputVerifies`、`TestNicknameTooLongIsFieldError` **全 PASS**。
- **HTTP 请求路径不可达**：构造 513 字节只能通过超长昵称，而昵称在 ≤32 处已被 `NICKNAME_INVALID` 拒，
  所以线上请求永远走不到 512 门。
- 因此该条从"N/A"更新为 **"已实现（库层可测）+ HTTP 不可达"**；不再记 FAIL，也不冒充"HTTP 可观测"。

## 结论一句话

**不建议用 `4eda665` 重启**：六项里第 6 项不达标——它的"只换 `TOKEN_SECRET`"仍返回 **401 `AUTH_TOKEN_INVALID`**
（旧语义），且 `EXPIRED` 未实现；这两条正是 `06c9f56`（`5a42bb43…`）修掉的。
若目标是"契约四码完整 + secret 作派生盐"，仍应用 `06c9f56`；若必须用 `4eda665`，须接受上述两条偏差。

## 已知偏差（`4eda665`）

1. **只换 `TOKEN_SECRET` → 401 `AUTH_TOKEN_INVALID`**（终值应为"不吊销"，200）。
2. **`AUTH_TOKEN_EXPIRED` 未实现**（契约 v1 已列为生效码，6h / 30min 两处）。
3. `SIG_INPUT_TOO_LONG` 已实现但 **HTTP 不可达**（字段级优先，属设计）。
4. 到期/租约类用例在本 head 无法构造（码不存在）。
