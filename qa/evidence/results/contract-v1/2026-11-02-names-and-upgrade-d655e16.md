# 错误名终值实测（`d655e16`，EPOCH 已撤回）+ 双向升级路径

- 日期：2026-11-02
- 服务端：`feat/server-skeleton@**d655e16**`
- 二进制：`/.octop/workspaces/0JXF1M/tmp/bin/yanshu-server-d655e16` —
  sha256 `4c331e1f6e58fd07248a8b3633eae8684d3f7139e54933ec1e66fc5aabf1ef9d`
- 投递工具：`deliver-d655e16` — sha256 `42ff1a03d7c14b39446fd3fa64bd34dd0607c8c6e6785acdb0e55c58598a6a29`
- 认证：`stub-allow`；schema 从零迁移（`gate_d65`）
- 迁移集：`0001_init` + `0002_upload_token_kid` + **`0004_drop_token_epoch`**（撤回 EPOCH/KID）

## 1. 错误名矩阵（逐字记录）

| 场景 | 状态码 | 错误名 |
|---|---|---|
| 基线（secret-A） | **201** | — |
| **只换 `TOKEN_SECRET`** | **401** | **`AUTH_TOKEN_REVOKED`** |
| 同 secret 下新签发 | **201** | — |
| 换 secret+kid 后旧 token | **401** | `AUTH_TOKEN_REVOKED` |
| 换 secret+kid 后最初 token | **401** | `AUTH_TOKEN_REVOKED`（不复活） |

**关键变化**：旧版本"只换 secret 报 `AUTH_SIGNATURE_INVALID`"的缺陷**已修**——
现在同一场景返回凭据类 **`AUTH_TOKEN_REVOKED`**，`AUTH_SIGNATURE_INVALID`
只留给签名本身不被接受（Core 的 `TestSM2RejectsForgery` 断言这条）。

> 说明一处看起来异常但正确的 204：② 与 ③ 用的是**同一把 secret**（只有 kid 变），
> 所以 ② 签发的 token 在 ③ 并未被吊销，再次上传 prelude 得到 **204（幂等成功）**。
> 真正被吊销的是 ① 的 token，它在 ③/④ 两次复打都是 **401 REVOKED**。

## 2. 升级路径：双向都过（本项已常规化）

`check_upgrade_path.py` 现在支持 `--column-expect present|absent|any`，
因为 `0004` 是**删列**迁移，方向必须可表达：

| 路径 | 期望 | 结果 |
|---|---|---|
| 老 `08d40e7`（无 kid 列）→ `5605907` | 列应**补上** | **10/10 PASS**（历史行补 `pre-kid`） |
| 老 `5605907`（有 kid 列）→ `d655e16` | 列应**被删除** | **9/9 PASS**（历史行保留、服务起、healthz 200、连跑两次幂等） |

两条都验了"历史行还在、服务能起、迁移幂等"——删列迁移最容易把老数据搞坏，这条覆盖到了。

## 3. 复跑

```sh
# 错误名矩阵
python3 qa/evidence/check_token_lifecycle.py --binary <bin> --dsn "<DSN>&search_path=<新 schema>" --ys-tool <ys-tool>
# 升级路径（列会被补上）
python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"
# 升级路径（列会被删除）
python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>" --column-expect absent
```
