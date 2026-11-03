# 交付状态（对 `d655e16`）：三条件 2/3 满足，token 名字待改名

- 日期：2026-11-02
- 对象：`feat/server-skeleton@**d655e16**`，自编 `yanshu-server-d655e16`
  （sha256 `4c331e1f6e58fd07248a8b3633eae8684d3f7139e54933ec1e66fc5aabf1ef9d`）
- 门槛定义见 `qa/evidence/DELIVERY-GATE.md`

## 1. 三条硬门槛

| # | 条件 | 结果 | 证据 |
|---|---|---|---|
| 1 | 内嵌内核 sha == `c1b87d0a…7259f`（127,313 B）+ 版本/导出 + 向量套件 | **PASS** | `server/kernel/yanshu_sm.wasm` 正是该字节；`ys_version()=0x00010000`、34 函数+memory；user-code 5 / normalize 20 / sm2 14 全过 |
| 2 | 迁移对已有库幂等（含 ALTER） | **PASS** | `5605907 → d655e16`（`0004` 删列）9/9；`08d40e7 → 5605907`（补列）10/10；历史行保留、服务起、`/healthz` 200、连跑两次幂等 |
| 3 | 冻结向量套件 + 证据二矩阵 | **PASS** | `check_all.sh`：一致性 26/26、prelude 6/6、证据二 6/6 + 11/11、自测 11/11 与 14/14 |

**结论：三条件均满足，产物可作为宿主候选**（前提是宿主库已跑过 `-migrate-only`）。

## 2. 唯一不满足项：token 轮换的错误名字面

| 场景 | 期望（spencer 裁定） | `d655e16` 实测 | 判定 |
|---|---|---|---|
| 轮换密钥 → 旧 token | `AUTH_TOKEN_STALE` | **`AUTH_TOKEN_REVOKED`** | **FAIL（待 Core 改名）** |
| 凭据值不匹配 | `AUTH_TOKEN_INVALID` | `AUTH_TOKEN_INVALID` | PASS |
| 签名本身 | `AUTH_SIGNATURE_INVALID` | 未在矩阵触发（Core 单测覆盖） | — |

原始响应体（逐字）：

```json
{"error":{"code":"AUTH_TOKEN_REVOKED","message":"upload token was revoked by a key rotation; create a new transfer","request_id":"req_e1f9adc52ad7d8b0"}}
```

这是**唯一**的阻塞点：功能（轮换即吊销、新 token 可用、旧 token 不复活）全部成立，
只是字面为临时的 `REVOKED`。Core 改名后我用 `check_token_lifecycle.py` 与
`server/scripts/token-rotation-check.sh` 各复跑一次即可转为 PASS。

## 3. 复跑

```sh
# 条件 1
python3 qa/evidence/check_server_kernel.py --server-dir <源码根> --vectors-dir <向量目录>
# 条件 2（删列迁移加 --column-expect absent）
python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"
# 条件 3
YS_SERVER_DIR=<源码根> qa/evidence/check_all.sh <rune-crate> <工作目录>
# 名字
python3 qa/evidence/check_token_lifecycle.py --binary <bin> --dsn "<DSN>&search_path=<新 schema>" --ys-tool <ys-tool>
```
