# 产物交付门槛（三条，缺一即"不可交付"）

> 任何要交给 spencer 替换宿主 `980fc44` 的服务端产物，必须**同时**满足下面三条。
> 判定由脚本产出，不接受口头声明；不满足时在结果文件里明写**缺哪条**，宿主继续跑旧产物。

## 条件 1：内嵌内核 == 验收冻结产物

- `server/kernel/yanshu_sm.wasm` 的 sha256 **必须**是
  `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B）；
- 二级校验：`ys_version() == 0x00010000`、34 个函数 + `memory`、0 import；
- 检查：`python3 qa/evidence/check_server_kernel.py --server-dir <源码根> --vectors-dir <向量目录>`
  （白名单含 Rune/Web 环境的 127,313 B 与 Core 环境的 130,653 B，但**必须同时过向量套件**才算同源）。

## 条件 2：迁移对**已有库**幂等（含 ALTER）

- 只测"全新建库"不算；
- 检查：`python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"`
  ——旧 schema 建库 → 插历史 `transfers` 行 → 新二进制 `-migrate-only` → 断言列存在/历史行完好 →
  起服务 `/healthz` 200 且无 `sweep failed` → **连跑第二次迁移幂等**；
- 删列迁移（例如 `0004_drop_token_epoch.sql`）用 `--column-expect absent`。

## 条件 3：冻结向量套件全过

- sm2 验签 15 条（`different_user_id` 因 ABI 无 userID 入参**不可执行**，显式跳过）、
  user-code 5 组、normalize 20 组、证据二矩阵（单块 6/6 + 多块 11/11）；
- 检查：`YS_SERVER_DIR=<源码根> qa/evidence/check_all.sh <rune-crate> <wd>`。

## 附：token 错误名期望（单独判定，不属三条门槛）

| 场景 | 期望字面（spencer 裁定） |
|---|---|
| 版本/密钥轮换 → 旧 token | **`AUTH_TOKEN_STALE`** |
| 凭据值不匹配/格式错/不存在 | `AUTH_TOKEN_INVALID` |
| 签名本身不被接受 | `AUTH_SIGNATURE_INVALID` |

实现若仍返回 `AUTH_TOKEN_REVOKED` → **记 FAIL 并注明"待 Core 改名"**，不迁就实现。
`AUTH_TOKEN_REVOKED` 只在"显式吊销"语义下才允许，当前不存在，验收里不引用。
`AUTH_TOKEN_EXPIRED` 属登记项（K2），本期不实现，**不算缺口**。
