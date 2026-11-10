# 产物交付门槛（三条，缺一即"不可交付"）

> 任何要交给 spencer 替换宿主 `980fc44` 的服务端产物，必须**同时**满足下面三条。
> 判定由脚本产出，不接受口头声明；不满足时在结果文件里明写**缺哪条**，宿主继续跑旧产物。

## 条件 1：内嵌内核 == 验收冻结产物

- **机器判定（唯一权威）**：`server/kernel/yanshu_sm.wasm` 的 sha256 **必须命中**
  `server/internal/auth/verifier.go` 的 `FrozenKernelSHA256` 白名单**首条**（首条 = 当前冻结产物；
  现在 = `daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de`，**140,762 B**）。
  白名单是运行期真正拦人的那一份 —— 不在里面服务端起不来，所以它才是门槛。
- 二级校验：字节数 = `check_server_kernel.py` 的 `FROZEN_BYTES`（**140762**）、导出 =
  `FROZEN_FUNCS`（**43**）个函数 + `memory`（合计 44 导出）、0 import、`ys_version() == 0x00010000`。
- **白名单里另两条不是本轮的交付期望值**：`8766048f…`（140,742 B，回滚目标）与 `c1b87d0a…`
  （127,313 B，灰度期旧镜像）只是"服务端允许加载"的历史产物；交付验收只认首条。
  （`c1b87d0a…` / 127,313 B / 34 函数是 **v0.1.1** 的冻结值，不是当前门槛 —— 拿它验收会把
  正确的当前内核判成"不可交付"。）
- 检查：`python3 qa/evidence/check_server_kernel.py --server-dir <源码根> --repo <仓库根>
  --vectors-dir <向量目录>`；期望 sha 由脚本从 `verifier.go` 首条**推导**，不在脚本里另写一份。
- 人读的冻结记录在 `docs/CRYPTO-PACK.md` §18.2。**两者不一致时先修文档**（不要拿过期文档当门槛，
  也不要把 `verifier.go` 改成迁就文档）。

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

| 场景 | 期望字面（现行裁定） |
|---|---|
| **只改 `TOKEN_SECRET`**（KID 不变） | **`AUTH_TOKEN_INVALID`**（派生密钥变了 → 凭据值不匹配，**这是正确行为**） |
| **递增 `KID`**（或 secret+KID 同改） | **`AUTH_TOKEN_STALE`**（签发版本已过期，优先于 INVALID） |
| 格式错/不存在 | `AUTH_TOKEN_INVALID` |
| 签名本身不被接受 | `AUTH_SIGNATURE_INVALID` |

**终值 `STALE`**；`AUTH_TOKEN_REVOKED` 当前不出现（只留给将来"显式吊销列表"语义）；
`AUTH_TOKEN_EXPIRED` 本期不实现（K2 登记），不算缺口。

实现若仍返回 `AUTH_TOKEN_REVOKED` → **记 FAIL 并注明"待 Core 改名"**，不迁就实现。
`AUTH_TOKEN_REVOKED` 只在"显式吊销"语义下才允许，当前不存在，验收里不引用。
`AUTH_TOKEN_EXPIRED` 属登记项（K2），本期不实现，**不算缺口**。
