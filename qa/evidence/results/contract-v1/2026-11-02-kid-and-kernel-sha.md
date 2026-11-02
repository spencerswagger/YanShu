# `kid` 令牌轮换 + 服务端内嵌内核 sha256 校验（`739293a`）

- 日期：2026-11-02
- 服务端：`feat/server-skeleton@**739293a**`，二进制 `yanshu-server-739293a`，
  sha256 `a9f3933ee8773f1cc5499dc063e0c3d14784d0e9cdb9a22621db760a3406fc44`
- 内核冻结产物：`c1b87d0a…7259f`（127,313B，head `031e95b`）
- 结论：**kid 轮换三态成立**；**服务端内嵌内核 sha 不一致 → FAIL**（见 §2）

## 1. token（kid）对照组：逐组只改一个变量

| 组 | 变量 | 旧 token 实测 | 错误名 |
|---|---|---|---|
| 基线 | secret=A、kid=k1 | **201** | — |
| **只换 kid** | kid k1→k2（secret 不变） | **401** | **`AUTH_TOKEN_REVOKED`** |
| **只换 secret** | secret A→B（kid 不变） | **401** | **`AUTH_SIGNATURE_INVALID`** |
| 轮换后重签发 | 新传输 + 新 token | **201** | — |

两种单变量都能吊销，但错误名不同：kid 落在凭据类 `AUTH_TOKEN_REVOKED`，
secret 变化落在 `AUTH_SIGNATURE_INVALID`。**后者是签名类错误名**，前端会误以为是签名问题；
建议 Core 把"secret 变了导致 token 不再匹配"也归到凭据类（`AUTH_TOKEN_INVALID`）。

复跑：

```sh
python3 qa/evidence/check_token_lifecycle.py --binary <yanshu-server> \
  --dsn "<DSN>&search_path=<schema>" --ys-tool <ys-tool> --kid k1
```

> `739293a` 起 `YANSHU_TOKEN_KID` 是**必配项**，不设服务端直接退出（fail closed）；
> 脚本已支持 `--kid`，并把 kid 变化写进输出。

### 1a. 决定性实验（Core 新产物，逐步记状态码与错误名）

用 Core 指的两个提交各自现编二进制（沙盒里没有他的 tarball，等价：同 commit、同 buildflags）：

| 步骤 | `ab4279a`（无 kid） | `9bce5bb`（有 kid，设 `YANSHU_TOKEN_KID=k1`） |
|---|---|---|
| ① 签发 token → `PUT /prelude` | **201** | **201** |
| ② 只改 `TOKEN_SECRET` 重启 → 同一 token | **401 `AUTH_SIGNATURE_INVALID`** | **401**（secret+kid 同改时 `AUTH_TOKEN_STALE`） |
| ③ 新 secret 下新建传输 → 新 token | **201** | **201** |
| ④ 恢复方式 | 重建传输即恢复（无重签发端点） | 同左；重签发端点未在 ABI/接口表出现 |

**结论：`ab4279a` 起「只换 `TOKEN_SECRET`」就构成一次性吊销**（201 → 401 → 新 token 201）。
我之前那次 **201** 用的是 `9065eb8`（及其产物 `980fc44`）——那版 `Validate` 只比库里 `SM3(token)`，
不重算，所以换 secret 不影响。两边不矛盾，是版本差异。

### 1a-2. 与裁定预期的对照（重要）

裁定预期：**只改 `TOKEN_SECRET`、版本不变 → 旧 token 必须仍有效（201）是正确行为**；
递增版本才吊销。按这个预期核对实现：

| 组 | 裁定预期 | 实测（`ab4279a` / `9bce5bb`） | 判定 |
|---|---|---|---|
| 只改 `TOKEN_SECRET`（版本不变） | **201 仍有效** | **401 `AUTH_SIGNATURE_INVALID`** / `AUTH_TOKEN_STALE` | **与预期不符**：当前实现把 secret 也当吊销开关 |
| 递增版本（EPOCH） | 401 `AUTH_TOKEN_STALE` | **EPOCH 不存在**；`kid`（`9bce5bb`）递增 → 401 `AUTH_TOKEN_STALE` | EPOCH 组 **BLOCKED**；kid 语义相近但不同名 |
| 版本递增后重签发（`POST /transfers/{id}/token`，PURPOSE 0x08） | 新 token 可用、旧 token 不复活 | **接口表里没有该端点** | **BLOCKED** |

**结论**：按裁定，"只改 secret 仍 201"才是预期；当前实现（`ab4279a` 起）会 401，
属**实现与裁定偏离**，不是我的测量问题。EPOCH 两组在现有二进制上不可执行。

### 1b. 「只改 secret 是否吊销」的历史（回答两边为什么各说各话）

| 服务端 commit | 只改 `TOKEN_SECRET` 后同 token | 原因 |
|---|---|---|
| `9065eb8` | **201（仍可用）** | `Validate` 只比库里 `SM3(token)`，与 secret 无关 |
| `08d40e7` | **401 `AUTH_SIGNATURE_INVALID`** | 改成"用当前 secret 重算 + 比对" |
| `739293a` | **401 `AUTH_SIGNATURE_INVALID`**（只改 secret）；**401 `AUTH_TOKEN_REVOKED`**（只改 kid） | 再加 kid 元数据，先比 kid 再比 token |
| `9bce5bb` | 只改 secret+kid → **401 `AUTH_TOKEN_STALE`** | 错误名收敛到 STALE |

**定案：在 `08d40e7` 及之后，"只改 secret"就会吊销；`9065eb8` 那次 201 是版本差异，不是矛盾。**
错误名分工建议：kid 变化→凭据类（现在 `AUTH_TOKEN_REVOKED`，对）；secret 变化→应改
`AUTH_TOKEN_INVALID`（现在仍报签名类 `AUTH_SIGNATURE_INVALID`）；伪造签名→保留
`AUTH_SIGNATURE_INVALID`。

## 2. 服务端内嵌内核 sha256：**FAIL（当前不一致）**

| 项 | 值 |
|---|---|
| Core 工作树 `server/kernel/yanshu_sm.wasm`（2026-11-02 17:49 复核，仍是这份） | **130,653 B / `8b89dd7f…154f9`** |
| 验收冻结产物 | **127,313 B / `c1b87d0a…7259f`** |
| `ys_version()` | 两者都是 `0x00010000` |
| 导出 | 两者都是 34 函数 + `memory` |

**结论：sha 不一致、但版本与导出数一致** —— 正是"同源不等于同字节"的活例子。
服务端若加载 `8b89dd7f…`，它验的就不是验收过的那份产物；这条必须换成 `c1b87d0a…` 才算数。

检查脚本：`python3 qa/evidence/check_server_kernel.py --server-dir <源码根> --vectors-dir <向量目录>`

判据（按裁定）不是"单一 sha"：

1. **sha256 在白名单内**：`c1b87d0a…`（127,313B，Rune/Web/Gate 环境）或
   `8b89dd7f…`（130,653B，Core 环境）——两者同源；
2. `ys_version()==0x00010000`、34 函数 + memory；
3. **该产物本身通过冻结向量套件**：user-code 5 组、normalize 20 组、sm2 验签 14 条
   （`different_user_id` 因 ABI 无 userID 入参而**不可执行**，显式跳过并打印）。

实测：Core 已把内嵌内核换成 `c1b87d0a…`，三条全 PASS。

## 3. 升级路径的一个真问题：老库缺 `upload_token_kid` 列

`739293a` 的内核变更里，`transfers` 新增了 `upload_token_kid`；但迁移只有
`0001_init.sql`（`CREATE TABLE IF NOT EXISTS`），**没有 ALTER**。
于是**已经跑过 0001 的库里不会再补这一列**：

```
level=WARN msg="sweep failed" err="store: list terminal:
  ERROR: column \"upload_token_kid\" does not exist (SQLSTATE 42703)"
```

判定：新建 schema（从零迁移）正常；**已有 schema 升级会缺列**。
宿主实例是已有库，直接换二进制大概率复现——要么加一条 `ALTER TABLE ... ADD COLUMN` 迁移，
要么明确重建 schema（后者会丢数据）。这条建议单列进 `docs/pending-tasks.md`。

## 4. 边界

- 本轮用 `stub-allow`（token 实验与验签无关）；真 `sm2` 的整链证据在 run #5 那份。
- 内嵌内核检查需要工作树里的 `.wasm`（该文件不在 git：根 `.gitignore` 有 `*.wasm`），
  所以只能在工作树上核对；拿不到即 BLOCKED，不当作通过。
