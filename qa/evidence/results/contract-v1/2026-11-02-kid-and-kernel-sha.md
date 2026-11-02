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

## 2. 服务端内嵌内核 sha256：**FAIL（当前不一致）**

| 项 | 值 |
|---|---|
| Core 工作树 `server/kernel/yanshu_sm.wasm` | **130,653 B / `8b89dd7f…154f9`** |
| 验收冻结产物 | **127,313 B / `c1b87d0a…7259f`** |
| `ys_version()` | 两者都是 `0x00010000` |
| 导出 | 两者都是 34 函数 + `memory` |

**结论：sha 不一致、但版本与导出数一致** —— 正是"同源不等于同字节"的活例子。
服务端若加载 `8b89dd7f…`，它验的就不是验收过的那份产物；这条必须换成 `c1b87d0a…` 才算数。

检查脚本：`python3 qa/evidence/check_server_kernel.py --server-dir <源码根>`
（sha 不等即 FAIL 并打印两侧字节数/ sha；版本或导出数不对也 FAIL；文件缺失为 BLOCKED）。
把冻结产物放进去后实测 PASS。

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
