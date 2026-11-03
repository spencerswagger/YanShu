# 收口证据（合并版）：宿主 `4eda665` / 另附 `8223096` 本地结果

> **证据来源标注规则**（本文件逐节注明）：
> `[宿主]` = 在 `http://127.0.0.1:18080` 真 `sm2` 实例上取；`[本地]` = 在沙盒自建实例上取（同产物或指定 head）。

## ① 产物三件套

| 产物 | 路径 | 完整 sha256 | 用于 |
|---|---|---|---|
| `yanshu-server` | `/.octop/workspaces/0JXF1M/tmp/srvbin-4ed/yanshu-server` | `cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9` | **宿主当前在跑** |
| `deliver` | 同上目录 `deliver` | `16e919fbc678081345ac217be5628fcf0a96a5a8567f72ca2c040d462d04a990` | 宿主投递 |
| `yanshu_sm.wasm` | 仓库 `server/kernel/` | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B） | 端侧内核 |

编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`（`deliver` 同式）
Go：`go1.27.0 linux/amd64`；构建环境：Gate 沙盒 `git archive <head>` + 独立 target，产物 sha256 与 Core 报的一致（双向可复现）。

## ② 三条件（`[本地]`，产物 `4eda665`）

| # | 条件 | 结果 |
|---|---|---|
| 1 | 内核 sha 三重核对 | **PASS**：工作区 = `git cat-file blob 4eda665:` = 启动日志 `kernel=`，均 `c1b87d0a…`/127,313 B（**非空 blob**） |
| 2 | 迁移对已有库幂等 | **PASS 10/10**：老 `08d40e7` 库缺列 → 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → **连跑两次 `rows 1→1`** |
| 3 | 冻结向量套件 | **PASS**：四形态 26/26、prelude 6/6、证据二 6/6 + 11/11；sm2 14 可执行 / user-code 5 / normalize 20 |

## ③ token 五步（`[本地]`，**head `8223096` / `yanshu-server` = `db58ae4799349cb1c72eafb9cb665a26bcfcf30bf0876d70e56b39f97335d79f`，非宿主**）

| 步 | 结果 |
|---|---|
| 基线（KID=1） | **200** |
| 只换 `TOKEN_SECRET` | **200（不吊销）** |
| **KID+1（改库，不重启）** | **401 `AUTH_TOKEN_STALE`**，同进程 **PID 不变**、`token_epoch` 1→2 |
| 新签发 | **200** |
| 旧 token 复打 | **401 `AUTH_TOKEN_STALE`**（不复活） |
| 超期（`created_at` 推 7h 前） | **401 `AUTH_TOKEN_EXPIRED`**（`token has expired; obtain a new one`） |

> 同一组在宿主 `4eda665` 上的差异：`[本地]` 只换 secret → **401 `AUTH_TOKEN_INVALID`**；`created_at` 推 7h 后 `/status` **仍 200**（该版无凭据超期判定）；`expires_at` 过后 sweeper 转 `EXPIRED`，`/prelude`、`/chunks` 均 **410 `TRANSFER_EXPIRED`**。

## ④ 四形态矩阵 + 生产路径

### 四形态矩阵（`[本地]`，端侧函数级，与宿主无关）

`PB_S` 在 wasm 64 / wasm_wire 65 / 原生 64 / 原生 65 四入口全 **`AWQW`**，校验位全 `X`；另 4 组公钥逐字符相同；26/26。

### 生产路径端到端（`[宿主]`，`http://127.0.0.1:18080`，真 `sm2`，产物 `4eda665`）

| 项 | 结果 |
|---|---|
| 源文件 | 2,506,889 B，sha256 `bb17026f83d3f13fe5d6a5e4aa5c05be73efcd0604fea0b0628d6dbf9e579dc9` |
| 投递 | 3 块（1 MiB），`deliver --sender-sk --recipient-sk` 真签名，`LEASED` |
| 取回 | `GET /prelude` 200（571 B）**逐字节一致**；三块 1,048,592 / 1,048,592 / 409,753 B **与本地密文逐字节一致** |
| 解密落盘 | sha256 = `bb17026f…79dc9`，**与源文件相同** |
| `ack` 后再取 | **410 `TRANSFER_CONSUMED`**（prelude 与 chunks 均 410） |
| 复跑（同次会话第二笔 12,000 B） | `ok=true`、`CONSUMED`，`ack` 后 prelude **410 `TRANSFER_CONSUMED`** |

## ⑤ 结论与已知偏差

**可部署产物**：优先 **`06c9f56`（`5a42bb43…`）**（六项全 PASS、含 `uploader_ip NULL` P0、四码完整）；
宿主当前 `4eda665`（`cc117070…`）在真 `sm2` 下端到端可用，但缺 `EXPIRED` 且 secret 即吊销。

已知偏差（如实，不美化）：

1. **`4eda665`/`dfd3e82`：只换 `TOKEN_SECRET` → 401 `AUTH_TOKEN_INVALID`**（"secret 不吊销"只在 `06c9f56` 成立）。
2. **`4eda665`/`dfd3e82`：`AUTH_TOKEN_EXPIRED` 未实现**（grep 0）；超期走 **410 `TRANSFER_EXPIRED`**，6h/30min 凭据时效未实现。
3. **`SIG_INPUT_TOO_LONG`（513 B）HTTP 不可达**：字段级校验先拒（`NICKNAME_INVALID`），码本身库层已实现 + 单测覆盖。
4. **旧 head 空 blob 问题**：`fa479d9`、`b516cc6` 的 `server/kernel/yanshu_sm.wasm` 在 git 里是 **0 字节**（`*.wasm` 被忽略），不可交付。
5. **跨版本 token 不兼容**：`4eda665` 用 `u64be(KID)`+`v2` 前缀，`dfd3e82`/`06c9f56` 用 `u32be(KID)`+`v1`；换产物会失效在传 token（数据无损）。
6. `4eda665` 的 `ValidateHash` 注释写"不重算"但线上走 `Derives()`（重算），属**过时注释**，建议修。
