# 收口证据（单文件）：`5a42bb43…` / head `06c9f56`

- 日期：2026-11-02
- **命名说明**：本产物**由 Gate 在沙盒内构建、构建环境已验证、两个二进制 sha256 已核**。
  结果与 Core 报的 `5a42bb43…` 逐字节一致，因此不存在"只有缩写"的问题。
- 服务端 head：`feat/server-skeleton@**06c9f56**`（P0：`uploader_ip` 为 NULL 时读传输 500）

## 一、产物三件套

| 文件 | 路径 | 完整 sha256（64 字符） |
|---|---|---|
| `yanshu-server` | `/.octop/workspaces/0JXF1M/tmp/bin06c/yanshu-server` | `5a42bb43d481926f9238e5016335354e4721224c2b7b8e34d7a24ec0d9426eb0` |
| `deliver` | `/.octop/workspaces/0JXF1M/tmp/bin06c/deliver` | `31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0` |
| `yanshu_sm.wasm` | 内核（仓库内 `server/kernel/`） | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B） |

编译命令原文：

```sh
cd server
go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server
go build -trimpath -buildvcs=false -ldflags "-s -w" -o deliver ./cmd/deliver
```

- **Go 版本**：`go1.27.0 linux/amd64`
- **构建环境**：Gate 的 YS-QA 沙盒（独立 target / 独立临时目录，未继承共享 `CARGO_TARGET_DIR`），
  源码来自 `git archive 06c9f56`，**产物 sha256 与 Core 报的一致**即为交叉验证通过。

## 二、三条件逐条结论

### ① 内核 sha 三重核对 —— **PASS**

| 核对点 | 结果 |
|---|---|
| 工作区 `server/kernel/yanshu_sm.wasm` | `c1b87d0ad9a847fa…7259f` / **127,313 B** |
| `git cat-file blob 06c9f56:server/kernel/yanshu_sm.wasm` | **同一 sha**；且被 git 跟踪（`ls-tree` 命中） |
| 启动日志 | `level=INFO msg="sm2 verifier loaded" kernel=./kernel/yanshu_sm.wasm version=0x00010000` |
| 导出/版本 | `ys_version()=0x00010000`、**34 函数 + memory**、0 import |

### ② 老库升级路径（含连跑两次）—— **PASS 10/10**

旧库（`08d40e7` 线，无 `upload_token_kid`）→ `-migrate-only`：`0002` 补列 + 回填、`0004` 状态表、
`0005` 幂等恢复 → 列存在、历史行 `upload_token_kid=pre-kid` → 服务起 + `/healthz` **200**、
无 `sweep failed` → **连跑两次迁移 `rows 1→1`、exit 0**。

### ③ 冻结向量套件 —— **PASS**

| 套件 | 结果 |
|---|---|
| sm2 验签 | **14 条可执行全过**（15 条中 1 条 `executable:false`：`different_user_id`，ABI 无 userID 入参，库层断言覆盖） |
| user-code | 5 组（含契约 `PB_S = AWQW`） |
| normalize | 20 组 |
| 证据二（生产路径） | 单块 **6/6**、多块 **11/11**，未报错 0，基线逐字节一致 |
| 其它常规项 | 用户码四形态 26/26、prelude-only 6/6 |

### ②b 回滚后向前修复（跑过「删 epoch」的库）—— **PASS 11/11**

模拟线上库曾跑过 `0004_drop_token_epoch.sql`（**列与状态表被删**、记账也抹掉）后升级到本版本：

| 断言 | 结果 |
|---|---|
| 损坏状态：`upload_token_kid` 列已删 | PASS（count=0） |
| 新版 `-migrate-only` | PASS（`migrations applied`） |
| **列恢复** | PASS（count=1） |
| **`token_kid_state` 恢复** | PASS（count=1） |
| 历史行回填 `pre-kid` | PASS |
| 再跑一次幂等 | PASS（`rows 1→1`） |
| 服务起 + `/healthz` 200 | PASS |
| **旧凭据 → 401 `AUTH_TOKEN_STALE`**（非 500、非 INVALID） | PASS |
| 启动日志无 `does not exist` / `sweep failed` | PASS |

**更强的一条（真实迁移路径，非手工模拟）**：用**含 `0004_drop_token_epoch.sql` 的 `d655e16` 二进制**建库
（它真的把列与状态表删掉）→ 插历史行 → 换本版本 `-migrate-only` → **12/12 PASS**：
列恢复、状态表恢复、历史行 `pre-kid`、连跑两次 `rows 1→1`、服务起 + `/healthz` 200、
**旧凭据 401 `AUTH_TOKEN_STALE`**（恢复没有复活旧凭据）。

复跑（两种力度都有脚本）：

```sh
# 手工模拟损坏（快）
python3 qa/evidence/check_restore_after_drop.py --binary <bin> --dsn "<DSN>"
# 真实迁移路径（旧版含 drop → 新版恢复）
python3 qa/evidence/check_restore_from_real_drop.py \
  --old-binary <d655e16 编的> --new-binary <新版> --dsn "<DSN>"
```

### ②c 两条 Go 回归 + P0（`uploader_ip` 为 NULL）

在 `06c9f56` 树上跑（该 head 相对 `d8d90a2` 只多这一处 P0 修复）：

```
--- PASS: TestMigrateUpgradeFromOldSchema      # 老库升级
--- PASS: TestMigrateRestoresAfterDrop         # 跑过 drop 迁移的库恢复
--- PASS: TestGetTransferWithNullUploaderIP    # P0：uploader_ip 为 NULL 不再 500
--- PASS: TestStaleTokenCannotBeReincarnated   # 旧凭据不复活
```

## 三、KID 矩阵（逐字错误名与 message）

| 步 | 场景 | 状态 | 错误名 / message |
|---|---|---|---|
| ① | 基线（EPOCH=1, secret=…0001） | **200** | — |
| ② | **只换 `TOKEN_SECRET`**（EPOCH 不变） | **200**（prelude 复传时 204，幂等） | — |
| ③ | **EPOCH+1**（`UPDATE token_kid_state SET kid=kid+1`，**不重启**） | **401** | **`AUTH_TOKEN_STALE`**，message `upload token is stale: its key version is no longer accepted` |
| ④ | EPOCH+1 后新签发 | **200** | — |
| ④b | 最初 token 复打 | **401** `AUTH_TOKEN_STALE` | **不复活** |
| 附 | 未配置 `YANSHU_TOKEN_EPOCH`（全新库） | **可启动**，`/v1/config` 返回 `"token_epoch":1` | — |
| 附 | 已记录 3、配 2（调小） | **exit 1** | `config: YANSHU_TOKEN_EPOCH must increase (current=3, provided=2); refusing to start` |
| 附 | 配 0 | **exit 1** | `config: YANSHU_TOKEN_EPOCH must be a positive decimal integer (got "0")` |

`/v1/config.token_epoch` 实测 **1 → 2**，随库内 KID 变化（服务不缓存旧值）。

## 四、四码覆盖（每码一条实测，互不顶替）

| 码 | 构造手法 | 实测 |
|---|---|---|
| `AUTH_TOKEN_STALE` | `UPDATE token_kid_state SET kid=kid+1`（不重启） | **401 `AUTH_TOKEN_STALE`** |
| `AUTH_TOKEN_INVALID` | 三种畸形 token：随机串 `Zx9-not-a-token` / 截断 / 非 base64url `@@@###$$$` | 三种均 **401 `AUTH_TOKEN_INVALID`** |
| `AUTH_TOKEN_EXPIRED` | 把传输 `created_at`/`updated_at` 推到 **7 小时前**（模拟超过 6 h 窗口，**非真等**） | **401 `AUTH_TOKEN_EXPIRED`**，message `token has expired; obtain a new one` |
| `AUTH_SIGNATURE_INVALID` | `YANSHU_VERIFIER=sm2` 下伪造 DER（`MEUCIQDdeadbeef`）与非 DER 文本注册 | 两种均 **401 `AUTH_SIGNATURE_INVALID`** |

未覆盖项（不充数）：**下载租约 30 分钟到期**未单独构造（同属 `EXPIRED` 分支，机制相同）。

## 四b、候选淘汰记录：`d8d90a2` **不可交付**

我按要求在 `d8d90a2` 上重跑了同一套检查，结果 **4 PASS / 1 FAIL**，失败项是决定性的：

| 项 | `d8d90a2` | `06c9f56`（本文件绑定的） |
|---|---|---|
| 内核三重核对 | PASS | PASS |
| 老库升级（`08d40e7`） | PASS 10/10 | PASS 10/10 |
| **跑过 `0004` drop 的库 → 恢复** | **FAIL**：`旧凭据 → 500 INTERNAL`（期望 401 `STALE`） | **PASS 12/12** |
| KID 五步 + 四码 | PASS（`STALE`/200/不复活/`token_epoch` 1→2） | PASS |
| 契约↔实现字面 | PASS（13 码一致，`REVOKED` 0） | PASS |

**根因**：`d8d90a2` 缺 `uploader_ip IS NULL` 的 P0 修复——恢复出来的历史行 `uploader_ip` 为 NULL，
读该传输直接 500。`06c9f56` 正是修这一处的提交（`TestGetTransferWithNullUploaderIP`）。

另外 `d8d90a2` 的迁移集里**同时存在** `0004_drop_token_epoch.sql` 与 `0004_token_kid_state.sql`：
每次迁移会先删列/删状态表再补回（`token_kid_state` 里已升的 `kid` 值会丢）。`06c9f56` 已删掉 drop 脚本，
只剩 `0001/0002/0004_token_kid_state/0005_restore`。

→ **结论：淘汰 `d8d90a2`，交付绑定 `06c9f56`（`5a42bb43…`）。**

## 四c、在线吊销：递增 EPOCH **不需要重启**（同一进程内实测）

脚本 `qa/evidence/check_epoch_online_revoke.py`（全程只起**一个**进程，中途改库、不重启）：

| 步 | 结果 |
|---|---|
| 起一次服务（`EPOCH=1`），签发凭据 → 打 status | **200** |
| **服务不停**，`UPDATE token_kid_state SET kid = kid + 1` | `UPDATE 1` |
| 同一进程、同一凭据再打 | **401 `AUTH_TOKEN_STALE`** |
| 同一进程读 `/v1/config.token_epoch` | **1 → 2** |
| 进程存活且 **PID 未变** | PASS（pid 未变） |

**结论：递增 EPOCH 立即生效、无需重启**——与"KID 是唯一吊销开关"的设计一致。
（只换 `TOKEN_SECRET` 的那条在「三、KID 矩阵」里已实测为 **200（不吊销）**。）

### ②d `SIG_INPUT` 上限口径（8 组实测，字段级优先）

| PURPOSE | 字段串上限 | `SIG_INPUT` 总长（= 40 + 字段串） |
|---|---:|---:|
| `0x01 REGISTER` | 69 | **109** |
| `0x02 NICKNAME_UPDATE` | 38 | 78 |
| `0x03 TRANSFER_CREATE` | 60 | 100 |
| `0x04 TRANSFER_REVOKE` | 36 | 76 |
| `0x05 INBOX_LIST` | 4 | 44 |
| `0x06 WS_HELLO` | 4 | 44 |
| `0x07 TRANSFER_ACK` | 36 | 76 |
| `0x08 UPLOAD_TOKEN_ISSUE` | 36 | 76 |

实测结论（`check_siginput_limits.py`，**4/4 通过**）：

| 用例 | 结果 |
|---|---|
| 长度表推导出的合法上限 == 109 | **PASS** |
| `REGISTER` 恰好 109 字节 | **PASS**（走到验签：401 `AUTH_SIGNATURE_INVALID`） |
| `REGISTER` 110 字节（PUBKEY 66） | **PASS**：字段级错误 400 `BAD_REQUEST`（非 TOO_LONG） |
| 昵称 33 字节 | **PASS**：400 `NICKNAME_INVALID`（字段级） |
| 513 字节（昵称 467） | **N/A（不可观测）**：返回 400 `NICKNAME_INVALID`——字段级校验先行，512 门在 HTTP 层不可达；契约将注明"防御性上限、当前不可达，若触发回 `BAD_REQUEST`" |

**结论：字段级优先、不用字节上限代替字段校验——实现正确**；缺的只是一个永远触发不了的专属码。
**基线用途**：以后有人改字段上限，直接用上表比对是否越界（109 是硬上限）。

## 五、结论

**建议 spencer 用这份产物重启**（`5a42bbdf…` 见上表；`deliver` 与内核同表），
重启后需复核三项：

1. `curl -fsS http://127.0.0.1:18080/healthz` → **200** `{"status":"ok",...}`；
2. 启动日志出现 **`sm2 verifier loaded kernel=./kernel/yanshu_sm.wasm version=0x00010000`**；
3. `curl -s http://127.0.0.1:18080/v1/config` 里 **`token_epoch`** 存在且等于 `YANSHU_TOKEN_EPOCH`。

启动 env（凭据占位）：

```sh
YANSHU_DATABASE_URL="<DSN，含 search_path>"
YANSHU_TOKEN_SECRET="<≥16B>"
YANSHU_TOKEN_EPOCH=1
YANSHU_VERIFIER=sm2
YANSHU_KERNEL_WASM=./kernel/yanshu_sm.wasm
YANSHU_BLOB_DIR=/var/lib/yanshu/blobs
YANSHU_LOG_DIR=/var/log/yanshu
YANSHU_ADDR=127.0.0.1:18080
```
