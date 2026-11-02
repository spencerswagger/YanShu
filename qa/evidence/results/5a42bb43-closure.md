# 收口证据（单文件）：`5a42bb43…` / head `06c9f56`

- 日期：2026-11-02
- **命名说明**：本产物**由 Gate 在沙盒内构建、构建环境已验证、两个二进制 sha256 已核**。
  结果与 Core 报的 `5a42bb43…` 逐字节一致，因此不存在"只有缩写"的问题。
- 服务端 head：`feat/server-skeleton@**06c9f56**`（P0：`uploader_ip` 为 NULL 时读传输 500）

> **证据来源总说明**
> - `[宿主]` = 在 `http://127.0.0.1:18080` 真 `sm2` 实例上取得（产物 **`4eda665` / `cc117070…`**、内核 `c1b87d0a…`、`YANSHU_TOKEN_EPOCH=1`）。
> - `[本地]` = 在沙盒自建实例上取得，**非宿主实例**；对应产物 `5a42bb43…`(head `06c9f56`)、`db58ae47…`(head `8223096`)、`a302dccf…`(head `4b3babd`)。
> - **浏览器端到端未交付**（前端未响应），由 Gate 以 **API 等价代跑**（见「④b」「④c」），强度＝协议层闭环、**未覆盖前端实现**。

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


### ②e P0 回归：`uploader_ip IS NULL` 的历史传输不再 500（`06c9f56`）

构造：正常投递一笔 → `UPDATE transfers SET uploader_ip = NULL` → 用同一 token 读 `/status`。

| 场景 | 实测 |
|---|---|
| 正常行（`uploader_ip=127.0.0.1`） | **200** |
| **置 NULL 后读同一传输** | **200**（`state=LEASED`、`chunk_count=3`…）——**不是 500** |
| 单测存在 | `server/internal/store/migrate_upgrade_test.go` 里 `TestGetTransferWithNullUploaderIP`（该树上 `go test` PASS） |

这条正是 `06c9f56` 相对 `4eda665`/`d8d90a2`/`4514848` 的 P0 差异：那几个 head 在"跑过删列版的库恢复"场景里，
历史行 `uploader_ip` 为 NULL 时读传输会 **500 INTERNAL**；本版正常返回。


## ④b · API 等价端到端（**非浏览器**，Gate 用 API 直接执行）

> **性质说明**：本节**替代**未交付的浏览器端到端。强度 = **协议层闭环**（真加密包 → 上传 → 凭码取回 →
> 真解密 → 逐字节一致 → ack 后 410），**未覆盖前端实现**（UI、浏览器 WebCrypto/WASM 加载、IndexedDB 私钥等）。
> 执行人：Gate；时间：2026-11-02；实例：**宿主** `http://127.0.0.1:18080`（真 `sm2`，产物 `4eda665`）。

| 步 | 动作 | 状态码 / 结果 |
|---|---|---|
| ① | 建包（`ys_pack_v1`，wasm 真加密） | 2,507,553 B，3 块（1 MiB） |
| ② | 投递（`deliver --sender-sk --recipient-sk` 真签名） | `ok=true`、`state=LEASED`、`chunks=3`，code `7759` |
| ③ | 凭码查询 `GET /v1/codes/7759` | **200**（186 B） |
| ④ | `GET /prelude` | **200**，568 B，带 `X-Ys-Download-Id` |
| ⑤ | `GET /chunks/{0,1,2}` | **200 / 200 / 200**，1,048,592 / 1,048,592 / 409,753 B |
| ⑥ | 服务端字节 vs 本地密文 | **prelude 一致 = True，三块一致 = True** |
| ⑦ | `ys_unpack_v1` 真解密（用服务端取回的字节重建包） | 落盘 **2,506,889 B** |
| ⑧ | 两端 sha256 | 落盘 `5ccada48061ab5e4f97507f87691d80030340cac5bcdb0270c2b3d7c291db6d7` = 源文件 —— **逐字节一致** |
| ⑨ | `ack` | `acked=true`、`state=CONSUMED` |
| ⑩ | ack 后再取 prelude / chunks/0 | **410 `TRANSFER_CONSUMED`**（原文如下） |

```json
{"error":{"code":"TRANSFER_CONSUMED","message":"transfer has been consumed","request_id":"…"}}
```

**复跑**：`qa/evidence/adapters/wasm_pack_probe.mjs`（pack/unpack）+ `server/bin/deliver`（`--sender-sk/--recipient-sk`），
取回与比对脚本见本节步骤 ③–⑧（等价于 `results/web/c1b87d0a-closure-web.md` 的 API 版本）。

## ④c · 宿主实例实测（`18080` / `4eda665` / 真 `sm2`）—— 由 Gate 代跑

> 标注：**宿主 `http://127.0.0.1:18080`，产物 `4eda665`（`cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9`），
> 内核 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`，`YANSHU_VERIFIER=sm2`，`YANSHU_TOKEN_EPOCH=1`。**
> 执行人：Gate（**代跑**，浏览器端到端未交付）。

| 步 | 动作 | 结果 |
|---|---|---|
| ① | 注册 + 挑战验签（真 SM2） | 成功（`deliver --sender-sk/--recipient-sk`，`ok=true`） |
| ② | 建包（`ys_pack_v1` 真加密） | 2,507,553 B，3 块（1 MiB） |
| ③ | 分块上传 + `complete` | `state=LEASED`、`chunks=3` |
| ④ | 凭码查询 `GET /v1/codes/7759` | **200**（186 B） |
| ⑤ | `GET /prelude` | **200**（568 B，带 `X-Ys-Download-Id`） |
| ⑥ | `GET /chunks/{0,1,2}` | **200 / 200 / 200**（1,048,592 / 1,048,592 / 409,753 B） |
| ⑦ | 服务端字节 vs 本地密文 | **prelude 一致 = True、三块一致 = True** |
| ⑧ | `ys_unpack_v1` 真解密（用服务端取回字节重建包） | 落盘 **2,506,889 B** |
| ⑨ | 两端 sha256 | 落盘 `5ccada48061ab5e4f97507f87691d80030340cac5bcdb0270c2b3d7c291db6d7` = 源文件 → **逐字节一致** |
| ⑩ | `ack` | `acked=true`、`state=CONSUMED` |
| ⑪ | ack 后再取 prelude / chunks/0 | **410 `TRANSFER_CONSUMED`** |

```json
{"error":{"code":"TRANSFER_CONSUMED","message":"transfer has been consumed","request_id":"…"}}
```

（宿主上另有一次 2,506,889 B 与一次 12,000 B 投递同样通过，`ack` 后均 410。）

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

实测（`check_siginput_limits.py`，**4/4 通过，第 5 条 N/A**）：

| 用例 | 结果 |
|---|---|
| 长度表推导上限 == 109 | **PASS** |
| `REGISTER` 恰好 109 字节 | **PASS**（走到验签：401 `AUTH_SIGNATURE_INVALID`） |
| `REGISTER` 110 字节 | **PASS**：400 `BAD_REQUEST`（字段级，非 TOO_LONG） |
| 昵称 33 字节 | **PASS**：400 `NICKNAME_INVALID`（字段级） |
| 513 字节（昵称 467） | **N/A（不可观测）**：400 `NICKNAME_INVALID`，字段级优先、512 门 HTTP 不可达 |

**结论：字段级优先、不以字节上限代替字段校验——实现正确**；专属码 `SIG_INPUT_TOO_LONG` 不可达。
**基线用途**：以后改字段上限时用上表比对是否越过 109。

## 五、结论与已知偏差

**① 协议层闭环**：由 `[本地]` 三份产物（`5a42bb43` / `db58ae47` / `a302dccf`，**均非宿主实例**）与 `[宿主]` 实测共同支撑——
加密→上传→凭码取回→真解密→逐字节一致→`ack` 后 410 全部成立（宿主两端 sha256 `5ccada48…1db6d7`；
本地 `06c9f56` 上为 `0fd76c0f…2ead12`）。
**② 浏览器端到端未交付**：前端未响应，由 Gate **以 API 等价代跑**（见「④b」「④c」），**未覆盖前端实现**
（UI、浏览器内 WASM 加载、IndexedDB 私钥、跨端 UI 流程）。

已知偏差（如实，不美化）：

1. **宿主产物是 `4eda665`**：其"只换 `TOKEN_SECRET` → 401 `AUTH_TOKEN_INVALID`"与契约（secret 不吊销）**不一致**；
   且无 `AUTH_TOKEN_EXPIRED`（超期走 410 `TRANSFER_EXPIRED`）。换 `06c9f56` 后两条消失。
2. **`SIG_INPUT_TOO_LONG`（513 B）HTTP 不可达**：昵称 ≤32 先被字段级拒（`400 NICKNAME_INVALID`），码本身库层已实现 + 单测覆盖。
3. **`[本地]` 结论不代表宿主**：token 五步、删列库恢复 12/12、P0 回归均在沙盒实例完成；宿主只做了只读与投递类实测。
4. **旧 head 不可交付**：`97d156c`、`b516cc6` 内核为空 blob（0 B）；`fa479d9` 缺 `0002` 迁移。
5. **跨版本 token 不兼容**：`4eda665`（`u64be`+`v2`）与 `06c9f56`（`u32be`+`v1`）不同；换产物失效在传 token（数据无损）。
