# 最终收口证据（单一文件）：宿主 `4eda665` + 交付候选 `06c9f56`

> **日报只引用本文件。** 所有数字都有来源文件（见 §5 附件清单）；标注规则：
> `[宿主]` = `http://127.0.0.1:18080` 真 `sm2` 实例；`[本地:X]` = 沙盒自建实例，X 为 head。

## 1. 产物与来源

| 角色 | head | `yanshu-server` sha256 | `deliver` sha256 | 内核 |
|---|---|---|---|---|
| **宿主正在跑** `[宿主]` | `4eda665` | `cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9` | `16e919fbc678081345ac217be5628fcf0a96a5a8567f72ca2c040d462d04a990` | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B） |
| **交付候选** `[本地]` | `06c9f56` | `5a42bb43d481926f9238e5016335354e4721224c2b7b8e34d7a24ec0d9426eb0` | `31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0` | 同上 `c1b87d0a…` |

- 宿主启动参数：`YANSHU_VERIFIER=sm2`（wazero 载冻结内核真验签）、`YANSHU_TOKEN_EPOCH=1`；`/v1/config.token_epoch` 实测 = **1**。
- 编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`（`deliver` 同式）；Go `go1.27.0 linux/amd64`。
- 交付候选的完整收口证据：`qa/evidence/results/5a42bb43-closure.md`（六项全 PASS）。

## 2. 宿主真认证端到端（**两次独立通过**）

### 2.1 Gate 批次 `[宿主]`

| 项 | 结果 |
|---|---|
| 跑批人 / 时间 | **Gate** / 2026-11-02 |
| 样本 | 2,506,889 B（`ys_pack_v1` 真加密，3 块 1 MiB，`.yspk` 2,507,553 B） |
| 投递 | `deliver --sender-sk --recipient-sk` 真签名，`ok=true`、`state=LEASED`（code `7759`） |
| 取回 | `GET /prelude` **200**（568 B）+ 三块 **200/200/200**（1,048,592 / 1,048,592 / 409,753 B）——**服务端返回字节与本地密文逐字节一致** |
| 解密 | `ys_unpack_v1` 落盘 **2,506,889 B**，sha256 **`5ccada48061ab5e4f97507f87691d80030340cacb5bcdb0270c2b3d7c291db6d7`** = 源文件 |
| `ack` 后 | prelude 与 `chunks/0` 均 **410 `TRANSFER_CONSUMED`** |
| 另两笔 | 2,506,889 B（sha `bb17026f…79dc9`，prelude 571 B）与 12,000 B，同样 ack 后 410 |

### 2.2 Web 批次 `[宿主]`

| 项 | 结果 |
|---|---|
| 跑批人 / 时间 | **Web** / `2026-11-02T19:14:47Z` |
| 样本 | `ys-e2e-input.bin` 2,506,889 B，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 客户端 | **两个独立 Chrome profile**（浏览器双端，覆盖前端实现） |
| 中转 | `core-host-18080-sm2`（`4eda665`、真 `sm2`、`TOKEN_EPOCH=1`）+ 冻结内核 `c1b87d0a…` |
| 结果 | 落盘 **2,506,889 B**，sha256 **与源完全相同**；`ack` 后再取 **410 `TRANSFER_CONSUMED`**；`acceptance: true` |

> 两批样本不同（`bb17026f…` / `5ccada48…` / `4b0c533a…` 是三份不同源文件），所以 sha 不同属正常；共同点是**落盘与源逐字节一致**且 **ack 后 410**。

## 3. 401 自愈（`AUTH_TOKEN_STALE`）`[本地:06c9f56]`

| 项 | 值 |
|---|---|
| 跑批人 | **Web** |
| 是否宿主 | **否**：用交付二进制 `06c9f56`（`5a42bb43…`）+ 冻结内核在本地起 `sm2` 实例真演练（宿主 `TOKEN_EPOCH=1` 不便构造） |
| 来源 | `results/web/c1b87d0a-sm2-token-heal.json` |

步骤：

1. 上传中断（已传 3 块，`record=true`）；
2. 旧 token 打 status → **401 `AUTH_TOKEN_STALE`**，响应原文
   `{"error":{"code":"AUTH_TOKEN_STALE","message":"upload token was revoked by a key version rotation; create a new transfer","request_id":"req_03af8ad4b890f21c"}}`；
3. 客户端 `resumeSend` **自动重建传输**（新 `transferId` `b09a5db4…`，state `READY`）；
4. B 端取回 **12,000 字节**，`bytesEqual=true`。

客户端按 `authFailed`（任意 401 通用分支）触发，**不依赖具体错误名**。

## 4. 三条件 / token 五步 / 四码 / 契约↔实现

### 4.1 三条件（`[本地:06c9f56]`，交付候选）

| # | 条件 | 结果 |
|---|---|---|
| 1 | 内核 sha 三重核对 | **PASS**：工作区 = `git cat-file blob 06c9f56:` = 启动日志 `kernel=`，均 `c1b87d0a…`（**非空 blob**，127,313 B） |
| 2 | 迁移对已有库幂等 | **PASS 10/10**（`pre-kid`、连跑两次 `rows 1→1`）；**跑过删列版的库经 `0005` 恢复 12/12**，旧凭据仍 401 `STALE` |
| 3 | 冻结向量套件 | **PASS**：四形态 26/26、prelude 6/6、证据二 6/6+11/11；sm2 14 可执行 / user-code 5 / normalize 20 |

### 4.2 token 五步（`[本地:06c9f56]`，真 `sm2`）

200（基线）→ **只换 secret 仍 200（不吊销）** → **KID+1 同进程 PID 不变 → 401 `AUTH_TOKEN_STALE`**、`token_epoch` 1→2 →
新签发 **200** → 旧 token 复打 **401**（不复活）→ 超期（`created_at` 推 7h）→ **401 `AUTH_TOKEN_EXPIRED`**。

> `[宿主:4eda665]` 差异：只换 secret → **401 `AUTH_TOKEN_INVALID`**；`created_at` 推 7h 后 `/status` 仍 200；`expires_at` 过后 sweeper 转 `EXPIRED`，`/prelude`、`/chunks` 返回 **410 `TRANSFER_EXPIRED`**。

### 4.3 四码（`[宿主]` 与 `[本地]` 分开）

| 码 | 实测 | 来源 |
|---|---|---|
| `AUTH_TOKEN_STALE` | 401（`upload token is stale…` / `revoked by a key version rotation…`） | `[本地:06c9f56]`、`[本地:4eda665]`、Web heal |
| `AUTH_TOKEN_INVALID` | 401（畸形 token 三种；宿主只换 secret） | `[宿主]`、`[本地]` |
| `AUTH_TOKEN_EXPIRED` | 401（`token has expired; obtain a new one`） | 仅 `[本地:06c9f56]`（宿主无此码） |
| `AUTH_SIGNATURE_INVALID` | 401（伪造 DER / 非 DER / 改 `SIG_INPUT` 一字节） | `[宿主]` |

### 4.4 契约 ↔ 实现字面核对

`check_contract_impl_parity.py`（契约 `origin/docs/contract-clarify` vs 实现 `06c9f56`）：
**FAIL —— 实现有、契约无：`SIG_INPUT_TOO_LONG`**（实现 `spec/errors.go:34` + 400 映射 + 单测 `TestSIGInputTooLong`）。
其余 13 码两侧一一对应，`AUTH_TOKEN_REVOKED` 两侧均 0。→ 契约应把该码写回 `§10.1`，注明"防御性上限、HTTP 不可达、触发返 400"。

## 5. 附件清单（每个数字都可回溯）

| 文件 | 内容 | 关键值 |
|---|---|---|
| `qa/evidence/results/5a42bb43-closure.md` | 交付候选六项收口 | `5a42bb43…` / `c1b87d0a…` |
| `qa/evidence/results/cc117070-host-closure.md` | 宿主六步 + 六项 | `cc117070…` |
| `qa/evidence/results/cc117070-secret-and-expiry.md` | 宿主 secret/超期原始响应 | `AUTH_TOKEN_INVALID` / `TRANSFER_EXPIRED` |
| `qa/evidence/results/2026-11-02-head-matrix.md` | 9 个 head × 六项对比 | 候选淘汰依据 |
| `results/web/c1b87d0a-sm2-e2e.md` / `.json` | Web 浏览器双端 e2e | `4b0c533a…482f` |
| `results/web/c1b87d0a-sm2-token-heal.json` | 401 自愈演练 | `AUTH_TOKEN_STALE` 原文 |
| `results/web/c1b87d0a-sm2-auth-branches.json` | 三分支响应体 | 签名/码/挑战 |
| `results/web/c1b87d0a-closure-web.md` | Web 侧收口 | 同上 |

## 6. 已知偏差清单

1. **宿主无 `AUTH_TOKEN_EXPIRED`**（`grep` 0 处）：6h/30min 凭据时效未实现，超期走 **410 `TRANSFER_EXPIRED`**。
2. **宿主"只换 `TOKEN_SECRET` → 401 `AUTH_TOKEN_INVALID`"**，与契约"secret 不吊销"不一致。
3. **`SIG_INPUT_TOO_LONG` HTTP 不可达**：昵称 ≤32 先被字段级拒（`NICKNAME_INVALID`）；码本身库层已实现。
4. **跨版本 token 不兼容**：`4eda665`（`u64be(KID)`+`v2`）vs `06c9f56`（`u32be(KID)`+`v1`）；换产物失效在传 token（数据无损）。
5. **旧 head 内核为空 blob**：`97d156c`、`b516cc6` 的 `server/kernel/yanshu_sm.wasm` 在 git 里 0 字节；`fa479d9` 缺 `0002` 迁移。
6. **过时注释**：`4eda665` 的 `ValidateHash` 写"不重算"，但线上走 `Derives()`（重算）。
7. **契约↔实现尚有一处不一致**：`SIG_INPUT_TOO_LONG`（见 4.4）。

## 7. 结论

**宿主 `4eda665` 在真 `sm2` 下端到端可用**（两条独立路径各一次逐字节一致 + ack 后 410）；
**推荐交付 `06c9f56`（`5a42bb43…`）**：六项全 PASS，修掉 `uploader_ip IS NULL` 的 500 与补齐 `EXPIRED`、secret 语义；
**换产物代价**：在传 `upload_token` 失效、需客户端重建传输，**数据无损**。
