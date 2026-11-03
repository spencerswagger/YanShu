# 收口证据：`8223096`（`db58ae47…`）—— 今晚交付产物

- 日期：2026-11-02
- **交付产物**：head `feat/server-skeleton@**8223096**`
  - `yanshu-server`：`db58ae4799349cb1c72eafb9cb665a26bcfcf30bf0876d70e56b39f97335d79f`
  - `deliver`：`31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0`
  - 内核：`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B）
- 编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`（`deliver` 同式）；Go `go1.27.0 linux/amd64`
- 构建环境：Gate 沙盒 `git archive 8223096` + 独立 target 构建（不继承共享 `CARGO_TARGET_DIR`），产物 sha256 与 Core 报的一致。

## ① 三条件（全部 `[本地]`，`8223096`）

| # | 条件 | 结果 |
|---|---|---|
| 1 | 内核 sha 三重核对 | **PASS**：工作区 = `git cat-file blob 8223096:` = 启动日志 `kernel=./kernel/yanshu_sm.wasm`，均 `c1b87d0a…`/127,313 B；`ys_version()=0x00010000`、34 函数 + memory |
| 2 | 迁移对已有库幂等 | **PASS 10/10**：老库缺列 → 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → **连跑两次 `rows 1→1`**；迁移集 `0001/0002/0004_token_kid_state/0005_restore`（无 drop） |
| 3 | 冻结向量套件 | **PASS**：四形态 26/26、prelude 6/6、证据二 6/6 + 11/11；sm2 14 可执行 / user-code 5 / normalize 20 |

## ② token 五步（`[本地]`，`8223096`，真 `sm2` 实例）

| 步 | 结果 |
|---|---|
| 基线（KID=1） | **200** |
| 只换 `TOKEN_SECRET` | **200（不吊销）** |
| **KID+1（改库，不重启）** | **401 `AUTH_TOKEN_STALE`**；同一进程 **PID 不变**、`token_epoch` **1→2** |
| 新签发 | **200** |
| 旧 token 复打 | **401 `AUTH_TOKEN_STALE`**（不复活） |
| 超期（`created_at` 推 7 小时前） | **401 `AUTH_TOKEN_EXPIRED`**（`token has expired; obtain a new one`） |

## ③ 四形态矩阵（`[本地]`，端侧函数级，与宿主无关）

`PB_S` 在 wasm 64B / wasm_wire 65B / 原生 64B / 原生 65B 四入口全 **`AWQW`**，校验位四者全 `X`；
另 4 组公钥逐字符相同；`normalize` 14 组一致；**26/26 通过**。

## ④ 生产路径端到端（`[本地]` 在 `8223096` 上起真 `sm2` 实例，2,506,889 B）

| 项 | 结果 |
|---|---|
| 源文件 | 2,506,889 B，sha256 `0fd76c0f0abc4ac90d7dc4f70f89032e499350d41c5a1558f26ab7a8722ead12` |
| 打包 | 3 块（1 MiB），`.yspk` 2,507,556 B |
| 投递（真签名） | `ok=true`、`state=LEASED`、`chunks=3` |
| 取回 | `GET /prelude` 与本地前导**逐字节一致**；三块**全部逐字节一致** |
| `ack` 后再取 | **410 `TRANSFER_CONSUMED`**（prelude 与 chunks/0 均 410，响应体原文见下） |

```json
{"error":{"code":"TRANSFER_CONSUMED","message":"transfer has been consumed","request_id":"req_613807…"}}
```

## ⑤ 结论与已知偏差

**结论：建议 spencer 换 `8223096`（`db58ae47…`）**——它是唯一一条完整链路都被验过的产物：
内核入库、迁移 10/10、向量全过、token 五步（含"不重启即吊销"与 `EXPIRED`）、端到端逐字节一致 + ack 后 410。

已知偏差（如实，不美化）：

1. **宿主当前跑的是 `4eda665`（`cc117070…`）**：它的"只换 `TOKEN_SECRET` → 401 `AUTH_TOKEN_INVALID`"与本产物/契约不一致；且无 `EXPIRED`（超期走 410 `TRANSFER_EXPIRED`）。换 `8223096` 后这两条消失。
2. **`SIG_INPUT_TOO_LONG`（513 B）HTTP 不可达**：昵称 ≤32 先被字段级拒（`400 NICKNAME_INVALID`），码本身库层已实现并有单测。
3. **旧 head 不可交付**：`97d156c`、`b516cc6` 的 `server/kernel/yanshu_sm.wasm` 在 git 里是**空 blob（0 B）**；`fa479d9` 连 `0002` 迁移都没有。
4. **Core 在冻结后又产出 `4b3babd`（`a302dccf…`）**：只改 EPOCH 默认值与一条迁移测试，**未经本轮复验**，不建议部署。
5. **跨版本 token 不兼容**：`4eda665` 用 `u64be(KID)`+`v2` 前缀，`8223096` 用 `u32be(KID)`+`v1`；换产物会失效在传 token（数据无损）。
