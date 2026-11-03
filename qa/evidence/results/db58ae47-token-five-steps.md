# token 五步（终局口径）+ 三条件终验：`8223096`

- 日期：2026-11-02
- head：`feat/server-skeleton@**8223096**`（`feat(auth)!: 终局保留 EPOCH —— 在线吊销、secret 仅作派生盐`）
- 产物（我自建）：
  - `yanshu-server` `db58ae4799349cb1c72eafb9cb665a26bcfcf30bf0876d70e56b39f97335d79f`
  - `deliver` `31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0`
- 内核（git blob @8223096）：`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f` / 127,313 B
- 迁移：`0001_init` → `0002_upload_token_kid` → `0004_token_kid_state` → `0005_restore_token_kid`
- 编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`

## 1. 五步（与"secret 不吊销、KID 在线吊销"的终局口径一致）

| 步 | 场景 | 状态 | 错误名 |
|---|---|---|---|
| ① | 基线（KID=1, secret=…0001） | **200** | — |
| ② | **只改 `TOKEN_SECRET`**（KID 仍 1） | **200（旧 token 仍可用）** | — |
| ③ | **KID+1（直接改库，不重启）** 旧 token | **401** | **`AUTH_TOKEN_STALE`** |
| ④ | KID+1 后新签发 | **200** | — |
| ④b | 最初 token 复打 | **401 `AUTH_TOKEN_STALE`**（不复活） | — |
| ⑤ | 超期（把传输 `created_at` 推到 7 小时前） | **401** | **`AUTH_TOKEN_EXPIRED`**（`token has expired; obtain a new one`） |

`/v1/config.token_epoch`：轮换前 **1** → 轮换后 **2**，**随 KID 变化**；③ 的 KID 递增是
`UPDATE token_kid_state SET kid = kid + 1`，**服务未重启**即生效（脚本每次起新进程只是为了换
`YANSHU_TOKEN_KID` 环境值；在线生效由库内状态驱动，`token_epoch` 同步反映）。

脚本：`qa/evidence/check_token_five_steps.py`（自起自停、逐步断言、退出码）。

## 2. 三条件（同一产物）

| # | 条件 | 结果 |
|---|---|---|
| 1 | 内核 sha（三重核对：工作区 + git blob + 启动日志） | **PASS**：工作区 `c1b87d0a…7259f`/127,313 B；`git cat-file blob 8223096:server/kernel/yanshu_sm.wasm` 同为该值；启动日志 `sm2 verifier loaded kernel=./kernel/yanshu_sm.wasm version=0x00010000`，`/healthz` 200 |
| 2 | 迁移对已有库幂等（含 `ADD COLUMN`） | **PASS 10/10**：缺列 → 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → 连跑两次 `rows 1→1` |
| 3 | 冻结向量套件 + 证据二 | **PASS**：sm2 14 条可执行（1 条 `executable:false` 跳过）、user-code 5、normalize 20；证据二 6/6 + 11/11 |

## 3. 相对 `dfd3e82` 的行为变化（重要）

| 场景 | `dfd3e82` | `8223096` |
|---|---|---|
| 只改 secret | 401 `AUTH_TOKEN_INVALID` | **200（仍可用）** |
| KID+1 | 需重启才生效 | **改库即生效**，401 `AUTH_TOKEN_STALE` |
| `AUTH_TOKEN_EXPIRED` | 代码无 | **已生效**（7 小时构造用例 → 401） |

结论：`8223096` 才是"secret 作派生盐、EPOCH 在线吊销"的终局实现，**`4eda665`/`dfd3e82` 都不是**。
建议宿主换到这份（或更新）：换 secret 不再误伤在传任务，吊销靠 KID 递增且不必重启。

## 4. 复跑

```sh
python3 qa/evidence/check_token_five_steps.py --binary <bin> --deliver <deliver> \
  --yspk <样本> --dsn "<DSN>&search_path=<schema>" --schema <schema> --work <含 blobs 的目录>
```
