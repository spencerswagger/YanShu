# 候选 head 对比表（定案用）

- 日期：2026-11-02
- 口径说明：第 3 列要求"无 `0004`"——这里按**无 `0004_drop_token_epoch.sql`** 判（`0004_token_kid_state.sql` 是**建状态表**，必须有，
  否则 KID 无从记录）。表里把它与 `0005_restore` 一并注明。

## 一、六项对照

| # | 候选 head | ① 内核真入库<br>`git cat-file blob` | ② 错误名<br>`REVOKED=0` 且 `STALE>0` | ③ 迁移清单<br>无 drop / 含 0002 | ④ 升级路径<br>老库 10/10 + 连跑两次 | ⑤ 冻结向量套件<br>26/26 + prelude 6/6 + 证据二 | ⑥ KID 矩阵<br>secret→`INVALID`、KID+1→`STALE`、不复活、调小拒启 | 备注 |
|---|---|---|---|---|---|---|---|---|
| 1 | `fa479d9` | **FAIL**（空 blob 0B） | PASS（0 / 5） | FAIL：**无 `0002`** | FAIL（缺列，已实测不可用） | 未验（无 0002 不构成可交付） | 部分（KID 有，`0002` 缺） | 早期 head，仓库里无内核、无 ALTER |
| 2 | `b516cc6` | **FAIL**（空 blob 0B） | PASS（0 / 8） | PASS（`0002` 有） | **PASS 10/10**（实测：`pre-kid`、`rows 1→1`） | PASS（5/20/14 + 6/6 + 11/11） | PASS（基线 200 → secret 401 `INVALID` → KID+1 401 `STALE` → 新 200 → 不复活） | 名字/迁移/矩阵都好，**但内核没进 git** |
| 3 | `5605907` | **PASS**（`c1b87d0a…`/127,313B） | PASS（0 / 9） | 部分：`0001/0002/0003`，**无 `0005`** | PASS 10/10（**跑过 drop 的库无法自动恢复**） | PASS | PASS（201 → secret 204 不吊销 → KID+1 401 `STALE` → 新 201 → 不复活 → 调小 exit 1） | 兜底方案；缺 `uploader_ip NULL` 的 P0 |
| 4 | `8f4f24c` | **PASS** | **FAIL**（7 / 0） | **FAIL：含 `0004_drop_token_epoch`** | PASS 10/10；**恢复路径 FAIL（500）** | PASS | FAIL（KID+1 返回 `REVOKED`；secret 走 `INVALID` 旧语义） | 第一个内核入库的 head，但带删列迁移 |
| 5 | `4514848` | **PASS** | **FAIL**（7 / 0） | **FAIL：含 `0004_drop`** | PASS 10/10；**恢复 FAIL 11/12（500 INTERNAL）** | PASS | FAIL（同上） | 与上面同缺陷，更新一点 |
| 6 | `71d62c3` | **PASS** | **FAIL**（7 / 0） | PASS（无 drop，含 `0005`） | PASS 10/10；`0005` 恢复由 `06c9f56` 实测 12/12 | PASS | FAIL（KID+1 仍 `REVOKED`） | **只差改名**；`06c9f56` 是它的后代 |
| 7 | `d8d90a2` | **PASS** | 部分（2 / 5，含残留 `REVOKED`） | **FAIL：含 `0004_drop`** | PASS 10/10；**恢复 FAIL（500 INTERNAL）** | PASS | PASS | 缺 `uploader_ip NULL` P0，且 drop 迁移残留 |
| 9 | `cc02e3c` | **PASS**（`c1b87d0a…`/127,313B；我的构建 sha 与 Core 报的 `d55554dc…` 逐字节一致） | PASS（`REVOKED`=0 / `STALE`=7；**但 `EXPIRED`=0，缺 v1 恢复的过期码**） | PASS（无 drop；`0001/0002/0004_token_kid_state/0005_restore`） | PASS 10/10；**恢复 FAIL 11/12（500 INTERNAL，缺 `uploader_ip NULL` P0）** | PASS（6/6 + 11/11） | **FAIL**：只换 secret → **401 `AUTH_TOKEN_INVALID`**（旧语义，终值应为 200 不吊销）；KID+1 → `STALE`、新签发 200、不复活 | `06c9f56` 的祖先；比它少 P0 与 EPOCH 默认 1 |
| 8 | **`06c9f56`** | **PASS**（`c1b87d0a…`/127,313B） | **PASS**（**0 / 7**） | **PASS**（无 drop；`0001/0002/0004_token_kid_state/0005_restore`） | **PASS 10/10 + 恢复 12/12**（连跑两次 `rows 1→1`） | **PASS**（5/20/14 + prelude 6/6 + 6/6+11/11 + 一致性 26/26） | **PASS**（200 → secret **200 不吊销** → KID+1 **401 `STALE`**（同进程、PID 不变）→ 新 200 → 不复活 → 调小 exit 1） | **唯一六项全 PASS** |

## 二、推荐

**`cc02e3c` 复核结论（2026-11-02 追加）：** 六项里 **4 PASS / 2 FAIL**——
① 内核入库 PASS（我的构建 `d55554dc…` 与 Core 报的一致）、② 名字 PASS（但 `EXPIRED` 缺失）、
③ 迁移清单 PASS、④ 老库升级 PASS 但**恢复路径 500（11/12）**、⑤ 向量 PASS、⑥ KID 矩阵 **FAIL**（secret 仍走旧语义 `401 INVALID`）。
→ **不建议用 `cc02e3c`**，仍用它的后代 `06c9f56`。

**用 `06c9f56`（`yanshu-server` = `5a42bb43d481926f9238e5016335354e4721224c2b7b8e34d7a24ec0d9426eb0`，
`deliver` = `31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0`）。**

理由三条（按权重）：

1. **六项里唯一全 PASS**：其它 head 至少有一项硬伤——内核没入库（`fa479d9`/`b516cc6`）、名字还是 `REVOKED`
   （`8f4f24c`/`4514848`/`71d62c3`）、或迁移集带 `0004_drop_token_epoch`（`8f4f24c`/`4514848`/`d8d90a2`）。
2. **只有它在"跑过删列版的库"上不 500**：`d655e16（真删列）→06c9f56` 恢复 **12/12**，
   旧凭据仍 `401 STALE`；同一测试在 `d8d90a2`/`4514848` 上是 **500 INTERNAL**（缺 `uploader_ip NULL` 的 P0）。
3. **在线吊销有严格实证**：同进程、**PID 不变**下 KID+1 立刻 `401 STALE`、`token_epoch` 1→2。

### 已知偏差（`06c9f56`，如实列）

1. **到期用例是构造的**：`EXPIRED` 通过把 `created_at` 推到 7 小时前触发，不是真等 6 小时；下载租约 30 分钟未单独构造。
2. **`SIG_INPUT_TOO_LONG`（513 字节）在 HTTP 层不可达**：昵称 ≤32 先被字段级拒；库层单测覆盖。
3. **宿主实例上未跑四形态/端到端**：全部证据来自沙盒自建实例（宿主 `4eda665` 仍是旧语义）。
4. **内核入库依赖 127,313 B 那一份**：跨环境可能构建出 130,653 B（从成员目录构建），已在检查里用白名单 + 向量套件兜住。
5. **`EXPIRED` 的 30 分钟租约分支**未构造用例（同 DECAY 分支，机制相同）。
