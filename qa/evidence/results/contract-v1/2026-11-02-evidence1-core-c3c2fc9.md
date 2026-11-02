# 证据一实测结果（**初步证据 · run #1**）：三处都查不到文件名与明文

> 本份是**第一次跑通**的记录：`verifier=stub-allow`（验签是桩）+ 日志靠**部署重定向 stdout**。
> 服务端内建日志落地后已按正式路径复扫过一次，见同目录
> `2026-11-02-evidence1-core-run2-logdir.md`。两份分开留档，别把 run #1 当最终结论。
> 真实 `sm2` 验签接入后还要跑 run #3。

- 日期：2026-11-02
- 对象：服务端 `feat/server-skeleton` @ `c3c2fc9`（PR #3），配端侧 `feat/endcrypto-wasm`
  @ `dbd66c4` 打出的**真契约包**（`YSPK/1.0`，2 块，2273B，prelude 549B）
- 表结构基线：`feat/server-skeleton@c3c2fc9` 的 `0001_init.sql`
  （8 张表：`codes` / `auth_challenges` / `transfers` / `transfer_chunks` /
  `transfer_downloads` / `idempotency_keys` / `audit_events` / `schema_migrations`）；
  白名单之外的任何表或列都会让本轮直接 FAIL
- 库：**`yanshu_test` 的独立 schema `gate_ev1`**（不扫 `yanshu_dev` / `yanshu_staging`，
  也不碰 `public` 与 Core 自己的测试 schema）；DSN 从 `/.keys/pg.env` 读取，
  **口令与 DSN 原文不进仓库、结果文件、日志与 PR**
- 结论：**三处全部 PASS，零命中**；退出码 0
- 并且做了 **3 组阳性对照**：分别把明文塞进存储、把文件名写进日志、把文件名写进 DB，
  三处都能被抓出来（退出码 1）——说明"没命中"不是因为检测器瞎了

## 跑的是哪个 commit、怎么起的

```sh
# 服务端（c3c2fc9），独立 schema + 独立 blob 目录 + stdout 重定向当日志
YANSHU_DATABASE_URL="$PG_TEST_DSN&search_path=gate_ev1" \
YANSHU_BLOB_DIR=<work>/blobs \
YANSHU_ADDR=127.0.0.1:18080 \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET=<随机> \
<work>/bin/yanshu-server > <work>/logs/server.log 2>&1
```

一键复跑：`qa/evidence/run_evidence1_core.sh <core-src> <rune-crate> <work>`（内部含
建 schema、起服务、打包、完整投递、三处检索、杀进程）。

## 投递样本（有辨识度，便于命中定位）

| 项 | 值 |
|---|---|
| 文件名 | `验收样本-首夜.txt`（主干 `验收样本-首夜`，扩展名 `.txt`） |
| 高熵片段 | 48 字符 base64url 随机串（每次生成） |
| 中文片段 | `鸿雁传书，一声便至，过而不留。` |
| 包 | 2261–2272B，`BLOCK_COUNT=2`，`CHUNK_SIZE=1024` |

## 投递过程（按 API.md 走完整流程）

`挑战 → 注册码 ×2（服务端按公钥重算码并比对）→ 建传输 → prelude → 2 块 → complete
→ GET prelude（开租约）→ GET 2 块 → 逐字节比对`

- 上传/下载的 prelude 与两块切片**逐字节一致**；`complete` 后状态 `READY`。
- **未 ack**（`--no-ack`）：ack 会按策略删密文，删掉之后扫"无明文"就成了空语料，
  所以本证据在 LEASED 状态下扫；"ack 后密文真删"属生命周期证据，另行验证。

## 两条边界（先读这两条再看结论）

**边界一：`YANSHU_VERIFIER=stub-allow` —— SM2 验签是桩，且是本轮为了联调显式打开的测试态。**
因此这份证据能证明的是「**存储 / 数据库 / 日志三处不落文件名与明文**」，
**不构成认证链路可用**：签名有没有被真正验过、公钥与码是否匹配、挑战是否一次性，
这些在 `stub-allow` 下统统没有被检验。换成真实验签（`YANSHU_VERIFIER=sm2`）后需要复跑一轮，
届时结论才能覆盖鉴权面。

**边界二：日志扫的是"部署重定向出来的 stdout 文件"，不是服务端的正式日志落盘。**
实测 Core 的 `YANSHU_LOG_DIR` **未被服务端使用**（`grep` 不到读取点，日志只写 stdout），
所以本轮把 `server.log` 重定向到哪里，就扫哪里。等 Core 把日志落地方式定下来
（实现目录写文件、或把 `YANSHU_LOG_DIR` 从文档里去掉并明确"只写 stdout、由部署方接管"），
**要按他正式的日志输出路径再扫一次**，这一条现在记为"待复扫"。

## 三处扫描结果

| 目标 | 语料量 | 强信号命中 | 结论 |
|---|---|---|---|
| 存储目录 `<BLOB_DIR>/<id[0:2]>/<id>/{prelude,chunks/00000000,00000001}` | 3 文件 / 2241B | 0 | PASS |
| PostgreSQL `yanshu_test` … schema `gate_ev1`（8 表 / 本次 172 行） | 全表文本列逐行 | 0 | PASS |
| 服务端日志（stdout 重定向） | 2 份 / 2773B | 0 | PASS |

- 检索项 6 个（文件名、主干、扩展名带点、扩展名裸串、高熵片段、中文片段），
  每个展开 1–8 种形态（raw / base64×4 / hex×2 / percent），共 31 种字节串。
- 数据库侧额外做了**表/列白名单断言（未知即 FAIL，不是"包含检查"）**：`codes`、`auth_challenges`、`transfers`、
  `transfer_chunks`、`transfer_downloads`、`idempotency_keys`、`audit_events`、
  `schema_migrations`；**零白名单外列**。
- 存储侧文件名只有 `prelude` 与 8 位块序号，无任何用户可控字符串。
- 漂移防护已验证：往 `gate_ev1` 里临时加一张白名单外的表，扫描立刻 `exit=1` 并打印差异；
  删掉后回到 `exit=0`。**基线之外的表/列不会静默放过。**

## 阳性对照（证明检测器真的在工作）

| 注入 | 结果 | 命中位置 |
|---|---|---|
| 把明文样本 `cp` 进 blob 目录 | **FAIL / 退出码 1** | `blobs/leak-canary.bin offset=… form=raw`（高熵片段 + 中文片段） |
| 往 `server.log` 追加一行 `upload name=验收样本-首夜.txt` | **FAIL / 退出码 1** | `log 文件 offset=…`（文件名 + 主干） |
| `update codes set nickname='验收样本-首夜.txt'` | **FAIL / 退出码 1** | `db:pg/gate_ev1.codes row#… col=nickname`（文件名 + 主干） |

三处复原后复扫恢复 PASS（退出码 0），说明命中来自注入本身，不是噪声。
**这三组对照已脚本化**（`run_evidence1_core.sh` 的 5b 步，`YS_EV1_CONTROLS=0` 可关），
复跑时会自动断言「注入 → 1、复原 → 0」，任一条不成立就判本轮证据不可信并以退出码 2 结束。

## 结论与边界

1. **服务端没有把文件名/明文写进存储、数据库或日志**：三处零命中，且三处都能被阳性对照触发
   （对照组由脚本自动跑，不等我手工补）。
2. **验签是桩 —— 见文首「两条边界」边界一**：本轮 `stub-allow`，签名只做形状检查；
   本证据只覆盖"不落明文"，**不构成认证链路可用**。
3. **库与 schema 隔离**：只用 `yanshu_test`，并在其中用独立 schema `gate_ev1`；
   脚本开头有硬守卫——DSN 指向的库不是 `yanshu_test` 就直接退出 2，不扫别人的数据。
   同一 workdir 里重复投递会留下多条历史 transfer，不影响结论。
4. **日志扫的是重定向出来的 stdout —— 见文首「两条边界」边界二**：
   `YANSHU_LOG_DIR` 实测未被服务端使用；等 Core 定了日志落地方式，按正式路径**再扫一次**。
5. **未覆盖**：ack 后删除、TTL 到期清理、撤回删密文（生命周期证据另做）；抓包层无明文
   （HTTPS 之外还有 SM4 密文）未在本次范围内。

## 跑的过程中修掉的一个假 PASS 风险（值得记）

第一次换到新 head 复跑时，结果"PASS"了，但存储目标其实**扫了 0 字节**——原因是上一轮的
服务进程还占着固定端口 18080，新进程 `bind: address already in use` 直接退出，而
`/healthz` 探活打到的是**旧进程**，于是密文落进了上一轮的目录，我扫的却是新 workdir 的空目录。

已加三道硬约束，任何一条不满足就以退出码 2 结束、不产结论：

1. 端口按 PID 派生（`18080 + $$ % 500`），不再固定；
2. 启动校验升级为"进程活着 + 日志里有 `listening` + 日志里没有 `bind: address already in use`"，
   不再只信 `/healthz`；
3. 投递后断言存储目录**非空**（`find "$SCAN_BLOB" -type f`），空即 BLOCKED ——
   "什么都没扫到"不许当 PASS。

## 附：本次没做的

- 未启动常驻实例（沙盒进程不跨调用存活），每次都是"起→投递→扫→杀"一遍过。
- 未接真实 SM2 验签；Core 侧 `internal/auth/verifier.go` 仍是挂载点。
