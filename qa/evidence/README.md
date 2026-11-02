# qa/evidence · 验收证据脚本

> **验收冻结 head：`031e95b`** —— wasm 127,313 B / sha256 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`；一键重跑：`qa/evidence/check_all.sh <rune-crate> <workdir>`。

两条证据的**可复跑脚本**：① 服务端无明文/无文件名；② 密文篡改必报错。

> **当前状态（2026-11-02 首夜·三轮）**
> * 默认布局 = **契约布局 `contract-v1`**（CRYPTO-PACK `YSPK/1.0`）。`rune-v1` 只能显式
>   `--layout rune-v1` 使用，且输出会打「非契约实现、不作验收」横幅。
> * 证据二**已按契约布局跑全量**（`results/contract-v1/`）：单块 5/5、多块 10/10、
>   补充变体 18/18，全部被明确拒绝，基线明文逐字节一致。
>   **生产导出路径已补跑**：wasm `ys_pack_v1` / `ys_unpack`（`--entry-kind production`），
>   结果同样 5/5、10/10、18/18 —— 见 `...-contract-v1-wasm.md`。
> * 旧布局（`rune-v1`）的历史结果留在 `results/rune-v1-noncontract/`，仅作对照。
> * 证据一**已跑出真结果**（`results/contract-v1/`）：对服务端 `c3c2fc9` 起真服务、
>   走完整投递，存储 / 数据库 / 日志三处零命中；并自动跑 3 组阳性对照
>   （往存储塞明文、往日志写文件名、往 DB 写文件名）证明检测器不是瞎的。
>   `--profile core-skeleton` 缺参时仍以退出码 4 结束，不伪装 PASS。

只依赖 **python3 ≥ 3.10 标准库**（PostgreSQL 检索额外用 `psql`；SQLite 用内置 `sqlite3`）。
不实现、不调用任何加解密；不读密钥与凭据文件；不修改被检对象。

---

## 0. 三十秒上手

```sh
# 自测（不需要 Rune / Core / 网络）
python3 qa/evidence/scan_plaintext.py --selftest      # 9/9
python3 qa/evidence/tamper_probe.py --selftest        # 13/13

# 证据二：对端侧真实实现跑全套篡改（需要端侧源码）
git -C <YanShu 仓库> archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune
qa/evidence/run_evidence2_rune.sh /tmp/rune/crypto/sm /tmp/ys-ev2

# 证据一：对已有投递的存储 + 数据库检索
python3 qa/evidence/scan_plaintext.py \
    --storage-root "$YANSHU_BLOB_DIR" --dsn "$YANSHU_DATABASE_URL" \
    --sample qa/evidence/fixtures/sample-delivery.example.json
```

---

## 1. 证据一：`scan_plaintext.py`

### 检索什么

| 检索项 | 说明 | 强度 |
|---|---|---|
| `file-name` | 原文件名（UTF-8 原串、base64×4、hex×2、percent-encode） | ≥8B 强 / <8B 弱 |
| `file-stem` | 文件名主干（去掉扩展名），同上形态 | ≥8B 强 / <8B 弱 |
| `file-ext-dot` | 扩展名带点，如 `.txt` | 按长度 |
| `file-ext-bare` | 扩展名裸串，如 `txt` | **恒弱**（见下） |
| `fragment:<id>` | 每段明文（高熵随机串、中文短句…），同上形态 | ≥8B 强 / <8B 弱 |

三类目标，缺一不可：

1. **存储目录**（递归，整文件流式扫，跨 1 MiB 缓冲区边界不漏）
2. **日志**（`--log-path` 文件/目录，或 `--log-cmd` 取命令输出流，如 `docker logs`/`journalctl`）
   —— 常被漏掉的第三个泄露面：很多实现会顺手把"上传成功 name=xxx"打进日志
3. **数据库**（PostgreSQL 经 `psql` 逐表逐行；SQLite 逐表逐行逐列）

### 命中强度的口径（别当成偷工减料）

短 ASCII 记号在随机密文里有真实概率偶然出现：3 字节记号在 1 GB 随机数据里期望命中约 0.25 次。
若一律判 FAIL，证据会长期假红、失去意义。因此：

* 载荷 **≥ 8 字节** → `hard`，命中 **FAIL**（退出码 1）
* 载荷 **< 8 字节** → `advisory`，命中照常打印位置，**不改退出码**
* `--strict` 把 `advisory` 全部升级为 FAIL —— 要字面语义时用它

### 退出码

| 码 | 含义 |
|---|---|
| 0 | PASS：所有强信号项未命中 |
| 1 | FAIL：至少一个强信号项命中（打印 文件/表 + 偏移 + 定位上下文） |
| 2 | BLOCKED：没有可检索目标、投递命令失败、`psql` 不可用等 |
| 3 | INCONCLUSIVE：扫了 0 文件 0 字节 0 行 —— "没命中"不构成证据 |
| 4 | PENDING：参数未就绪（服务端未合入 / 未起 / migrations 未跑）—— 既非 PASS 也非 FAIL |

### 服务端骨架 profile

`--profile core-skeleton`（或 `YS_PROFILE=core-skeleton`）会按 `feat/server-skeleton` 的约定取值：

* 存储根目录：`YANSHU_BLOB_DIR`（默认 `./data/blobs`），布局
  `<root>/<pkg[0:2]>/<pkg>/prelude`、`…/chunks/<index>`（`server/internal/blob/disk.go`）
* 数据库：`YANSHU_DATABASE_URL`
* 表/列白名单 = **7 张业务表**（`0001_init.sql`）+ **1 张迁移记账表** `schema_migrations`
  （`store.go` 里建、只有 version/applied_at，**不是业务表**）；检索前先核对：
  **缺表 → PENDING（服务端没跑起来）；出现基线之外的任何表/列 → FAIL（exit 1）并打印差异**，
  防止实现方改表后白名单静默放过。基线与 commit 记在 `CORE_SCHEMA_BASELINE` 并写进结果文件

任一必需项拿不到 → 打印缺什么、以退出码 4 结束，不出假结论。

### 出真证据需要哪些参数（可勾选清单）

| # | 参数 | 默认值 / 现状（2026-11-02 实测） | 缺了会怎样 |
|---|---|---|---|
| 1 | `YANSHU_BLOB_DIR` | 默认 `./data/blobs`；布局 `<root>/<id[0:2]>/<id>/{prelude,chunks/<8 位序号>}` | 退出码 4，报"存储根目录不存在" |
| 2 | `YANSHU_DATABASE_URL` | schema 由 DSN 的 `search_path` 决定，未指定即 `public`；本仓库脚本用 `--pg-schema` 传（psql 的 URI 不认 `search_path` 参数） | 退出码 4，报"拿不到 transfers / transfer_chunks" |
| 3 | migrations | 服务端**启动时自动跑**（`internal/store` 里带 `schema_migrations` 记账）；手工跑法见 `server/README.md` | 退出码 4，报"缺表：codes、auth_challenges…" |
| 4 | 日志位置 | `--log-path` / `--log-cmd`；两种落地都支持：① 部署重定向 stdout（`YS_EV1_LOG_MODE=stdout`，默认）② 服务端内建按日滚动 `YANSHU_LOG_DIR`（`YS_EV1_LOG_MODE=dir`，`2bc7dae` 起可用，会按投递日期选当日文件） | 退出码 4，报"日志路径未知" |
| 6 | 真认证（可选） | `YS_EV1_VERIFIER=sm2`：服务端以真 SM2 验签启动，`deliver` 自动补 `--sender-sk/--recipient-sk` 真签名；需要 Core `08d40e7` 及以上 | 用 stub-allow 也能跑，但只覆盖"不落明文"，不覆盖鉴权 |
| 5 | 触发一次完整投递 | `--deliver-cmd '<命令>'`，命令 stdout 需给出 `code` / `package_id` / `blob_dir` / `db_url` / `log_path` 五个键 | 缺键 → 退出码 4 并点名；命令本身失败 → 2；命令成功但语料为空 → 3 |

五项齐了才算"参数就绪"；任何一项缺，`--profile core-skeleton` 都会点名并以退出码 4 结束。

> **库固定 `yanshu_test`**：`run_evidence1_core.sh` 开头会解析 DSN 的库名，不是
> `yanshu_test` 直接退出 2（`YS_EXPECT_DB` 可改，但不建议）。schema 用独立的
> `gate_ev1`，不碰 `public` 与 Core 自己的测试 schema。DSN 只从 `/.keys/pg.env`
> 之类的环境读取，**口令与原文不落任何文件**。

### 接 Core 的投递驱动（一条命令）

`run_evidence1_core.sh` 内置两个位置可换：

| 变量 | 含义 |
|---|---|
| `YS_DELIVER_BIN` | 换成 Core 的投递驱动（入参是 `.yspk`，不是明文） |
| `YS_DELIVER_ARGS` | 传给驱动的参数模板，`{pack}` 会被替换成本次生成的 `.yspk` 路径 |

驱动只要在 stdout 给出 `code` / `package_id` / `blob_dir` / `db_url` / `log_path`，
脚本就会用驱动报出的路径去扫；给不出就退回本次 workdir，缺项会明确报出来。

```sh
YS_BASE_DSN="$PG_TEST_DSN" \
YS_DELIVER_BIN=/path/to/core-deliver \
YS_DELIVER_ARGS='--pack {pack}' \
qa/evidence/run_evidence1_core.sh <core-src> <rune-crate> /tmp/ys-ev1
```

### 投递钩子：任意命令 + 从 stdout 解析标识

`--deliver-cmd '<命令>'` 先跑一次投递，再读它的 stdout 取标识。**不绑定任何具体实现**：
换成另一套服务端，只要命令还能吐出这五个键，脚本不用改。

* 输入（传给命令的环境变量）：`YS_SAMPLE_JSON`、`YS_SAMPLE_FILE`（明文样本）、
  `YS_SAMPLE_NAME`、`YS_SAMPLE_MIME`、`YS_SAMPLE_ID`、`YS_RECIPIENT_CODE`
* 输出（stdout，JSON 或 `key=value` 行均可）：

| 键 | 含义 |
|---|---|
| `code` | 收件方用户码 |
| `package_id` | 服务端返回的传输 ID |
| `blob_dir` | 服务端存储根目录 |
| `db_url` | 数据库连接串（输出里打码，不落文件） |
| `log_path` | 服务端日志路径 |

**少任何一个 → 退出码 4 并点名缺哪个**，绝不猜路径。五个齐了就直接当检索目标用
（显式 `--storage-root/--dsn/--log-path` 优先）。

### 输出与数据来源

```
[05] fragment:hi-entropy     hard     storage    7      HIT    明文片段（48B）
       ↳ /var/lib/yanshu/blobs/ab/cd1234  offset=22  form=raw  before=0a746f6b656e3a20 after=…
```

只回显左右各 8 字节的十六进制定位上下文，**不回显整段明文**；`--json-out` 同样只存 hex 上下文。
PostgreSQL 走 `row_to_json`：`TEXT` 列明文原样、`BYTEA` 列以 `\x<hex>` 出现，所以 hex 形态的
检索项正是用来抓 `bytea` 里的明文。

---

## 2. 证据二：`tamper_probe.py`

### 用例

| 用例 | 做什么 | 对应契约 |
|---|---|---|
| `baseline` | **未篡改包必须解出与原文一致的明文**（否则 BLOCKED，防假 PASS） | §13 |
| `flip-envelope-header` | 翻转包头 1 字节（签名覆盖区 / 密钥派生区） | §10.2 |
| `flip-chunk-header` | 翻转块头 1 字节（块号） | §6.2 / §6.4 |
| `flip-chunk-data` | 翻转密文中间 1 字节 | §7 / §13#20 |
| `drop-middle-chunk` | 删除中间块整条记录 | §6.4 / §13#22 |
| `swap-chunks` | 交换两个块的顺序 | §6.4 |
| `splice-donor-chunk` | 用**另一个包**的合法块替换整块（需 `--donor`） | §13#20 |
| `flip-chunk-tag`（`--extra-cases`） | 翻转 GCM tag 1 字节 | §7.1 |
| `drop-chunk-slice`（`--extra-cases`） | 只删"密文+tag"、留块头 | §6.2 |
| `truncate-tail`（`--extra-cases`） | 截掉尾块 | §6.4 / §13#22 |
| `reject-legacy-format`（`--extra-cases`） | 把旧 `rune-v1` 格式包（40B 头）喂给契约实现，必须被拒（**版本闸门，不是篡改**） | §2 版本策略 |

判定：**解密失败（清单层 / AEAD 层 / 结构层任一道拒绝）= PASS**；
**解密成功或返回部分明文 = FAIL**。错误名只作诊断打印，**不参与通过判定**——
换实现、换布局、换分层顺序都会改错误名，绑死错误码等于把证据绑在实现细节上。
脚本另会统计错误名分布：若所有失败都塌成同一个通用错误，会打诊断警告（不判 FAIL）。

`--expect-plaintext <file>` 给了以后，baseline 还要逐字节比对明文，否则整轮不算数。

> 预期内的观察（不是缺陷）：契约里清单摘要是第一道防线、AEAD tag 是第二道，
> 所以端到端篡改**通常拿不到 tag 类错误**（清单层先拦）。两层各自可触发由实现方的
> 单元级反例覆盖，Gate 只记录这个观察，不据此判 FAIL。

### 包布局（两套，自动识别）

`--layout` 默认 `contract-v1`（契约权威）；`auto` 按包头判别，输出里会写明：

| 布局 | 来源 | 特征 | 用途 |
|---|---|---|---|
| `contract-v1`（**默认**） | `docs/CRYPTO-PACK.md` v1 冻结稿 | HEADER 112B、块头 16B | 验收 |
| `rune-v1` | 端侧旧实现（已被删除） | HEADER 40B、块头 9B | **已不可解析**：显式指定报 `LAYOUT_UNAVAILABLE` 并**退出码 4**（不静默回落契约布局）；历史结果归档在 `results/rune-v1-noncontract/`，不重跑不删除（确需复现设 `YS_ALLOW_ARCHIVED_LAYOUT=1`） |
| `auto` | 按头部判别 | — | 排查用；判不出即报错 |

两者**曾不一致**（差异清单见 `results/rune-v1-noncontract/2026-11-02-evidence2-rune-v1.md`）。脚本不猜测：
识别不出就报错退出，绝不拿一套布局去解释另一套的字节。

### 解密后端

| `--backend` | 契约 | 是否生产路径 |
|---|---|---|
| `cmd` | `{in}`/`{out}` 替换成路径；成功 exit 0；失败 exit≠0 且把错误名打到 stdout/stderr | ✅ |
| `cargo-test` | 用 Rune crate 的两个测试过滤器（正向 + 反向），密文经 `YS_TAMPER_ENVELOPE` 传入 | ⚠ 测试入口 |
| `selftest` | 结构校验 + 合成完整性摘要（**不是密码学**），只验证脚本逻辑 | ⚠ 测试替身 |
| `always-ok` | 恒成功，只用于证明"解密成功会被判 FAIL" | ⚠ 测试替身 |

非生产路径时输出顶部会打印
`⚠ 当前走的是测试入口而非生产导出路径 —— 这份结果不能作为最终验收证据`。

### 输入包

* `--envelope <file>`：真实 `.yspk`（端侧产出）。
* `--fixture builtin`：内置契约公开向量（`fixtures/yspk-contract-v{1,2}.hex`，743B/3 块、522B/1 块），
  用于解析回归；**不含任何私钥/口令**。
* `--donor <file>`：`splice-donor-chunk` 需要的第二个包；不给则该项 SKIP（不算 FAIL）。

---

## 3. 目录

```
qa/evidence/
├─ scan_plaintext.py            证据一
├─ tamper_probe.py              证据二
├─ STARTUP.md                   常驻实例启动配方（可直接粘走执行）
├─ check_code_consistency.py    跨实现一致性：用户码派生（4 入口）+ 码归一化（wasm vs Core）
├─ check_prelude_meta.py        prelude-only 元数据语义（能读 + 标注未校验 + 整包入口拒绝半包）
├─ check_token_lifecycle.py     token 生命周期实测（轮换 TOKEN_SECRET / EPOCH 后旧 token 是否失效）
├─ check_upgrade_path.py        **升级路径**：老库缺列 → 跑新版迁移 → 列补上/历史行完好/服务起/幂等
├─ check_restore_after_drop.py  **回滚恢复（模拟）**：手工删列/删表 → 新版迁移恢复 → 旧凭据 401 STALE
├─ check_restore_from_real_drop.py **回滚恢复（真实）**：用含 drop 迁移的旧二进制建库 → 新版恢复
├─ check_contract_impl_parity.py **契约↔实现字面双向核对**（任一方向缺/多即 FAIL，禁 REVOKED）
├─ check_all.sh                 一条命令跑全部：构建 → 自测 → 用户码 → prelude 元数据 → 证据二
├─ run_evidence1_core.sh        证据一一键复跑（起真服务 → 投递 → 三处扫 → 阳性对照）
├─ run_evidence2_contract.sh    证据二一键复跑（契约布局，Rust 原生入口）
├─ run_evidence2_wasm.sh        证据二一键复跑（**wasm 生产导出路径**）
├─ run_evidence2_rune.sh        证据二一键复跑（旧布局，仅对照）
├─ adapters/
│  ├─ ys_pack_probe.rs          Gate 侧驱动（Rust 原生 API）
│  ├─ wasm_pack_probe.mjs       Gate 侧驱动（wasm C ABI，生产导出路径）
│  ├─ build_probe.sh            把驱动塞进端侧 crate 的临时副本并编译
│  └─ README.md                 为什么这样构建、怎么接
├─ fixtures/                    契约公开测试向量 + 样本描述示例
└─ results/                     实测结果，**按布局分目录**：
    ├─ contract-v1/             对契约实现（默认布局）→ 算验收
    └─ rune-v1-noncontract/     对旧/其它实现 → 只作记录与对照
```

---

## 4. 自测覆盖了什么

`scan_plaintext.py --selftest`（9 项）：样本生成/回读、3 MiB 随机语料 0 误报、
跨 1 MiB 缓冲区边界命中且偏移精确、base64 形态命中、文件名命中、
SQLite（`BLOB` 原文 + `TEXT` 十六进制）命中且干净行 0 误报、空语料判 INCONCLUSIVE、
core 表/列白名单核对、`--strict` 强度升级。

`tamper_probe.py --selftest`（13 项）：契约样例解析（743B / 522B）、布局自动识别、
`rune-v1` 布局解析、`rune-v1` 四类篡改、合成包解析（1/2/3 块）、契约布局四类篡改、
附加 3 条用例、**恒成功后端必须被判 FAIL**（判定逻辑非空转）、单块包自动 SKIP、
截断包解析被拒、错误摘要可读、cmd 后端接线（含"没取到错误码时如实标注"）。

---

## 5. 还缺什么

| # | 缺的东西 | 挡住哪一步 |
|---|---|---|
| 1 | ~~Core 服务端跑起来~~ | 已完成：`c3c2fc9` 起真服务 + 完整投递（见 results） |
| 2 | 真实 SM2 验签（Core 侧仍是桩） | 鉴权强度不在本轮证据范围；接了真验签后再复跑一次 |
| 3 | `docs/API.md` 落盘 | 内置 HTTP 投递 / 从服务端拉包重组（见 TODO） |
| 4 | 契约与实现**布局对齐**（`CRYPTO-PACK` vs `pack.rs::layout`） | 证据二现在按 `rune-v1` 跑；对齐后固定一套 |
| 5 | Web 侧 wasm 适配层 | 证据二改用浏览器/Node 侧解密入口再跑一遍 |

未做（第二晚）：UI/手机实测、性能基准、抓包无明文、限速与锁定、国密交叉验证。

### TODO

* `scan_plaintext.deliver_via_http()`：按 `docs/API.md` + 传输映射实现 prelude/块切片上传。
* `tamper_probe`：从服务端"prelude + 块切片"重组成 `.yspk`，省掉手工导出。
* 证据一增补"抓包"数据源（pcap → 同样的检索项）。

---

## 6. 已知限制

1. **PG 是逻辑层扫描**（`row_to_json`）：覆盖表数据，不覆盖 WAL / 数据页残留 / 未 VACUUM 的死元组。
2. **短记号是弱信号**：扩展名裸串、< 8 字节片段命中只报警不改退出码；严格口径加 `--strict`。
3. **`splice-donor-chunk` 要求 donor 块等长**，否则 SKIP 并说明原因。
4. **`cargo-test` 后端需要 Rune 提供两个过滤器**（正向 + 反向）；只给一个时 baseline 会 SKIP。
5. **`scan_plaintext` 只做存在性检索**，不做语义判断：命中位置仍需人复核。
6. **证据二的 `cmd` 后端若只拿到非零退出码、没有错误名**，会在结果里如实标注"未取到错误码"，
   不会把"程序崩了"当成"明确报错"。

---

## 7. 安全与红线

* 脚本里**没有**任何密钥、凭据、真实分享码；样例里的 `hi-entropy` 是随机串，不是真实令牌。
* `fixtures/*.hex` 是 `docs/CRYPTO-PACK.md` §15 公布的**公开测试向量**，`DK` 只以 SM2 密文出现，
  不含私钥；生产代码不得引用。
* 证据二用的密钥是每次现场生成的，落在 workdir（默认 `/tmp`），不入仓库、不入日志。
* 数据库连接串只从参数/环境变量取，输出统一打码（`user:***@host`）。
* 临时产物都在系统临时目录，结束即删；给了 `--out-dir`/`--keep` 才保留。
* 脚本只读被检对象（存储目录、数据库只读连接），不写、不改、不删服务端数据。

---

## 8. 变更记录

* 2026-11-02 首夜：骨架落地。证据一（存储 + PG/SQLite 检索、投递钩子、8 项自测）；
  证据二（YSPK 解析、四类篡改 + 3 条附加、4 种后端、10 项自测）。
* 2026-11-02 首夜·三轮：默认布局切到契约布局（`--layout` 默认 `contract-v1`），
  非契约布局输出加"不作验收"横幅并在 JSON 里带 `contract_compliant`；
  证据一新增**日志扫描**（`--log-path` / `--log-cmd`）与五项参数可勾选清单。
* 2026-11-02 首夜·二轮：证据二接上端侧真实实现（`adapters/ys_pack_probe.rs` + `run_evidence2_rune.sh`），
  新增 `--layout`（contract-v1 / rune-v1 / auto）、`--expect-plaintext`（baseline 明文比对），
  实测 10/10 + 16 种补充变体全部被拒；证据一新增 `--profile core-skeleton` 与退出码 4（PENDING）。
