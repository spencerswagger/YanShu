# qa/evidence · 验收证据脚本

两条证据的**可复跑脚本**：① 服务端无明文/无文件名；② 密文篡改必报错。

> **当前状态（2026-11-02 首夜·二轮）**
> * 证据二 **已能出真结果**：对象是端侧真实实现（`crypto/sm` 的 `pack::unpack`），
>   10/10 篡改全部被明确拒绝，附加 16 种变体无一漏网 —— 见
>   `results/2026-11-02-evidence2-rune.md`。
> * 证据一仍是骨架：检索逻辑、投递钩子、数据库/存储扫描都已可用且自测通过，
>   但**服务端还没跑起来**（`feat/server-skeleton` 未合入、migrations 未跑），
>   强制 `--profile core-skeleton` 会明确打印「待 Core 合入 + 参数确认」并以退出码 4
>   结束 —— 既不伪装 PASS，也不误报 FAIL。

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

目标：**存储目录**（递归，整文件流式扫，跨 1 MiB 缓冲区边界不漏）+ **数据库**
（PostgreSQL 经 `psql` 逐表逐行；SQLite 逐表逐行逐列）。

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
* 表/列白名单来自 `server/internal/store/migrations/0001_init.sql`（7 张表）；检索前先核对，
  缺表或出现白名单外的表/列都会在报告里点名

任一必需项拿不到 → 打印缺什么、以退出码 4 结束，不出假结论。

### 投递钩子（等闭环一成就能接）

`--deliver-cmd '<命令>'` 会先跑一次投递，再检索。命令通过环境变量拿到样本：

```
YS_SAMPLE_JSON / YS_SAMPLE_FILE / YS_SAMPLE_NAME / YS_SAMPLE_MIME / YS_SAMPLE_ID
YS_RECIPIENT_CODE   收件方 4 位码（只透传，不打印、不落盘）
```

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

判定：**解密成功 = FAIL**（含"返回部分明文"）；**明确报错 = PASS**。
`--expect-plaintext <file>` 给了以后，baseline 还要逐字节比对明文，否则整轮不算数。

### 包布局（两套，自动识别）

`--layout auto`（默认）按包头判别，输出里会写明：

| 布局 | 来源 | 特征 |
|---|---|---|
| `contract-v1` | `docs/CRYPTO-PACK.md` v1 冻结稿 | HEADER 112B、块头 16B |
| `rune-v1` | `crypto/sm/src/pack.rs::layout` 当前实现 | HEADER 40B、块头 9B |

两者**目前不一致**（差异清单见 `results/2026-11-02-evidence2-rune.md`）。脚本不猜测：
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
├─ run_evidence2_rune.sh        证据二一键复跑（对端侧真实实现）
├─ adapters/
│  ├─ ys_pack_probe.rs          Gate 侧驱动：用 yanshu-sm 打包 / 解包
│  ├─ build_probe.sh            把驱动塞进端侧 crate 的临时副本并编译
│  └─ README.md                 为什么这样构建、怎么接
├─ fixtures/                    契约公开测试向量 + 样本描述示例
└─ results/                     实测结果（按日期）
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
| 1 | Core 的服务端**跑起来**（合入 main + migrations + `YANSHU_BLOB_DIR`/`YANSHU_DATABASE_URL` 落地） | 证据一的真实检索（现在只能 PENDING） |
| 2 | 端到端投递（A 加密上传 → B 解密落盘） | 证据一没有真实投递产物 |
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
* 2026-11-02 首夜·二轮：证据二接上端侧真实实现（`adapters/ys_pack_probe.rs` + `run_evidence2_rune.sh`），
  新增 `--layout`（contract-v1 / rune-v1 / auto）、`--expect-plaintext`（baseline 明文比对），
  实测 10/10 + 16 种补充变体全部被拒；证据一新增 `--profile core-skeleton` 与退出码 4（PENDING）。
