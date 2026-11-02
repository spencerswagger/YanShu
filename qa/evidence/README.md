# qa/evidence · 验收证据脚本（骨架）

两条证据的**可复跑脚本**：① 服务端无明文/无文件名；② 密文篡改必报错。

> 现状：首夜（2026-11-02）闭环未通，端侧加密内核与服务端骨架还在写。
> 这两个脚本是**骨架 + 可参数化驱动**：逻辑与判定已经能自测，端侧入口一就绪即可跑真证据。
> 每个脚本都带 `--selftest`，不需要 Rune/Core/网络就能验证"脚本本身不是空壳"。

只依赖 **python3 ≥ 3.10 标准库**（DB 检索额外用 `psql` 客户端；SQLite 用内置 `sqlite3`）。
不实现、不调用任何加解密；不读密钥与凭据文件；不修改被检对象。

---

## 0. 三十秒上手

```sh
# 自测（现在就能跑，两个都应显示全 PASS）
python3 qa/evidence/scan_plaintext.py --selftest
python3 qa/evidence/tamper_probe.py --selftest

# 证据一：对已有投递的存储 + 数据库检索
python3 qa/evidence/scan_plaintext.py \
    --storage-root /var/lib/yanshu/blobs \
    --dsn "$TEST_DATABASE_URL" \
    --sample qa/evidence/fixtures/sample-delivery.example.json

# 证据二：解析/构造预演（不跑解密）
python3 qa/evidence/tamper_probe.py --fixture builtin --dry-run --extra-cases
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

任何 advisory 命中都会在汇总行单独计数，不会被静默吞掉。

### 退出码

| 码 | 含义 |
|---|---|
| 0 | PASS：所有强信号项未命中 |
| 1 | FAIL：至少一个强信号项命中（逐条打印 文件/表 + 偏移 + 定位上下文） |
| 2 | BLOCKED：没有可检索目标、投递命令失败、`psql` 不可用等 |
| 3 | INCONCLUSIVE：扫了 0 文件 0 字节 0 行 —— "没命中"不构成证据 |

> 退出码 3 是刻意的：扫空目录/空库拿到 PASS 是假证据。要么给出真实存储根目录，要么先跑投递。

### 投递钩子（等闭环一成就能接）

`--deliver-cmd '<命令>'` 会先跑一次投递，再检索。命令通过环境变量拿到样本：

```
YS_SAMPLE_JSON   样本描述 JSON 路径
YS_SAMPLE_FILE   样本文件路径（sample.bin）
YS_SAMPLE_NAME   原文件名（就是要去搜的那个名字）
YS_SAMPLE_MIME
YS_SAMPLE_ID
YS_RECIPIENT_CODE  收件方 4 位码（只透传，不打印、不落盘）
```

投递命令非 0 退出 → 脚本以 2 退出（BLOCKED），不会拿半截数据出结论。

### 定位输出长什么样

```
[05] fragment:hi-entropy     hard     storage    7      HIT    明文片段（48B）
       ↳ /var/lib/yanshu/blobs/ab/cd1234  offset=22  form=raw  before=0a746f6b656e3a20 after=0a6e6f74653a20e9
```

只回显左右各 8 字节的十六进制定位上下文，**不回显整段明文**；`--json-out` 同样只存 hex 上下文。

### 数据来源口径

* 存储目录：整目录递归，不假设 Core 的块命名规则（Core 的布局变了也不用改脚本）。
* PostgreSQL：`row_to_json` 逐行取，`TEXT` 列明文原样、`BYTEA` 列以 `\x<hex>` 出现，
  所以 hex 形态的检索项正是用来抓 `bytea` 里的明文的。
* SQLite：逐列取，`BLOB` 按原始字节扫、`TEXT` 按 UTF-8 扫。

---

## 2. 证据二：`tamper_probe.py`

### 用例

| 用例 | 做什么 | 对应契约 |
|---|---|---|
| `baseline` | **未篡改的包必须先能解密成功**（否则 BLOCKED，防假 PASS） | §13 |
| `flip-envelope-header` | 翻转包头 1 字节（`KDF_SALT`，签名覆盖区） | §10.2 |
| `flip-chunk-header` | 翻转块头 1 字节（`CHUNK_INDEX`） | §6.2 / §6.4 |
| `flip-chunk-data` | 翻转密文中间 1 字节 | §7 / §13#20 |
| `drop-middle-chunk` | 删除中间块整条记录 | §6.4 / §13#22 |
| `swap-chunks` | 交换两个块的顺序 | §6.4 |
| `splice-donor-chunk` | 用**另一个包**的合法块替换整块（需 `--donor`） | §13#20 |
| `flip-chunk-tag`（`--extra-cases`） | 翻转 GCM tag 1 字节 | §7.1 |
| `drop-chunk-slice`（`--extra-cases`） | 只删"密文+tag"、留块头 | §6.2 |
| `truncate-tail`（`--extra-cases`） | 截掉尾块 | §6.4 / §13#22 |

判定：**解密成功 = FAIL**（含"返回部分明文"）；**明确报错 = PASS**。
任何一条 FAIL → 退出码 1。全 PASS（允许 SKIP）→ 0。基线不过/后端缺失 → 2。

### 解密后端（按就绪程度挑一条）

| `--backend` | 契约 | 是否生产路径 |
|---|---|---|
| `cmd` | `{in}` 替换成密文路径；成功 exit 0；失败 exit≠0 且把 `CRYPTO_*` 打到 stdout/stderr | ✅ |
| `cargo-test` | 用 Rune crate 的两个测试过滤器：`--cargo-test-error-filter`（断言篡改必报错）、`--cargo-test-ok-filter`（断言合法包能解）；通过 exit 0；密文经 `YS_TAMPER_ENVELOPE` 传入 | ⚠ 测试入口 |
| `selftest` | 结构校验 + 合成完整性摘要（**不是密码学**），只验证脚本逻辑 | ⚠ 测试替身 |
| `always-ok` | 恒成功，只用于证明"解密成功会被判 FAIL" | ⚠ 测试替身 |

非生产路径时，输出顶部会明确打印：
`⚠ 当前走的是测试入口而非生产导出路径 —— 这份结果不能作为最终验收证据`。

### 输入包

* `--envelope <file>`：真实 `.yspk`（端侧产出，或按契约 §12 从服务端 prelude + 块切片重组）。
* `--fixture builtin`：内置契约公开向量（`fixtures/yspk-contract-v{1,2}.hex`，743B/3 块 与 522B/1 块），
  用于自检解析与构造。**不含任何私钥/口令**。
* `--donor <file>`：第四个用例需要第二个包；不给则该项 SKIP（不算 FAIL）。

---

## 3. 自测覆盖了什么

`scan_plaintext.py --selftest`（8 项）：样本生成/回读、3 MiB 随机语料 0 误报、
跨 1 MiB 缓冲区边界命中且偏移精确、base64 形态命中、文件名命中、
SQLite（`BLOB` 原文 + `TEXT` 十六进制）命中且干净行 0 误报、空语料判 INCONCLUSIVE、
`--strict` 强度升级。

`tamper_probe.py --selftest`（10 项）：契约样例解析（743B/522B 两种）、合成包解析（1/2/3 块）、
四类篡改全部被拒、附加 3 条用例、**恒成功后端必须被判 FAIL**（判定逻辑非空转）、
单块包自动 SKIP、截断包解析被拒、错误摘要可读、cmd 后端接线（含"没取到错误码时如实标注"）。

---

## 4. 骨架状态：还缺什么才能出真证据

| # | 缺的东西 | 挡住哪一步 | 就绪后怎么接 |
|---|---|---|---|
| 1 | Core 的**存储根目录**与**数据库 schema** | 证据一没有检索目标 | 直接给 `--storage-root` / `--dsn`，无需改脚本 |
| 2 | 端到端投递能跑通 | 证据一拿不到真实投递产物 | 填 `--deliver-cmd`（或用已有投递的存储） |
| 3 | Rune 的**解密入口**（CLI 或测试二进制） | 证据二只能跑 `selftest` | `--backend cmd --decrypt-cmd '...'` |
| 4 | 一份真实 `.yspk` 样本 | 证据二没有真包可破坏 | `--envelope`；或用 `--fixture builtin` 先做解析回归 |
| 5 | `docs/API.md`（HTTP+WS 契约） | 没有内置 HTTP 投递 / 从服务端拉包重组 | 见下方 TODO，落盘后补两条分支 |

未做（第二晚）：UI/手机实测、性能基准、抓包无明文、限速与锁定、国密交叉验证。

### TODO（留给闭环后）

* `scan_plaintext.deliver_via_http()`：按 `docs/API.md` + `CRYPTO-PACK §12` 实现 prelude/块切片上传。
* `tamper_probe`：从服务端"prelude + 块切片"重组成 `.yspk`，省掉手工导出。
* 证据一增补"抓包"数据源（pcap → 同样的检索项）。

---

## 5. 已知限制（写清楚，别当成通过）

1. **PG 是逻辑层扫描**（`row_to_json`）：覆盖表数据，不覆盖 WAL / 数据页残留 / 未 VACUUM 的死元组。
   若怀疑物理层泄露，需要另做 `pg_dump` 或直接翻数据目录（第二晚）。
2. **短记号是弱信号**：扩展名裸串、< 8 字节片段命中只报警不改退出码；要严格口径加 `--strict`。
3. **`splice-donor-chunk` 要求 donor 块长度相同**，否则 SKIP 并说明原因（等长是包格式的常态：
   `CHUNK_SIZE` 相同即等长）。
4. **`cargo-test` 后端需要 Rune 提供两个过滤器**（正向 + 反向）；只给一个时 baseline 会 SKIP。
5. **`scan_plaintext` 只做"存在性检索"**，不做语义判断：命中位置仍需人复核（脚本给的是偏移与定位上下文）。

---

## 6. 安全与红线

* 脚本里**没有**任何密钥、凭据、真实分享码；样例里的 `hi-entropy` 是随机串，不是任何真实令牌。
* `fixtures/*.hex` 是 `docs/CRYPTO-PACK.md` §15 公布的**公开测试向量**，`DK` 只以 SM2 密文出现，
  不含私钥；生产代码不得引用。
* 数据库连接串只从参数/环境变量取，输出统一打码（`user:***@host`）。
* 临时产物都在系统临时目录，结束即删；给了 `--out-dir`/`--keep` 才保留。
* 脚本只读被检对象（存储目录、数据库只读连接），不写、不改、不删服务端数据。

---

## 7. 变更记录

* 2026-11-02 首夜：骨架落地。证据一（存储 + PG/SQLite 检索、投递钩子、8 项自测）；
  证据二（YSPK 解析、四类篡改 + 3 条附加、4 种后端、9 项自测）。
  依赖未就绪：Rune 解密入口、真实 `.yspk`、`docs/API.md`、Core 存储/DB 布局。
