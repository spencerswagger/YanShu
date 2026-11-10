# 干净环境真实收发自测 · 清单一键执行版

一个脚本 + 一份清单，回答「打出来的这版，在干净机器上到底能不能真收真发、重启会不会丢」。
**不依赖谁在改代码**：脚本自己从 git ref 取纯净树、自己建新库、自己生成密钥。

## 一键跑

```sh
# 前置：go / psql / git；DSN 的角色要能 CREATE DATABASE
python3 qa/evidence/release/clean_env_selftest.py \
  --ref origin/main \
  --dsn "$TEST_DATABASE_URL" \
  --work /tmp/yanshu-clean \
  --rows 600000 \
  --json-out /tmp/yanshu-clean.json
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--ref` | `origin/main` | 用 `git archive` 取**纯净树**（无 `.git`、无构建产物），不切分支、不动工作树 |
| `--dsn` | `TEST_DATABASE_URL` | 连它建一个**新库** `yanshu_selftest_<UTC>`；不碰既有库/既有 schema |
| `--work` | `/tmp/yanshu-clean` | 空的数据目录（blobs/logs/bin/secrets 全在它下面），跑完默认删掉 |
| `--rows` | `600000` | 建索引锁写实测用的行数；太小会判 BLOCKED（窗口 <300ms 不可判定） |
| `--skip-index` | 关 | CI 快速跑时可跳过（约省 13s） |
| `--skip-restart` | 关 | 跳过 down/up（不建议：那正是「密钥不变」的证明） |
| `--keep` | 关 | 保留工作目录与新库，排障用；不加则结束时**真的删**（日志会打印） |
| `--selftest-break-keys` | 关 | 自检用：down 之后故意改写 `token_secret`，验证「密钥不变」那条会红 |
| `--json-out` | 无 | 结构化结果（含每项证据、二进制 sha256、ref/commit） |

退出码：`0` 全过 ｜ `1` 有 FAIL ｜ `2` 前置缺失（BLOCKED，不算失败）。

## 清单（脚本逐条断言，PASS 必须带原始值）

| # | 检查项 | 判据 | 证明什么 |
|---|---|---|---|
| 1 | 纯净检出 | 树里没有 `.git`、文件数 > 50 | 测的不是谁的工作区 |
| 2 | 新库是空的 | 迁移前 `public` 表数 = 0 | 没有旧 schema 兜底 |
| 3 | secrets 首次生成 | 两个文件 0600 + 纯 hex | 与 compose `init` 同口径 |
| 4 | 首次启动 | `/healthz` 200，迁移自动落库 | 空数据目录能自举 |
| 5 | 上传后密文落盘 | ack 前块目录**存在** | 后面那条"删除"才有对照 |
| 6 | 真收真发 A | prelude + 每块**两侧 sha256 相同**；ack → `CONSUMED` | 收发不是"看起来成功" |
| 7 | ack 后密文删除 | 块目录不存在 | 过而不留 |
| 8 | 真收真发 B | 留一条 `READY`，记录 prelude/chunk sha256 | 给重启比对留样本 |
| 9 | 契约 §1.7.4 | 终结态上传 = `410 TRANSFER_CONSUMED`（不是 401） | 规则真跑，不是文档写着 |
| 10 | 契约 §1.7.4 | 未终结 + 伪造凭据 = `401 AUTH_TOKEN_INVALID` | 阴性对照，防"一律 410" |
| 11 | 契约 §0.2 | 未路由路径 = 404 JSON 信封 | main 未含 #58 时记 **WARN**（不算通过、也不算失败） |
| 12 | 建索引锁写 | 普通 `CREATE INDEX` 期间单条写 >300ms；`CONCURRENTLY` <300ms | 迁移不会挡写 |
| 13 | down | `SIGTERM` 后 exit=0 | 优雅退出 |
| 14 | down && up 密钥不变 | 每次 `up` 前重跑一遍 compose init，再比 secrets 两文件 sha256 前后一致 | 重启不换密钥（init 若被改成重新生成，这条会红） |
| 15 | 重启后密文不变 | 同一 transfer 的 prelude/chunk sha256 与重启前相同 | 数据没被搬坏 |
| 16 | 重启后旧凭据仍可用 | 旧 `upload_token` 打 status = 200 | 重启不把用户凭据作废（**注意**：这不能证明 secret 没换，`upload_token` 校验只比 SM3，secret 只作派生盐） |

## 预期输出样例（2026-11-11 03:39 CST 真跑，main `200d26b`）

```
PASS  纯净检出（无 .git、空数据目录）                commit=200d26b350c3 files=498
PASS  新库是空的（迁移前 public 无表）              tables=0
PASS  secrets 首次生成（0600，hex）               sha256={'token_secret': '…'} mode={'token_secret': '0o600'…}
PASS  首次启动（空数据目录 + 新库，迁移自动落库）      healthz=200 log=…/selftest-server.log
PASS  上传完成后密文确实落盘（ack 前）              … exists=True
PASS  真收真发 A：prelude+3 块逐字节一致 + ack→CONSUMED  sha256(prelude)=88e785f8ea20… ack=200 CONSUMED
PASS  ack 后密文物理删除                          残留=False
PASS  真收真发 B：留一条 READY 供 down/up 后比对     tid=… sha={'prelude': '88e785f8ea'…}
PASS  契约 §1.7.4：终结态上传必须 410（且不返回 401）  410 TRANSFER_CONSUMED
PASS  契约 §1.7.4：未终结 + 伪造凭据必须 401 …       401 AUTH_TOKEN_INVALID
WARN  契约 §0.2：未路由路径必须是错误信封             404 text/plain（main 未含 #58，记 SKIP 不算通过）
PASS  建索引期间写入不被阻塞（普通 vs CONCURRENTLY）  普通建索引 12xx ms/写最长 11xx ms；CONCURRENTLY …/写最长 <300ms
PASS  down：进程正常退出                          exit=0
PASS  down && up 后 secrets sha256 不变          token=… pg=…
PASS  重启后取回同一密文 sha256 不变               before=88e785f8ea… after=88e785f8ea…
PASS  重启后旧 upload_token 仍可用（凭据不因重启失效）  status=200
PASS 15　WARN(SKIP) 1　FAIL 0　共 16 项　结论：PASS
```

（完整原始日志与 JSON 在 `results/`，每次运行带 UTC 时间戳与二进制 sha256。上面 `WARN` 不影响退出码，
它只说明"main 还没合 #58"；#58 合入后这项会自动转 PASS，不需要改脚本。`--skip-index` / `--skip-restart`
跳过的项也记 WARN，所以汇总行会把 PASS / WARN / FAIL **分开计数**，不会把没跑的算成通过。）

## 自检：这两条"密钥不变"真能红吗

```sh
python3 qa/evidence/release/clean_env_selftest.py --skip-index --selftest-break-keys ...
# 期望：down 之后改写 token_secret → 「down && up 后 secrets sha256 不变」FAIL，退出码 1
```

这是 Owl II 复审提的必改项：原来的写法只在首次启动前读一次 secret，down/up 复用同一个 env，
第 14 条**结构上不可能红**。现在每次 `up` 前都重跑一遍 compose init（不存在才生成）并**从文件重读**
secret 构造 env —— init 若被改成"每次重新生成"，或有人换了密钥，第 14 条会立刻红。

## 反向验证（门禁必须能红）

```sh
qa/evidence/release/negative_checks.sh origin/main /tmp/yanshu-negative
```

三处故意破坏 + 一处基线。脚本自己建一个**隔离库**（`yanshu_neg_<UTC>`）跑，跑完删掉 ——
httpapi 夹具用的是固定 schema 名，跟别人同时跑同一包会互删 schema，不隔离就会冒出
`no schema has been selected to create in` 这种"假失败"。

判定不是"退出码非 0 就算抓到"，而是**必须红在预期断言上**：

| 变异 | 必须出现的断言消息 |
|---|---|
| `#57-a` 事务迁移里塞普通 `CREATE INDEX` | `0011_mutant_plain_index.sql` |
| `#57-b` 删掉 `0010` 的 `-- yanshu:no-transaction` 头 | `文件头没有` |
| `#56` 把「终结态预判」挪到「凭据存在性」之后 | `§1.7.4 被违反` |

（只要求"有 `--- FAIL`"是不够的：环境炸库也会产生 `--- FAIL`，那会把"跑不起来"误判成"门禁有牙"。）

退出码：0 = 三处全被抓；1 = 有变异没被抓（门禁假绿）；2 = 环境不成立（连不上库/并发踩踏，
**不是**门禁结论）。

## 已知边界

- 沙盒无 docker，脚本走**原生进程**（二进制 + 真 PG + 独立数据目录），不跑 `docker compose`。
  compose 的 `down && up` 与这里验证的语义相同（密钥文件、数据卷、二进制不变），但**容器层未验**；
  有 docker 的机器上建议再用 `docker compose up -d && down && up -d` 复核一遍。
- `--rows` 太小（建索引 <300ms）会直接判 BLOCKED，而不是给一个"没阻塞"的假结论。
- 契约 §0.2 那项依赖 #58 是否已合入，脚本用 WARN 标注，不冒充通过。
