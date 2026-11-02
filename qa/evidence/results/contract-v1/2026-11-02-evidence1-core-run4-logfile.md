# 证据一复扫（run #4）：日志改用 `YANSHU_LOG_FILE`，并对比 LEASED / CONSUMED 残留

- 日期：2026-11-02
- 对象：服务端 `feat/server-skeleton` @ `28d75b0` + 端侧 `feat/endcrypto-wasm` @ `a33c2de`
- 库：`yanshu_test` / schema `gate_ev1`；投递：Core 官方 `server/bin/deliver`
- **日志：`YANSHU_LOG_FILE` 指向的正式文件**（`server-file.log`，3119B）——
  不是之前的 stdout 重定向，也不是 `YANSHU_LOG_DIR`（那个变量服务端不再用）
- 结论：三处零命中，退出码 0；三组阳性对照全部成立

## 复跑

```sh
YS_BASE_DSN="$PG_TEST_DSN" \
YS_EV1_LOG_MODE=file \
YS_DELIVER_BIN=core-deliver \
qa/evidence/run_evidence1_core.sh <core-src> <rune-crate> /tmp/ys-ev1
```

## 三处扫描

| 目标 | 语料量 | 强信号命中 |
|---|---|---|
| 存储 `<BLOB_DIR>/c2/c2cc9f…/{prelude,chunks/*}` | 3 文件 / 2242B | 0 |
| PostgreSQL `yanshu_test`…`gate_ev1` | 8 表（7 业务 + 1 记账）/ 373 行 | 0 |
| **`YANSHU_LOG_FILE`** `server-file.log` | 1 份 / 3119B | 0 |

阳性对照（存储注入 / 日志注入 / DB 注入 / 复原）全部按预期：1 / 1 / 1 / 0。

## 新增：LEASED 与 CONSUMED 两种终态的存储残留对比

同一套流程跑两次投递，唯一差别是第二次带 ack（服务端按策略删密文）：

| 状态 | 怎么产生 | 该笔 transfer 目录 | 说明 |
|---|---|---|---|
| **LEASED** | `deliver --no-ack` | **3 个文件（prelude + 2 块，2242B）** | 证据一就是扫这个状态——密文还在，扫"无明文"才有意义 |
| **CONSUMED** | `deliver`（不传 `--no-ack`，走完整 ack） | **目录已删除，0 个文件** | 服务端在 ack 后真删了密文 |

全局文件数 LEASED→CONSUMED 是 `3 → 3`，**不是没删**：第二次那笔删干净了，
剩下的 3 个文件属于第一次故意没 ack 的那笔（对照用）。所以这条对比必须**按 transfer 目录看**，
不能看全局计数——看全局会得出"删了但没删"的错误结论。

> 这条也回答了"收到即删"到底做实没有：**做实了**（该笔目录整体消失，不是只删块）。

## 追加：按 Core 给的完整命令形态复跑

Core 确认 `deliver` 支持 `--dsn "${PG_DSN}&search_path=<schema>"`（pgx 侧已能解析），
脚本默认参数随即补上 `--dsn {dsn}`，并新增**存储落点断言**（驱动报的 `storage_path`
必须落在本次 `blob_dir` 下且非空）。复跑结果：存储 3 文件 / 2242B、日志 1 份 / 3119B、
DB 8 表（7 业务 + 1 记账）/ 474 行，**三处零命中**，阳性对照 1/1/1/0，退出码 0。

## 边界（仍然有效）

1. **认证仍是 `stub-allow`**：本证据只覆盖"存储/DB/日志不落明文"，不构成认证验收。
2. **日志来源**：本轮是 `YANSHU_LOG_FILE` 的正式文件；`YANSHU_LOG_DIR` 那条已被服务端废弃，
   本工具保留 `YS_EV1_LOG_MODE=dir/stdout` 只为复现历史 run。

## 未覆盖

真实验签、TTL 到期清理、撤回删密文、抓包层无明文。

## 附：宿主常驻实例上的跨端冒烟（非证据，库是 `yanshu_dev`）

spencer 在宿主起的常驻实例 `http://127.0.0.1:18080`（契约 v1 / `YSPK/1.0` / 1 MiB 块）上做了一次冒烟：

| 项 | 结果 |
|---|---|
| `/healthz` | 200 `{"status":"ok","api_version":"v1","contract":"v1"}` |
| `/v1/config` | `chunk_size=1048576`、`max_plaintext=4294967296`、`ttl≤86400`、STUN 已下发、`ws_url` 空 |
| 单块包（715B 明文 / 1 块 / 1226B 密文） | 投递 `state=LEASED`；GET 回来的 prelude 495B **逐字节一致** |
| 三块包（3072B 明文 / 3 块 / 3746B 密文） | 投递 `state=LEASED`；prelude + 3 块 **全部逐字节一致** |

> 这是"跨端冒烟"，不是证据：库是 `yanshu_dev`、走 `stub-allow`，且用的是宿主实例。
> 证据类扫描仍只用 `yanshu_test` 的 `gate_ev1`，不扫 `yanshu_dev`。

## 追加：`9065eb8` + `YANSHU_LOG_DIR`（按日滚动）复扫

Core 在 `9065eb8` 把日志做成**按 UTC 日期滚动**（`<dir>/yanshu-server-YYYY-MM-DD.log`，
0640，默认保留 7 天，只清理自己的命名规则）。证据一改成扫这个目录：

```sh
YS_BASE_DSN="$PG_TEST_DSN" YS_EV1_LOG_MODE=dir YS_DELIVER_BIN=core-deliver \
qa/evidence/run_evidence1_core.sh <core@9065eb8> <rune-crate> /tmp/ys-ev1
```

| 目标 | 语料量 | 命中 |
|---|---|---|
| 存储 | 3 文件 / 2240B | 0 |
| PostgreSQL `gate_ev1` | 8 表（7 业务 + 1 记账）/ 571 行 | 0 |
| **轮转日志** `yanshu-server-2026-11-02.log` | 1 份 / 3132B | 0 |

阳性对照 1/1/1/0（**日志那条注入的就是轮转文件本身**），退出码 0。

**边界更新**：日志这条不再是"部署重定向的 stdout"，而是**服务端自己写的正式轮转文件**；
认证仍是 `stub-allow`，所以本证据依旧不构成认证验收。

### 跨天滚动怎么处理

滚动会换文件名，硬编码"今天"的文件名会在边界前后漏扫。做法：

1. 记录本次运行开始时间 `T_START`；启动后断言 `find <dir> -name 'yanshu-server-*.log' -newermt @T_START`
   至少有一个非空文件，否则 BLOCKED；
2. **扫描整个目录**（两天都覆盖），而不是单个文件；
3. 阳性对照注入到目录里**最新**那个文件。

模拟验证：把当日文件复制成"次日"名字后再扫 → `日志 2 份 / 6264B`；
只按单个文件名扫 → `日志 1 份 / 3132B`（少一半，正是要避免的漏扫）。
