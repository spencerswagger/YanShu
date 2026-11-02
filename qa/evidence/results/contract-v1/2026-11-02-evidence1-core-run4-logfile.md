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
| PostgreSQL `yanshu_test`…`gate_ev1` | 8 表 / 373 行 | 0 |
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
