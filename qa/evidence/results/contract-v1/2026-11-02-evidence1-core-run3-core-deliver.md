# 证据一复扫（run #3）：投递改用 Core 官方 `deliver`，日志用内建滚动

- 日期：2026-11-02
- 对象：服务端 `feat/server-skeleton` @ `2bc7dae`（含 `cmd/deliver` 与内建日志滚动），
  配端侧 `feat/endcrypto-wasm` @ `e9f8254` 打的真契约包
- 库：`yanshu_test` / schema `gate_ev1`（DSN 从 `/.keys/pg.env` 读，不落文件）
- 日志：服务端内建 `yanshu-server-2026-11-02.log`
- **投递：Core 的 `server/bin/deliver`**（不再用 Gate 自己的投递客户端）
- 结论：三处零命中，退出码 0；三组阳性对照全部成立

## 与 run #1 / #2 的差别

| 项 | run #1（初步） | run #2 | run #3（本份） |
|---|---|---|---|
| 日志 | 部署重定向 stdout | 内建滚动 | 内建滚动 |
| 投递 | Gate 的 `core_delivery.py` | Gate 的 `core_delivery.py` | **Core 官方 `deliver`** |
| 验签 | stub-allow | stub-allow | **stub-allow（仍未接真 SM2）** |

差异集中在"投递是谁做的、日志落在哪"；**认证链路仍然是桩**，两条边界继续有效。
真实 `sm2` 接入后跑 run #4。

## 复跑（一条命令）

```sh
YS_BASE_DSN="$PG_TEST_DSN" \
YS_EV1_LOG_MODE=dir \
YS_DELIVER_BIN=core-deliver \
qa/evidence/run_evidence1_core.sh <core-src> <rune-crate> /tmp/ys-ev1
```

`YS_DELIVER_BIN=core-deliver` 会现场编译 `<core-src>/server/cmd/deliver`，并用这套参数调它：

```
--base-url http://127.0.0.1:{port} --yspk {pack} --no-ack --blob-dir {blob} --json-out {json}
```

- `{port}` 是本次脚本挑的空闲端口；`{pack}` 是本次生成的真 `.yspk`；`{blob}` 是本次 blob 目录；
  `{json}` 是驱动写出的 JSON，**脚本从这份 JSON 取 `package_id` / `blob_dir`（`storage_path`）
  / `schema`**，不从 stdout 猜。
- 未传 `--dsn`：Core 的 `deliver` 用 pgx 解析 DSN，带 `search_path` 参数会连不上；
  `--dsn` 只用于打印 database/schema，没必要为它牺牲 schema 隔离。
- 服务端必须 `YANSHU_VERIFIER=stub-allow`，否则 `deliver` 退出码 4（fail-closed），
  脚本会以 BLOCKED 收场，不会假装成功。

## 结果

| 目标 | 语料量 | 强信号命中 |
|---|---|---|
| 存储 `<BLOB_DIR>/6a/6a149164589b726626cc674835da1ce8/{prelude,chunks/*}` | 3 文件 / 2241B | 0 |
| PostgreSQL `yanshu_test`…`gate_ev1` | 8 表 / 283 行 | 0 |
| 内建日志 `yanshu-server-2026-11-02.log` | 1 份 / 3035B | 0 |

阳性对照：存储注入 → 1、日志注入 → 1、DB 注入 → 1、复原 → 0。

## 本轮修掉的三个坑（都会造成假证据）

1. **端口撞车**：改用"内核给空闲端口"（`bind(127.0.0.1, 0)`）而不是固定/PID 派生端口；
   启动校验也补上了"日志里有 listening + 无 bind 失败 + 进程活着"。
2. **`sed` 吃 `&`**：占位符替换原来用 `sed`，DSN 里的 `&` 被当成"整个匹配"展开，
   结果拼出一个坏 DSN（`…disable{dsn}search_path=…`），扫描直接 PENDING。改成 python 替换。
3. **`--deliver-json` 优先**：脚本现在优先读驱动写出的 JSON 文件，缺失才退回 stdout 解析；
   同义键 `transfer_id→package_id`、`storage_path→blob_dir` 都认；**必填只有这两个**，
   缺了退出码 4 并点名。

## 未覆盖

真实验签、ack 后删除 / TTL / 撤回、抓包层无明文（同前几轮）。
