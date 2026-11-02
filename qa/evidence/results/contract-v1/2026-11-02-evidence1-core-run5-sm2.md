# 证据一 run #5：**真认证链路**（`YANSHU_VERIFIER=sm2`）

- 日期：2026-11-02
- 对象：服务端 `feat/server-skeleton` @ `08d40e7`（含 `deliver --sender-sk/--recipient-sk`），
  端侧 `feat/endcrypto-wasm` @ `0f33a15` 打的真契约包
- 库/schema：`yanshu_test`.`gate_ev1`（Gate 自己起实例，不碰宿主实例与 `yanshu_dev`）
- 认证：**`YANSHU_VERIFIER=sm2`（真实 SM2 验签，非 stub）**
- 日志：`YANSHU_LOG_DIR` 轮转文件 `yanshu-server-2026-11-02.log`
- 投递：Core 官方 `deliver`，**带真签名**（`--sender-sk` / `--recipient-sk`）
- 结论：**三处零命中，退出码 0**；三组阳性对照 1/1/1/0

## 与前四轮的定位差异

| 轮次 | 认证 | 日志 | 投递 |
|---|---|---|---|
| run #1（初步） | stub-allow | 部署重定向 stdout | Gate 客户端 |
| run #2 | stub-allow | 内建按日滚动 | Gate 客户端 |
| run #3 | stub-allow | 内建滚动 | Core `deliver` |
| run #4 | stub-allow | `YANSHU_LOG_FILE` | Core `deliver` |
| **run #5（本份）** | **真 `sm2`** | `YANSHU_LOG_DIR` 轮转 | Core `deliver` + **真签名** |

前四份证明"不落明文"；**本份才同时覆盖鉴权面**——注册与建包都过了真实 SM2 验签，
签名不对根本进不来，所以这一轮扫到的语料是"真认证下产生的密文"。

## 复跑（一条命令）

```sh
YS_BASE_DSN="$PG_TEST_DSN" \
YS_EV1_VERIFIER=sm2 \
YS_EV1_LOG_MODE=dir \
YS_DELIVER_BIN=core-deliver \
qa/evidence/run_evidence1_core.sh <core-src> <rune-crate> /tmp/ys-ev1
```

`YS_EV1_VERIFIER=sm2` 会：① 服务端以 `YANSHU_VERIFIER=sm2` 启动；
② 给 `deliver` 自动补 `--sender-sk <alice.sk> --recipient-sk <bob.sk>`（真签名必需）。
脚本会打印 `verifier: sm2`，跑错模式一眼能看出来。

## 结果

| 目标 | 语料量 | 强信号命中 |
|---|---|---|
| 存储（本次 blob 根，`storage_path` 已断言） | 3 文件 / 2241B | 0 |
| PostgreSQL `yanshu_test`.`gate_ev1` | 8 表（7 业务 + 1 记账）/ 658 行 | 0 |
| 轮转日志 `yanshu-server-2026-11-02.log` | 1 份 / 2994B | 0 |

阳性对照：存储注入 → 1、日志注入 → 1、DB 注入 → 1、复原 → 0。
终态对比：`LEASED` 该笔 3 文件 / 2241B；`CONSUMED` 该笔目录整体消失。

## 一点实操记录

`deliver` 在 `sm2` 下必须带真签名；`9065eb8` 那版还没有 `--sender-sk/--recipient-sk`，
直接跑会 `flag provided but not defined: -sender-sk`（脚本会以 BLOCKED 收场，不假装成功）。
用 `08d40e7`（或更新的 head）才有这两个参数。

## 边界

- 本份认证已为真，但仍属于**单机自起实例**（非宿主常驻实例）；宿主切 `sm2` 后可用同一命令复跑对照。
- 未覆盖：token 轮换后的吊销行为（已实测"轮换 secret 不吊销旧 token"，Core 正在加 `kid`/epoch）、
  TTL/撤回、抓包层无明文。
