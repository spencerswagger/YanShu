# 证据一 run #5：**真认证链路**（`YANSHU_VERIFIER=sm2`）

> **验收锚点：锚 sha256，不锚 head 号** —— 冻结产物 sha256 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313B）；head 号仅作溯源，sha256 一变则全部重跑。


- 日期：2026-11-02
- 对象：服务端 `feat/server-skeleton` @ **`08d40e7`**，二进制
  `yanshu-server-08d40e7`（sha256 `275fc463d5ed876c1dd5db720b0414b770e0f8d43aa51de65e68bcc819f6af55`）；
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

## 追加：在 `28d75b0` 上按新 stdout 形态复跑（stub-allow）

Core 把 `deliver` 的 stdout 改成**一行 JSON（15 键）**、人读摘要改到 stderr。脚本已按此调整：

* 采集时 **stdout 与 stderr 分开**（`2>"$work/deliver.err"`），只解析 stdout 的 JSON；
* 仍然优先 `--json-out` 文件，缺文件才用 stdout；
* 从 JSON 里取 `storage_path` 做落点断言（必须落在本次 blob 根下且非空）。

`28d75b0` 上复跑（`stub-allow`）：存储 3 文件 / 2241B、日志 1 份 / 3133B、DB 8 表（7+1）/ 708 行，
**三处零命中**，阳性对照 1/1/1/0，退出码 0。

> 注：`--sender-sk/--recipient-sk` 是 `980fc44` 才加的；`28d75b0` 上跑 `sm2` 会
> `flag provided but not defined: -sender-sk`（脚本 BLOCKED，不假装成功）。
> 所以 **sm2 复跑要用 `980fc44` 或更新的 head**（本文件上半部分用的 `08d40e7`）。

## 一点实操记录

`deliver` 在 `sm2` 下必须带真签名；`9065eb8` 那版还没有 `--sender-sk/--recipient-sk`，
直接跑会 `flag provided but not defined: -sender-sk`（脚本会以 BLOCKED 收场，不假装成功）。
用 `08d40e7`（或更新的 head）才有这两个参数。

## 边界

- 本份认证已为真，但仍属于**单机自起实例**（非宿主常驻实例）；宿主切 `sm2` 后可用同一命令复跑对照。
- 未覆盖：token 轮换后的吊销行为（已实测"轮换 secret 不吊销旧 token"，Core 正在加 `kid`/epoch）、
  TTL/撤回、抓包层无明文。
