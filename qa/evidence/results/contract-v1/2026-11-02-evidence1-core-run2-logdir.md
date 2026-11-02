# 证据一复扫（run #2）：按**服务端内建按日滚动日志**重跑

- 日期：2026-11-02
- 对象：服务端 `feat/server-skeleton` @ `2bc7dae`（内建日志落地 `9065eb8` 起），
  配端侧 `feat/endcrypto-wasm` @ `dbd66c4` 打的真契约包（2 块，2273B）
- 表结构基线：`c3c2fc9` 的 `0001_init.sql` —— **7 张业务表** + `schema_migrations` 记账表（共 8），**本轮实测未变**
- 库：`yanshu_test` 的独立 schema `gate_ev1`
- 日志：**服务端自己写的** `YANSHU_LOG_DIR/yanshu-server-YYYY-MM-DD.log`
  （本轮 `yanshu-server-2026-11-02.log`，2734B），不再是"部署重定向的 stdout"
- 结论：**三处零命中，退出码 0**；三组阳性对照全部成立

## 与 run #1 的差别（两次分开留档）

| 项 | run #1（初步证据） | run #2（本份） |
|---|---|---|
| 日志来源 | 部署重定向的 stdout 文件 | **服务端内建按日滚动文件** |
| Core commit | `c3c2fc9` | `2bc7dae`（表结构未变） |
| 验签 | `stub-allow` | `stub-allow`（**仍未接真实 SM2**） |
| 结论 | 三处零命中 + 对照成立 | 三处零命中 + 对照成立 |

> 认认真真的差别只有日志来源这一项；**认证链路仍然是桩**，两条边界继续有效
> （见 run #1 文件里的「两条边界」一节）。真实 `sm2` 接入后还要再跑 run #3。

## 复跑

```sh
YS_BASE_DSN="$PG_TEST_DSN" \
YS_EV1_LOG_MODE=dir \
qa/evidence/run_evidence1_core.sh <core-src> <rune-crate> <workdir>
```

`YS_EV1_LOG_MODE=dir` 会在启动时设 `YANSHU_LOG_DIR`，并**按投递时间选当日文件**
（`yanshu-server-$(date -u +%F).log`）作为扫描目标，扫不到当日文件就 BLOCKED ——
不硬编码文件名，避免"跨天换名后扫到空文件还判 PASS"。

## 结果

| 目标 | 语料量 | 强信号命中 | 结论 |
|---|---|---|---|
| 存储目录 | 3 文件 / 2242B | 0 | PASS |
| PostgreSQL `yanshu_test`…`gate_ev1` | 8 表（7 业务 + 1 记账）/ 233 行 | 0 | PASS |
| **内建日志** `yanshu-server-2026-11-02.log` | 1 份 / 2734B | 0 | PASS |

阳性对照：存储注入 → exit 1；日志注入（往当日滚动文件追加一行带文件名）→ exit 1；
DB 注入（`codes.nickname` 写文件名）→ exit 1；复原后 → exit 0。

## 本轮顺手修掉的一个"静默扫空"问题

`--log-path` 之前只接受目录：直接指一个**文件**时 `os.walk` 什么也遍历不到 →
"日志 0 份 / 0 字节"，但结论仍显示 PASS。是**阳性对照**把它抓出来的
（日志注入后仍 exit=0）。已改成文件/目录都支持，并在跑前断言当日日志文件非空。
这条也说明：对照组不是形式主义，它抓到的正是"扫描器自己瞎了"这一类最危险的假 PASS。

## 未覆盖（同 run #1）

真实验签、ack 后删除 / TTL / 撤回的生命周期、抓包层无明文。日志保留策略（7 天清理）
只按文档确认，没有实测跨天滚动（需要自然跨天或改系统时间，风险大于收益）。
