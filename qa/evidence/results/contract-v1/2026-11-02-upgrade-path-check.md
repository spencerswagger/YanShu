# 升级路径检查（常规项）

- 日期：2026-11-02
- 脚本：`qa/evidence/check_upgrade_path.py`
- 起因：`739293a` 给 `transfers` 加了 `upload_token_kid`，但迁移只有 `CREATE TABLE IF NOT EXISTS`、
  没有 `ALTER` —— **全新库正常、已有库升级直接报 `column ... does not exist`**，会让宿主重启起不来。

## 1. 这一步测什么（十项断言，缺一不可）

1. 建干净 schema；
2. 用**旧二进制** `-migrate-only` 建"老库"；
3. 断言老库**确实没有**目标列（证明在测"缺列 → 补列"，不是空跑）；
4. 往 `transfers` 插一行**历史数据**（模拟真实老库）；
5. 换**新二进制**跑 `-migrate-only`；
6. 断言目标列**已存在**；
7. 断言历史行**还在**；
8. 断言历史行的新列**有合理值**（非 NULL）；
9. 起服务，`/healthz` **200**，日志无 `sweep failed` / `does not exist`；
10. **连跑第二次**迁移，断言幂等（退出 0、行数不变）。

用法：

```sh
python3 qa/evidence/check_upgrade_path.py \
  --old-binary <旧版 yanshu-server> --new-binary <新版 yanshu-server> \
  --dsn "<基础 DSN>" --schema gate_upgrade_probe
```

已接进 `check_all.sh`（设 `YS_OLD_BINARY`/`YS_NEW_BINARY`/`YS_BASE_DSN` 即自动跑）。

## 2. 实测（老 `08d40e7` → 新 `5605907`）：**10/10 PASS**

| 断言 | 结果 |
|---|---|
| 老库缺 `upload_token_kid` | PASS（count=0） |
| 插入历史 transfers 行 | PASS |
| 升级后列存在 | PASS（count=1） |
| 历史行仍存在 | PASS（rows=1） |
| 历史行新列合理值 | PASS（`value=pre-kid`） |
| 升级后服务起 + `/healthz` 200 + 无缺列报错 | PASS |
| 迁移连跑两次幂等 | PASS（rows 1→1） |

结论：**迁移缺口已修**。历史行补的默认值是 `pre-kid`（可读、不误导为某个真实版本）。

## 3. 对 `739293a` 的处置

`739293a` 存在该缺口，**不可用于已有库的宿主**；本轮已实测 `7239888` 及之后修复，
`5605907` 是当前最新并通过本检查。历史记录保留在
`2026-11-02-kid-and-kernel-sha.md` 的 §3（含当时的报错原文），不再作为可交付候选。
