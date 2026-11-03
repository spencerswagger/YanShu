# 最终验收 `97d156c`：四条逐项结论

- 日期：2026-11-02
- 对象：`feat/server-skeleton@**97d156c**`，自编 `yanshu-server`（sha256
  `0caed2686b0db842c9a5129138db0592faa1cd56f1553e207beeb7909d5578c0`）、
  `deliver`（`2428ecfa12f4302ffd9e445f7228fa7a2e891a1546630ae7c60bfe5e2ca487ae`）
- 迁移集：`0001_init` + `0002_upload_token_kid` + `0003_token_kid_state`

## 结论表

| # | 项 | 结果 | 说明 |
|---|---|---|---|
| 1 | 内核 sha == `c1b87d0a…7259f`（127,313 B） | **未验（FAIL）** | `97d156c` 的 `server/kernel/yanshu_sm.wasm` 在 git 里是**空 blob（0 字节）**——该 head **早于** `bae4a22`（Core 加 `!kernel/yanshu_sm.wasm` 例外那次）。`8f4f24c` / `71d62c3` 上才验到 `c1b87d0a…` / 127,313 B |
| 2 | 迁移升级 + 连跑两次 + KID 调小 | **PASS** | 10/10：老 `08d40e7` 库缺列 → `0002` 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → **连跑两次 rows 1→1**；KID 5→6 正常起，**1 → exit 1**，文案 `YANSHU_TOKEN_KID=1 is lower than the recorded maximum 6: kid must strictly increase (choose a larger number)` |
| 3 | 冻结向量套件 + 证据二 | **PASS** | 自测 11/11、14/14；一致性 26/26；prelude 6/6；证据二 6/6 + 11/11 + 变体（`--entry-kind production`） |
| 4 | token 四态 | **PASS** | 只改 secret → **401 `AUTH_TOKEN_INVALID`**；只改 KID → **401 `AUTH_TOKEN_STALE`**；两者都改 → **`AUTH_TOKEN_STALE`**；新签发 201；两枚旧 token 复打均 401 STALE（不复活） |

## token 四态原始记录

```
① 基线 (secret-A, kid=1)          → 201
② 只换 secret (kid=1)             → 401 AUTH_TOKEN_INVALID
   ② 新签发                        → 201
③ 只换 kid (secret-B, kid=2)      → 401 AUTH_TOKEN_STALE
   ③ 上一轮 token 是否复活          → 401 AUTH_TOKEN_STALE
④ 换 kid 后新签发                 → 201
   ④ 最初 token 是否复活            → 401 AUTH_TOKEN_STALE
```

## 需要主持人裁决的两点

1. **内核没进仓库的 head 不能当交付物**：`97d156c` 的 checkout 里没有内核文件，
   别人 clone 后 `YANSHU_VERIFIER=sm2` 起不来。要么用 `bae4a22` 之后的 head，要么明确交付"二进制+内核文件"两份。
2. **最新 head `71d62c3` 的错误名是 `AUTH_TOKEN_REVOKED`**（`grep` 只有 `INVALID`/`REVOKED`，
   **没有 `STALE`**），与现行裁定（`STALE`）冲突；而 `97d156c` 是 `INVALID`+`STALE`（符合裁定）。
   也就是说：**符合裁定的 head 没有内核，有内核的最新 head 又不符合裁定**。

## 复跑

```sh
python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <本 head 编的> --dsn "<DSN>"
python3 qa/evidence/check_token_lifecycle.py --binary <同> --dsn "<DSN>&search_path=<新 schema>" --ys-tool <ys-tool> --kid 1
qa/evidence/check_all.sh <rune-crate> <wd>
```
