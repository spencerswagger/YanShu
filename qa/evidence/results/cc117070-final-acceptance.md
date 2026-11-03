# 四条最终验收（产物 `cc117070…`，head `4eda665`）

- 日期：2026-11-02
- 服务端 head：`feat/server-skeleton@**4eda665**`（比 `5a9c75f`/`97d156c` 更新，本轮取到的最新）
- 产物（我自建，与 Core 报的逐字节一致）：
  - `yanshu-server`：`cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9`
  - `deliver`：`16e919fbc678081345ac217be5628fcf0a96a5a8567f72ca2c040d462d04a990`
  - 内核：`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f` / 127,313 B
- 编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`
  （`deliver` 同式），Go 1.27.0 linux/amd64
- 迁移：`0001_init` → `0002_upload_token_kid` → `0004_token_kid_state` → `0005_restore_token_kid`

## 四条结论

| # | 项 | 结论 | 关键证据行 |
|---|---|---|---|
| 1 | 内核 sha（含 git 跟踪 + blob） | **PASS** | `PASS 被 git 跟踪（server/kernel/yanshu_sm.wasm @ 4eda665）`；`PASS HEAD blob sha256 == 冻结值（127,313 字节 / c1b87d0ad9a847fa…）`；`PASS ys_version() = 0x00010000`、`PASS 导出 = 34 函数 + memory` |
| 2 | 迁移升级 + 连跑两次 + KID 调小 | **PASS** | `10/10 通过`：`PASS 老库缺列 count=0` → `PASS 升级后列存在 count=1` → `PASS 历史行 pre-kid` → `PASS 服务起 + /healthz 200 + 无 sweep failed` → `PASS 迁移连跑两次幂等（rows 1→1）`；KID 5、6 正常起，**1 → exit 1**：`YANSHU_TOKEN_KID=1 is lower than the recorded maximum 6: kid must strictly increase (choose a larger number)` |
| 3 | 冻结向量套件 + 证据二 | **PASS** | `PASS 向量：user-code 5 组`、`PASS 向量：normalize 20 组`、`PASS 向量：sm2 验签 14 条（15 条中 14 条可执行；跳过 different_user_id——ABI 无 userID 入参）`；证据二 `单块 6/6`、`多块 11/11`（均含变体）、`未报错 0`、未篡改基线逐字节一致；一致性 26/26、prelude 6/6 |
| 4 | token 四态 + `SIG_INPUT` 边界 | **PASS（含 1 条 INCONCLUSIVE）** | token：`201` → 只改 secret `401 AUTH_TOKEN_INVALID` → 只改 KID `401 AUTH_TOKEN_STALE` → 两者都改 `AUTH_TOKEN_STALE` → 新签发 `201` → 两枚旧 token 复打均 `401 STALE`（不复活）；伪造 DER `401 AUTH_SIGNATURE_INVALID`。`SIG_INPUT`：109 接受、110 拒绝（`BAD_REQUEST`）、昵称 33 → `NICKNAME_INVALID`（字段级）、513 → **INCONCLUSIVE**（HTTP 不可达，字段级先拒；库层 `TestSIGInputTooLong` 等四项我跑过全 PASS） |

## 唯一需要标注的一处

`SIG_INPUT` 513 字节在 HTTP 层**不可达**：昵称 ≤32 等字段校验先拒，`SIG_INPUT_TOO_LONG` 只在库层单测触发
（`TestSIGInputTooLong` PASS）。这与契约"字段级优先"一致，不是 FAIL，也不冒充 PASS。

## 复跑

```sh
# 1 内核（跟踪 + blob + 工作区 + 版本/导出 + 向量）
python3 qa/evidence/check_server_kernel.py --server-dir <源码根> --repo <仓库> --git-ref 4eda665 \
        --vectors-dir <向量目录>
# 2 迁移升级
python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"
# 3 向量 + 证据二
YS_SERVER_DIR=<源码根> qa/evidence/check_all.sh <rune-crate> <wd>
# 4 token 四态 + SIG_INPUT
python3 qa/evidence/check_token_lifecycle.py --binary <bin> --dsn "<DSN>" --ys-tool <t> --kid 1
python3 qa/evidence/check_siginput_limits.py --binary <bin> --dsn "<DSN>" --kid 9
```
