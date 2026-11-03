# Core 三步原样复跑 + 四条终验（`dfd3e82`）

- 日期：2026-11-02
- head：`feat/server-skeleton@**dfd3e82**`（比 `7239888`/`5a9c75f` 更新；`fix(auth): KID 参与 token 派生（u32be），旧凭据不可复活`）
- 产物（我自建）：
  - `yanshu-server` `83a99ffc432ee10dc250f2eb6a7c67078ad99f4b2b18e44b20b6d4e1da21b5cd`
  - `deliver` `75ac3ad9e9f5128ac58884fc860b74999594f79f13660a347ffc8a4fa339723f`
  - 内核（git blob @dfd3e82）`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f` / 127,313 B
- 编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`（Go 1.27.0）

## 1. Core 给的三步（原样复跑，只改一个变量）

| 步 | 场景 | 状态码 | 原始错误名 |
|---|---|---|---|
| ① | `secret=rotation-secret-0001`、`KID=1` | **200** | — |
| ② | **只改 secret**（`…0002`，KID 仍 1）→ 同一 token | **401** | **`AUTH_TOKEN_INVALID`** |
| ②b | 同实例新传输的新 token | **200** | — |
| ③ | **只改 KID**（=2，secret 不变）→ 上一轮 token | **401** | **`AUTH_TOKEN_STALE`** |

**PASS —— 与 Core 描述逐条一致。** 脚本：`qa/evidence/check_core_three_steps.py`（自起自停、逐步断言、退出码）。

## 2. 四条最终验收

| # | 项 | 结论 | 关键行 |
|---|---|---|---|
| 1 | 内核 sha（含 git 跟踪 + blob） | **PASS** | `PASS 被 git 跟踪（@ dfd3e82）`、`PASS HEAD blob sha256 == 冻结值（127,313 / c1b87d0a…）`、`PASS ys_version()=0x00010000`、`PASS 34 函数 + memory` |
| 2 | 迁移升级 + 连跑两次 | **PASS 10/10** | 老库缺列 → 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → `rows 1→1` |
| 3 | 冻结向量套件 + 证据二 | **PASS** | user-code 5 / normalize 20 / **sm2 14 条可执行**（1 条 `executable:false` 跳过）；证据二 6/6 + 11/11 |
| 4 | token 四态 + `SIG_INPUT` | **PASS**（含 1 条 INCONCLUSIVE） | 见 §1；`SIG_INPUT` 109 接受、110 字段级、昵称 33 → `NICKNAME_INVALID`、513 不可达（`TestSIGInputTooLong` 覆盖） |

## 3. 可交付三件套

| 产物 | 路径 | 完整 sha256 |
|---|---|---|
| 服务端 | `/.octop/workspaces/0JXF1M/tmp/srvbin-dfd/yanshu-server` | `83a99ffc432ee10dc250f2eb6a7c67078ad99f4b2b18e44b20b6d4e1da21b5cd` |
| 投递工具 | `/.octop/workspaces/0JXF1M/tmp/srvbin-dfd/deliver` | `75ac3ad9e9f5128ac58884fc860b74999594f79f13660a347ffc8a4fa339723f` |

```sh
cd server
go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server
go build -trimpath -buildvcs=false -ldflags "-s -w" -o deliver ./cmd/deliver
```

env（凭据占位）：

```sh
YANSHU_DATABASE_URL="<DSN 从 /.keys/pg.env 读，含 search_path>"
YANSHU_TOKEN_SECRET="<≥16B>"
YANSHU_TOKEN_KID=1
YANSHU_VERIFIER=sm2
YANSHU_KERNEL_WASM=./kernel/yanshu_sm.wasm
YANSHU_BLOB_DIR=/srv/yanshu/blobs
YANSHU_LOG_DIR=/srv/yanshu/logs
YANSHU_ADDR=127.0.0.1:8080
```

## 4. 复跑

```sh
python3 qa/evidence/check_core_three_steps.py --binary <bin> --deliver <deliver> \
  --yspk <样本.yspk> --dsn "<DSN>&search_path=<schema>" --work <含 kernel/ 的目录>
```
