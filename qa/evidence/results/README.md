# results · 证据结果存放约定

> ## 验收锚定规则（先读这条）
>
> **锚产物 sha256，不锚 head 号。** 冻结产物：
> `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（**127,313 B**）。
>
> 1. 证据里的 wasm sha256 等于它 → **同一份验收产物**，不论 head 号写的是
>    `80400ec` / `031e95b` / `233805a`（这几个提交的内核源码零改动，产物同字节）；
> 2. 证据文件头仍要记 `head + sha256` 两个，但**判定同源以 sha256 为准**；
>    sha256 一变，所有证据一律重跑；
> 3. 为什么：**同一 commit 跨环境重建的 sha256 可能不同**（已实测 130,653 B /
>    `8b89dd7f…` 与 127,313 B / `c1b87d0a…`），所以 head 号不足以为凭；
> 4. 跨环境允许不同构建时，用「sha256 白名单 + 该产物通过冻结向量套件」双条件判定。

结果**按布局分目录**存放，目录名一眼能看出是"对契约实现"还是"对非契约实现"：

```
results/
├─ contract-v1/            用契约布局（CRYPTO-PACK YSPK/1.0，默认）跑的结果 → 算验收
└─ rune-v1-noncontract/    用旧/其它布局跑的结果 → 只作记录与对照，不算验收
```

文件命名：`YYYY-MM-DD-evidence<编号>-<对象>.md`，例如
`rune-v1-noncontract/2026-11-02-evidence2-rune-v1.md`、
`contract-v1/2026-11-03-evidence2-contract-v1.md`。


## 今晚验收证据一览（按产物 sha256 组织）

冻结产物（**验收锚**）：**127,313 B** /
`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`
（`ys_version()=0x00010000`、`ys_header_len()=112`、34 函数 + memory = 35 导出 / 0 import）。

### A. 绑定冻结产物 `c1b87d0a…`（同字节，head 仅溯源）

| 证据文件 | wasm sha256 | 认证 | 入口类型 | 可复跑命令 | 结论 |
|---|---|---|---|---|---|
| `contract-v1/c1b87d0a-evidence2-freeze.md` | `c1b87d0a…7259f`（127,313B） | — | wasm-production | `qa/evidence/run_evidence2_wasm.sh <rune-crate> <wd>` | **闭合**：6/6 + 11/11 + 变体 18/18，未报错 0 |
| `contract-v1/c1b87d0a-user-code-consistency.md` | `c1b87d0a…7259f` | — | wasm + 原生 | `python3 qa/evidence/check_code_consistency.py --wasm <w> --ys-tool <t>` | **闭合**：26/26（四形态 `PB_S=AWQW`、校验位 `X`、反向 65→64 得 `X2EH`、归一化 14 组） |
| `contract-v1/2026-11-02-prelude-meta.md` | `c1b87d0a…7259f` | — | wasm-production | `python3 qa/evidence/check_prelude_meta.py --wasm <w>` | **闭合**：prelude-only 可读且 `data_verified:false`；整包入口拒绝半包；篡改必失败（6/6） |
| `web/2026-11-02-D-core-sm2-real-auth.md`（Web 产出） | `c1b87d0a…7259f` | **真 sm2** | wasm-production | 由 Web 的复跑脚本执行 | **闭合**：浏览器双端真验签、2 506 889 字节逐字节一致（服务端 `caf00ac`） |

一键全跑（含上面三条）：`YS_SERVER_DIR=<源码根> qa/evidence/check_all.sh <rune-crate> <wd> [--base-url URL]`
= 构建 → 两个自测 → 用户码一致性 26/26 → prelude 元数据 6/6 → 证据二 6/6+11/11 →
内嵌内核 sha 校验（给了 `YS_SERVER_DIR` 才跑），末尾打印产物 sha256。

### B. 服务端证据（不绑 wasm 产物，按服务端 commit/二进制 sha）

| 证据文件 | 服务端 | 二进制 sha256 | 认证 | 可复跑命令 | 结论 |
|---|---|---|---|---|---|
| `contract-v1/2026-11-02-evidence1-core-run5-sm2.md` | `08d40e7` | `275fc463…6af55` | **真 sm2** | `YS_EV1_VERIFIER=sm2 YS_EV1_LOG_MODE=dir YS_DELIVER_BIN=core-deliver qa/evidence/run_evidence1_core.sh …` | **闭合**：存储/DB/日志三处零命中，对照 1/1/1/0 |
| `contract-v1/2026-11-02-core-script-token-rotation-d655e16.md` | —（服务端证据） | `d655e16` | `4c331e1f…f1ef9d` | stub-allow | native-api | `sh server/scripts/token-rotation-check.sh --bin … --deliver … --yspk … --dsn … --blob …` | **Core 官方脚本 6/6 PASS**；原始 body：`AUTH_TOKEN_REVOKED`（轮换）/ `AUTH_TOKEN_INVALID`（值不对），`message` 明写"由密钥轮换导致" |
| `contract-v1/2026-11-02-names-and-upgrade-d655e16.md` | —（服务端证据） | `d655e16` | `4c331e1f…f1ef9d` | stub-allow | native-api | `check_token_lifecycle.py …`；`check_upgrade_path.py [--column-expect absent]` | **错误名终值**：只换 secret → 401 `AUTH_TOKEN_REVOKED`（旧版误报签名类已修）；**删列迁移**升级路径 9/9 PASS |
| `contract-v1/2026-11-02-upgrade-path-check.md` | —（服务端证据） | 老 `08d40e7` → 新 `5605907` | — | — | native-api | `python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"` | **升级路径常规项**：老库缺列 → 迁移补列 → 历史行完好（`pre-kid`）→ 服务起 + healthz 200 → 连跑两次幂等（10/10） |
| `contract-v1/2026-11-02-token-naming-authority-5605907.md` | —（服务端证据） | `5605907` | `3c1e4b2b…35f98f` | stub-allow | native-api | `check_token_lifecycle.py ...`（`--kid` 即 epoch） | **命名权威表**：只改 secret → 204（不吊销）；只改 epoch → 401 `AUTH_TOKEN_STALE`；两者都改 → STALE 优先；新签发 201、旧 token 不复活；epoch 调小拒启动 |
| `contract-v1/2026-11-02-host-binary-7239888.md` | —（服务端证据） | `7239888` | `bd64d23c…d7d6d7` | stub/sm2 | native-api | `check_token_lifecycle.py --kid 1 …`；`yanshu-server -migrate-only` 验升级路径 | **三件套 + 升级路径已修**：老库（`08d40e7`）升级后补上 `upload_token_kid` 并起得来；token 四步 201 → 401 `AUTH_TOKEN_INVALID`（secret）→ 401 `AUTH_TOKEN_STALE`（kid）→ 新 201，旧 token 不复活 |
| `contract-v1/2026-11-02-token-kid-fa479d9.md` | —（服务端证据） | `fa479d9` | 二进制前缀 `b9d4086e…` | stub-allow | native-api | `python3 qa/evidence/check_token_lifecycle.py --kid k1 --binary <bin> --dsn "<DSN>" --ys-tool <t>` | **token 已验证（kid）**：基线 201 → 只换 secret 401 `AUTH_SIGNATURE_INVALID` → 只换 kid 401 `AUTH_TOKEN_STALE` → 新签发 201、旧 token 不复活；不设 KID 启动 exit 1 |
| `contract-v1/2026-11-02-kid-and-kernel-sha.md` | `ab4279a`/`9bce5bb`/`739293a` | 各自现编 | stub-allow | `check_token_lifecycle.py --kid k1 …`；`check_server_kernel.py --server-dir <src> --vectors-dir <vec>` | token 三态已验证（201→401→201，待统一错误名）；内嵌内核已换冻结产物、白名单+向量套件全 PASS；老库缺 `upload_token_kid` 列（唯一真 BLOCKED） |
| `contract-v1/2026-11-02-host-binary-980fc44.md` | `08d40e7` | `275fc463…6af55` | 真 sm2 / stub | `python3 qa/evidence/check_token_lifecycle.py --binary <bin> …` | 二进制三件套；token 三态 201→401→201 |
| `contract-v1/2026-11-02-evidence1-core-run4-logfile.md` | `28d75b0` | — | stub-allow | `YS_EV1_LOG_MODE=file … run_evidence1_core.sh` | 日志改 `YANSHU_LOG_FILE`/`LOG_DIR`；LEASED vs CONSUMED 残留对比 |
| `contract-v1/2026-11-02-evidence1-core-run3-core-deliver.md` | `2bc7dae` | — | stub-allow | `YS_DELIVER_BIN=core-deliver …` | 投递改用 Core 官方 `deliver` |
| `contract-v1/2026-11-02-evidence1-core-run2-logdir.md` | `2bc7dae` | — | stub-allow | `YS_EV1_LOG_MODE=dir …` | 内建按日滚动日志复扫 |
| `contract-v1/2026-11-02-evidence1-core-c3c2fc9.md` | `c3c2fc9` | — | stub-allow | `YS_EV1_LOG_MODE=stdout …` | **初步证据 run #1** |

### C. 历史对照（不作验收）

| 证据文件 | 产物 | 说明 |
|---|---|---|
| `contract-v1/2026-11-02-evidence2-contract-v1-wasm.md` | `9df8b8c3…`（125,839B） | 更早 head 的生产路径结果，仅对照 |
| `contract-v1/2026-11-02-evidence2-contract-v1.md` | — | Rust 原生入口版，仅对照 |
| `rune-v1-noncontract/2026-11-02-evidence2-rune-v1.md` | — | 旧布局，**不作验收**（`--layout rune-v1` 现报 `LAYOUT_UNAVAILABLE` 退出 4） |

### 总体结论

**已闭合**：证据二（篡改必报错，生产路径）、用户码/校验位四形态一致性 + 反向用例、
prelude-only 元数据语义、证据一（存储/DB/日志零命中 + 三组阳性对照，含真 `sm2` 那份）、
token 轮换（kid → `AUTH_TOKEN_REVOKED`）。

**仍 BLOCKED / 待跟进**：

1. ~~已有 schema 升级缺 `upload_token_kid` 列~~ → **已闭合且有常规检查**（`check_upgrade_path.py`）：
   老 `08d40e7` → 新 `5605907` 十项断言全 PASS（列补上、历史行 `pre-kid`、服务起、连跑两次幂等）。
   **`739293a` 存在该缺口，不可用于已有库**；`7239888` 起修复。
2. **token 命名以实测为准（`d655e16`，最新）**：只换 `TOKEN_SECRET` → **401 `AUTH_TOKEN_REVOKED`**
   （旧版误报 `AUTH_SIGNATURE_INVALID` 的缺陷已修）；`AUTH_TOKEN_INVALID`（值不匹配/格式错）与
   `AUTH_TOKEN_EXPIRED`（上传 6h / 租约 30min）未在本矩阵触发，属实现内已存在、待单独构造用例。
   历史实测（`5605907` 的 EPOCH 版：只改 epoch → `AUTH_TOKEN_STALE`）保留在
   `2026-11-02-token-naming-authority-5605907.md`，**EPOCH 已在 `d655e16` 撤回（`0004` 删列）**。

其余项全部闭合：证据二（生产路径 6/6 + 11/11 + 变体 18/18）、用户码/校验位四形态 26/26 + 反向用例、
prelude-only 6/6、证据一（存储/DB/日志零命中 + 三组阳性对照，含真 `sm2`）、
token 轮换功能、服务端内嵌内核同源（白名单 + 向量套件）。
