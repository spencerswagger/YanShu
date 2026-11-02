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
| `contract-v1/2026-11-02-delivery-8f4f24c.md` | —（交付判定） | `8f4f24c` | `2c4e8c69…4118ead` | — | native-api | 三条门槛各一条命令（见该文件末节） | **三条件全过 → 可交付**：内核 `c1b87d0a…`/127,313B、升级 10/10（`pre-kid`、连跑两次幂等）、向量与证据二全过；唯一待办是错误名字面 |
| `contract-v1/2026-11-02-delivery-gate-status.md` | —（交付判定） | `d655e16` | `4c331e1f…f1ef9d` | stub-allow | native-api | 见 `qa/evidence/DELIVERY-GATE.md`（三条各一条命令） | **交付门槛 2/3 达标**：内核 PASS、迁移 PASS、向量 PASS；**唯一不达标 = 轮换错误名仍为 `AUTH_TOKEN_REVOKED`（待改 `AUTH_TOKEN_STALE`）** |
| `contract-v1/2026-11-02-core-script-token-rotation-d655e16.md` | —（服务端证据） | `d655e16` | `4c331e1f…f1ef9d` | stub-allow | native-api | `sh server/scripts/token-rotation-check.sh --bin … --deliver … --yspk … --dsn … --blob …` | **Core 官方脚本 6/6 PASS**；原始 body：`AUTH_TOKEN_REVOKED`（轮换）/ `AUTH_TOKEN_INVALID`（值不对），`message` 明写"由密钥轮换导致" |
| `contract-v1/2026-11-02-names-and-upgrade-d655e16.md` | —（服务端证据） | `d655e16` | `4c331e1f…f1ef9d` | stub-allow | native-api | `check_token_lifecycle.py …`；`check_upgrade_path.py [--column-expect absent]` | **错误名终值**：只换 secret → 401 `AUTH_TOKEN_REVOKED`（旧版误报签名类已修）；**删列迁移**升级路径 9/9 PASS |
| `contract-v1/2026-11-02-upgrade-path-check.md` | —（服务端证据） | 老 `08d40e7` → 新 `5605907` | — | — | native-api | `python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"` | **升级路径常规项**：老库缺列 → 迁移补列 → 历史行完好（`pre-kid`）→ 服务起 + healthz 200 → 连跑两次幂等（10/10） |
| `contract-v1/2026-11-02-token-naming-authority-5605907.md` | —（服务端证据） | `5605907` | `3c1e4b2b…35f98f` | stub-allow | native-api | `check_token_lifecycle.py ...`（`--kid` 即 epoch） | **命名权威表**：只改 secret → 204（不吊销）；只改 epoch → 401 `AUTH_TOKEN_STALE`；两者都改 → STALE 优先；新签发 201、旧 token 不复活；epoch 调小拒启动 |
| `contract-v1/2026-11-02-host-binary-7239888.md` | —（服务端证据） | `7239888` | `bd64d23c…d7d6d7` | stub/sm2 | native-api | `check_token_lifecycle.py --kid 1 …`；`yanshu-server -migrate-only` 验升级路径 | **三件套 + 升级路径已修**：老库（`08d40e7`）升级后补上 `upload_token_kid` 并起得来；token 四步 201 → 401 `AUTH_TOKEN_INVALID`（secret）→ 401 `AUTH_TOKEN_STALE`（kid）→ 新 201，旧 token 不复活 |
| `contract-v1/2026-11-02-token-kid-fa479d9.md` | —（服务端证据） | `fa479d9` | 二进制前缀 `b9d4086e…` | stub-allow | native-api | `python3 qa/evidence/check_token_lifecycle.py --kid k1 --binary <bin> --dsn "<DSN>" --ys-tool <t>` | **token 已验证（kid）**：基线 201 → 只换 secret 401 `AUTH_SIGNATURE_INVALID` → 只换 kid 401 `AUTH_TOKEN_STALE` → 新签发 201、旧 token 不复活；不设 KID 启动 exit 1 |
| `cc117070-final-acceptance.md` | —（四条终验） | `4eda665` | `cc117070…7e571f9` | stub + sm2 | native-api | 见该文件末节（四条命令） | **四条：内核（跟踪+blob）PASS、迁移升级 10/10 PASS、向量+证据二 PASS、token 四态 PASS**；`SIG_INPUT` 513 为 INCONCLUSIVE（HTTP 不可达，库层单测覆盖） |
| `contract-v1/2026-11-02-final-six-4eda665.md` | —（终版复核） | `4eda665` | `cc117070…7e571f9`（与 Core 报的一致） | sm2 | native-api | 六项命令见文件内 | **六项全 PASS**：内核（git 跟踪 + blob sha 均 `c1b87d0a…`）、错误名 grep（无 REVOKED/EXPIRED）、迁移清单、升级 10/10、向量 14 条可执行、KID 四态；`SIG_INPUT` 513 为 INCONCLUSIVE（库层单测覆盖） |
| `contract-v1/2026-11-02-siginput-limits.md` | —（限额验收） | `97d156c` | — | sm2 | native-api | `python3 qa/evidence/check_siginput_limits.py --binary <bin> --dsn "<DSN>" --kid 9` | **4/5**：长度表 109 与契约一致、109 接受、110/昵称 33 走字段级；**`SIG_INPUT_TOO_LONG` 未实现且不可达**（513 被昵称校验先拒） |
| `contract-v1/2026-11-02-final-acceptance-97d156c.md` | —（最终验收） | `97d156c` | `0caed268…d5578c0` | stub-allow + sm2 | native-api | 见文件末节（三条命令） | **四条：迁移/KID 单调/向量/token 四态全 PASS；内核 sha 未验**——该 head 仓库里内核是空 blob（早于 `bae4a22`） |
| `contract-v1/2026-11-02-rejudge-b516cc6.md` | —（服务端证据） | `b516cc6` | `26739fd3…b81e…` | stub-allow + 真 sm2 | native-api | `check_token_lifecycle.py --kid 1 …`；`check_upgrade_path.py` | **按现行裁定全部 PASS**：只改 secret → `AUTH_TOKEN_INVALID`（设计如此）、只改 KID → `AUTH_TOKEN_STALE`、旧 token 不复活；升级 10/10（`pre-kid`、连跑两次幂等）；四码覆盖（签名类/凭据类互不顶替） |
| `contract-v1/2026-11-02-kid-and-kernel-sha.md` | `ab4279a`/`9bce5bb`/`739293a` | 各自现编 | stub-allow | `check_token_lifecycle.py --kid k1 …`；`check_server_kernel.py --server-dir <src> --vectors-dir <vec>` | 历史记录：早期 head 的行为与升级缺口（已由后续提交修复，留档对照） |
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

**交付门槛**（详见 `qa/evidence/DELIVERY-GATE.md`）：内核 sha / 迁移升级 / 向量套件三条。

| head | 内核 sha | 迁移升级 | 向量/证据二 | token 名字 | 可交付？ |
|---|---|---|---|---|---|
| `8f4f24c` | PASS `c1b87d0a…` | PASS 10/10 | PASS | `REVOKED`（不符裁定） | 否（名字） |
| `97d156c` | **未验（内核不在仓库，空 blob）** | PASS 10/10 | PASS | `INVALID`/`STALE` ✅ | 否（缺内核） |
| `71d62c3` | PASS | 未跑 | 未跑 | `REVOKED`（不符裁定） | 否（名字） |

→ **结论：目前没有一个 head 同时满足三条 + 名字**。等 Core 在含内核的 head 上把名字改成 `STALE`。

**仍 BLOCKED / 待跟进**：

1. ~~schema 升级缺列~~ → **已闭合**（`0002` 补列 + `pre-kid` 回填）：`08d40e7 → b516cc6` 10/10 PASS。
2. ~~token 错误名~~ → **已闭合**：`b516cc6` 上只有 `AUTH_TOKEN_INVALID` 与 `AUTH_TOKEN_STALE`，
   `AUTH_TOKEN_REVOKED` 已不出现（`d655e16` 的那次是旧产物）。
3. **重签发端点未实现**（`POST /v1/transfers/{id}/token`，契约 §1.7.5 已定义）——
   **进度差，不是 BLOCKED**；`AUTH_TOKEN_EXPIRED` 属 K2 登记，本期不实现，也不算缺口。

其余项全部闭合：证据二（生产路径 6/6 + 11/11 + 变体 18/18）、用户码/校验位四形态 26/26 + 反向用例、
prelude-only 6/6、证据一（存储/DB/日志零命中 + 三组阳性对照，含真 `sm2`）、
token 矩阵（INVALID/STALE 两码 + 四码覆盖）、服务端内嵌内核同源（白名单 + 向量套件）。

## 经验条目（防重复踩坑）

### 经验一：同源不同字节的根因是**构建入口用错**（2026-11-02）

之前那对 `127,313 B / c1b87d0a…` 与 `130,653 B / 8b89dd7f…` 不是"环境差异"，是**从错的目录构建**：

| 命令 | 结果 |
|---|---|
| `cd crypto && cargo build --release --target wasm32-unknown-unknown -p yanshu-sm` | **127,313 B / `c1b87d0a…`**（唯一正确） |
| `cd crypto/sm && cargo build …`（成员目录） | 130,653 B / `8b89dd7f…`（绕过 workspace 的 `Cargo.lock` 与 `[profile.release]`） |

教训：① 同一份源码可以有**两种字节**，判定只能比 **sha256**——commit 号、导出数、`ys_version()`、
"能跑通"都不足以为凭；② 交付说明必须写**唯一正确构建命令**并注明"禁止从成员目录构建"。

（另一面：根 `.gitignore` 的 `*.wasm` 会让 `server/kernel/yanshu_sm.wasm` 被静默跳过——
有的提交里它是**空 blob**，别人 clone 拿不到内核。）

### 经验二：入参宽度错一位造成的"假缺陷"

同一把公钥 `PB_S`：传 **64 字节 `X‖Y` → `AWQW`**（正确）；误传 **65 字节（`0x04‖X‖Y`）给只收
64 字节的 `ys_user_code`** → 内核把 `0x04` 当 X 首位、整体错位一字节 → `X2EH`，且**不报错**。
规矩：**每个公钥入参函数调用前显式断言缓冲区长度**；65 字节形态只走 `ys_user_code_wire`。

### 经验三：零命中的证据必须配阳性对照

"存储/日志/DB 三处零命中"本身可能是检测器瞎了。每轮必须做三组注入对照（塞明文到存储、
写文件名到日志、写文件名到 DB）→ 期望 exit=1；复原 → exit=0。对照不成立即判本轮不可信。

### 经验四：向量超出 ABI 能力时，标"不可执行 + 别处断言"，而不是判 FAIL

**做法（2026-11-02 定，Rune `221c300` 落地）**：向量自带 `executable` 字段，`false` 表示
"该条需要的能力超出已验证 ABI"，**不计入通过/拒绝统计**，并在 `note` 写明原因与替代覆盖点。

样板 `different_user_id`：只改 `user_id`、签名体不变，而 ABI 验签**没有 userID 入参**
（固定国标默认串），固定默认 ID 下**必然通过**——当"必拒"就会把正确实现判成 FAIL。
于是向量改成 `expect_verify=true` + **`executable:false`**，原意图"换 ID 必拒"挪到
**库层断言** `sig_conventions.rs::different_user_id_must_fail_at_library_level`。

统计口径：**15 = 14 可执行（10 正 + 4 负）+ 1 不可执行**；
`check_server_kernel.py` 直接读 `executable` 跳过并打印原因（老向量无该字段时回退看 `user_id`）。

### 经验五：假 PASS 的两种来源（都被实盘抓到过）

1. **旧进程占端口**：第二个实例 `bind: address already in use` 起不来，旧实例继续应答 →
   旧 token 得 200、密文落旧目录而扫新目录却"PASS"。修法：端口由内核分配、三重判活
   （进程活 + 日志 `listening` + 无 bind 错误）、并断言落盘路径在本次 blob 根下。
2. **`--log-path` 指向单个文件**：`os.walk` 遍历不到 → 日志 0 份却 PASS。修法：文件/目录都支持，
   逐目标空语料告警。

### 经验六：二进制资产必须验「被 git 跟踪 + blob sha == 期望值」（2026-11-02 实盘）

根 `.gitignore` 里的 `*.wasm` 会让 `git add -A` **静默跳过** `server/kernel/yanshu_sm.wasm`：
本地有、提交里没有，`97d156c` / `b516cc6` 的仓库副本里它是**空 blob（0 字节）**，
别人 clone 之后 `YANSHU_VERIFIER=sm2` 直接起不来。

规矩（已做成常驻断言，`check_server_kernel.py --repo … --git-ref …`）：

1. `git ls-tree -r <ref> -- server/kernel/yanshu_sm.wasm` 必须命中（证明**被跟踪**）；
2. `git cat-file blob <ref>:… | sha256sum` 必须等于冻结值（证明**提交的字节对**）；
3. 工作区与 HEAD 无差异（证明**跑的就是提交的**）。

第 2 条是关键：只比工作区会漏掉"工作区对、提交为空"这种情况。
