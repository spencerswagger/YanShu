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
| `contract-v1/2026-11-02-kid-and-kernel-sha.md` | `739293a` | `a9f3933e…6fc44` | stub-allow | `check_token_lifecycle.py --kid k1 …`；`check_server_kernel.py --server-dir <src>` | kid 轮换三态成立；**内嵌内核 sha 与冻结不一致（BLOCKED/FAIL）**；老库缺 `upload_token_kid` 列 |
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
1. **服务端内嵌内核 sha ≠ 冻结产物**（130,653B / `8b89dd7f…` vs 127,313B / `c1b87d0a…`）；
2. **已有 schema 升级缺 `upload_token_kid` 列**（迁移只有 `CREATE TABLE IF NOT EXISTS`，无 ALTER）；
3. **`只改 secret` 的 401 仍报 `AUTH_SIGNATURE_INVALID`**（应为凭据类 `AUTH_TOKEN_INVALID`）。

规矩：同一结论只留一份；重跑加新文件不覆盖；非契约/旧 head 的必须写明"不作验收"；
文件名 + head + sha256 三者齐了才算可追溯。

## 标准做法：零命中必须配阳性对照

"扫不到明文"只有在**检测器被证明能扫到**时才算证据。所以每一份"零命中"的结论都必须自带
至少一组阳性对照：把样本明文（或文件名）**注入同一处**，再跑一次，必须 FAIL；复原后必须回 PASS。
任一条对照不成立 → 本轮结论作废（脚本以退出码 2 结束）。

证据一的三处（存储 / 数据库 / 日志）各有一组注入，已脚本化在 `run_evidence1_core.sh` 的 5b 步
（`YS_EV1_CONTROLS=0` 可关，但不建议）。这条对任何"阴性结论"都适用，别只当证据一的规矩。

## 验收锚点：**锚 sha256，不锚 head 号**

head 号只作溯源；**同一份验收产物以 sha256 为准**。规则：

- 文件名形如 `<sha256 前 8 位>-<主题>.md`（当前冻结产物：`c1b87d0a`，127,313 字节，
  `ys_version()=0x00010000`）；head 号写在正文里；
- sha256 变了 → 所有证据重跑，旧的保留但标"历史"；
- 跨环境构建可能产生不同 sha（例如内核随仓库打进 tarball 时的 130,653 字节版
  `8b89dd7f…`），此时以**"sha256 白名单 + 该产物通过冻结向量套件"**判定同源，
  而不是死抠一个哈希。

## 验收口径更正：`different_user_id` **不是拒绝用例**（2026-11-02）

验签向量集里有条 `different_user_id`：它只改了向量里的 `user_id` 字段，`sig_input`/`sig_der`
与 `REGISTER` 逐字节相同。而内核 ABI 的验签**没有 userID 入参**（固定国标默认串），
所以**服务端在固定默认 ID 下必然验签通过**——把它当"必拒"会把正确实现判成 FAIL。

正确口径：这条在"固定默认 ID 的验签器"上**不可执行**，或断言"策略结果为通过"；
"换 ID 必拒"只对**带 ID 入参**的验器成立。

> Gate 的脚本不判定这条（本目录的检查项里没有它），此处只固定口径，避免后来人照旧期望值判。

## 经验：同源 ≠ 同字节（跨环境重建 sha 不同）

同一 commit 在不同工具链/环境下重建出的 wasm，**sha256 可能不同**。本沙盒实测：

| 产物 | 大小 | sha256 |
|---|---:|---|
| 验收冻结产物（Gate/Web/Rune 三方一致） | 127,313 B | `c1b87d0a…7259f` |
| Core 工作树里内嵌的那份 | 130,653 B | `8b89dd7f…154f9` |

两者的 `ys_version()` 与导出数完全相同（`0x00010000`、34 函数 + memory），
所以**只看版本/导出/commit 都发现不了差异**——但服务端验的就不是验收过的那份字节。

规矩：

1. 验收比 **sha256**，不比 commit；head 号只作溯源；
2. 服务端内嵌内核必须单独校验：`check_server_kernel.py --server-dir <源码根>`
   （sha 不等 FAIL、版本/导出不符 FAIL、文件缺失 BLOCKED）；
3. 跨环境允许不同构建时，用「sha256 白名单 + 该产物通过冻结向量套件」双条件判定，
   不能只凭"同 commit"放行。

## 反例二：入参宽度错一位造成的"假缺陷"（2026-11-02，P0 级误报）

**现象**：同一把公钥 `PB_S`，wasm 的 `ys_user_code` 给出 `X2EH`，原生 `ys-tool` 给出
`AWQW`（契约 §15.1 的值）。看起来像"wasm 与原生实现分叉"，一度被当成 P0。

**根因**：调用侧宽度错了。`ys_user_code` 收 **64 字节 `X‖Y`**；我的探针当时给它传了
**65 字节缓冲区（`0x04‖X‖Y`）**，内核读到 `0x04‖X[0..63]` 再补一个 `0x04`，
参与 SM3 的字节整体错位一位 → 算出另一个码。原生侧传 65 字节给只收 64 的入口则直接报错，
所以只有 wasm 那一侧"静默出错"。

**为什么它像内核 bug**：同一个函数、两种写法、两个值，**没有任何报错**；
而"重建产物后值变了"又像是代码被改过——实际是同一份产物在不同调用宽度下的两种结果。

**修法与规矩**：

1. 驱动按入口宽度准备缓冲区：64 字节入口给纯 `X‖Y`，`ys_user_code_wire` 给 `0x04‖X‖Y`；
2. **每个公钥入参函数调用前断言缓冲区长度**（`buf.length === 64|65`，不符直接退出），
   不再靠记忆；
3. 跨实现一致性检查（`check_code_consistency.py`）常驻：5 组公钥 × 4 入口；
4. 用三个 head 实测（`12b3d94` 两侧都出 `GPNV`、`86fde3c` 改成收 65 字节、
   `233805a` 两宽度都 `AWQW`）证明"代码确实改过"，与"调用错位"是两件事。

## 反例：一个被判成 PASS 的假证据（2026-11-02 实盘踩到）

**现象**：换新 commit 复跑证据一，结论 PASS、退出码 0，但**存储目标扫了 0 字节**。
**根因**：上一轮的服务进程还占着固定端口 18080，新进程 `bind: address already in use` 直接退出；
`/healthz` 探活打到的是**旧进程**，于是密文落进了上一轮的 blob 目录，我扫的却是新 workdir 的空目录。
"什么都没扫到"被判成了 PASS。

**修法（都已固化进脚本）**：

1. 端口不写死、也不按 PID 派生，直接取内核给的空闲端口；
2. 启动校验 = 进程活着 + 日志里有 `listening` + 日志里**没有** `bind: address already in use`，
   不再只信 `/healthz`；
3. 投递后**断言本次密文落在本次 blob 根下且非空**（用驱动报的 `storage_path` 校验前缀）；
4. 扫描器对每个目标单独报"0 字节/0 行"，阳性对照不成立即整体判本轮不可信（退出码 2）。

**教训**：阴性结论（"扫不到 X"）必须同时证明"确实扫到了该扫的东西"。
这条与"零命中必须配阳性对照"是一体两面。

规矩：

1. **同一份结论只放一个文件**，重跑就加新文件，不覆盖历史。
2. 非契约布局的结果，文件头必须写清"不作验收"以及"为什么"。
3. 反例用例的**通过判定与错误码无关**：只要解密失败（任一道防线拒绝）就算 PASS，
   错误名只作诊断记录。换实现/换布局后错误名会变，这是预期，不是回归。
4. 结果文件里**不放密钥、不放明文**：只写错误名、字节数、偏移、路径（路径不含用户内容），
   命中上下文最多左右各 8 字节 hex。
5. 每份结果都要带**可复跑命令**与对象版本（分支 + commit）。

现有结果：

| 文件 | 对象 | 状态 |
|---|---|---|
| `contract-v1/2026-11-02-evidence1-core-c3c2fc9.md` | 服务端 @ `c3c2fc9` + 契约包（**初步证据 · run #1**：stub-allow + stdout 重定向日志） | 三处零命中，3 组对照全部触发 |
| `contract-v1/2026-11-02-evidence1-core-run2-logdir.md` | 服务端 @ `2bc7dae`（**run #2**：内建按日滚动日志） | 三处零命中，3 组对照全部触发；认证仍是桩 |
| `contract-v1/2026-11-02-evidence1-core-run3-core-deliver.md` | 服务端 @ `2bc7dae` + **Core 官方 `deliver`**（**run #3**） | 三处零命中，3 组对照全部触发；认证仍是桩 |
| `contract-v1/2026-11-02-evidence1-core-run4-logfile.md` | 服务端 @ `28d75b0`（**run #4**：`YANSHU_LOG_FILE` + LEASED/CONSUMED 残留对比） | 三处零命中；ack 后该笔密文目录整体删除 |
| `contract-v1/2026-11-02-user-code-consistency.md` | 端侧 @ `f1ef9f9`（用户码派生 × 归一化跨实现一致性） | 20/20 通过；P0 定位为驱动调用约定 bug，非内核缺陷 |
| `contract-v1/2026-11-02-evidence1-core-run5-sm2.md` | 服务端 @ `08d40e7`（**run #5：真 `sm2` 验签 + 轮转日志 + 真签名投递**） | 三处零命中，3 组对照成立；同时覆盖鉴权面 |
| `contract-v1/2026-11-02-evidence2-contract-v1.md` | 端侧 @ `de6d6e1`（契约布局，Rust 原生 API 入口） | 5/5、10/10、18/18；入口属测试入口 |
| `contract-v1/2026-11-02-evidence2-contract-v1-wasm.md` | 端侧 @ `e9f8254`（**wasm-production**，`ys_version()`=0.1.0） | 5/5、10/10、18/18；可作为 v1 验收（待 Web 集成后补 C 份） |
| `rune-v1-noncontract/2026-11-02-evidence2-rune-v1.md` | 端侧 `crypto/sm` @ `12b3d94`（旧布局） | 记录与对照 |
