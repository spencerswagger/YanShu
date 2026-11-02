# 雁书 · Web 前端（`web/`）

一次性加密文件互传的浏览器端：**本机加密 → 中转只存密文 → 另一端本机解密落盘**。
契约（不实现第二套）：`docs/CRYPTO-PACK.md`（`YSPK/1.0`）与 `docs/API.md`；端侧内核接口：`crypto/include/yanshu_sm.h`（Rune 的 PR #4）。

## 当前状态

| 项 | 状态 |
|---|---|
| 端侧内核（真 WASM） | **已接**：`WebAssembly.instantiate(bytes, {})`，0 import，按头文件绑定导出；当前内核默认**契约布局**（HEADER 112） |
| 布局标签 | 界面如实区分 **契约布局 YSPK/1.0** / **旧布局（HEADER 40，待对齐契约）** / 开发桩 / 未就绪 |
| 端到端闭环 | **已跑通（真内核，不是桩）**：浏览器双端、真国密（SM3/SM4-GCM/SM2）、分块上传、下载落盘逐字节一致 |
| 会话式包装 | **在 JS 侧**（`crypto/session.js`）：prelude + 逐块切片 + 导出/恢复；内核只用现有导出，不需要新增接口 |
| 传输 | **已对 Core 真服务跑通**（`feat/server-skeleton`，`/v1` 路径）；`relay/dev-relay.mjs` 只留作无服务时的本地替身 |
| 大文件 | **受限**：内核当前是整包接口（`ys_pack` 一次吃整份明文），前端上限 64 MiB；流式接口已进排期 |

> 本轮不做：直传/WebRTC（只留禁用开关）、WebSocket 在线通知、二维码、最近联系人、拉黑、昵称修改入口、真机实测。

## 跑起来

```bash
cd web
npm install

# 1) 端侧内核产物（不入库）：仓库根先构建，再同步到 web/public/
#    cd ../crypto && CARGO_TARGET_DIR=/.cache/rust-web cargo build --release --target wasm32-unknown-unknown -p yanshu-sm
npm run wasm:sync

# 2) 本地中转（内存、不验签、只存不透明字节）
npm run relay                 # http://127.0.0.1:8787

# 3) 前端
npm run dev                   # http://127.0.0.1:5173（auto：加载到 wasm 就用真内核）
```

门禁：

```bash
npm test        # node --test：单测 + 双端闭环 + 真内核集成测试（49 例）
npm run build   # vite build（产物带严格 CSP）
```

桩模式（**只在没有 wasm 时**用，产物以 `YSSTUB01` 开头、界面有红条）：

```bash
npm run dev:stub              # 未加密；本地中转要配 YS_DEV_RELAY_VERIFY_DIGESTS=off
```

## 目录

```
web/
├── index.html                  移动端 viewport、无外链脚本
├── vite.config.js              dev 反代 /v1；生产构建注入严格 CSP
├── relay/dev-relay.mjs         开发用中转（API.md 子集，内存实现，不验签）
├── scripts/sync-wasm.mjs       把内核 wasm 同步到 public/
├── src/
│   ├── config.js               基址 / 块大小 / 上限 / 退避 / 桩开关
│   ├── crypto/
│   │   ├── abi.js              ★ 与内核对齐的唯一位置：导出清单、错误名映射、差异备忘
│   │   ├── wasm.js             instantiate + 线性内存 alloc/free + 公钥/签名边界转换
│   │   ├── layout.js           整包 → prelude + 块切片的纯算术（按内核包头长度选策略）
│   │   ├── session.js          会话式包装：PackSession / UnpackSession（导出/恢复、逐块喂入、边界报错）
│   │   ├── stub.js             UnavailableKernel（报未就绪）/ DevStubKernel（开发桩）
│   │   ├── errors.js           CRYPTO_* 端侧错误码与文案
│   │   └── index.js            选择实现；生产构建拒绝开发桩
│   ├── net/                    client / auth（YSAUTH1）/ api / upload / download / errors
│   ├── store/                  IndexedDB 身份（私钥只本机）与续传记录
│   ├── lib/                    base64url / 字节 / 位图 / 退避 / DER / 日志
│   ├── components/             我的码 / 发文件 / 待收 / 运行记录
│   └── App.vue                 装配与状态提示
└── tests/
```

## 重建内核与"产物 ↔ 源码同源"校验（一条命令）

```bash
cd web
npm run wasm:rebuild        # 默认 origin/feat/endcrypto-wasm 的最新 commit
# 指定某个 commit / 跳过 fetch：
YS_KERNEL_REF=<sha> npm run wasm:rebuild
```

`scripts/rebuild-wasm.mjs` 会依次做：`git fetch` → 解析 ref 的 commit → `git archive` 导出到临时目录（不动工作区、不建 worktree）
→ `cargo build --release --target wasm32-unknown-unknown -p yanshu-sm`（独立 target 目录）→ 实例化核验 → 写产物与溯源。

随时核验手上这个产物（不重建、只检查）：

```bash
npm run wasm:check     # 打印 commit/sha256/ys_version/HEADER + 四个布局特征逐项 true/false
```

**核验不通过就不产出产物**（任一项失败直接非 0 退出）：

| 校验项 | 期望 |
|---|---|
| import | **0** |
| `ys_version()` | `0x00010000` |
| `ys_header_len()` | `112`（单一契约格式，无布局切换） |
| 6 参自证解包 | `ys_unpack_v1` / `ys_unpack_meta_v1`（arity 6；探测按 arity，改名 `_v2` 也能接） |
| `ys_sm2_sign_der` / `ys_pack_v1` | 必须存在（`ys_pack_v1` 的公钥形态按"先 64 再 65"探测并记住） |

**界面标签按契约 §2.3 的四条内核合规判据**（"不是桩 ≠ 合规"）。注意：当前 ABI **没有**
`ys_layout_of()` / `ys_get_layout()`（单一格式后被删掉，导出清单可证），所以判据是：

1. `ys_version() === 0x00010000`；
2. `ys_header_len() === 112`；
3. **契约 §15 的 V1 样例包真解一次**（`web/src/crypto/fixtures.js` 存的就是 §15.2 的 522 字节整包 +
   §15.1 的接收方私钥；解出的 `hi.txt` / `text/plain` / `hello` 必须逐项对上）；
4. 把 V1 样例的 `VERSION_MAJOR` 改成 `0x02`，必须被拒为 `CRYPTO_VERSION_UNSUPPORTED`。

四条全过才显示「真实加密 · 契约布局内核（YSPK/1.0）」；否则「真实加密 · 非契约布局内核（待对齐）」并在红条列出未通过项。
**本机码不缓存旧的**：本地记录带 `codeAlgo` 版本；每次启动都用当前内核重算 `ys_user_code`，
与存的值不一致（或算法版本变了）就覆盖、作废旧注册态，并在界面提示"本机码已按当前内核重新派生，请重新告知对方"。
测试里有一条硬断言：契约 §15.1 的 `PB_S` 必须算出 **`AWQW`**；`npm run wasm:check` 同时打印
"传 64 字节（正确）= AWQW / 传 65 字节（错用）= 另一个码"，这正是"wasm 算出别的码"最常见的根因。

空文件名按契约裁决处理：`NAME_LEN = 0` 合法，落盘显示「未命名」并保留扩展名（`未命名.txt`）；
界面上不假设 `FLAGS.NAME_OBFUSCATED` 与 `NAME_MODE` 一致，名字语义只以 `ys_unpack_meta` 的 JSON 为准。
另外 `tests/legacy-reject.test.js` 用旧布局产物（HEADER 40）产一个包喂给默认解包入口，断言必须被拒
（实测 `CRYPTO_VERSION_UNSUPPORTED`）——**默认路径不会静默接受两种布局**。

产物落在 `public/ys_kernel.wasm`，同时写 `public/ys_kernel.build.json`：
`{commit, builtAt, sha256, bytes, imports, exports, ysVersion, headerLen, unpackV1Arity}`。
**页面底部会显示当前内核的 commit/版本/导出数/产物 sha256**（读不到就显示"来源未记录"），
`tests/wasm-real.test.js` 会断言"wasm 的 sha256 == 溯源里的 sha256、版本/包头一致"——所以"产物是不是从那个 commit 编的"是可核对的，不靠记忆。
（`ys_kernel.build.json` 是产物级元数据，按 `.gitignore` 不入库。）

## 端侧内核绑定（`crypto/include/yanshu_sm.h`）

- **内存**：`ys_alloc` / `ys_free`（长度必须一致），指针是线性内存偏移；字符串按"指针+长度"传，不假设 C 字符串。
- **错误**：一律用 `ys_error_name(code, out, cap, out_len)` 取名字再分支（`abi.js` 把名字映射成 `CRYPTO_*`），不猜返回码。
- **身份**：`ys_sm2_keygen` / `ys_sm2_pubkey` / `ys_sm2_sign` / `ys_sm2_verify`；私钥 32 字节只在本机。
- **码**：`ys_user_code`（4 位）、`ys_normalize_code`（大小写 / 易混字符口径由内核给，前端不自己实现 Crockford）。
- **包**：`ys_pack` 出字节、`ys_unpack` / `ys_unpack_meta` 吃字节；前端**不解析** prelude 与块头。
- **随机**：需要随机的接口都传 `seed`（32 字节 `crypto.getRandomValues` 现取，不复用）。

### 与冻结契约的差异（等内核返工，业务代码不用动）

| 项 | 内核现状 | 契约 | 适配层处理 |
|---|---|---|---|
| 公钥 | 64 字节 `X‖Y` | 65 字节未压缩点 | `WasmKernel.toWire` 补/去 `0x04` |
| 签名 | `r‖s` 64 字节 | DER 70..72 | `lib/der.js` 编解码 |
| 包头 | 40 字节 | 112 字节（含 `SENDER_PUB`） | `layout.js` 按 `ys_header_len()` 选切分策略，返工后自动切到契约那套 |
| `ys_unpack*` | 需调用方传发送方公钥 | 公钥在包内、可离线解包 | 适配层入参；业务从 `GET /codes/{code}` 取（服务端可信） |

**传输切分不靠解析**：`PRELUDE_LEN = packLen − n × 记录头长 − 明文长度`，块切片 = 记录头之后那段（`PT_LEN+16`）。
前端只做 §4.2 的算术与 §6.3 的记录头重建，不读包内字段。

## 两个上限（实测，产品级约束）

内核 `ys_pack` 是**整包**接口（一次吃整份明文），因此整包与明文同时在内存里。实测（Node + 同一份 wasm 产物，1 MiB 块）：

| 文件大小 | pack 耗时 | wasm 线性内存峰值 | 进程 RSS | 判断 |
|---:|---:|---:|---:|---|
| 8 MiB | 0.58 s | 34.5 MiB | 100 MiB | 手机可用 |
| 32 MiB | 1.9 s | 130.5 MiB | 245 MiB | 桌面可用；低端手机有风险 |
| 64 MiB（当前上限） | 4.0 s | 258.5 MiB | 437 MiB | 桌面边界；移动端不稳 |

- **触发条件**：`file.size > config.maxPackSize`（默认 64 MiB）→ 直接报 `FILE_TOO_LARGE`，不读文件、不上传。
- **建议**：v1 把上限登记为已知限制（移动端建议 16–32 MiB），或做流式（Ark 已把"流式分块 API"列入 §15 排期）。
- **8 MiB 续传阈值**：`pack.length > config.maxPersistPack`（8 MiB）时本机不保存会话快照 → 刷新后不能续传（当前页面内仍可续）；超过则只能重发。

## 服务端重启 / 凭证失效的自愈（为切 `sm2` 真认证准备）

服务端切 `sm2` 会重启，`YANSHU_TOKEN_SECRET` 变化 → 旧 `upload_token` 立刻失效。客户端不把用户卡在错误页：

- **上传侧**：遇到 `401 AUTH_MISSING`（凭证失效）→ 自动重建一次传输（新 idempotency key）→ 重传 prelude 与块；界面提示"凭证失效，正在重建传输…"。
- **下载侧**：遇到 `409 DOWNLOAD_NOT_STARTED` / `401`（租约失效）→ 重新取 prelude 开新租约，再取一次。
- 两条都有单测覆盖（`tests/loop.test.js`：上传凭证失效、下载租约失效）。
- `AUTH_CODE_MISMATCH` 等鉴权错误按 `describeError` 显示明确文案，不吞掉。

`SIG_INPUT` 自测：`npm run siginput:dump` 打印七种 PURPOSE 的逐字节 hex（固定 nonce/code/transfer_id），
可直接与服务端/Rune 的样例 diff；字段顺序与宽度由 `src/net/auth.js` 一处定义，`tests/siginput.test.js` 断言。

## 安全与纪律

- **私钥只在本机**：只写 IndexedDB（`store/identity.js`），不上传、不备份、不导出、不进日志；上 wire 的只有 65 字节公钥。
- **日志只记元数据**：方法/路径/状态/大小/块数（`lib/log.js` 有字段白名单），不记文件名、明文、密钥、签名原文。
- **桩不许假装加密**：未就绪替身一律 `CRYPTO_NOT_READY`；开发桩产物 `YSSTUB01` + `STUB-NOT-ENCRYPTED` + 界面红条；生产构建拒绝启用。
- **零第三方运行时脚本**：Vue 打进 bundle，无 CDN；生产构建注入 `script-src 'self'` 等 CSP。
- 路径/字段/错误码全部照 `docs/API.md`，不自行发明（例如绝不出现 `filename`）。

## 已验证 / 未验证

**已验证（`npm test`，49 例；真内核 6 例不跳过）**

- 真内核：0 import、导出齐全、密钥对/码/归一化/签名验签、打包→切分→拼回→解包明文一致、改 1 字节/换别包块必须失败、包里搜不到文件名与明文片段
- 会话包装：导出快照恢复后 prelude/切片逐字节相同、乱序喂入可解、重复块/越界/长度不符/缺块/关闭后喂入都明确报错
- 真内核 + 真中转：Node 链路（5 块）与**浏览器双端 + Core 真服务**（2.4 MiB / 3 块）都跑通，下载落盘逐字节一致
- 浏览器双端（两个独立 profile）：2.4 MiB 文件 → 真加密 → 3 块 → 另一端解密 → 落盘 2506889 字节，逐字节一致
- 传输编排：按 `/status` 的 `bitmap/missing` 续传、撤回后 410、幂等 204 / 冲突 409、429 带 `Retry-After`
- 契约口径（API.md 定稿 `376c5b5`）：计数只在 ack 成功 +1、同一 `download_id` 重复 ack 只计一次、
  收件箱 `ready/all` 不含终结态、`507` 配额错误不自动重试
- 撞码：`409 CODE_TAKEN` 自动换密钥对重试一次；再冲突停下等用户
- 移动端：320/390/768 三档无横向溢出、正文 ≥14px、按钮 ≥44px

**证据文件（两次分开存放，见 `results/web/`）**

- A：`dev relay + 旧布局内核` —— 仅跨浏览器链路证据，**不作验收**。
- B：`Core 真实服务 + 契约布局内核`（沙盒内自起）—— 同一份样本落盘逐字节一致。
- C：`宿主常驻实例 127.0.0.1:18080 + 契约布局内核 0f33a15` —— 同流程复跑，1 MiB 分块 → 3 块，落盘逐字节一致（服务端仍 `stub-allow`）。
- 复跑条件：Core 把 `YANSHU_VERIFIER` 换成真实 SM2 验签后，用同一脚本再跑一份。

**未验证 / 做不到**

- 与 Core 真服务联调（Core 的 HTTP 服务还没跑起来；本地只有 dev relay）
- >64 MiB 文件（内核整包接口；流式接口已排期）
- 刷新后续传：只在本机留着密文包（≤8 MiB）时可行；更大只能重发（整包接口无法重建会话）
- 真机 / 跨浏览器实测、1 GB 性能
