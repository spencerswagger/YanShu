# 雁书 · Web 前端（`web/`）

一次性加密文件互传的浏览器端：**本机加密 → 中转只存密文 → 另一端本机解密落盘**。
契约（不实现第二套）：`docs/CRYPTO-PACK.md`（`YSPK/1.0`）与 `docs/API.md`。

## 当前状态（重要，别误读）

| 项 | 状态 |
|---|---|
| 端侧内核接入（`src/crypto/`） | **代码就绪、真内核未接**：WASM 产物还没到，`auto` 模式下如实报 `CRYPTO_NOT_READY` |
| 传输闭环（prelude + 分块 + 续传 + 终结态） | **已实现并用集成测试验证**（`tests/loop.test.js`，真 HTTP + 真编排代码） |
| 加密是否真？ | **否**。除 `--wasm` 模式外没有任何真实国密运算；开发桩是"可逆异或"，界面有红条提示 |
| 中转 | 只有本地开发用 `relay/dev-relay.mjs`（内存版，不验签）；Core 的 HTTP 服务还没跑起来 |

也就是说：**今晚打通的是"传输编排 + 端侧接口 + UI 流程"，不是密码学闭环**。
真加密闭环缺两件东西：① Rune 按 `src/crypto/abi.js` 导出会话式 WASM 接口；② Core 起一个符合 `docs/API.md` 的 HTTP 服务。

## 跑起来

```bash
cd web
npm install

# 终端 1：本地开发中转（内存、不验签、只存不透明字节）
npm run relay                 # http://127.0.0.1:8787

# 终端 2：开发桩模式（未加密，仅打通 UI/传输）
npm run dev:stub              # http://127.0.0.1:5173

# 真内核到货后（把 wasm 放到 web/public/ys_kernel.wasm）
npm run dev                   # auto：能加载就用真内核，加载不到就如实报未就绪
```

门禁：

```bash
npm test        # node --test（单测 + 双端闭环集成测试，共 33 例）
npm run build   # vite build（产物带严格 CSP）
```

> `*.wasm` 在仓库根 `.gitignore` 里，wasm 产物不入库；真内核由 Rune 产出后本地放置。

## 目录

```
web/
├── index.html                  移动端 viewport、无外链脚本
├── vite.config.js              dev 反代 /v1；生产构建注入严格 CSP
├── relay/dev-relay.mjs         开发用中转（API.md 子集，内存实现）
├── src/
│   ├── config.js               基址/块大小/退避/桩开关
│   ├── crypto/
│   │   ├── abi.js              ★ 与 Rune 对齐的唯一地方：导出函数表 + 错误码映射
│   │   ├── wasm.js             实例化、线性内存 alloc/free、输入输出拷贝
│   │   ├── stub.js             UnavailableKernel（报未就绪）/ DevStubKernel（开发桩）
│   │   ├── errors.js           CRYPTO_* 端侧错误码与文案
│   │   └── index.js            选择实现；生产构建拒绝开发桩
│   ├── net/
│   │   ├── client.js           HTTP：错误信封、429 Retry-After、5s→20s→60s 退避
│   │   ├── auth.js             YSAUTH1 签名输入（7 种用途）+ 挑战 → 鉴权头
│   │   ├── api.js              契约端点封装（路径/字段/头写死）
│   │   ├── upload.js           发送编排：两遍读文件、prelude、分块、续传、complete
│   │   ├── download.js         接收编排：prelude→块→解密→落盘→ack
│   │   └── errors.js           错误码 → 用户文案（含三种终结态）
│   ├── store/
│   │   ├── db.js               IndexedDB 封装（测试用内存 backend）
│   │   └── identity.js         密钥对与码；撞码自动换密钥对重试一次
│   ├── lib/                    base64url / 字节 / Crockford / 位图 / 退避 / DER / 日志
│   ├── components/             我的码 / 发文件 / 待收 / 运行记录
│   └── App.vue                 装配与状态提示
└── tests/                      node --test（不依赖浏览器）
```

## 端侧内核接口（`src/crypto/abi.js`）

Web 侧只需要 5 类能力，全部走 **扁平指针 + 长度**，`0` 成功、负数错误码：

1. 身份：`ys_identity_generate / public / code`、`ys_sign`、`ys_verify`、`ys_sm3`、`ys_code_of_public`、`ys_normalize_code`
2. 打包：`ys_pack_open → ys_pack_digest × N → ys_pack_seal → ys_pack_chunk × N`、`ys_pack_info`、`ys_pack_export / import / close`
3. 解包：`ys_unpack_open`（输出清单 JSON）→ `ys_unpack_chunk × N` → `ys_unpack_finish`、`ys_unpack_close`
4. 内存：`ys_alloc / ys_free`、`ys_abi_version`
5. 可选：`ys_version`、`ys_error_name`

**为什么必须是会话式**：清单里含每块 SM3，而清单在 prelude 里、prelude 要先上传（`CRYPTO-PACK` §4.3 / §12），
所以发送方必须"先摘要一遍、再逐块加密上传"。整包进出（`ys_pack(整份明文)`）撑不住 1 MiB 分块上传，
也不允许 Web 自己去切包——切包等于解析包内字段，违反"包内字段只由 WASM 读写"的边界（§16）。

**已知待对齐点**（2026-11-02 夜，见 `crypto/sm/src/ffi.rs` 的当前形态）：

- 公钥长度：契约 §9.1 是 **65 字节未压缩点**（`0x04‖X‖Y`），当前 crate 是 64 字节（`X‖Y`）；
  §3.4 的码由 65 字节派生，不一致会导致"码"和"发送方码校验"对不上。
- 打包/解包：需要 prelude 与块切片级接口（如上），而不是整包。
- 签名：DER（70..72）或 64 字节 `r‖s` 都行——Web 会把 64 字节按 §10.4 转 DER（`lib/der.js`）。

## 安全与纪律

- **私钥只在本机**：只写 IndexedDB（`store/identity.js`），不上传、不备份、不导出、不进日志；上 wire 的只有 65 字节公钥。
- **日志只记元数据**：方法/路径/状态/大小/块数（`lib/log.js` 有字段白名单），不记文件名、明文、密钥、签名原文。
- **桩不许假装加密**：`UnavailableKernel` 一律抛 `CRYPTO_NOT_READY`；`DevStubKernel` 产物以 `YSSTUB01` 开头、
  prelude 里带 `STUB-NOT-ENCRYPTED` 与明文"密钥"，界面常驻红条；**生产构建拒绝启用**（`crypto/index.js`）。
- **零第三方运行时脚本**：Vue 打进 bundle，无 CDN；生产构建注入 `script-src 'self'` 等 CSP（`vite.config.js`）。
- 文件头/路径/错误码全部照 `docs/API.md` 写死，不自行发明字段（例如绝不出现 `filename`）。

## 已验证 / 未验证

**已验证（`npm test`，33 例）**

- 双端闭环：A 端加密上传（多块）→ 中转 → B 端取回解密 → 落盘字节一致；`ack` 后中转密文被删
- 刷新续传：`GET /status` 的 `bitmap/missing` → 只补缺失块 → `complete`
- 终结态：撤回后另一端取件 `410 TRANSFER_REVOKED`
- 幂等：同块重复 PUT → `204`；改内容 → `409 CHUNK_CONFLICT`
- 429：带 `Retry-After`，客户端按"退避值与 Retry-After 取大"等待
- 撞码：`409 CODE_TAKEN` → 自动换密钥对重试一次；再冲突停下等用户
- 桩防线：未就绪替身不产出任何"加密成功"；生产构建拒绝开发桩；桩拒绝解 `YSPK` 真包

**未验证（缺依赖）**

- 真实 SM4-GCM/SM2/SM3 与 `YSPK/1.0` 逐字节一致（等 Rune 的 WASM + §15 测试向量）
- 与 Core 的真实接口联调（等 Core 的 HTTP 服务）
- 真机 / 跨浏览器实测、1 GB 性能
- 直传（WebRTC）、WS 在线通知：**本轮不做**，界面只留"待第二晚"的说明

## 本轮明确没做

直传/打洞、WebSocket 在线态与待收推送、二维码、最近联系人、拉黑、昵称修改入口、多语言、主题美化、动画。
