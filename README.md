# 雁书 YanShu

一次性加密文件互传：浏览器端侧国密加解密、服务器只存密文、免注册免登录。

- 需求基线：`/docs/REQUIREMENTS.md`（方案 v7 定稿整理）
- 端侧密钥与码：SM2 密钥对 + 4 位 Crockford Base32 用户码（公钥派生，撞码则重生成密钥对）
- 文件加密：SM4-GCM 分块（1MiB，nonce 含块序 + 末块标志）
- 传输：默认服务器中转；打洞成功可切 P2P 直传（不引入 TURN，只配 STUN）

## 仓库结构

| 路径 | 内容 |
|---|---|
| `server/` | 中转服务端（Go）。只存不透明密文块，不解析 prelude/块内容；启动与接口见 `server/README.md` |
| `server/kernel/yanshu_sm.wasm` | 服务端内嵌的端侧内核冻结产物（启动时按 sha256 白名单校验） |
| `crypto/` | 端侧国密内核（Rust，自研 SM3 / SM4-GCM / SM2，编译到 wasm32，raw C ABI） |
| `crypto/include/yanshu_sm.h` | Web 侧调用的 C ABI 头（函数清单 + 错误码） |
| `docs/` | 契约文档：`API.md`（HTTP/WS 接口契约）、`CRYPTO-PACK.md`（加密包格式）、`ABI.md`（端侧 C ABI 最终版）、`crypto-pack-impl-notes.md`（实现与契约 §15 样例逐字节对照）、`DRAFT-FIELDS.md`（服务端对齐结果与残留偏离） |
| `qa/evidence/` | 可复跑的验收证据脚本与结果归档（证据一：无明文/无文件名检索；证据二：密文篡改必报错）；总入口 `check_all.sh`，结果见 `qa/evidence/results/` |
| `vectors/` | 交叉验证供给：`host-crosscheck.json`（宿主对照请求）、`sm2-verify-vectors.json`（服务端验签向量） |
| `testdata/vectors.json` | 全 hex 测试向量（SM3/SM4-GCM/SM2/用户码/完整加密包） |
| `scripts/crosscheck/` | GmSSL 逐字节交叉验证（`run.sh` 一键复跑） |
| `scripts/wasm-smoke/` | wasm C ABI 冒烟测试（Node，无 wasm-bindgen） |

