# 雁书 YanShu

一次性加密文件互传：浏览器端侧国密加解密、服务器只存密文、免注册免登录。

- 需求基线：`/docs/REQUIREMENTS.md`（方案 v7 定稿整理）
- 端侧密钥与码：SM2 密钥对 + 4 位 Crockford Base32 用户码（公钥派生，撞码则重生成密钥对）
- 文件加密：SM4-GCM 分块（1MiB，nonce 含块序 + 末块标志）
- 传输：默认服务器中转；打洞成功可切 P2P 直传（不引入 TURN，只配 STUN）

## 仓库结构

| 路径 | 内容 |
|---|---|
| `crypto/` | 端侧国密内核（Rust，自研 SM3 / SM4-GCM / SM2，编译到 wasm32，raw C ABI） |
| `crypto/include/yanshu_sm.h` | Web 侧调用的 C ABI 头（函数清单 + 错误码） |
| `docs/crypto-pack-impl-notes.md` | 实现与 `docs/CRYPTO-PACK.md` v1 的对照（§15 样例逐字节核对） |
| `vectors/host-crosscheck.json` / `.md` | 宿主侧对照请求（机器可读 + 人读表格） |
| `testdata/vectors.json` | 全 hex 测试向量（SM3/SM4-GCM/SM2/用户码/完整加密包） |
| `scripts/crosscheck/` | GmSSL 逐字节交叉验证（`run.sh` 一键复跑） |
| `scripts/wasm-smoke/` | wasm C ABI 冒烟测试（Node，无 wasm-bindgen） |

