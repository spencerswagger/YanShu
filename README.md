# 雁书 YanShu

一次性加密文件互传：浏览器端侧国密加解密、服务器只存密文、免注册免登录。

- 需求基线：`/docs/REQUIREMENTS.md`（方案 v7 定稿整理）
- 端侧密钥与码：SM2 密钥对 + 4 位 Crockford Base32 用户码（公钥派生，撞码则重生成密钥对）
- 文件加密：SM4-GCM 分块（1MiB，nonce 含块序 + 末块标志）
- 传输：默认服务器中转；打洞成功可切 P2P 直传（不引入 TURN，只配 STUN）

## 目录

- `server/`：中转服务端（Go）。只存不透明密文块，不解析 prelude/块内容；启动与接口见 `server/README.md`。
- `docs/`：契约文档。`CRYPTO-PACK.md` 是加密包格式（Ark）；`DRAFT-FIELDS.md` 是服务端骨架期暂定契约，待 `API.md` 冻结后对齐。

