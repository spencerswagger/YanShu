# 宿主侧对照请求（YSPK/1.0）

> 由 `cargo run --release --bin gen-host-crosscheck` 生成，值与仓库内实现同源。
> 机器可读版本：`vectors/host-crosscheck.json`（同目录）。

共 **22 条**。全部 hex 小写、无 `0x`，整数大端。

## 工具能力对照

| tool_requirement | 含义 |
|---|---|
| `openssl` | OpenSSL 3.5.7 命令行直接可算 |
| `openssl-lib` | 需要 OpenSSL 库（如 EVP_KDF / EVP AEAD），CLI 不够 |
| `gmssl-cli` | 需要 GmSSL 命令行（`gmssl sm4 -gcm`；OpenSSL 的 `enc` 不支持 AEAD） |
| `gmssl-lib` | **必须 GmSSL 库**：要固定 k 才能逐字节；OpenSSL 只能做解密/验签方向 |

## 清单

| id | algo | 输入要点 | 期望长度 | 编码 | 工具 | 备注 |
|---|---|---|---:|---|---|---|
| `sm3-001` | SM3 | plaintext | 32 | hex | `openssl` | 空串 |
| `sm3-002` | SM3 | plaintext | 32 | hex | `openssl` | 1 字节 0x00 |
| `sm3-003` | SM3 | plaintext | 32 | hex | `openssl` | 标准 abc |
| `sm3-004` | SM3 | plaintext | 32 | hex | `openssl` | 中文 UTF-8（14 个汉字 + 标点） |
| `sm3-005` | SM3 | plaintext | 32 | hex | `openssl` | 1 MiB 数据只给摘要与生成规则（不塞全文） |
| `hmac-001` | HMAC-SM3 | key; plaintext | 32 | hex | `openssl` | HMAC 块长 64；OpenSSL 3.x 用 -mac HMAC -digest SM3 |
| `hkdf-001` | HKDF-SM3 | ikm; salt; info; info_text | 16 | hex | `openssl-lib` | RFC 5869 结构，PRF=HMAC-SM3；OpenSSL CLI 无 HKDF-SM3 子命令，需 EVP_KDF 或脚本 |
| `hkdf-002` | HKDF-SM3 | ikm; salt; info; info_text | 16 | hex | `openssl-lib` | 同 hkdf-001，info 换成清单密钥 |
| `sm4gcm-001` | SM4-GCM | key; nonce; aad; plaintext | 16 | hex（ciphertext ‖ tag，tag 为末尾 16 字节） | `gmssl-cli` | 空明文 / 零 key / 零 nonce / 无 AAD |
| `sm4gcm-002` | SM4-GCM | key; nonce; aad; plaintext | 17 | hex（ciphertext ‖ tag，tag 为末尾 16 字节） | `gmssl-cli` | 1 字节明文 |
| `sm4gcm-003` | SM4-GCM | key; nonce; aad; plaintext | 32 | hex（ciphertext ‖ tag，tag 为末尾 16 字节） | `gmssl-cli` | 正好一整块 16 字节 |
| `sm4gcm-004` | SM4-GCM | key; nonce; aad; plaintext | 31 | hex（ciphertext ‖ tag，tag 为末尾 16 字节） | `gmssl-cli` | 非整块 15 字节 |
| `sm4gcm-005` | SM4-GCM | key; nonce; aad; plaintext | 1016 | hex（ciphertext ‖ tag，tag 为末尾 16 字节） | `gmssl-cli` | 跨块 1000 字节 + 20 字节 AAD |
| `sm4gcm-006` | SM4-GCM | key; nonce; aad; plaintext | 21 | hex（ciphertext ‖ tag，tag 为末尾 16 字节） | `gmssl-cli` | 契约 §15.2 块 0：真实 AAD_CHUNK(32B) + 块 nonce（末块） |
| `sm2-enc-001` | SM2-encrypt | pub; k; plaintext | 129 | hex（0x04 ‖ C1.x(32) ‖ C1.y(32) ‖ C3(32) ‖ C2） | `gmssl-lib` | 契约 §15.1 夹具：封装 32 字节 DK（长度必须 32） |
| `sm2-enc-002` | SM2-encrypt | pub; k; plaintext | 98 | hex（0x04 ‖ C1.x(32) ‖ C1.y(32) ‖ C3(32) ‖ C2） | `gmssl-lib` | 1 字节边界（每个实现都应支持的最小长度） |
| `sm2-sign-001` | SM2-sign | priv; pub; k; sig_input; sig_input_len | 70 | DER（SEQUENCE{r,s}，70..72 字节） | `gmssl-lib` | API §1.3 REGISTER（CODE=AWQW） |
| `sm2-sign-002` | SM2-sign | priv; pub; k; sig_input; sig_input_len | 71 | DER（SEQUENCE{r,s}，70..72 字节） | `gmssl-lib` | API §1.3 TRANSFER_CREATE（prelude_sm3 取契约 §15.2 的 prelude） |
| `sm2-sign-003` | SM2-sign | priv; pub; k; sig_input; sig_input_len | 72 | DER（SEQUENCE{r,s}，70..72 字节） | `gmssl-lib` | API §1.3 NICKNAME_UPDATE（昵称 UTF-8） |
| `sm2-sign-004` | SM2-sign | priv; pub; k; sig_input; sig_input_len | 70 | DER（SEQUENCE{r,s}，70..72 字节） | `gmssl-lib` | 契约 §10.2 包签名 SIG_INPUT（YSSIG1，§15.5 样例） |
| `yspk-v1-min` | YSPK/1.0 pack | recipient_pub; sender_priv; dk; kdf_salt; k_enc; k_sig; created_at_ms; mime; ext; plaintext | 522 | hex（完整包字节） | `gmssl-lib` | 契约 §15.2 最小单块包（522 字节），已逐字节核对 |
| `yspk-v1-multi` | YSPK/1.0 pack | recipient_pub; sender_priv; dk; kdf_salt; k_enc; k_sig; created_at_ms; mime; ext; plaintext; plaintext_len | 743 | hex（完整包字节） | `gmssl-lib` | 契约 §15.3 多块包（CHUNK_SIZE=32，3 块，743 字节），已逐字节核对 |

## 需要 GmSSL（OpenSSL 不够）的条目

| id | 为什么 |
|---|---|
| `sm4gcm-001` | OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag |
| `sm4gcm-002` | OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag |
| `sm4gcm-003` | OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag |
| `sm4gcm-004` | OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag |
| `sm4gcm-005` | OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag |
| `sm4gcm-006` | OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag |
| `sm2-enc-001` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `sm2-enc-002` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `sm2-sign-001` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `sm2-sign-002` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `sm2-sign-003` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `sm2-sign-004` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `yspk-v1-min` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |
| `yspk-v1-multi` | 需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签 |

OpenSSL 能独立完成的部分：`sm3-*`、`hmac-001`；`hkdf-*` 需要 OpenSSL 库里的 HKDF（EVP_KDF）；SM4-GCM 用 OpenSSL 库（EVP_EncryptInit_ex + EVP_CTRL_GCM_GET_TAG）也可以，CLI 不行。
