# GmSSL 逐字节交叉验证

用 **GmSSL 3.1.1**（官方 C 实现）重算 `testdata/vectors.json` 里的每一条向量，与 Rust 实现
逐字节比对；并做反向验证（GmSSL 生成 → 本实现验收）。全绿才算验收。

## 一键复跑

```sh
scripts/crosscheck/run.sh
```

前置：

1. 编译好的 GmSSL 3.1.1 源码树（`include/gmssl/*.h` + `build/bin/libgmssl.a` + `build/bin/gmssl`）。
   查找顺序：`$GMSSL_DIR` → `/.cache/ys/GmSSL-3.1.1` → `../GmSSL-3.1.1` → `/opt/GmSSL-3.1.1`。
2. Rust 工具链 + `python3` + `gcc`。

没有 GmSSL 时可以 `GMSSL_AUTOBUILD=1 scripts/crosscheck/run.sh`（需 cmake，会下载 v3.1.1 源码并编译）。

自己编 GmSSL：

```sh
curl -L -o gmssl.tar.gz https://codeload.github.com/guanzhi/GmSSL/tar.gz/refs/tags/v3.1.1
tar xzf gmssl.tar.gz && cd GmSSL-3.1.1
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && make -j"$(nproc)"
```

## 脚本做了什么

| 阶段 | 内容 | 谁算的 |
|---|---|---|
| A1 | SM3 摘要 | `gmssl sm3` 命令行 |
| A2 | HMAC-SM3、HKDF-SM3 | `libgmssl`（oracle 里调 `sm3_hmac` 拼 HKDF） |
| A3 | SM4-GCM 密文 + tag | `gmssl sm4 -gcm` 命令行（输出 = ct‖tag） |
| A4 | SM2 公钥、ZA、C1C3C2 加密、r‖s 签名 | `libgmssl`，**固定 k**（见下） |
| A5 | 4 位用户码 | `gmssl sm3` + Python 按 Crockford 规则重算 |
| B | **整个加密包**（header/记录/每块/清单/签名） | Python 用 GmSSL 原语重新拼出来，逐字节比 |
| C | GmSSL 真随机加密/签名 → 本实现解密/验签/解包 | 反向 |
| D | `gmssl sm4 -gcm` 命令行密文 → 本实现解密 | 反向 |

### 为什么 SM2 也能"逐字节"比

GmSSL 的 `sm2_do_encrypt` / `sm2_sign` 内部用 `rand_bytes()`。oracle（`oracle.c`）**自己实现了
`rand_bytes`**，链接时优先于 `libgmssl.a` 里的 `rand.o`，于是传入固定 k 后 GmSSL 的
SM2 输出就是确定性的 —— 可以和 Rust 侧同 k 的结果逐字节比，而不只是"验签通过"。

`sm2_bn_rand_range` 是"取 32 字节、`< n` 才收"，所以只要给的 k 合法，第一次就是它。

## 实测结果（GmSSL 3.1.1 / Rust 1.99.1）

```text
PASS 77 / FAIL 0
```

覆盖：SM3 5 条、HMAC-SM3 3 条、HKDF-SM3 4 条、SM4-GCM 6 组×2（加密+解密）、
SM2 3 组密钥（公钥 + ZA）、4 组加密（密文 + GmSSL 反向解密）、3 组签名（r‖s + GmSSL 验签）、
3 组用户码（码 + 2 条规范化）、4 个加密包（整包字节）、
反向 3 组随机 SM2 加密/签名 + 4 组解包 + 4 组篡改拒绝 + 6 组 GCM 反向解密。

## 哪部分不是"GmSSL 直接给的"

* **HKDF-SM3**：GmSSL 没有 HKDF-SM3 的现成 API，oracle 里按 RFC 5869 用它的 `sm3_hmac` 拼了
  20 行——PRF 与 HMAC 是 GmSSL 的，HKDF 的拼装逻辑在 oracle 侧独立于 Rust 实现。
* **加密包的"封装"**：GmSSL 不认识雁书的包格式，B 阶段是在 Python 里按
  `docs/crypto-pack-v1-draft.md` 用 GmSSL 原语重拼——这正好验证了"布局常量 + 拼接顺序"没有
  只跟自己一致。
* **Crockford 编码**：Python 里独立实现（GmSSL 只负责 SM3 那一步）。
* **性能**不做交叉验证（GmSSL 的 SM4 是 C 优化版，比 Rust 快，没意义）。
* wasm 与 native 走同一份 Rust 代码，ABI 差异由 `scripts/wasm-smoke/smoke.mjs` 覆盖，
  不在本脚本里重复。

## 文件

| 文件 | 作用 |
|---|---|
| `run.sh` | 一键：定位 GmSSL → 编 oracle → 编 ys-tool → 跑比对 |
| `oracle.c` | 链接 `libgmssl.a` 的对照实现（含 `rand_bytes` 覆盖） |
| `crosscheck.py` | 解析向量、调两侧、逐字节比、打印第一处差异偏移 |

产物落在 `tmp/crosscheck/`（已被 `.gitignore` 忽略）。
