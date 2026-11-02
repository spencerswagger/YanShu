# 雁书 YanShu · 端侧国密内核（Rust → wasm32）

一次性加密文件互传的**端侧**部分：SM3 / SM4-GCM / SM2 / 加密包 / 4 位用户码。
全部自研，**不依赖任何外部密码库**（连大数库都没有：SM2 用自写的 256 位 Montgomery 运算）。

```
crypto/
├── Cargo.toml          workspace
├── include/yanshu_sm.h  C ABI 头（wasm 导出函数 + 错误码）
└── sm/
    ├── src/
    │   ├── bigint.rs   256 位整数 + Montgomery 模运算（SM2 用）
    │   ├── sm3.rs      SM3 + HMAC-SM3
    │   ├── sm4.rs      SM4 分组（加/解密单块）
    │   ├── gcm.rs      SM4-GCM（128 位 tag，查表 GHASH）
    │   ├── hkdf.rs     HKDF-SM3
    │   ├── sm2.rs      密钥对 / C1C3C2 加解密 / 签名验签
    │   ├── pack.rs     加密包 v1 打包 + 严格解包（格式锚点全在 `layout`）
    │   ├── code.rs     4 位 Crockford Base32 用户码
    │   ├── rng.rs      Rng trait / OsRng / SeedRng（wasm）
    │   ├── ffi.rs      raw C ABI（`#[no_mangle] extern "C"`）
    │   └── bin/        gen-vectors / bench-sm4 / ys-tool
    └── tests/pack_strictness.rs  篡改矩阵（每种篡改对应具体错误码）
```

## 纯 Rust API 是主入口

wasm 只是另一种调用方式：`pack::pack` / `pack::unpack` / `sm2::*` / `code::*` 都能在宿主侧直接单测。

```rust
use yanshu_sm::{code, pack, sm2};

let mut rng = yanshu_sm::rng::OsRng::new();
let alice = sm2::keygen(&mut rng);
let bob = sm2::keygen(&mut rng);
let bob_code = code::from_public_key(&bob.public_key); // 4 位码

let input = pack::PackInput {
    recipient_public: &bob.public_key,
    sender_private: &alice.private_key,
    name: "报告.pdf",
    mime: "application/pdf",
    block_size: pack::layout::DEFAULT_BLOCK_SIZE,
    data: b"...",
};
let bytes = pack::pack(&input, &mut rng).unwrap();
let out = pack::unpack(&bytes, &bob.private_key, &alice.public_key).unwrap();
```

## 构建 / 测试

```sh
cd crypto
cargo test                      # 25 单元 + 8 契约样例 + 5 篡改矩阵 + 23 §13 检验
cargo test --release            # 同上（快）
cargo run --release --bin bench-sm4 -- 32
cargo run --release --bin gen-vectors -- ../testdata/vectors.json
cargo run --release --bin gen-host-crosscheck -- ../vectors   # 宿主对照请求（JSON + MD）
```

> 有的镜像只有 `gcc` 没有 `cc`。**只在宿主（x86_64）构建时**按 target 设置：
> `export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc`。
> ⚠️ **不要用全局 `RUSTFLAGS="-C linker=gcc"` 或 `CC=…` 覆盖**：那会给 wasm32 目标
> 也套上 host linker，报 `linker ... not found` 或产出非 wasm 对象。构建 wasm 时保持
> `--target wasm32-unknown-unknown` 且不覆盖全局 linker（本仓库的脚本都按 target 设置）。

## wasm32 构建（raw C ABI，不引 wasm-bindgen）

```sh
rustup target add wasm32-unknown-unknown   # 沙盒已装
cargo build --release --target wasm32-unknown-unknown
# 产物：$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/yanshu_sm.wasm
node scripts/wasm-smoke/smoke.mjs <上面那个 wasm>
```

实测：**约 121 KB，29 个函数导出，0 个 import**（没有 JS 胶水依赖；其中 23 个签名与首版一致，2 个按 P1 改了）。
导出清单见 `include/yanshu_sm.h`，核心是：

`ys_alloc/ys_free/ys_version/ys_error_name` · `ys_default_block_size` · `ys_header_len`（112）·
`ys_sm3/ys_hmac_sm3/ys_hkdf_sm3` ·
`ys_sm4_encrypt_block/ys_sm4_decrypt_block/ys_sm4_gcm_encrypt/ys_sm4_gcm_decrypt` ·
`ys_sm2_keygen/ys_sm2_pubkey/ys_sm2_encrypt/ys_sm2_decrypt/ys_sm2_sign/ys_sm2_verify` ·
`ys_user_code/ys_check_symbol/ys_normalize_code` · `ys_pack/ys_pack_v1` · `ys_unpack/ys_unpack_meta`（P1：包内自证来源）· `ys_sm2_sign_der` · `ys_error_name_v1`

约定：长度用 `size_t`（wasm32 = 4 字节）；返回 0 成功、负数为错误码；`out_len` 在缓冲区
不足时也会写入所需长度（返回 -2），JS 可以"先问大小再分配"。

## 加密包格式

**默认布局**严格按 **`docs/CRYPTO-PACK.md` v1（`YSPK/1.0`）** 实现；另保留
全库只有这一种格式（首版 rune-v1 已删除，不再有第二套）：

- HEADER 112 字节（字段偏移集中在 `pack::v1::OFF_*`）、SENDER_PUB 65、WRAPPED_KEY 129；
- 块记录 = 16 字节块头 + 密文 + 16 字节 tag，nonce = `u64be(index) ‖ 000000 ‖ last`；
- 清单 `YSM1` 整体加密，每块放 `SM3(明文)`；
- 签名 `SIG_INPUT = "YSSIG1" ‖ 0100 ‖ HEADER[0..72) ‖ SENDER_PUB ‖ MANIFEST_SEC`，DER 编码。

契约 §15 的四组样例在 `crypto/sm/tests/contract_samples.rs` 里逐字节断言；
实现与契约的对照说明见 `docs/crypto-pack-impl-notes.md`。

> 口径提醒：包内公钥是 **65 字节带 0x04**；原语层 API 用 64 字节 `X‖Y`。
> 用户码是对 **65 字节**公钥做 SM3。

## 测试向量与交叉验证

`testdata/vectors.json` 是全 hex 向量文件，包含：

* `meta` + `conventions`：算法参数口径（C1C3C2 顺序、点编码、签名 R‖S 非 DER、GCM nonce/AAD 规则、
  HKDF salt/info、用户码编码、加密包每个字段与 nonce/AAD 规则），宿主侧照它复算；
* 每条向量还带 `plaintext_len` / `aad_len` / `nonce_len` / `msg_len` / `pack_bytes` 等**长度口径**；
* SM3 / HMAC-SM3 / HKDF-SM3 / SM4-GCM（空明文、1 字节、16 字节、15 字节、带 AAD 1000 字节）/
  SM2（3 组密钥含 ZA、4 组加密、3 组签名）/ 用户码 / 4 个完整加密包（含空文件与多块）。

比对脚本 `scripts/crosscheck/`：

* 本机有 GmSSL 就逐字节重算（SM2 固定 k，密文/签名一致）；
* 没有 GmSSL 时读 `testdata/gmssl-expected.json`（`--emit-template` 生成模板给宿主填），
  缺失条目打印 `SKIP 待宿主对照` 而不是 FAIL；
* 两者都没有也照跑，退出码 0。

## 用户码

`code = CrockfordBase32(SM3(公钥))[0..4]`，字母表 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`，
输入规范化 `O→0`、`I/L→1`、去 `-`、大小写不敏感。**保持 4 位，不加长**。

需求基线提到"建议加 1 位 Crockford 校验字符"：本实现**没有**把它放进码里（否则就是 5 位）。
校验字符算法以 `code::check_symbol()` 单独提供，仅作为输入校验工具备选，不参与码生成 ——
要不要用由 Ark/spencer 拍板。

撞码：`code::generate_until_free(rng, max_attempts, |code| 服务端说已占用)`，
命中已占用就换密钥对重算，超限返回 `CODE_EXHAUSTED`。wasm 侧由 JS 用
`ys_sm2_keygen` + `ys_user_code` 循环实现同样逻辑（避免回调跨 ABI）。

## 性能（粗测，release，单核，沙盒）

| 项 | 数值 |
|---|---|
| SM4-GCM 加密 | ≈ 56 MB/s |
| SM4-GCM 解密 | ≈ 55 MB/s |
| SM4-ECB 单块 | ≈ 84 MB/s |

GHASH 用 8 位查表（原来逐位实现只有 8.5 MB/s）。没做 SIMD/AES-NI 级优化，按任务要求"够用即可"。
1 GB 文件按 1 MiB 分块 ≈ 18~20 s 纯加密（不含网络）。

## 已知限制 / 风险

1. **不是常数时间**：SM2 标量乘、模逆、比较都有数据相关分支。浏览器本地场景可接受，
   但没有做侧信道加固（明确不在本轮范围）。
2. **整包内存 API**：`ys_pack`/`ys_unpack` 一次吃下整个包；1 GB 文件在 wasm32 里会吃掉
   2~3 倍内存。流式分块接口是下一轮的事（Web 侧大文件必须配合）。
3. **wasm 随机源由调用方负责**：`seed` 必须每次用 `crypto.getRandomValues` 现取。
   内核混入了进程内计数器做兜底，但同一 seed 跨会话复用仍会导致 k 复用（灾难性），
   Web 侧务必按文档调用。
4. **SM2 加密/签名临时标量**用拒绝采样（`< n` 且非 0），没有做 RFC 6979 式确定性 k。
5. 私钥只在本机（IndexedDB），本 crate 不做持久化、不做备份。
