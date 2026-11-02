# adapters · 把端侧内核接到证据二

`tamper_probe.py --backend cmd` 需要一个"能解密、失败会明确报错"的可执行入口。
端侧内核（`crypto/sm`）目前没有导出 CLI，所以这里放一个最小驱动：

* `ys_pack_probe.rs` —— 40 行的胶水：`keygen` / `pack` / `unpack`，只调
  `yanshu_sm::pack` 与 `yanshu_sm::sm2` 的公开 API，不含任何密码学实现
* `build_probe.sh` —— 把驱动塞进端侧 crate 的**临时副本**并编译

## 为什么不在仓库里放 Cargo.toml

`yanshu-sm` 不在 `main` 上。如果写成 `path = "../../crypto/sm"` 的依赖，本分支
单独 checkout 就会构建失败。所以改成"运行时复制一份 crate 到临时目录 + 塞一个 bin"：
仓库里只有源码，谁都能对着任意 checkout 复跑。

## 用法

```sh
# 取端侧源码到任意目录（不进仓库）
git -C <YanShu 仓库> archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune

# 编译（产物在 /tmp/ys-probe-build，或 $CARGO_TARGET_DIR）
qa/evidence/adapters/build_probe.sh /tmp/rune/crypto/sm
# → /.cache/rust/release/ys_pack_probe

# 手工试一把（契约布局 YSPK/1.0：公钥入包，unpack 不再收发送方公钥）
PROBE=$(qa/evidence/adapters/build_probe.sh /tmp/rune/crypto/sm)
$PROBE keygen /tmp/alice.sk /tmp/alice.pk
$PROBE keygen /tmp/bob.sk /tmp/bob.pk
$PROBE pack  /tmp/plain.bin /tmp/a.yspk --recipient-pk /tmp/bob.pk --sender-sk /tmp/alice.sk \
       --name "样本.bin" --mime application/octet-stream --ext bin --chunk-size 1048576
$PROBE unpack /tmp/a.yspk /tmp/out.bin --recipient-sk /tmp/bob.sk
```

密钥文件：`sk` 32B、`pk` 64B（`x‖y`）。`pack` 需要 65B `0x04‖x‖y`，驱动会按需补前缀；
`unpack` 只需要收件方私钥（发送方公钥已在包里，可用 `--expect-sender-code` 顺带比对 §13 #18）。

一键跑全套（含篡改检查）：`qa/evidence/run_evidence2_rune.sh /tmp/rune/crypto/sm`。

## 为什么不继承 `CARGO_TARGET_DIR`

沙盒里全局设了 `CARGO_TARGET_DIR=/.cache/rust`，多人共用。实测过一次：拿 A 版本源码
构建，cargo 却复用了别人编译出的 `libyanshu_sm`（报错里出现的字段属于新版本），
等于**拿别人的源码产出当自己的证据**。所以 `build_probe.sh` 默认把 target 放到临时目录
（`$work/target`），要共享必须显式 `YS_PROBE_TARGET_DIR=…`。

## ABI 口径（照头文件，不照记忆）

- **公钥入参一律 64 字节 `X‖Y`，不带 `0x04`**（0x04‖X‖Y 只出现在包内 `SENDER_PUB`）。
  传 65 字节给 `ys_pack_v1` 会得到 `CRYPTO_CURVE_INVALID`——本驱动踩过，现按 64 传、
  收到 65 字节时自动去掉前缀。
- **解包符号**：优先 6 参 `ys_unpack_v2` / `ys_unpack_v1`（名字随版本变），
  没有则回退 **7 参** `ys_unpack(pack,len,priv,sender_pub_or_0,out,cap,out_len)` 并把第 4 参传 `0`。
- **绝不能拿 6 个实参去调 7 参的那个导出**：wasm 会静默丢掉多余实参、整体错位一位
  （`out` 收到公钥指针、`out_len` 收到容量数字）→ 内存踩踏。驱动因此在调用前**断言
  `fn.length`**（wasm 导出函数的 `.length` 就是形参个数），对不上直接退出 2。

## 驱动的输出契约

| 场景 | stdout | 退出码 |
|---|---|---|
| 解包成功 | `OK <明文字节数> <块数>`，明文写到 `--out` | 0 |
| 解包失败 | `ERR <错误名>`（如 `MANIFEST_MISMATCH`），**不写任何输出文件** | 1 |
| 参数/IO 错误 | `probe: <原因>`（stderr） | 2 |

密钥文件是**裸字节**（sk 32B、pk 64B `x‖y`），不是 hex 或文本，避免被误当配置提交。
驱动的 stdout 只报长度，不回显密钥。

## 已知不一致（2026-11-02，待端侧确认）

`ys_user_code`（wasm，64 字节入参）与 `ys-tool user-code`（原生，65 字节入参）**算出的码不同**：

| 输入 | wasm `ys_user_code` | `ys-tool user-code` | 契约 §15.1 |
|---|---|---|---|
| 契约样例 `PB_S` | `X2EH` | **`AWQW`** | **`AWQW`** |
| 本次投递包内公钥 | `FXWD` | `M8NE`（= SM3(65B) 手算） | — |

`ys-tool` 与手算、与契约样例一致；wasm 侧对不上。浏览器拿这个码去注册会被服务端按
"码与公钥不匹配"拒掉。已报给实现方，驱动暂不依赖 `ys_user_code`。

## 换别的实现怎么办

任何满足上表契约的二进制都能接：`--backend cmd --decrypt-cmd '<命令> {in} {out}'`。
等 Web 侧把 wasm 适配层做好，也可以把 `{in}` 交给 Node 脚本驱动 wasm 再跑一遍。
