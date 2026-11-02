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

# 手工试一把
PROBE=$(.…build_probe.sh /tmp/rune/crypto/sm)
$PROBE keygen /tmp/alice.sk /tmp/alice.pk
$PROBE keygen /tmp/bob.sk /tmp/bob.pk
$PROBE pack  /tmp/plain.bin /tmp/a.yspk --recipient-pk /tmp/bob.pk --sender-sk /tmp/alice.sk \
       --name "样本.bin" --mime application/octet-stream --block-size 1048576
$PROBE unpack /tmp/a.yspk /tmp/out.bin --recipient-sk /tmp/bob.sk --sender-pk /tmp/alice.pk
```

一键跑全套（含篡改检查）：`qa/evidence/run_evidence2_rune.sh /tmp/rune/crypto/sm`。

## 驱动的输出契约

| 场景 | stdout | 退出码 |
|---|---|---|
| 解包成功 | `OK <明文字节数> <块数>`，明文写到 `--out` | 0 |
| 解包失败 | `ERR <错误名>`（如 `MANIFEST_MISMATCH`），**不写任何输出文件** | 1 |
| 参数/IO 错误 | `probe: <原因>`（stderr） | 2 |

密钥文件是**裸字节**（sk 32B、pk 64B `x‖y`），不是 hex 或文本，避免被误当配置提交。
驱动的 stdout 只报长度，不回显密钥。

## 换别的实现怎么办

任何满足上表契约的二进制都能接：`--backend cmd --decrypt-cmd '<命令> {in} {out}'`。
等 Web 侧把 wasm 适配层做好，也可以把 `{in}` 交给 Node 脚本驱动 wasm 再跑一遍。
