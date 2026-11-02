# 端侧内核（wasm）副本

`yanshu_sm.wasm` 是端侧 crate `crypto/sm` 的构建产物，服务端 `YANSHU_VERIFIER=sm2`
用 wazero 加载它、调 `ys_sm2_verify_der` 做验签（路线 B：不维护第二套 SM2 实现）。

| 项 | 值 |
|---|---|
| 来源分支/提交 | `feat/endcrypto-wasm` @ `f1ef9f9a1212ce48ae40d3891750ee7c8da81d9d` |
| 大小 | 130 653 B |
| sha256 | `8b89dd7fc033b9f4b316238d1d7507b161bbc74ff3547643d00981ed8da154f9` |
| 导出 | 34 个函数 + `memory`，**0 个 import** |
| 用到的导出 | `ys_alloc` / `ys_free` / `ys_sm2_verify_der` / `ys_version` |
| 版本 | `ys_version() == 0x00010000`（`YSPK/1.0`） |

## 重新生成

```sh
git archive feat/endcrypto-wasm crypto/sm | tar -x -C /tmp/ys-kernel
cd /tmp/ys-kernel/crypto/sm
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/yanshu_sm.wasm <repo>/server/kernel/
sha256sum <repo>/server/kernel/yanshu_sm.wasm   # 与上表不一致时更新本文件
```

注意：构建 wasm 时**不要**全局覆盖 `RUSTFLAGS`/`CC`（会把 linker 带偏，见端侧
`docs/ABI.md`）；上面这条命令不需要额外参数。

## 更新流程

内核升级时：换文件 → 更新本文件的两个值（commit、sha256）→ `go test ./internal/auth/`
会重跑端侧验签向量（`internal/gm/testdata/sm2-verify-vectors.json`），失败即说明口径漂移。
