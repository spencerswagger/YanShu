# 端侧内核（wasm）副本

`yanshu_sm.wasm` 是端侧 crate `crypto/sm` 的构建产物，服务端 `YANSHU_VERIFIER=sm2`
用 wazero 加载它、调 `ys_sm2_verify_der` 做验签（路线 B：不维护第二套 SM2 实现）。

| 项 | 值 |
|---|---|
| 来源分支/提交 | `feat/endcrypto-wasm` @ **`031e95b`**（与验收冻结 head `80400ec` 同产物） |
| 大小 | **127 313 B** |
| sha256 | **`c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`** |
| 导出 | 34 个函数 + `memory`，**0 个 import** |
| 用到的导出 | `ys_alloc` / `ys_free` / `ys_sm2_verify_der` / `ys_version` |
| 版本 | `ys_version() == 0x00010000`（`YSPK/1.0`） |

## 重新生成（必须从 workspace 根构建）

```sh
git archive <commit> | tar -x -C /tmp/ys-kernel
cd /tmp/ys-kernel/crypto                 # ← 这里是 workspace 根（有 Cargo.toml + Cargo.lock）
cargo build --release --target wasm32-unknown-unknown -p yanshu-sm
cp target/wasm32-unknown-unknown/release/yanshu_sm.wasm <repo>/server/kernel/
sha256sum <repo>/server/kernel/yanshu_sm.wasm   # 与上表不一致就更新本文件
```

⚠️ **不要 `cd crypto/sm` 再构建**：从成员目录构建会绕过 workspace 的 `Cargo.lock` 与
`[profile.release]`（`opt-level=3`/`lto`/`codegen-units=1`），产物 130 653 B / `8b89dd7f…`，
与冻结产物不同字节（行为和版本一致，但**不能**拿它当"同源"证据）。

## 更新流程

换内核时：按上面命令重建 → 更新本文件三处（commit、大小、sha256）→ 跑
`go test ./internal/auth/`（会加载本文件跑端侧验签向量与双向对账）→ 跑
`scripts/token-rotation-check.sh` 之外的 `sm2` 全链路。
