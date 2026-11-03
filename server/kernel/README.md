# 端侧内核（wasm）副本

`yanshu_sm.wasm` 是端侧 crate `crypto/sm` 的构建产物，服务端 `YANSHU_VERIFIER=sm2`
用 wazero 加载它、调 `ys_sm2_verify_der` 做验签（路线 B：不维护第二套 SM2 实现）。

| 项 | 值 |
|---|---|
| 来源分支/提交 | `feat/kernel-streaming` @ **`e2aa01e`**（流式内核；字节兼容 YSPK/1.0） |
| 大小 | **140 742 B** |
| sha256 | **`8766048ffdd16b9de8c4f3fea49590ec0802418dea9ad0fdca68f0e05bb625f8`** |
| 旧内核 | `c1b87d0a…7259f`（127 313 B）保留在启动白名单中用于灰度，本目录只保留新内核 |
| 导出 | 43 个函数 + `memory` = 44，**0 个 import** |
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

## 更新流程（用冻结 head 的产物覆盖，不要用自己重建的）

1. 取端侧**冻结 head** 的 `yanshu_sm.wasm`（验收组公布的那份），覆盖本目录同名文件；
2. `sha256sum kernel/yanshu_sm.wasm` 必须等于验收公布值（当前
   `8766048f…25f8`），否则**不提交**；
3. 更新本文件三处：来源 commit、字节数、sha256；
4. 跑 `go test ./internal/auth/`（加载本文件跑验签向量 + 双向对账）与 `sm2` 全链路。

> 本文件被根目录 `.gitignore` 的 `*.wasm` 规则命中，靠 `server/.gitignore` 的
> `!kernel/yanshu_sm.wasm` 例外才进仓库；新增内核文件时记得同样放行。
