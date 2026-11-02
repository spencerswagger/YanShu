# 跨实现一致性：用户码派生 + 码归一化（2026-11-02）

- 对象：端侧 `feat/endcrypto-wasm` @ `f1ef9f9`（wasm 127,313B + 原生 `ys-tool`）
- 脚本：`qa/evidence/check_code_consistency.py`（可复跑、有 PASS/FAIL 与退出码）
- 结论：**20/20 通过** —— 四个入口逐字符一致，`PB_S = AWQW`；归一化在 wasm 与 Core 两侧同判

## 复跑

```sh
git -C <YanShu> archive f1ef9f9 | tar -x -C /tmp/rune
(cd /tmp/rune/crypto/sm && CARGO_TARGET_DIR=$PWD/target \\
   cargo build --release --target wasm32-unknown-unknown && \\
   CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc \\
   CARGO_TARGET_DIR=$PWD/target cargo build --release --bin ys-tool)

python3 qa/evidence/check_code_consistency.py \\
  --wasm /tmp/rune/crypto/sm/target/wasm32-unknown-unknown/release/yanshu_sm.wasm \\
  --ys-tool /tmp/rune/crypto/sm/target/release/ys-tool \\
  --base-url http://127.0.0.1:18080        # 可选：归一化再对一次 Core
```

## 1) 用户码派生：四个入口一致

5 组公钥（契约 `PB_S` + 4 组现场生成），每组都跑四个入口：

| 入口 | 入参形态 |
|---|---|
| wasm `ys_user_code` | 64B `X‖Y` |
| wasm `ys_user_code_wire` | 65B `0x04‖X‖Y` |
| `ys-tool user-code` | 64B |
| `ys-tool user-code` | 65B |

结果全部逐字符相同，且 `PB_S → AWQW`（契约 §15.1 值，校验位 `X`）。

## 2) 归一化：wasm 与 Core 同判

14 组输入（接受 7 / 拒绝 7），含 `a-w-q-w`、` AWQW `、`AW\tQW`、`AWQW\r\n`、`0WQW`、
`OI`、`AWQ`、**`AWQWX`（5 位整体拒绝、不截断）**、`AWQW-X`、`AWQU`、`AWQ!`、中文、空串。
wasm 的接受/拒绝与期望全部一致；对 Core 服务端能判的用例（400 `CODE_FORMAT_INVALID` vs 404）
也与 wasm 同判。少数用例因**码查询限速/锁定**返回 423，脚本按"判不了"跳过而不是记 PASS——
这类"跳过"必须在报告里显式写明，否则就是拿限速当一致。

## 3) 一个必须澄清的更正：P0 是我这边的调用约定 bug

上一轮我报的"`ys_user_code` 三方不一致（`FXWD` / `M8NE` / `X2EH`）"，根因在**我的驱动**：
我给 64 字节入参的 `ys_user_code` 传了一个 **65 字节缓冲区（含 `0x04` 前缀）**，
内核读到 `0x04‖X[0..63]` 再补一个 `0x04`，哈希输入整体错位一位 → 算出不同的码。

修驱动后（按入口宽度准备缓冲区：64 字节入口给纯 `X‖Y`，wire 入口给 `0x04‖X‖Y`），
四个入口全部 `AWQW`。Rune 的根因判断与 Web 的复测结论都成立，**内核没有算错**。
这条我按"证据脚本自身的缺陷"归档，避免以后有人再把它当成内核 bug 追。

## 4) 边界

- 归一化的 Core 侧比对走码查询接口，受 `code_lookup_per_min=30` 限速；连续跑会被 423/429 挡，
  脚本把这类响应记为"判不了"，不计入一致。
- 本检查不覆盖码碰撞策略（撞码重生成密钥对），那属于端侧 + 服务端联调用例。
