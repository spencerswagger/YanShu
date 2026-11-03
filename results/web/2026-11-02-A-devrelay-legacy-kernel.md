# 证据 A · **dev relay + 旧布局内核**（跨浏览器链路证据，**不是**最小闭环验收）

> **限定（写死在文件头）**
> - 中转 = **dev relay**（`web/relay/dev-relay.mjs`，内存、不验签）——**不是** Core 服务端。
> - 内核 = **契约返工前旧布局**（`ys_header_len()` = 40，公钥 64 字节入参，`r‖s` 签名，解包需发送方公钥）。
> - 因此本文件**不能**作为「最小闭环通过」或契约验收依据；它的用途只有一个：**跨浏览器链路证据**。

| 项 | 值 |
|---|---|
| 运行标签 | `A-devrelay-legacy-kernel` |
| 日期 | 2026-11-02 |
| 前端 | `web/`（Vue 3 + Vite，dev server） |
| 中转 | `web/relay/dev-relay.mjs`（dev relay） |
| 内核 | 旧布局 wasm（HEADER 40），构建自 `feat/endcrypto-wasm` 契约返工前的提交 `12b3d94`（`ys_version()=0x00010000`、24 导出、0 import） |
| 界面标签 | `真实加密 · 旧布局内核（待对齐契约）`（页面顶部另有红条：不能作为契约验收） |
| 样本 | `ys-e2e-input.bin`，2 506 889 字节，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 客户端 | 两个独立 Chrome profile（= 两个身份，IndexedDB 隔离） |

## 流程

A 端：选文件 → 输入 B 的 4 位码 → 查昵称 → 加密并发送（真 SM4-GCM/SM2/SM3，3 块）→ 界面显示「已发送」。
B 端：待收 → 刷新 → 取回并解密 → 浏览器下载落盘。

## 结果

- 发送成功（`state: READY`），接收成功（`ack` 后状态终结）。
- 落盘 `ys-e2e-input.bin`：**2 506 889 字节**，sha256 与源文件**完全相同**（`bytesEqual: true`）。
- 结果 JSON：`results/web/2026-11-02-A-devrelay-legacy-kernel.json`
- 截图：`outbound/screenshots/A-devrelay-legacy-kernel-{A-prepared,A-sent,B-inbox,B-received}.png`（工作区，不入库）

## 这份证据能说明 / 不能说明

**能**：浏览器两端（选文件、码、进度、上传、待收、取回、解密、落盘）在**真加密**下走通，字节一致；
传输编排、错误映射、移动端布局都没有阻塞问题。

**不能**：不能证明契约布局（HEADER 112 / `SENDER_PUB` 入包 / DER / 公钥 65）成立；
不能证明 Core 服务端行为；不能作为验收。

## 重跑条件

Rune 契约版内核 + Core 真实 HTTP 服务到位后，用**同一套流程、同一份样本**跑第二次，
结果见 `results/web/2026-11-02-B-core-contract-kernel.md`。第一次在第二次跑出来之前不作数。
