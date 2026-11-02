# 证据 C2 · 真 sm2 认证端到端（宿主机实例）

> **锚 sha256，不锚 head 号**：内核产物 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127 313 B）；
> head `80400ec` 只作溯源。sha 一变，本证据作废需重跑。

| 项 | 值 |
|---|---|
| 运行标签 | `c1b87d0a-sm2-e2e` |
| 日期 | 2026-11-02 |
| 中转 | **宿主 `http://127.0.0.1:18080`，`yanshu-server-4eda665`（sha256 `cc117070…e571f9`），`YANSHU_VERIFIER=sm2`（wazero 载内核真验签），`YANSHU_TOKEN_EPOCH=1`** |
| 内核 | 冻结产物 `c1b87d0a…` / 127 313 B / 34 函数 + `memory` / 0 import / `ys_version()=0x00010000` / HEADER 112 |
| 样本 | `ys-e2e-input.bin` 2 506 889 字节，sha256 `4b0c533a77c670b05d0ee1bd235449ff312c27ee8b3375a492c5a88ac058482f` |
| 分块 | 服务端 `chunk_size=1048576` → **3 块**（2×1 MiB + 409 601 B） |
| 客户端 | 两个独立 Chrome profile（两个身份） |

## 端到端结果

注册 → 建包（`ys_pack_v1`，64 字节公钥）→ prelude + 3 块 PUT → complete → 收件箱 → 取 prelude（`ys_unpack_meta_prelude` 先显示「来自谁/文件名/大小/块数」，标**未校验**）→ 逐块 GET → `ys_unpack_v1` 验签解密 → 落盘（切**已校验**）→ `ack`。

- 落盘 `ys-e2e-input.bin`：**2 506 889 字节**，sha256 与源文件**完全相同**。
- 结果 JSON：`results/web/c1b87d0a-sm2-e2e.json`
- 与 `stub-allow` 的两份（`2026-11-02-B/C-*.md`）分开留档。

## 真认证才有的三条分支（同一次运行内实测）

| 分支 | 构造 | 实测 |
|---|---|---|
| 昵称签名（`NICKNAME_UPDATE`=0x02） | 真签名 + 真挑战 | **200**（真验签通过） |
| 篡改签名一字节 | DER 末字节取反 | **401 `AUTH_SIGNATURE_INVALID`** |
| 请求路径码 ≠ 头里的码（签名对头里的码有效） | 路径用 B 的码、头与签名用 A 的码 | **401 `AUTH_CODE_MISMATCH`**（**不是**签名错） |
| 复用已用挑战 | 同一 `challenge_id` 二次提交 | **401 `AUTH_CHALLENGE_INVALID`**（不被误报成签名错） |
| token 分支 | 宿主 `EPOCH=1`，未构造 stale | 本次未出现 401 凭据类错误；客户端 401 自愈分支有单测覆盖（`AUTH_MISSING`→重建传输、租约失效→重开） |

（原始输出：`notes/c2-auth-checks.mjs` 的运行结果 `results/web/c1b87d0a-sm2-auth-branches.json`。）

## 标签与产物核对

- `npm run wasm:check`：`ys_user_code` 64B=`AWQW` / 65B=`X2EH`；`ys_check_symbol` 64B=`X` / wire-65=`X`（四值同屏）。
- `describeKernel()` → 契约布局（§2.3 四条：版本 / HEADER / V1 样例真解 / 版本闸门）。
- 页面底部显示 commit + `ys_version` + HEADER + 导出数 + sha256，与 `public/ys_kernel.build.json` 一致。

## 能说明 / 不能说明

**能**：真实服务端验签下的完整闭环（注册/建包/inbox/ack 全过验签）、端侧加解密、分块传输、落盘逐字节一致；
三类鉴权失败彼此可区分（签名 / 码不一致 / 挑战）。
**不能**：不能替代 Gate 的篡改与零明文证据；未构造 `AUTH_TOKEN_STALE`（需改宿主 EPOCH，属运维动作，不在本证据范围）；
大文件上限见 PR「v1 已知限制」。
