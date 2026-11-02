# 收口证据（单文件）：`5a42bb43…` / head `06c9f56`

- 日期：2026-11-02
- **命名说明**：本产物**由 Gate 在沙盒内构建、构建环境已验证、两个二进制 sha256 已核**。
  结果与 Core 报的 `5a42bb43…` 逐字节一致，因此不存在"只有缩写"的问题。
- 服务端 head：`feat/server-skeleton@**06c9f56**`（P0：`uploader_ip` 为 NULL 时读传输 500）

## 一、产物三件套

| 文件 | 路径 | 完整 sha256（64 字符） |
|---|---|---|
| `yanshu-server` | `/.octop/workspaces/0JXF1M/tmp/bin06c/yanshu-server` | `5a42bb43d481926f9238e5016335354e4721224c2b7b8e34d7a24ec0d9426eb0` |
| `deliver` | `/.octop/workspaces/0JXF1M/tmp/bin06c/deliver` | `31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0` |
| `yanshu_sm.wasm` | 内核（仓库内 `server/kernel/`） | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B） |

编译命令原文：

```sh
cd server
go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server
go build -trimpath -buildvcs=false -ldflags "-s -w" -o deliver ./cmd/deliver
```

- **Go 版本**：`go1.27.0 linux/amd64`
- **构建环境**：Gate 的 YS-QA 沙盒（独立 target / 独立临时目录，未继承共享 `CARGO_TARGET_DIR`），
  源码来自 `git archive 06c9f56`，**产物 sha256 与 Core 报的一致**即为交叉验证通过。

## 二、三条件逐条结论

### ① 内核 sha 三重核对 —— **PASS**

| 核对点 | 结果 |
|---|---|
| 工作区 `server/kernel/yanshu_sm.wasm` | `c1b87d0ad9a847fa…7259f` / **127,313 B** |
| `git cat-file blob 06c9f56:server/kernel/yanshu_sm.wasm` | **同一 sha**；且被 git 跟踪（`ls-tree` 命中） |
| 启动日志 | `level=INFO msg="sm2 verifier loaded" kernel=./kernel/yanshu_sm.wasm version=0x00010000` |
| 导出/版本 | `ys_version()=0x00010000`、**34 函数 + memory**、0 import |

### ② 老库升级路径（含连跑两次）—— **PASS 10/10**

旧库（`08d40e7` 线，无 `upload_token_kid`）→ `-migrate-only`：`0002` 补列 + 回填、`0004` 状态表、
`0005` 幂等恢复 → 列存在、历史行 `upload_token_kid=pre-kid` → 服务起 + `/healthz` **200**、
无 `sweep failed` → **连跑两次迁移 `rows 1→1`、exit 0**。

### ③ 冻结向量套件 —— **PASS**

| 套件 | 结果 |
|---|---|
| sm2 验签 | **14 条可执行全过**（15 条中 1 条 `executable:false`：`different_user_id`，ABI 无 userID 入参，库层断言覆盖） |
| user-code | 5 组（含契约 `PB_S = AWQW`） |
| normalize | 20 组 |
| 证据二（生产路径） | 单块 **6/6**、多块 **11/11**，未报错 0，基线逐字节一致 |
| 其它常规项 | 用户码四形态 26/26、prelude-only 6/6 |

## 三、KID 矩阵（逐字错误名与 message）

| 步 | 场景 | 状态 | 错误名 / message |
|---|---|---|---|
| ① | 基线（EPOCH=1, secret=…0001） | **200** | — |
| ② | **只换 `TOKEN_SECRET`**（EPOCH 不变） | **200**（prelude 复传时 204，幂等） | — |
| ③ | **EPOCH+1**（`UPDATE token_kid_state SET kid=kid+1`，**不重启**） | **401** | **`AUTH_TOKEN_STALE`**，message `upload token is stale: its key version is no longer accepted` |
| ④ | EPOCH+1 后新签发 | **200** | — |
| ④b | 最初 token 复打 | **401** `AUTH_TOKEN_STALE` | **不复活** |
| 附 | 未配置 `YANSHU_TOKEN_EPOCH`（全新库） | **可启动**，`/v1/config` 返回 `"token_epoch":1` | — |
| 附 | 已记录 3、配 2（调小） | **exit 1** | `config: YANSHU_TOKEN_EPOCH must increase (current=3, provided=2); refusing to start` |
| 附 | 配 0 | **exit 1** | `config: YANSHU_TOKEN_EPOCH must be a positive decimal integer (got "0")` |

`/v1/config.token_epoch` 实测 **1 → 2**，随库内 KID 变化（服务不缓存旧值）。

## 四、四码覆盖（每码一条实测，互不顶替）

| 码 | 构造手法 | 实测 |
|---|---|---|
| `AUTH_TOKEN_STALE` | `UPDATE token_kid_state SET kid=kid+1`（不重启） | **401 `AUTH_TOKEN_STALE`** |
| `AUTH_TOKEN_INVALID` | 三种畸形 token：随机串 `Zx9-not-a-token` / 截断 / 非 base64url `@@@###$$$` | 三种均 **401 `AUTH_TOKEN_INVALID`** |
| `AUTH_TOKEN_EXPIRED` | 把传输 `created_at`/`updated_at` 推到 **7 小时前**（模拟超过 6 h 窗口，**非真等**） | **401 `AUTH_TOKEN_EXPIRED`**，message `token has expired; obtain a new one` |
| `AUTH_SIGNATURE_INVALID` | `YANSHU_VERIFIER=sm2` 下伪造 DER（`MEUCIQDdeadbeef`）与非 DER 文本注册 | 两种均 **401 `AUTH_SIGNATURE_INVALID`** |

未覆盖项（不充数）：**下载租约 30 分钟到期**未单独构造（同属 `EXPIRED` 分支，机制相同）。

## 五、结论

**建议 spencer 用这份产物重启**（`5a42bbdf…` 见上表；`deliver` 与内核同表），
重启后需复核三项：

1. `curl -fsS http://127.0.0.1:18080/healthz` → **200** `{"status":"ok",...}`；
2. 启动日志出现 **`sm2 verifier loaded kernel=./kernel/yanshu_sm.wasm version=0x00010000`**；
3. `curl -s http://127.0.0.1:18080/v1/config` 里 **`token_epoch`** 存在且等于 `YANSHU_TOKEN_EPOCH`。

启动 env（凭据占位）：

```sh
YANSHU_DATABASE_URL="<DSN，含 search_path>"
YANSHU_TOKEN_SECRET="<≥16B>"
YANSHU_TOKEN_EPOCH=1
YANSHU_VERIFIER=sm2
YANSHU_KERNEL_WASM=./kernel/yanshu_sm.wasm
YANSHU_BLOB_DIR=/var/lib/yanshu/blobs
YANSHU_LOG_DIR=/var/log/yanshu
YANSHU_ADDR=127.0.0.1:18080
```
