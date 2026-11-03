# 命名权威表：token 矩阵实测（`5605907`）

- 日期：2026-11-02
- 服务端：`feat/server-skeleton@**5605907**`（本轮实际取到的最新 head）
- 二进制：`/.octop/workspaces/0JXF1M/tmp/bin/yanshu-server-5605907` —
  sha256 `3c1e4b2bc8fd5c349a0222909699c948eeab26f92c327965a5daaa038835f98f`
- 投递工具：`deliver-5605907` — sha256 `4d377bb2e25206233b15d52d7851d7dbf7e2428b463ab8dc81d1de76ef22598e`
- 编译命令原文：

```sh
cd <YanShu>/server
go build -trimpath -buildvcs=false -o yanshu-server-5605907 ./cmd/yanshu-server
go build -trimpath -buildvcs=false -o deliver-5605907       ./cmd/deliver
```

- schema：`yanshu_test`.`gate_560`（从零迁移）；认证 `stub-allow`（与签名无关）

## 1. 矩阵（逐字记录服务端返回）

| 场景 | 改了什么 | 状态码 | 错误名字符串 | message（原样截断） | 备注 |
|---|---|---|---|---|---|
| 基线 | secret-A、epoch=1 | **201** | — | — | prelude 上传成功 |
| **只改 secret** | secret-A→B，epoch 不变 | **204** | — | — | **旧 token 仍有效**（204 = prelude 已存在、幂等成功） |
| **只改 epoch** | epoch 1→2，secret 不变 | **401** | **`AUTH_TOKEN_STALE`** | `upload token is stale: its key version is no longer accepted` | 版本作废 |
| **两者都改** | secret-B + epoch=2 | **401** | **`AUTH_TOKEN_STALE`** | 同上 | 先比版本 → STALE 优先 |
| 轮换后新签发 | epoch=2 | **201** | — | — | 新 token 可用 |
| 最初 token 复打 | — | **401** | **`AUTH_TOKEN_STALE`** | 同上 | **不复活** |

**结论**：在当前实现里，**只有 epoch 变化会让旧 token 失效**；`secret` 变化不吊销
（与 Core 新设计一致）。命名以本表为准：**`AUTH_TOKEN_STALE`**（版本失效）。
`AUTH_TOKEN_INVALID` 在本矩阵中未被触发（secret 不再导致不匹配）；`AUTH_TOKEN_EXPIRED`
代码里存在（上传 6 h / 下载租约 30 min），本表未覆盖到期场景。

## 2. 启动行为（两处与之前口径不同，实测为准）

| 场景 | 结果 | 证据 |
|---|---|---|
| **全新 schema、完全不设 `YANSHU_TOKEN_EPOCH`/`KID`** | **能启动**（默认 epoch=1），`/healthz` **200** | 不是必配项（与 `7239888` 的 KID 必配不同） |
| **epoch 调小**（已记录 3，配置成 1） | **exit 1** | `YANSHU_TOKEN_EPOCH=1 is lower than the recorded epoch 3: epoch must strictly increase` |
| 已记录 epoch=2、又用未设（默认 1）起 | **exit 1** | 同上原因（默认值低于记录值） |
| 未设 KID/EPOCH 的旧变量名 | `YANSHU_TOKEN_KID` 仍被接受为 `YANSHU_TOKEN_EPOCH` 的别名 | 代码注释明确"兼容旧变量名" |

**单调递增校验确实存在且生效**，但"未配置即拒启动"在**全新库上不成立**——
只有在库里已有更高 epoch 时才会因为默认值 1 而拒启动。运维含义：**新部署可以不配**，
但**升级或轮换过的实例必须配且只能调大**。

## 3. 复跑

```sh
python3 qa/evidence/check_token_lifecycle.py --binary <bin> --dsn "<DSN>&search_path=<新 schema>" --ys-tool <ys-tool>
# 若要验 epoch 轮换：脚本的 --kid 参数即 epoch（旧名兼容）
```
