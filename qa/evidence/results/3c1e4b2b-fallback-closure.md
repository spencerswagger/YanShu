# 兜底收口证据：`5605907`（`3c1e4b2b…`）

> 用途：若 Core 交不出干净快照，本文件即最终交付依据。
> **但请注意**：Core 后续已交出 `06c9f56`（`5a42bb43…`），它含 P0 修复且**已完整验收**，
> 见 `5a42bb43-closure.md`；本文件是**退路**，不是首选。

- 日期：2026-11-02
- head：`feat/server-skeleton@**5605907**`
- 产物：**由 Gate 在沙盒内构建**（`git archive 5605907` + 独立 target），
  与 Core 报的 sha 一致，已完成构建环境验证。

## 一、三件套

| 文件 | 路径 | 完整 sha256 |
|---|---|---|
| `yanshu-server` | `/.octop/workspaces/0JXF1M/tmp/bin/yanshu-server-5605907` | `3c1e4b2bc8fd5c349a0222909699c948eeab26f92c327965a5daaa038835f98f` |
| `deliver` | `/.octop/workspaces/0JXF1M/tmp/bin/deliver-5605907` | `4d377bb2e25206233b15d52d7851d7dbf7e2428b463ab8dc81d1de76ef22598e` |
| `yanshu_sm.wasm` | 仓库内 `server/kernel/yanshu_sm.wasm` | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B） |

```sh
cd server
go build -trimpath -buildvcs=false -o yanshu-server ./cmd/yanshu-server
go build -trimpath -buildvcs=false -o deliver ./cmd/deliver
```

- Go 版本：`go1.27.0 linux/amd64`
- 构建环境：Gate 的 YS-QA 沙盒，`git archive` 导出源码编译（不继承共享 `CARGO_TARGET_DIR`），
  产物 sha256 与 Core 报的一致 → 双向可复现。

## 二、三条件

| # | 条件 | 结论 | 证据 |
|---|---|---|---|
| 1 | 内核 sha | **PASS** | 工作区 `c1b87d0a…`/127,313 B；`git cat-file blob 5605907:server/kernel/yanshu_sm.wasm` **同 sha**（不是空 blob）；启动日志 `sm2 verifier loaded kernel=./kernel/yanshu_sm.wasm version=0x00010000`；34 函数 + memory |
| 2 | 已有库升级（补列 + 连跑两次） | **PASS 10/10** | 老 `08d40e7` 库缺列 → `0002` 补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → 连跑两次 `rows 1→1` |
| 3 | 冻结向量套件 | **PASS** | sm2 14 条可执行（1 条 `executable:false` 跳过）、user-code 5、normalize 20；一致性 26/26；prelude 6/6；证据二 6/6 + 11/11 |

复跑：`check_server_kernel.py --repo … --git-ref 5605907`、`check_upgrade_path.py`、`check_all.sh`。

## 三、KID/EPOCH 矩阵（逐字记录）

| 步 | 场景 | 结果 |
|---|---|---|
| ① | 基线（EPOCH=1） | **201**（prelude 首次上传） |
| ② | **只换 `TOKEN_SECRET`**（EPOCH 不变） | **204**（旧凭据仍有效，预检幂等成功） |
| ③ | **EPOCH+1**（改库、不重启） | **401 `AUTH_TOKEN_STALE`**，message `upload token is stale: its key version is no longer accepted` |
| ④ | 两者都改 | **401 `AUTH_TOKEN_STALE`**（STALE 优先） |
| ⑤ | 换 EPOCH 后新签发 | **201** |
| ⑥ | 最初 token 复打 | **401 `AUTH_TOKEN_STALE`**（不复活） |
| 附 | 未配置 EPOCH（全新库） | **可启动**，`/v1/config` 返回 `"token_epoch":1` |
| 附 | EPOCH 调小（记录 3 → 配 2） | **exit 1**：`config: YANSHU_TOKEN_EPOCH must increase (current=3, provided=2); refusing to start` |

## 四、四码覆盖

| 码 | 构造 | 实测 |
|---|---|---|
| `AUTH_TOKEN_STALE` | EPOCH+1 | **401 `AUTH_TOKEN_STALE`** |
| `AUTH_TOKEN_INVALID` | 三种畸形 token（随机串 / 截断 / 非 base64url） | 三种均 **401 `AUTH_TOKEN_INVALID`** |
| `AUTH_TOKEN_EXPIRED` | 传输 `created_at` 推到 **7 小时前**（模拟 6h 窗口，非真等） | **401 `AUTH_TOKEN_EXPIRED`**，message `token has expired; obtain a new one` |
| `AUTH_SIGNATURE_INVALID` | `sm2` 下伪造 DER（`MEUCIQDdeadbeef`） | **401 `AUTH_SIGNATURE_INVALID`** |

未覆盖：**下载租约 30 分钟**到期未单独构造（同属 `EXPIRED` 分支）。

## 五、结论与**已知偏差清单**

**是否建议重启：可以，但优先用 `06c9f56`（`5a42bb43…`）。** 若必须用兜底，本产物也能起、行为与契约四码一致。

已知偏差（如实列，未美化）：

1. **缺 `uploader_ip IS NULL` 的 P0 修复**：`5605907` 早于该修复。若库里存在 `uploader_ip` 为 NULL 的历史行
   （例如从更早版本升级而来），读取该传输会 **500 INTERNAL**。这正是 `06c9f56` 修掉的问题。
2. **迁移集只有 `0001/0002/0003`**：没有 `0005_restore_token_kid.sql`，因此**跑过 `0004_drop_token_epoch` 的库
   无法被自动恢复**（列/状态表不会自己回来），必须换 `06c9f56` 或手工补。
3. **`AUTH_TOKEN_EXPIRED` 的构造是"改库时间"**，不是真等 6 小时；30 分钟租约未构造。
4. **在线吊销验证**：本文件里 EPOCH+1 是"改库后新进程读取"；`06c9f56` 上才做了**同进程 PID 不变**的严格验证。
5. **错误名**：本 head 返回 `STALE`/`INVALID`/`EXPIRED`，与终值一致，**未见 `REVOKED`**。

→ 一句话：**兜底可用，但首选 `06c9f56`（`5a42bb43…`）**；选兜底时必须接受第 1、2 条风险。
