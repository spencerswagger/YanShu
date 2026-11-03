# 用 Core 的脚本跑 token 轮换（`d655e16`）：6/6 PASS + 原始响应体

- 日期：2026-11-02
- 产物：`feat/server-skeleton@**d655e16**`，我在沙盒里自己编的
  `yanshu-server-d655e16`（sha256 `4c331e1f6e58fd07248a8b3633eae8684d3f7139e54933ec1e66fc5aabf1ef9d`）
- 脚本：`server/scripts/token-rotation-check.sh`（Core 提供，**未改动逻辑**，只在本地副本里把
  每次请求的 response body 追加进日志，用于取证）
- 认证：`stub-allow`；schema 从零迁移

## 1. 脚本输出（逐行）

```
== 0) 迁移 ==
== 1) 基线：签发并可用 ==
PASS  baseline status → 200 (ok)
PASS  wrong token → 401 AUTH_TOKEN_INVALID
== 2) 轮换 TOKEN_SECRET → 旧 token 立刻 REVOKED ==
PASS  rotated: 旧 token → 401 AUTH_TOKEN_REVOKED
PASS  rotated: 新 token → 200 (ok)
== 3) 再轮换一次 → 上一轮 token 也 REVOKED，新 token 可用 ==
PASS  rotate-again: 旧 token → 401 AUTH_TOKEN_REVOKED
PASS  rotate-again: 新 token → 200 (ok)
全部通过（3 组轮换 × 旧拒/新可用）     exit=0
```

## 2. 原始响应体（这是判定字面的唯一依据）

```json
{"error":{"code":"AUTH_TOKEN_REVOKED","message":"upload token was revoked by a key rotation; create a new transfer","request_id":"req_e1f9adc52ad7d8b0"}}
```

```json
{"error":{"code":"AUTH_TOKEN_INVALID","message":"upload token is invalid for this transfer","request_id":"req_e4e04aae07587f63c"}}
```

**结论**：`d655e16` 上服务端实际返回的是 **`AUTH_TOKEN_REVOKED`**（轮换）与
**`AUTH_TOKEN_INVALID`**（值不对），`message` 也写明"由密钥轮换导致 / 请重建传输"。
与我的实测一致，与"STALE"的说法**不一致**——差异来自产物版本：
`5605907`（EPOCH 版）返回 `AUTH_TOKEN_STALE`，`d655e16`（EPOCH 已由 `0004` 撤回）返回
`AUTH_TOKEN_REVOKED`。

## 3. 顺手抓到一个"假 PASS"的机会（已排除）

我第一次手工复现时，第二个实例因**端口被旧进程占用**而起不来（日志
`fatal err="listen tcp ... bind: address already in use"`），旧 secret 的实例继续应答，
于是"旧 token 换 secret 后仍 200"——这正是 `results/README.md` 里那条假 PASS 反例。
本表用的是 Core 脚本（它会先 `kill` 再起、按端口探活），且我在两次实例上分别确认了
`listening` 日志，排除了这种情况。

## 4. 另外两项状态

| 项 | 状态 |
|---|---|
| 内嵌内核 sha | **PASS**：`d655e16` 的 `server/kernel/yanshu_sm.wasm` = `c1b87d0a…`（127,313 B），`ys_version()=0x00010000`、34 函数+memory、向量套件（user-code 5 / normalize 20 / sm2 14）全过 |
| 升级路径 | **PASS**：`08d40e7→5605907`（补列）10/10、`5605907→d655e16`（`0004` 删列）9/9 |

## 5. 复跑

```sh
sh server/scripts/token-rotation-check.sh \
  --bin <yanshu-server> --deliver <deliver> --yspk <样本.yspk> \
  --dsn "<DSN>&search_path=<已建 schema>" --blob <blob 目录> --port 18110
```
