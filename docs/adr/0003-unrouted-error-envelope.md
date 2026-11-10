# ADR-0003：未匹配路由 / 未定义方法也必须走契约错误信封

| 项 | 值 |
|---|---|
| 状态 | **已采纳**（2026-11-10） |
| 日期 | 2026-11-10 |
| 适用版本 | 服务端 v0.2.x 起（不抬 `api_version`） |
| 关联文档 | `docs/API.md` §0.2（错误信封）、§3（接口总表）、§10.1（错误码表） |
| 影响面 | 只补两条**此前未定义**的错误码；不改字段、不改路径、不改包字节、不改既有码语义 |

## 1. 问题

`API.md` §0.2 写死一条全局规则：

> **所有非 2xx 响应统一**：`{"error":{"code","message","scope","retry_after","request_id"}}`

§10 又写死客户端义务：「**客户端必须按 `code` 分支**；`message` 仅供开发者阅读」。

但这两条规则在运行时**没有执行**——服务的路由用的是 `http.ServeMux`，它在两种情况下自己抢答，
完全绕过 `writeError`：

| 输入 | 修前实测响应 | 契约要求 |
|---|---|---|
| `GET /v1/nope`（路径不存在） | `404` + `text/plain` + `404 page not found` | `404` + JSON 信封（含 `code` / `request_id`） |
| `DELETE /v1/config`（方法未定义） | `405` + `text/plain` + `Method Not Allowed` | `405` + JSON 信封（含 `code` / `request_id`） |
| `POST /v1/stats`（同上） | `405` + `text/plain` + `Method Not Allowed` | 同上 |

后果不是"文案不好看"，而是**防护缺口**：

1. 客户端侧 `describeError()` 按 `code` 分支（`web/src/net/errors.js`），拿不到 `code` 只能落到
   "请求失败（undefined）"——用户看到的是一个没有任何处置动作的死胡同；
2. 没有 `request_id`，运维无法把这次失败与服务端日志对上；
3. `405` 根本不在 §10 的错误码表里——"契约以外的行为"正是 §10「唯一权威」要禁的东西。

同一类问题的前例是 §1.7.4 的判定顺序：规则写在文档里，正常流转的用例永远走不到，
门禁（`check_contract_impl_parity.py` 只做字符串双向比对、不执行行为）一直是绿的。

## 2. 决定

### 2.1 新增两个错误码（只补定义，不改既有码）

| `code` | HTTP | 含义 | 客户端处置 |
|---|---:|---|---|
| `ROUTE_NOT_FOUND` | 404 | 请求路径不在 §3 接口总表里（客户端/中间层拼错地址） | 修客户端或网关配置；不要重试 |
| `METHOD_NOT_ALLOWED` | 405 | 路径在 §3 表里，但该方法不是该行的定义内方法（响应带 `Allow` 头） | 改用 `Allow` 里的方法；不要重试 |

**分界（写死，避免与对象级 404 混淆）**：

- `ROUTE_NOT_FOUND` = **路径本身不存在**；
- `CODE_NOT_FOUND` / `TRANSFER_NOT_FOUND` / `CHUNK_NOT_FOUND` = **路径成立、对象不存在**（语义不变）；
- 也就是说：`GET /v1/codes/AWQW` 在码未注册时仍然必须是 `404 CODE_NOT_FOUND`，
  **不许**被 `ROUTE_NOT_FOUND` 顶替。

### 2.2 实现落点

- 路由表收敛为**唯一声明处** `(*API).routes()`（`server/internal/httpapi/api.go`）：
  注册 handler 与兜底判定用同一张表，杜绝"文档有、路由漏"；
- `guardUnrouted` 用 `ServeMux.Handler(r)` 的返回值判"是否真的没命中"：
  模板为空即 mux 正要自己回 404/405，此时改由 `unrouted.handler()` 写契约信封；
- "路径存在但方法不对"的判定复用 Go 的模板匹配：另建一个**只注册路径、不注册方法**的 mux，
  命中即 405（并回 `Allow`）。**不手搓** `{code}` / `{transferId}` 通配逻辑——手搓必然与真实路由分叉。

### 2.3 不做的选项

| 选项 | 为什么不选 |
|---|---|
| 复用 `TRANSFER_NOT_FOUND` / `BAD_REQUEST` 顶替 | 语义错位：客户端会把"地址拼错"当成"传输没了"或"参数非法"，处置动作全错 |
| 只改文案、保持 text/plain | 违反 §0.2（信封是硬规则），且客户端仍无法按 `code` 分支 |
| 抬 `api_version` | 不新增字段、不改既有码语义，客户端对**新码**的缺省路径（`请求失败（code）`）已可用，无需抬版本 |

## 3. 门禁

`server/internal/httpapi/fallback_test.go`（不依赖 PG，纯路由门禁）：

- `TestUnroutedPathKeepsContractEnvelope`：5 条不存在路径 × 断言 `404` + JSON 信封 + `code == ROUTE_NOT_FOUND`；
- `TestWrongMethodKeepsContractEnvelope`：4 组"路径成立、方法不对" × 断言 `405` + 信封 + `code == METHOD_NOT_ALLOWED` + `Allow` 含正确方法；
- `TestRoutedRequestsAreNotSwallowed`（**阴性对照**）：§3 表里每一行都必须走到真 handler，
  否则"兜底"会退化成"一律 404 也算通过"；同时登记路由条数下限，漏注册会被点名。

A/B 判据：把同一份用例打回 `origin/main`（修前）——`guardUnrouted` 不存在，
`GET /v1/nope` 实测 `404 text/plain`、`DELETE /v1/config` 实测 `405 text/plain`（原始输出见 PR）。
