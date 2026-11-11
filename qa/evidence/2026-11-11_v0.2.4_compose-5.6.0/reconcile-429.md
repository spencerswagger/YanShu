# 对账：429 与「1024 次 200」到底怎么读（Gate · 2026-11-12）

> 只做对账，不新跑测试；机器已回收。**结论先写在最前面：我上一轮「1024 次全 200、传输层通」的说法
> 现有留存证据不支持，撤回。**

## 1) 429 行数与时间跨度（客户端 console，原文可复跑）

数据源：`results/20261111T155607-v0.2.4/logs/21-browser-transfer.log`（第 2 轮 1 GiB）

```
[129.8s] RECV-CONSOLE(error) Failed to load resource: the server responded with a status of 429 (Too Many Requests)
[135.4s] RECV-CONSOLE(error) Failed to load resource: the server responded with a status of 429 (Too Many Requests)
[141.0s] RECV-CONSOLE(error) Failed to load resource: the server responded with a status of 429 (Too Many Requests)
...
[563.8s] RECV-CONSOLE(error) Failed to load resource: the server responded with a status of 429 (Too Many Requests)
[569.3s] RECV-CONSOLE(error) Failed to load resource: the server responded with a status of 429 (Too Many Requests)
[574.8s] RECV-CONSOLE(error) Failed to load resource: the server responded with a status of 429 (Too Many Requests)
```

| 轮次 | 429 条数 | 时间跨度 | 间隔 |
|---|---|---|---|
| 第 1 轮（`…150720…`） | 0 条（该轮日志只有 12 行，我没开 console 埋点） | — | — |
| 第 2 轮（`…155607…`） | **81 条** | **129.8s → 574.8s** | min 5.4 / 中位 **5.6** / max 5.8s |

第 1 轮那 81 条 429 是**服务端日志侧**的计数（现场 `grep -c`），不是客户端 console —— 两轮的「81」**不是同一个统计**，
别混用（这也是前面口径打架的一个来源）。

## 2) `chunks` 200 的行数，以及它是否落在 574.8s 之后

- **留存证据里没有逐行的服务端 chunk 日志**（只存了 8 行 `tail` 和聚合计数），所以「每条 200 的时间戳」**无法完整列出**。
- 现存的两条计数：
  - `N200 = 1024`：现场在 **`clean-v0.2.4-c` 栈**上 `docker compose logs yanshu-server | grep -c 'status=200'`（含 `chunks/` 过滤）。
  - 该栈**不止跑过 1 GiB 这一条**：16:01 起我还在**同一个栈**上跑了 256 MiB 对照（`src-256m.bin`，256 块）。
- **口径瑕疵（我的问题）**：`N200=1024` 是**跨传输合计**，不能归属到 1 GiB 那条；`PUT chunks` 返回的是
  **201 Created / 204 No Content**（`handlers_blobs.go:190-193`），所以 200 确实只可能来自 GET，但**哪个 tid 的 GET，我证明不了**。
- 我保留的唯一服务端原始片段（`tail`）末行是 **`16:04:42.995Z`**（≈ t+515s），而客户端 console 的 429 一直记到
  **t+574.8s（≈16:05:42）**。两者**对不上**：要么那份 `tail` 取得早、要么日志被截断 —— 我当场没把完整服务端日志拉回本地，
  现在机器没了，**这条链路断在这里**。

结论：**「1024 次 200 是否发生在 574.8s 之后」我无法用记录证明，也没法证伪。** Core 的说法在时间线上可能成立。

## 3) chunk index 覆盖（这是唯一能定性的判据，但我没有数据）

- 判定应该看：已成功的 GET 里 `index` 是否覆盖 `0..1023`、缺哪些段。
- 现场只取了**计数**（`grep -c`）和**8 行尾巴**，**没有按 index 去重取集合**，服务端原始日志也没落盘。
- 所以：**「69% 是没取完，还是取完没保存」——现有证据不能定论。**

另外必须自我披露一条采样缺陷：客户端的 `RECV-PROGRESS` 我写在 `try { await recv.innerText('body') } catch {}` 里，
**异常被静默吞掉**。日志里 418.8s 之后 0 条 progress、但 429 还在源源不断 → 高概率是**采样挂了**，不是传输停了。
也就是说「707/1024 @418.8s」这个数**在两种解读下都能成立**（取块停了 / 采样停了），它不能当判据。

## 4) 结论

- **撤回**我上一轮的「1024 次全 200、传输层通、根因只在浏览器保存」——现有留存证据不足以支撑，且 `N200` 口径被我自己污染了（同栈另一条传输）。
- **不采纳**「429 是噪音」这个说法；429 是真的、均匀的、每 5.6s 一次，`TransferReadPerIP=120/60s` = 2 块/秒 = 1024 块下限 512s，**它至少是主要的时间成本**。
- 也**不能**据此说「Core 完全正确」：Core 引用的「707 @574.8s」在日志里**不存在**（707 出现在 **418.8s**，之后没有 progress 行）。
- 唯一能一击定性的数据是**按 index 归并的 GET 明细**，只能在新机上重跑时抓（脚本已改成记录每次 GET 的 index+状态+时间）。
- 口径判定不变：**口径 2 仍 FAIL**（无论 69% 是没取完还是没保存，落地文件都没有、两侧 sha256 都不成立）。
