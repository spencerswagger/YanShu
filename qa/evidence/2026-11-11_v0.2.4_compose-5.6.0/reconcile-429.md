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

## 5) 补记（2026-11-12 01:10，新机重跑后：这个缺口已闭合）

上面第 3 节点出的唯一决定性判据「按 index 归并的 GET 明细」，在新机 `sbx-yanshu-yanshu-v025-767e`
重跑时拿到了**完整服务端日志**（`results/20261112T0051-v0.2.4-rerun/server-chunks-get.log.gz`，2200 行）。

- 本轮（同一台机、同一镜像 `v0.2.4`、干净 compose）：`GET chunks` **1097 = 1024×200 + 73×429**，
  跨度 456.7 s；令牌桶预测 `120 + 2/s×456.7 = 1033`，实测 1024（差 0.9%）。
- **index 覆盖不必靠日志**：`save-sink-probe` 用测试替身接住落盘，得到 `1073741824 B / 1024 次写入 /
  src 与 out sha256 逐字相同`。内核在 `streamUnpackEnd()` 缺块/摘要不符会报错 —— 走通且 sha 相同
  ⇒ **1024 个块全部到位**（顺序与内容都对）。
- 因此「取块停了 / 采样停了」这个二义性到此结束：**取块没停，是落盘这一跳没有代码接住**（见 README §7）。
- 仍保留的判断：旧机那轮（`…155607…`）的 `N200=1024` 口径确实被同栈 256 MiB 对照污染，
  不能用；本轮数据是本机独立跑的，不受影响。

---

# 追加：第二次对账（2026-11-12 01:50 CST，新机现场有三份日志可数）

## 三份日志的 429 计数（同一口径：客户端 console 里 `status of 429` 的行数）

| 日志 | 429 条数 | 首条 | 末条 | 窗口 | 折合间隔 | 出处 |
|---|---|---|---|---|---|---|
| 旧机 第 2 轮（我的） | **81** | 129.8s | 574.8s | 445.0s | 5.49s | `results/20261111T155607-v0.2.4/logs/21-browser-transfer.log` |
| 本机 `run.log`（我的脚本重跑） | **78** | 134.1s | 578.0s | 443.9s | 5.69s | `results/20261111T162526-v0.2.4-rerun/run.log` |
| 本机 `probe.log`（save-sink 探针） | **73** | 143.7s | 584.4s | 440.7s | 6.04s | `results/20261111T162526-v0.2.4-rerun/probe.log` |

**对账结论：81 / 78 / 73 不是矛盾，是三次不同轮次。** 三份日志的 429 都满足「一条 ≈ 每 5.5–6.0 秒」，
即 **条数 ≈ 下载时长 / 5.6s**；`59` 对应的是约 330 秒的窗口（更短的一轮或只截了一段），
只要把「按哪份日志、哪个时间段」说清，三个数可以并存。**我此前拿 81 去打 Ops 的 59 是不对的**，
应当问「你数的是哪一份日志的哪个窗口」——这一条我认。

## Ops 的两条判断，代码侧已核（只读代码）

```go
// server/internal/spec/limits.go:47-49
TransferReadPerIP:       Limit{WindowSeconds: 60, Max: 120, Burst: 120},   // 2 块/秒
TransferReadPerTransfer: Limit{WindowSeconds: 60, Max: 600, Burst: 600},   // 10 块/秒
```

- 与仓库**一致**（tag v0.2.4 与 main 同值）。
- `server/internal/config` 里**没有任何 env 能覆盖这两个额度**（grep 无命中）；
  `docker-compose.yml` 里与配额相关的只有 `YANSHU_STORAGE_QUOTA_BYTES`，无 `*_LIMIT*`/`*_RATE*`。
- 所以「5.40–5.68s 近乎等距 = per-IP 限速设计问题，不是并发突刺」——**成立**：
  等距是 2 块/秒令牌桶的确定性反馈，不是并发抖动。

## 这次对账带出的关键反转（比数字重要）

本机 `probe.log` + `save-sink-probe.json`（用 `showSaveFilePicker` 测试替身，把字节真写到磁盘）：

```
bytes=1073741824  writes=1024  elapsed=601.8s
src_sha256 = 424f47694dce624070bfa995e584ddf0012bf4e40a74c5e726a71e241f58a8e4
out_sha256 = 424f47694dce624070bfa995e584ddf0012bf4e40a74c5e726a71e241f58a8e4   ← 逐字相同
```

- 说明：**1024 块真的能收满、解密正确、字节一致**；限速只让它慢（~600s），不是"取不完"。
- 我此前「69% 停住」的判断可以结案为**采样缺陷**（`innerText` 异常被 `catch{}` 吞掉），不是传输停。
- 但这条是**注入替身**跑出来的，**不能**当作「v0.2.4 通过」——真正的缺陷在保存/ack 顺序（见 `negative-save`）。
