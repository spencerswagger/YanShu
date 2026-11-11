# 「块都 200 了却没落地」的证据链（逐条给原始物，缺的明说缺）

## A. 服务端 ack 之后会不会删块？删了还能不能重取？

代码事实（`web/src/net/download.js` 尾部，v0.2.4 tag）：

```js
const blob = new Blob([plain], { type: ... })
if (save) { report({phase:'saving', ...}); save(blob, safeFileName(...)) }   // ① 先落盘
if (ack)  { report({phase:'acking', ...}); await api.ack({ transferId, downloadId }) }  // ② 后 ack
```

- **顺序是「先落盘、后 ack」**；服务端 ack 时才「随即删除密文」（页面提示原话就是“确认取件（服务端随即删除密文）”）。
- 本次 1 GiB **根本没走到 ack**（没出现 `已保存至本机`，脚本也从未发出 ack），
  所以**服务端密文没有被删**，理论上可重取；16 MiB 那轮走到 ack，服务端日志有 `POST ack 200`（宿主侧也看到了）。
- 「ack 之后再 GET chunk 返回什么码」：契约上应是 410/404 一类（§1.7.4 终结态 410 是 2026-11-11 那轮修过的），
  但**本轮没做这个实验、机器已回收 → 这条记为未验证**，不编。

## B. `downloads/` 为空 —— 是服务端空还是浏览器没写出？

`downloads/` 是**浏览器侧**的目录（我传给 chromium 的 CDP `downloadPath=/data/ys-fixtures/downloads`），
服务端只有密文块卷 `blobdata`（`/app/data/blobs`），**服务端从不写明文**。

两个位置的原文（当次 `ls -l`，已抄进本文件，原始终端已随机器消失）：

```
# 浏览器侧（CDP 下载目录）
/data/ys-fixtures/downloads:
total 0

# 浏览器侧（chromium 默认 HOME 下载目录，防「落到默认目录」漏判）
/data/home/Downloads:
total 0
```

```
# 服务端侧（blobdata 卷）：**未取** —— 机器 00:14 被回收，`docker compose exec` 已无法执行
```

结论：**是浏览器侧没写出明文**；服务端侧「有没有密文」这次没查到（缺这一条数据）。

## C. 接收端 28 分钟里有没有报错？

逐条 grep 客户端日志（`results/20261111T155607-v0.2.4/logs/21-browser-transfer.log`）：

| 类别 | 条数 |
|---|---|
| `RECV-PAGEERROR`（未捕获异常） | **0** |
| `RECV-REQFAIL`（网络层失败） | **0** |
| `RECV-CONSOLE(error)` 429 | **81** |
| `已保存至本机` | **0** |

→ **纯静默**：没有异常、没有网络失败、没有"保存成功"提示；进度条停在 `707/1024` 之后再无变化。

## D. 内存侧（解释「静默卡住」的物理约束）

- 现场 `ps` 采样：单个 renderer **RSS ≈ 1.3 GB**（`/usr/lib/chromium/chromium --type=renderer`），机器还剩 3.6 GB，**未 OOM**。
- 代码路径：`unpack.finish()` 返回**整份明文**（`plain`），紧接着 `new Blob([plain])` —— 1 GiB 场景下
  明文 1 GiB + Blob 复制 1 GiB ≈ **2 GiB 峰值**，且 `save()` 是 `createObjectURL + a.click()` 一次性交付。
- 这与"进度停在 69%、无报错、无输出"是自洽的：卡在**组装 Blob / 交付下载**这一跳，而不是取块。

## E. 还差哪条数据（机器已回收，无法再取）

1. 服务端 `blobdata` 卷里这条传输的密文是否仍在（可判定「块是否被删/被 ack」）；
2. 客户端 `inflight` 峰值（需浏览器 network 面板或给 `api.getChunk` 加埋点）；
3. ack 之后再 GET 同一块的真实状态码（契约是 410，未实测）。
