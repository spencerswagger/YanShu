# 2273 次请求是不是同一条传输？（结论：不是，且含上传）

## 统计口径要说清

`2273` 这组数字来自**第一个栈**（`/data/clean-v0.2.4`）的 `docker compose logs yanshu-server | grep -c 'chunks/'`，
那个 `chunks/` 的 grep 同时命中两类路由：

| 路由 | 方法 | 说明 |
|---|---|---|
| `/v1/transfers/{id}/chunks/{index}` | **PUT** | 上传密文块（`handlePutChunk`，`api.go:81`） |
| `/v1/transfers/{id}/chunks/{index}` | **GET** | 下载密文块（`handleGetChunk`，`handlers_blobs.go:201`） |

而第一个栈上跑过 **4 条传输**：3 条 16 MiB 调试跑（15:19:53 / 15:21:19 / 15:22:41 三次 201）+ 1 条 1 GiB（15:34 起）。

对账：

```
上传 PUT  ≈ 1024（1 GiB） + 16×3（16 MiB×3） ≈ 1072
下载 GET  ≈ 1024（1 GiB） + 16（只有 probe3 真下完） ≈ 1040
429       = 81
合计      ≈ 2193，与实测 2273 相差 ~80（重试/探测，未分类）
```

→ **2273 ≠ 某条传输的下载请求数**，不能用来推「1 GiB 的块有没有取完」。

## 单条传输的干净数字（这才该拿来判定）

第 2 轮跑在**新栈** `clean-v0.2.4-c` 上，那个栈**只跑过这一条 1 GiB 传输**，统计：

- `N200 = 1024`（恰好等于块数 1024）
- 末条 chunk 行 `16:04:42.995Z`（其中夹一条 429，说明 429 是重试、不占 200 名额）
- → **每条块恰好一次 200，块全部到手**；429 是超出 2 块/秒额度的那部分重试。

## 附带纠正一条「64 MiB 上限」的说法

`web/src/config.js:55 maxPackSize = 64 MiB`，但 `web/src/net/upload.js` 里这个检查**只在 `canStream=false`（整包接口）时生效**：

```js
if (canStream) { ...return streamUpload(...) }        // 1 GiB 走这条：分块上传
if (file.size > config.maxPackSize) { throw FILE_TOO_LARGE }   // 只有整包路径才卡 64 MiB
```

本轮 1 GiB 上传路径实测产生了 1024 个块 PUT 200，说明走的是 `streamUpload`，
所以**「64 MiB 与 1 GiB 冲突」在上传侧不成立**；保存侧（`download.js`）没有任何 64 MiB 判定，它是
`new Blob([plain])` 全量组装。这条要修的是「下载/保存路径不支持大文件」，不是「上传卡 64 MiB」。
