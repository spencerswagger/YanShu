# legacy-tags：已发布 tag 的横向对照（16 MiB，逐个镜像真跑）

运行环境：InstaBox（Docker 29.8.2 / compose v5.6.0 / Chromium 154），镜像全部取自华为云 SWR 官方 tag，
**无本地 build、未改 compose 里的 tag**（用 `YANSHU_IMAGE_TAG` 这把官方开关切版本）。

| 镜像 tag | 界面「已保存至本机」 | `downloads/` 文件数 | ack 计数 | 传输终态 | 页面报错 | 判定 |
|---|---|---|---|---|---|---|
| v0.1.4 | 是 / 是 | 0 / 0 | 0 → 2（delta=2） | **未取到**（见下） | 无 | 假成功 |
| v0.2.1 | 是 / 是 | 0 / 0 | 0 → 2（delta=2） | **未取到** | 无 | 假成功 |
| v0.2.2 | 是 / 是 | 0 / 0 | 0 → 2（delta=2） | **未取到** | 无 | 假成功 |
| v0.2.3 | 是 / 是 | 0 / 0 | 0 → 2（delta=2） | **未取到** | 无 | 假成功 |
| v0.2.4 | 是 / 是 | 0 / 0 | 0 → 2（delta=2） | **未取到** | 无 | 假成功 |

- 「是 / 是」= 场景 A（出厂 sink）与场景 B（注入 `QuotaExceededError`）**都**报成功。
- 「0 / 0」= 两个场景下载目录里都没有任何文件。
- 「无」= 两个场景的页面都**没有**任何错误文案（`error_text` 全为空，`console_errors` 只有 CSP 提示与一条无关 404）。

## 关于「传输终态」这一列（必须说清楚，不许含糊）

- **运行时没取到**：要取它需要先抓 `transferId` 再 `GET /v1/transfers/{id}`；我加了抓取补丁，
  但机器在 03:47 被回收（约定 04:14，`ssh` 直接 `Permission denied (publickey)`），补丁没能跑第二轮。
- **代码侧可以确定最终状态名**（`server/internal/httpapi/handlers_transfers.go` 的 `handleAck`）：
  ```go
  if res.Consumed && res.Counted {
      a.purgeCiphertext(r, res.Transfer.ID)     // 密文被删
  }
  ```
  `store.AckDownload` 把传输落成终态 **`CONSUMED`**（`spec.StateConsumed = "CONSUMED"`，`ReasonConsumed`），
  之后 `GET /v1/transfers/{id}` 是 200 + `state=CONSUMED`，再取块是 **410 `TRANSFER_CONSUMED`**。
  契约里叫 `CONSUMED`，不叫 `DELETED`——查的时候别找错字段名。
- 也就是说：**ack 那两行 200 已经是「密文被 purge」的触发点**；四项现象里前三项是实测，第四项是代码事实、缺运行时复验。

## 结论（一句话）

**「v0.1.4–v0.2.4 全部已发布版本，下载一律静默丢数据」这条能站住 —— 已实证 5 个版本**
（v0.1.4 / v0.2.1 / v0.2.2 / v0.2.3 / v0.2.4，四项现象完全一致：报成功、0 文件、ack 已发、无报错）。
`v0.2.0` 未单独跑（SWR 上 tag 存在，但时间被机器回收打断），按前端代码审查它同样 `save()` 调用为 0，属同一形态，**未实证、不并入计数**。

## 复跑

```sh
./run.sh negative-save --tag v0.2.3 --ev results/v0.2.3     # 每个 tag 约 56 秒（镜像已缓存时）
```

四个现象会同时打进 `results/<tag>/negative-save-summary-<tag>.txt`；
想补「传输终态」这一列，用本仓库 `negative-save.mjs`（已含 `transfer_state_after` 抓取）重跑一次即可。
