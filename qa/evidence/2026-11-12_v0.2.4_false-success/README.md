# 「假成功」镜像实证：v0.1.4 / v0.2.1 / v0.2.2 / v0.2.3 / v0.2.4（Gate · 2026-11-12）

一句话：**这五个已发布 tag，用 16 MiB 文件下载，界面都会说「已保存至本机」，磁盘上一个字节都没有，
而 ack 已经把服务端密文删了**——用户拿不回来。这不是 1 GiB 才有的问题。

## 结论表（每格都是一次真跑，不是读代码推的）

| 镜像 tag | 界面「已保存至本机」 | 下载目录文件数 | ack 计数 | 页面可见报错 | 判定 |
|---|---|---|---|---|---|
| v0.2.4 | 是（A/B 两场景都是） | 0 / 0 | 0 → 2 | 无 | **假成功** |
| v0.2.3 | 是 / 是 | 0 / 0 | 0 → 2 | 无 | **假成功** |
| v0.2.2 | 是 / 是 | 0 / 0 | 0 → 2 | 无 | **假成功** |
| v0.2.1 | 是 / 是 | 0 / 0 | 0 → 2 | 无 | **假成功** |
| v0.1.4 | 是 / 是 | 0 / 0 | 0 → 2 | 无 | **假成功** |

- 与 Web 的代码结论完全吻合：`v0.2.4 web/src/net/download.js` 流式收尾 `await sink.close()`(:139) → `if (ack) api.ack()`(:142) → `return`(:145)，
  **没有 `save()`**；`save` 只在整包回退 `receiveOnce` 里。
- ack 原文（v0.2.4）：
  ```
  time=2026-11-11T18:07:01.735Z ... method=POST route="POST /v1/transfers/{transferId}/ack" status=200 bytes=106
  time=2026-11-11T18:07:26.002Z ... method=POST route="POST /v1/transfers/{transferId}/ack" status=200 bytes=106
  ```

## 怎么测的（两个场景，16 MiB，单轮 ~56 秒）

```sh
./run.sh negative-save --tag v0.2.4 --ev results/v0.2.4
```

脚本 `negative-save.mjs` 用两个独立浏览器（发送端/接收端各一个 profile）：

- **场景 A｜出厂 sink**：headless Chromium 没有 `showSaveFilePicker`，产品退回内存 sink。
  断言：**界面说「已保存至本机」→ 下载目录必须真有文件**。v0.1.4–v0.2.4：界面说保存了，文件 0 个 → 假绿。
- **场景 B｜写盘必失败**：`Page.addScriptToEvaluateOnNewDocument` 注入
  `window.showSaveFilePicker = undefined` + `navigator.storage.getDirectory = async () => { throw new DOMException('quota','QuotaExceededError') }`。
  断言：**必须出现错误文案、且不得出现「已保存至本机」**。v0.1.4–v0.2.4：仍然说保存了、没有任何错误 → 假绿。
- 浏览器侧下载落地用 CDP `Browser.setDownloadBehavior{behavior:'allow', downloadPath}` 显式打开
  （headless 下 `downloadsPath` 不生效，会把下载**静默丢掉**，不显式设会导致误判）。
- 两个场景都盯 `downloads/` 与 `$HOME/Downloads` 两处，避免「落到默认目录」漏判。

## v0.2.5 复验口径（同一条命令）

```sh
./run.sh negative-save --tag <v0.2.5 tag> --ev results/<v0.2.5>
```

必须同时满足：
1. 场景 A：界面说「已保存至本机」⇒ 下载目录**必须有文件**，且与源文件 sha256 一致；
2. 场景 B：界面**必须**出现可见错误（配额/写盘/交付任一文案），**不得**出现「已保存至本机」；
3. **失败场景 ack 计数不得增加**（delta 必须为 0）——这条正踩在 v0.2.4 的死因上；
4. 失败后 OPFS 无残留（`saveStream.cleanup()` 生效）。

## 目录内容

```
README.md                 本文件
run.sh                    preflight|up|transfer|secrets|negative-save|all（本目录自成一体，可直接拷到机器上跑）
negative-save.mjs         负面实测脚本（A/B 两场景 + CDP 下载落地 + 四现象归集）
verify-sha256.sh          两侧完整 64 位 sha256 + 字节数比对
results/<tag>/            每个 tag 一轮：negative-save.json、negative-save-summary-<tag>.txt、
                          negative-save-src-<tag>.sha256、neg-image-digest-<tag>.txt、logs/
```

> 注：`results/<tag>/` 里 `negative-save.json` 的 `body_tail` 保留了界面原文，可直接核对"已保存至本机"这句话。
> 运行环境：InstaBox（Docker 29.8.2 / compose v5.6.0 / Chromium 154 / Debian 13），镜像全部来自华为云 SWR 官方 tag，无本地 build。
