# 时间线（真实现场，UTC / CST 并列；没有一项是估的）

| UTC | CST | 事件 | 结果 |
|---|---|---|---|
| 15:06:19 | 23:06 | SSH 连上 `sbx-yanshu-yanshu-clean-225e`（Docker 29.8.2 / compose v5.6.0 / Chromium 154） | 通 |
| 15:07:09 | 23:07 | `run.sh preflight` | PASS 5/5（含 `docker run` 真起容器） |
| 15:07:20 | 23:07 | `run.sh up --work /data/clean-v0.2.4`（空目录 + 官方 compose + SWR tag） | **PASS 12/12**，三容器 healthy，`/healthz` ok |
| 15:34–15:36 | 23:34–23:36 | 第 1 轮 1 GiB：发送端加密+上传 | 76s 传完，发送端显示已发送 |
| 15:36–16:04 | 23:36–00:04 | 第 1 轮接收端下载 | chunk 请求 2273 次（1072×200 / 81×429），**无落地文件** |
| 15:56:07 | 23:56 | 第 2 轮 1 GiB（加了 console/进度埋点，新 clean 目录 `-c`） | 该轮 `up` 12/12 PASS |
| 16:04:42 | 00:04 | 第 2 轮服务端 chunk：**1024 次 200（块数 1024，全拉完）** | 传输层 OK |
| 16:04:37→ | 00:04→ | 第 2 轮接收端：进度停在 `下载中 69% · 解密中 69%（707/1024）` | 无 download 事件、`downloads/` 空、无「已保存至本机」 |
| 15:45 | 23:45 | `run.sh secrets`（down && up -d） | **PASS**，两密钥 sha256 前后逐字相同 |
| 16:02 | 00:02 | 256 MiB 对照（想量「多大开始坏」） | 发起正常、点下载后每 ~5.5s 一次 429，**未拿到落地文件** |
| 16:14 | 00:14 | 机器被回收，`ssh` → `Permission denied (publickey)`（约定 00:28，提前约 14 分钟） | 现场不可再取 |

## 卡在哪一条（精确到命令）

```sh
# 卡在这一条之后的「保存」一跳（命令本身返回 0，但产物不存在）
node browser-transfer.mjs --url http://127.0.0.1:18080/ \
  --src /data/ys-fixtures/src-v0.2.4-1-GiB.bin \
  --out /data/clean-v0.2.4/landed-v0.2.4.bin --gib 1 \
  --evidence .../results/20261111T155607-v0.2.4 --dl-dir /data/ys-fixtures/downloads
# 原始报错：无（页面无 pageerror、无 download 事件）；原始现象：
#   logs/21-browser-transfer.log 末段只有 429 console error + 进度停在 707/1024
#   ls -l /data/ys-fixtures/downloads/  → total 0
```

对比：同一脚本、同一台机器，`run.sh up` 与 `run.sh secrets` 全 PASS —— 所以不是环境起不来，是**保存这一跳**。

## 已产出 / 未产出

- 已产出：源 sha256 `39094ee9f6ba02c4b18f120f8bfae347d96eefd33da4e30ef08e780277b2c315`（1073741824 B）；
  secrets 前后两组值（见 `results/20261111T150720-v0.2.4/secrets-compare.txt`）。
- 未产出：**落地文件 sha256**（文件根本没生成）→ 口径 2 判 FAIL，不编数、不留空。
