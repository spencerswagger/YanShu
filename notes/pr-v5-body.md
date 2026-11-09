## 改了什么

**① TTL 可见（服务端权威）**
- `net/upload.js`：发送结果与本地记录改用服务端 `POST /transfers` 返回的 `expires_at`（流式与整包两条路都覆盖），缺失时才退回「服务端时间基准 + TTL 秒」推算。
- `components/SendPanel.vue`：发送完成态把写死的「24 小时后自动删除」换成 TTL 胶囊（服务端值）。
- `components/InboxPanel.vue`：过期行判定改用 `serverClock`（服务端时间基准 + 单调推进），原先用本机 `Date.now()` 相减，设备时钟偏了会误判。

**② 速度 / ETA**
- `components/InboxPanel.vue`：接收侧接入 `SpeedLine`（速度 · 剩余时间 · 已传/总大小）与「下载中 N%」，数据源是 `download.js` 的真实字节进度；`lib/speed.js` 新增 `stageLabel()`。
- `components/SendPanel.vue`：删除旧的 `rateText/etaText`（另一套按 Date.now 平均值算的速率），统一走 `createSpeedMeter`（EWMA + 异常态）。
- `net/download.js`：`unpack.finish()` 前让出一帧，否则同步解密会把「解密中」这段状态挤掉，永远画不出来。

**③ 平台统计**
- `components/StatsCard.vue` / `net/stats.js` 接 `GET /v1/stats`：今日/累计的「已取走 / 流量 / 新建」六项；形状不对/超时/报错一律返回 null → 整块隐藏。

**④ 元数据长期存在**
- 修 `net/upload.js` 流式路径：`complete` 后没有把落库记录翻成终态，导致「最近传输」永远显示「传输中」，并把已完成的传输列进「未完成的上传」。
- 旧记录没有 `expiresAt` 时不渲染 TTL 胶囊（不猜、不显示假 TTL）。

**其它**
- `SendPanel.vue`：拖入区改为常驻，选完文件后仍能看到文件名/大小，也能重新选（原先 `v-if="!file"` 把文件名一起藏了，只能刷新页面换文件）。
- 新增 `web/tsconfig.json` + `npm run typecheck`（`vue-tsc --noEmit`，`allowJs`、`checkJs:false`：JS 项目的模板/导入/语法级检查，不含 JS 类型推断）。

## 为什么

v5 收尾：TTL 对用户可见（含临界与已过期态）、传输显示真实速率与实际剩余时间、平台统计接统一口径接口。

## 影响

- **依赖**：平台统计依赖 `GET /v1/stats`（后端 PR #48）。该接口未上线时前端静默降级（区块隐藏），不报错、不阻塞主流程。
- 文案：全部沿用 `docs/UI-COPY.md`（T1/T2/S1/S2/S4/S5/S6/P1）；只删掉了未登记的写死文案「24 小时后自动删除」。
- 行为变化：发送完成态改为显示服务端 TTL；接收行在下载中会多一行速度/ETA。
- **已知口径差异（需产品确认）**：UI-COPY S3 的「解密中 N%」在流式接收下不存在——流式是逐块边下边解（进度显示「解密块 i/N」），只有非流式回退路径才有独立「解密中」阶段。前端不造百分比，按实际显示。

## 怎么验

```bash
cd web
npm run typecheck      # vue-tsc 0 error
npm test               # 119 例全绿
npm run build
# 真服务端（含 /v1/stats）+ 真内核，两个 Chrome 身份，A 发 96 MiB、B 收：
node scripts/v5-evidence.mjs --api=http://127.0.0.1:18080 --serve=dist \
  --dsn="$PG_DEV_DSN" --size=96 --out=../results/ui-v5
```

证据：`results/ui-v5/`（9 张真跑截图 + `evidence.json` 的 16 项断言），说明见 `results/ui-v5/README.md`。
