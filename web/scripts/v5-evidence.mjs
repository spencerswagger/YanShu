#!/usr/bin/env node
/**
 * v5 前端三块的证据脚本（可复跑，失败非 0 退出）。
 *
 * 覆盖：
 *   ① TTL 可见：真发 4 笔（1 笔大文件 + 3 笔小文件），把 3 笔小文件的 `expires_at`
 *      在库里改成 +42 分钟 / +2 天 / 已过去 1 分钟，收件列表应同时出现
 *      「23 小时后过期 / 42 分钟后过期 / 2 天后过期 / 已过期，无法取回」，过期行的下载按钮置灰；
 *   ② 速度 / ETA：发送（速度行 + 剩余时间 + 已传/总大小）与接收（下载中 N% → 解密中 + 速度行），
 *      采样的是真实 DOM 文本，不是脚本拼的字符串；
 *   ③ 平台统计：`GET /v1/stats` 的真实 JSON vs 界面上的翻牌器数字，逐个字段核对；
 *   ④ 元数据永久：同上（记录只会累积，不因旧记录而报错/错位）。
 *
 * 前置：真服务端在 --api 上（含 /v1/stats），前端已 `npm run build`（--serve=dist）。
 * 用法：
 *   node scripts/v5-evidence.mjs --api=http://127.0.0.1:18080 --serve=dist \
 *     --out=results/ui-v5 --dsn="postgres://…" [--size=96]
 */
import { spawn } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { extname, join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

import { formatBytesTotal, formatCount } from '../src/net/stats.js'

const arg = (name, def) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`))
  return hit ? hit.split('=').slice(1).join('=') : def
}
const CHROME = process.env.CHROME || '/usr/lib/chromium/chromium'
const OUT = resolve(arg('out', 'results/ui-v5'))
const SERVE = arg('serve', 'dist')
const API = arg('api', 'http://127.0.0.1:18080')
const DSN = arg('dsn', process.env.EVIDENCE_DSN || '')
const SIZE_MB = Number(arg('size', '96'))
const PORT = Number(arg('port', '4173'))

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
}

/** 静态服务 + `/v1`、`/healthz` 反代到真服务端（同源，CSP 只放 'self'） */
function startStaticServer(dir, port) {
  const root = resolve(dir)
  const server = createServer((req, res) => {
    if (req.url.startsWith('/v1') || req.url.startsWith('/healthz')) {
      const target = new URL(API)
      const proxied = httpRequest(
        { hostname: target.hostname, port: target.port, path: req.url, method: req.method, headers: req.headers },
        (up) => {
          res.writeHead(up.statusCode || 502, up.headers)
          up.pipe(res)
        },
      )
      proxied.on('error', () => {
        res.writeHead(502)
        res.end('bad gateway')
      })
      req.pipe(proxied)
      return
    }
    const path = join(root, decodeURIComponent(req.url.split('?')[0]))
    const file = existsSync(path) && statSync(path).isFile() ? path : join(root, 'index.html')
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' })
    createReadStream(file).pipe(res)
  })
  return new Promise((res) => server.listen(port, '127.0.0.1', () => res(server)))
}

function launchChrome(port, profile) {
  return spawn(
    CHROME,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profile}`,
      '--window-size=1440,900',
      'about:blank',
    ],
    { stdio: 'ignore' },
  )
}

async function openTab(port, url) {
  const res = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' })
  return res.json()
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl)
  let id = 0
  const pending = new Map()
  const ready = new Promise((res, rej) => {
    ws.onopen = () => res()
    ws.onerror = () => rej(new Error('CDP 连接失败'))
  })
  const events = []
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data)
    if (msg.id && pending.has(msg.id)) {
      const { res, rej } = pending.get(msg.id)
      pending.delete(msg.id)
      msg.error ? rej(new Error(msg.error.message)) : res(msg.result)
    } else if (!msg.id) {
      events.push(msg)
    }
  }
  return {
    ready,
    send(method, params = {}) {
      const mid = ++id
      return new Promise((res, rej) => {
        pending.set(mid, { res, rej })
        ws.send(JSON.stringify({ id: mid, method, params }))
      })
    },
    events,
    close: () => ws.close(),
  }
}

async function evalJs(c, expression) {
  const r = await c.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text || 'eval failed')
  return r.result?.value
}

async function shot(c, file) {
  const r = await c.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  writeFileSync(file, Buffer.from(r.data, 'base64'))
  return file
}

const setViewport = (c, width, height, mobile) =>
  c.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile, screenWidth: width, screenHeight: height })

/** 轮询直到 fn 返回真值（返回该值），超时抛错 */
async function until(fn, { timeout = 120_000, every = 200, what = 'condition' } = {}) {
  const t0 = Date.now()
  for (;;) {
    const v = await fn()
    if (v) return v
    if (Date.now() - t0 > timeout) throw new Error(`timeout waiting for ${what}`)
    await sleep(every)
  }
}

function psql(sql) {
  return new Promise((res, rej) => {
    const p = spawn('psql', [DSN, '-v', 'ON_ERROR_STOP=1', '-tAc', sql], { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (err += d))
    p.on('close', (code) => (code === 0 ? res(out.trim()) : rej(new Error(err || `psql exit ${code}`))))
  })
}

const result = { app: '', api: API, sizeMb: SIZE_MB, shots: [], checks: [], failures: [], stats: null, ttl: null, send: null, recv: null }
let server = null
const procs = []
let exitCode = 0

const check = (ok, label, detail) => {
  result.checks.push({ ok: Boolean(ok), label, detail })
  if (!ok) result.failures.push(`${label}（${JSON.stringify(detail)}）`)
}

try {
  if (!DSN) throw new Error('缺少 --dsn（改 expires_at 需要直连 PG）')
  mkdirSync(OUT, { recursive: true })
  server = await startStaticServer(SERVE, PORT)
  const appUrl = `http://127.0.0.1:${PORT}/`
  result.app = appUrl
  await until(async () => (await fetch(`${API}/healthz`).catch(() => null))?.ok, { what: 'api /healthz', timeout: 30_000 })

  procs.push(launchChrome(9333, '/tmp/ys-v5-a'))
  procs.push(launchChrome(9334, '/tmp/ys-v5-b'))
  await sleep(1500)

  // ── B 端：拿收件码 ─────────────────────────────────────────────
  const tabB = await openTab(9334, appUrl)
  const cB = cdp(tabB.webSocketDebuggerUrl)
  await cB.ready
  await cB.send('Page.enable')
  await cB.send('Runtime.enable')
  await cB.send('Log.enable')
  await setViewport(cB, 390, 844, true)
  const peerCode = await until(
    async () => {
      const v = await evalJs(cB, `document.querySelector('.code')?.textContent?.trim() || ''`)
      return v && v !== '——' && v.length >= 4 ? v : ''
    },
    { what: 'B 端码', timeout: 90_000 },
  )
  result.peerCode = peerCode

  // ── A 端：首屏（平台统计真实数字）────────────────────────────
  const tabA = await openTab(9333, appUrl)
  const cA = cdp(tabA.webSocketDebuggerUrl)
  await cA.ready
  await cA.send('Page.enable')
  await setViewport(cA, 390, 844, true)
  await until(async () => evalJs(cA, `!!document.querySelector('.stats-card')`), { what: 'A 首屏', timeout: 90_000 })
  await sleep(1200)

  const readStatsDom = `(() => [...document.querySelectorAll('.stats-card .stat')].map((s) => ({
    k: s.querySelector('.k')?.textContent?.trim() || '',
    v: (s.querySelector('.flip')?.textContent || '').replace(/\\s+/g, ''),
  })))()`

  const sendFile = async (name, mb, parts = null) => {
    const ev = await evalJs(
      cA,
      `(async () => {
        const peer = document.querySelector('#peer');
        if (!peer) return { ok: false, why: 'no #peer' };
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(peer, ${JSON.stringify(peerCode)});
        peer.dispatchEvent(new Event('input', { bubbles: true }));
        peer.dispatchEvent(new Event('blur', { bubbles: true }));
        await new Promise((r) => setTimeout(r, 900));
        if (!document.querySelector('.confirm')) return { ok: false, why: 'recipient not confirmed' };
        const input = document.querySelector('.drop input[type=file]');
        if (!input) return { ok: false, why: 'no file input' };
        const n = ${mb};
        const chunks = [];
        for (let i = 0; i < n; i++) chunks.push(new Uint8Array(1024 * 1024));
        const dt = new DataTransfer();
        dt.items.add(new File(chunks, ${JSON.stringify(name)}, { type: 'application/octet-stream' }));
        input.files = dt.files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
        await new Promise((r) => setTimeout(r, 400));
        if (document.querySelector('.done .seal')) return { ok: false, why: 'stale done block still visible' };
        const btn = [...document.querySelectorAll('button')].find((b) => (b.textContent || '').trim() === '发送文件');
        if (!btn) return { ok: false, why: 'no send button' };
        if (btn.disabled) return { ok: false, why: 'send disabled' };
        btn.click();
        return { ok: true };
      })()`,
    )
    if (!ev?.ok) throw new Error(`send ${name} failed: ${ev?.why}`)
    await sleep(250)
    await until(async () => evalJs(cA, `!!document.querySelector('.progress-block') || !!document.querySelector('.done .seal')`), {
      what: `${name} 进入发送`,
      timeout: 30_000,
    })
  }

  // ── ② 发送侧：速度 / ETA 采样 + 截图 ─────────────────────────
  await sendFile(`v5-evidence-${SIZE_MB}m.bin`, SIZE_MB)
  const sendSamples = []
  let shotSending = false
  const sampled = await until(
    async () => {
      const s = await evalJs(
        cA,
        `(() => {
          const line = document.querySelector('.progress-block .speed-line');
          return {
            speed: line?.querySelector('.speed')?.textContent?.trim() || '',
            warn: line?.querySelector('.warn')?.textContent?.trim() || '',
            eta: line?.querySelector('.eta')?.textContent?.trim() || '',
            pair: line?.querySelector('.meta')?.textContent?.trim() || '',
            done: !!document.querySelector('.done .seal'),
          };
        })()`,
      )
      if (s && (s.speed || s.warn || s.eta)) sendSamples.push(s)
      if (!shotSending && s && s.speed) {
        shotSending = true
        result.shots.push(await shot(cA, join(OUT, 'sending-speed-390x844.png')))
        await setViewport(cA, 1440, 900, false)
        await sleep(200)
        result.shots.push(await shot(cA, join(OUT, 'sending-speed-1440x900.png')))
        await setViewport(cA, 390, 844, true)
      }
      return s?.done ? s : null
    },
    { what: '发送完成', timeout: 300_000, every: 120 },
  )
  await sleep(1200)
  const sentTtl = await evalJs(cA, `document.querySelector('.done .ttl')?.textContent?.trim() || ''`)
  result.doneDebug = await evalJs(cA, `document.querySelector('.done')?.innerText || '(no .done)'`)
  result.send = { samples: sendSamples.slice(0, 12), lastSample: sampled, doneTtl: sentTtl }
  check(sendSamples.some((s) => /\d+(\.\d+)?\s*(MB|KB)\/s/.test(s.speed)), '发送速度行有真实速率数字', sendSamples[0])
  check(sendSamples.some((s) => /剩|即将完成/.test(s.eta)), '发送 ETA 有真实文案', sendSamples.find((s) => s.eta))
  check(sendSamples.some((s) => /MB \/ |GB \/ /.test(s.pair)), '已传/总大小为 x/y 形式', sendSamples.find((s) => s.pair))
  check(/小时后过期/.test(sentTtl), '发送完成态显示服务端 TTL', sentTtl)
  result.shots.push(await shot(cA, join(OUT, 'sent-done-390x844.png')))

  // ── ① TTL：再造 3 笔小传输，改 expires_at 造三态 ─────────────
  for (let i = 1; i <= 3; i++) {
    await sendFile(`v5-ttl-${i}.bin`, 1)
    await until(async () => evalJs(cA, `!!document.querySelector('.done .seal')`), { what: `第 ${i} 笔小传输完成`, timeout: 120_000 })
    await sleep(300)
  }
  const rows = await psql(
    `SELECT transfer_id, expires_at FROM transfers WHERE recipient_code = '${peerCode}' AND state = 'READY' ORDER BY created_at DESC LIMIT 3`,
  )
  const ids = rows
    .split('\n')
    .map((l) => l.split('|')[0])
    .filter(Boolean)
  if (ids.length < 3) throw new Error(`库里只有 ${ids.length} 笔可改的 READY 传输`)
  await psql(`UPDATE transfers SET expires_at = now() + interval '42 minutes 30 seconds' WHERE transfer_id = '${ids[0]}'`)
  await psql(`UPDATE transfers SET expires_at = now() + interval '50 hours' WHERE transfer_id = '${ids[1]}'`)
  await psql(`UPDATE transfers SET expires_at = now() - interval '1 minute' WHERE transfer_id = '${ids[2]}'`)

  await evalJs(cB, `document.querySelector('button[aria-label="刷新"]')?.click()`)
  await sleep(1500)
  const ttlRows = await evalJs(
    cB,
    `(() => [...document.querySelectorAll('.rlist .ritem')].map((li) => ({
      ttl: li.querySelector('.ttl')?.textContent?.trim() || '',
      expiredClass: !!li.querySelector('.ttl.expired'),
      rowExpiredClass: li.classList.contains('expired'),
      rowOpacity: Number(getComputedStyle(li).opacity),
      nameDecoration: getComputedStyle(li.querySelector('.rname')).textDecorationLine,
      btnDisabled: !!li.querySelector('button[aria-label="下载并解密"]')?.disabled,
    })))()`,
  )
  result.ttl = ttlRows
  const ttls = ttlRows.map((r) => r.ttl)
  check(ttls.some((t) => /^\d+ 小时后过期$/.test(t)), '列表显示「N 小时后过期」', ttls)
  check(ttls.includes('42 分钟后过期'), '列表显示「42 分钟后过期」', ttls)
  check(ttls.includes('2 天后过期'), '列表显示「2 天后过期」', ttls)
  check(ttls.includes('已过期，无法取回'), '列表显示「已过期，无法取回」', ttls)
  const expiredRow = ttlRows.find((r) => r.ttl === '已过期，无法取回') || {}
  check(expiredRow.btnDisabled, '过期行下载置灰', expiredRow)
  check(expiredRow.rowExpiredClass && expiredRow.rowOpacity < 0.8, '过期行整行灰化', expiredRow)
  check(/line-through/.test(expiredRow.nameDecoration || ''), '过期行文件名删除线', expiredRow)
  result.shots.push(await shot(cB, join(OUT, 'ttl-four-states-390x844.png')))
  await setViewport(cB, 1440, 900, false)
  await sleep(400)
  result.shots.push(await shot(cB, join(OUT, 'ttl-four-states-1440x900.png')))
  await setViewport(cB, 390, 844, true)

  // ── ② 接收侧：点下载 → 两段进度 + 速度行 ────────────────────
  const clicked = await evalJs(
    cB,
    `(() => {
      const rows = [...document.querySelectorAll('.rlist .ritem')];
      const row = rows.find((li) => !li.querySelector('.ttl.expired') && (li.textContent || '').includes('${SIZE_MB} MB'))
        || rows.find((li) => !li.querySelector('.ttl.expired'));
      const btn = row?.querySelector('button[aria-label="下载并解密"]');
      if (!btn || btn.disabled) return false;
      btn.click();
      return true;
    })()`,
  )
  check(clicked, '点到了未过期行的下载按钮', clicked)
  const recvSamples = []
  let shotRecv = false
  let recvFail = ''
  await until(
    async () => {
      const s = await evalJs(
        cB,
        `(() => {
          const saved = !!document.querySelector('.banner.info');
          const p = document.querySelector('.row-progress');
          const banners = [...document.querySelectorAll('.banner')].map((b) => (b.textContent || '').trim());
          if (!p) return { stage: '', speed: '', eta: '', pair: '', msg: '', saved, banner: banners, still: false };
          const metas = [...p.querySelectorAll('.meta')].filter((el) => !el.closest('.speed-line'));
          return {
            stage: p.querySelector('.stage')?.textContent?.trim() || '',
            speed: p.querySelector('.speed-line .speed')?.textContent?.trim() || '',
            eta: p.querySelector('.speed-line .eta')?.textContent?.trim() || '',
            pair: p.querySelector('.speed-line .meta')?.textContent?.trim() || '',
            msg: (metas.at(-1)?.textContent || '').trim(),
            saved,
            banner: banners,
            still: true,
          };
        })()`,
      )
      if (s) recvSamples.push(s)
      const pct = Number((s?.stage || '').match(/下载中 (\d+)%/)?.[1] || -1)
      if (s && s.stage && !shotRecv && pct >= 20) {
        shotRecv = true
        result.shots.push(await shot(cB, join(OUT, 'receiving-two-stage-390x844.png')))
      }
      return s?.saved ? s : null
    },
    { what: '接收完成', timeout: 300_000, every: 60 },
  ).catch((e) => {
    recvFail = e.message
  })
  result.recv = {
    samples: recvSamples.slice(0, 12),
    fail: recvFail,
    console: cB.events
      .filter((e) => e.method === 'Runtime.consoleAPICalled' || e.method === 'Log.entryAdded')
      .slice(-20)
      .map((e) => ({ m: e.method, t: e.params?.entry?.text || e.params?.args?.map((a) => a.value ?? a.description).join(' ') })),
  }
  if (recvFail) {
    result.shots.push(await shot(cB, join(OUT, 'receiving-failure-390x844.png')))
    throw new Error(`接收未完成：${recvFail}；最后状态 ${JSON.stringify(recvSamples.at(-1))}`)
  }
  check(recvSamples.some((s) => /下载中 \d+%/.test(s.stage)), '接收显示「下载中 N%」', recvSamples.map((s) => s.stage))
  check(
    recvSamples.some((s) => /解密中 \d+%/.test(s.stage)),
    '接收同时显示「解密中 N%」（与下载百分比同为真实字节）',
    recvSamples.map((s) => s.stage),
  )
  // 流式接收把解密摊到每块（`解密块 i/N`），没有独立「解密中」阶段；非流式回退路径才有（单测覆盖）
  check(
    recvSamples.some((s) => /解密块 \d+\/\d+/.test(s.msg)),
    '逐块解密在进度里可见（解密块 i/N）',
    recvSamples.map((s) => s.msg),
  )
  check(recvSamples.some((s) => /\d+(\.\d+)?\s*(MB|KB)\/s/.test(s.speed)), '接收速度行有真实速率', recvSamples.map((s) => s.speed))
  await sleep(800)
  result.shots.push(await shot(cB, join(OUT, 'received-done-390x844.png')))

  // ── ④ 平台统计：API 真数字 vs 界面翻牌器 ────────────────────
  const stats = await (await fetch(`${API}/v1/stats`)).json()
  result.stats = { api: stats }
  await evalJs(cA, `location.reload()`)
  await sleep(3500)
  await setViewport(cA, 390, 844, true)
  await sleep(1200)
  const domStats = await evalJs(cA, readStatsDom)
  result.stats.dom = domStats
  const want = {
    今日已取走: formatCount(stats.today.consumed),
    今日流量: formatBytesTotal(stats.today.consumed_bytes),
    今日新建: formatCount(stats.today.created),
    累计已取走: formatCount(stats.total.consumed),
    累计流量: formatBytesTotal(stats.total.consumed_bytes),
    累计新建: formatCount(stats.total.created),
  }
  const norm = (v) => String(v).replace(/\s+/g, '')
  const got = Object.fromEntries(domStats.map((r) => [r.k, norm(r.v)]))
  check(stats.today.consumed >= 1 && stats.today.consumed_bytes > 0, 'API 有真实今日取走/流量', stats.today)
  check(Object.entries(want).every(([k, v]) => got[k] === norm(v)), '界面六项与 /v1/stats 逐项一致', { want, got })
  result.shots.push(await shot(cA, join(OUT, 'stats-platform-390x844.png')))
  await setViewport(cA, 1440, 900, false)
  await sleep(500)
  result.shots.push(await shot(cA, join(OUT, 'stats-platform-1440x900.png')))

  // 未完成上传列表不应把已完成记录算进去（元数据永久 + 流式落库终态）
  const pendingCount = await evalJs(
    cA,
    `[...document.querySelectorAll('h2')].filter((h) => (h.textContent || '').includes('未完成的上传')).length`,
  )
  result.pendingHeadings = pendingCount
  check(pendingCount === 0, '已完成的流式传输不再出现在「未完成的上传」', pendingCount)
} catch (err) {
  result.failures.push(`脚本异常：${err.message}`)
} finally {
  writeFileSync(join(OUT, 'evidence.json'), JSON.stringify(result, null, 2))
  for (const p of procs) p.kill('SIGKILL')
  server?.close()
  if (result.failures.length) {
    exitCode = 1
    console.error('FAILURES:')
    for (const f of result.failures) console.error(' -', f)
  } else {
    console.log(`OK ${result.checks.length} 项检查通过，截图 ${result.shots.length} 张 → ${OUT}`)
  }
  process.exit(exitCode)
}
