#!/usr/bin/env node
/**
 * v5 ① 终审探针：TTL **翻转时刻**与「点击兜底」的独立复测（真 Chromium + 真 API + 真库时刻）。
 *
 * 验两件事：
 *   A. 翻转一致性：造一条 `expires_at = now + N 秒` 的行 → 首屏加载后**不刷新、不点击** →
 *      页内 rAF 探针记录「胶囊翻成已过期 / 整行灰化 / 下载置灰」三个事件的时刻，
 *      再与**库里的精确到期时刻**比：是否同帧、滞后多少、有没有比服务端更早判过期。
 *   B. 点击兜底：把定时器冻住（模拟后台标签页被节流，tick 不跑）→ 等真实时间越过到期 →
 *      界面仍显示"未过期"时点下载 → 必须**一个请求都不发**、直接把行翻成过期态。
 *
 * 用法：
 *   node qa/evidence/v5/ui_ttl_flip.mjs --dist <web/dist> --api http://127.0.0.1:PORT \
 *        --dsn "$TEST_DATABASE_URL" --schema gate_v5_flip --out <dir> [--seconds 20] [--click-seconds 8]
 */
import { spawn } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { extname, join, resolve, dirname } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const arg = (name, def = '') => {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`))
  if (eq) return eq.split('=').slice(1).join('=')
  const i = process.argv.indexOf(`--${name}`)
  if (i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) return process.argv[i + 1]
  return def
}

const DIST = resolve(arg('dist'))
const API = arg('api').replace(/\/$/, '')
const DSN = arg('dsn')
const SCHEMA = arg('schema', 'gate_v5_flip')
const OUT = resolve(arg('out', join(HERE, '.flip-out')))
const SECONDS = Number(arg('seconds', '20'))
const CLICK_SECONDS = Number(arg('click-seconds', '8'))
const CHROME = process.env.CHROME || '/usr/lib/chromium/chromium'
const PORT = Number(arg('port', '4193'))

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2',
}

function startStaticServer(dir) {
  const root = resolve(dir)
  const server = createServer((req, res) => {
    if (req.url.startsWith('/v1') || req.url.startsWith('/healthz')) {
      const t = new URL(API)
      const up = httpRequest({ hostname: t.hostname, port: t.port, path: req.url, method: req.method, headers: req.headers },
        (r) => { res.writeHead(r.statusCode || 502, r.headers); r.pipe(res) })
      up.on('error', () => { res.writeHead(502); res.end('bad gateway') })
      req.pipe(up)
      return
    }
    const p = join(root, decodeURIComponent(req.url.split('?')[0]))
    const file = existsSync(p) && statSync(p).isFile() ? p : join(root, 'index.html')
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' })
    createReadStream(file).pipe(res)
  })
  return new Promise((ok) => server.listen(PORT, '127.0.0.1', () => ok(server)))
}

function launchChrome(port, profile) {
  return spawn(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--window-size=1440,900', 'about:blank'],
    { stdio: 'ignore' })
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl)
  let id = 0
  const pending = new Map()
  const ready = new Promise((ok, no) => { ws.onopen = () => ok(); ws.onerror = () => no(new Error('CDP 连接失败')) })
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data)
    if (m.id && pending.has(m.id)) {
      const { ok, no } = pending.get(m.id)
      pending.delete(m.id)
      m.error ? no(new Error(m.error.message)) : ok(m.result)
    }
  }
  return {
    ready,
    send(method, params = {}) {
      const mid = ++id
      return new Promise((ok, no) => { pending.set(mid, { ok, no }); ws.send(JSON.stringify({ id: mid, method, params })) })
    },
    close: () => ws.close(),
  }
}

const evaluate = async (c, expression) => {
  const r = await c.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text || 'eval failed')
  return r.result?.value
}

/** 在页面脚本之前注入：抓 fetch/XHR + 每帧采样 TTL 三态翻转（PACING 由 rAF 决定，约 16ms） */
const BOOTSTRAP = `
const __freeze = new URLSearchParams(location.search).get('freeze') === '1';
if (__freeze) {
  // 模拟被节流的后台标签页：应用一启动就没有定时器（expiryTicker 的 setTimeout 不生效）
  window.setTimeout = () => 0;
  window.setInterval = () => 0;
  window.__frozen = true;
}
window.__reqs = [];
window.__ev = [];
window.__t0 = { date: Date.now(), perf: performance.now() };
(() => {
  const of = window.fetch;
  window.fetch = function (...a) {
    try { window.__reqs.push({ u: String(a[0] && a[0].url ? a[0].url : a[0]), m: (a[1] && a[1].method) || 'GET', t: Date.now() }); } catch (e) {}
    return of.apply(this, a);
  };
  const ox = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u, ...r) {
    try { window.__reqs.push({ u: String(u), m: String(m), t: Date.now() }); } catch (e) {}
    return ox.call(this, m, u, ...r);
  };
})();
(() => {
  const state = { pill: false, row: false, btn: false };
  const tick = () => {
    const row = document.querySelector('.rlist .ritem');
    if (row) {
      const pill = row.querySelector('.ttl');
      const btn = row.querySelector('button.icon-btn');
      const s = {
        pill: Boolean(pill && pill.classList.contains('expired')),
        row: row.classList.contains('expired'),
        btn: Boolean(btn && btn.disabled),
      };
      for (const k of ['pill', 'row', 'btn']) {
        if (s[k] && !state[k]) window.__ev.push({ kind: k, date: Date.now(), perf: performance.now() });
        if (!s[k]) state[k] = false;
      }
    }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})();
true;
`

function seed(args) {
  return new Promise((ok) => {
    const p = spawn('python3', [join(HERE, 'v5_flip_seed.py'), '--base-url', API, '--schema', SCHEMA,
      '--recipient', args.recipient, '--seconds', String(args.seconds),
      '--size', String(args.size || 7340032), ...(DSN ? ['--dsn', DSN] : [])],
      { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (err += d))
    p.on('close', (rc) => ok({ rc, out, err }))
  })
}

const result = { out: OUT, seconds: SECONDS, clickSeconds: CLICK_SECONDS, failures: [] }
let server = null
const procs = []
let exitCode = 0

try {
  mkdirSync(OUT, { recursive: true })
  server = await startStaticServer(DIST)
  const appUrl = `http://127.0.0.1:${PORT}/`

  procs.push(launchChrome(9353, '/tmp/ys-flip-probe'))
  await sleep(1600)
  const tab = await (await fetch('http://127.0.0.1:9353/json/new?' + encodeURIComponent(appUrl), { method: 'PUT' })).json()
  const c = cdp(tab.webSocketDebuggerUrl)
  await c.ready
  await c.send('Page.enable')
  await c.send('Page.addScriptToEvaluateOnNewDocument', { source: BOOTSTRAP })
  await c.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false, screenWidth: 1440, screenHeight: 900 })
  await sleep(6000)

  const code = await evaluate(c, `(() => { const el = document.querySelector('.code'); return el ? el.textContent.trim() : '' })()`)
  result.code = code
  if (!code || code === '——') throw new Error('本机码未就绪')

  // ── A. 翻转一致性
  const seeded = await seed({ recipient: code, seconds: SECONDS, size: 7340032 })  // 7 MiB → 列表里显示 7.0 MB
  if (seeded.rc !== 0) throw new Error(`造数据失败：${seeded.err.trim().slice(-300)}`)
  result.seed = JSON.parse(seeded.out.trim().split('\n').pop())
  const dbMs = Date.parse(result.seed.db_expires_at)
  const apiMs = Date.parse(result.seed.api_expires_at)
  result.dbExpiresAt = result.seed.db_expires_at
  result.apiExpiresAt = result.seed.api_expires_at
  result.dbFractionMs = dbMs - apiMs // 库里的精确值比接口值多的那部分（秒级截断掉的）

  await c.send('Page.reload')
  await sleep(5000)
  result.inboxRowsAfterLoad = await evaluate(c, `document.querySelectorAll('.rlist .ritem').length`)

  let ev = []
  for (let i = 0; i < 60; i++) {
    ev = await evaluate(c, `window.__ev || []`)
    if (ev.some((e) => e.kind === 'pill') && ev.some((e) => e.kind === 'row') && ev.some((e) => e.kind === 'btn')) break
    await sleep(500)
  }
  result.events = ev
  const at = (k) => ev.find((e) => e.kind === k) || null
  const pill = at('pill'); const row = at('row'); const btn = at('btn')
  if (!pill || !row || !btn) {
    result.failures.push(`没采到完整翻转事件：pill=${Boolean(pill)} row=${Boolean(row)} btn=${Boolean(btn)}`)
  } else {
    result.skewRowVsPillMs = row.date - pill.date
    result.skewBtnVsPillMs = btn.date - pill.date
    result.flipVsDbMs = pill.date - dbMs       // >0 滞后，<0 提前
    result.flipVsApiMs = pill.date - apiMs     // 相对「接口给的秒级时刻」的偏差
    if (result.skewRowVsPillMs > 50 || result.skewBtnVsPillMs > 50) {
      result.failures.push(`三者不同帧：row-pill=${result.skewRowVsPillMs}ms btn-pill=${result.skewBtnVsPillMs}ms（>50ms 视为不同帧）`)
    }
    if (result.flipVsDbMs < -1200) {
      result.failures.push(`比服务端早判过期 ${-result.flipVsDbMs}ms（超过秒级截断能解释的 1s 上限）`)
    }
  }

  // ── B. 点击兜底（把 tick 冻住 = 后台节流）
  const seeded2 = await seed({ recipient: code, seconds: CLICK_SECONDS, size: 5242880 })  // 5 MiB → 5.0 MB
  if (seeded2.rc !== 0) throw new Error(`造数据失败：${seeded2.err.trim().slice(-300)}`)
  result.seed2 = JSON.parse(seeded2.out.trim().split('\n').pop())
  await c.send('Page.navigate', { url: appUrl + '?freeze=1' })
  await sleep(5000)
  result.clickPhase = {
    rowsAfterLoad: await evaluate(c, `document.querySelectorAll('.rlist .ritem').length`),
    frozen: await evaluate(c, `Boolean(window.__frozen)`),
  }
  const waitMs = CLICK_SECONDS * 1000 + 2500
  await sleep(waitMs)
  result.clickPhase.waitedMs = waitMs
  result.clickPhase.beforeClick = await evaluate(c, `(() => {
    const row = [...document.querySelectorAll('.rlist .ritem')].find((li) => (li.textContent || '').includes('5.0 MB')) || document.querySelector('.rlist .ritem')
    const pill = row && row.querySelector('.ttl')
    const btn = row && row.querySelector('button.icon-btn')
    return {
      pillText: pill ? pill.textContent.trim() : '',
      pillExpired: pill ? pill.classList.contains('expired') : null,
      rowExpired: row ? row.classList.contains('expired') : null,
      btnDisabled: btn ? btn.disabled : null,
      rowText: row ? (row.textContent || '').replace(/\\s+/g, ' ').slice(0, 40) : '',
    }
  })()`)

  result.clickPhase.requestsBefore = await evaluate(c, `window.__reqs.length`)
  await evaluate(c, `(() => {
    const rows = [...document.querySelectorAll('.rlist .ritem')]
    const row = rows.find((li) => (li.textContent || '').includes('5.0 MB')) || rows[0]
    const btn = row && row.querySelector('button[aria-label="下载并解密"], button.icon-btn')
    if (btn) btn.click()
    return true
  })()`)
  await sleep(1500)
  result.clickPhase.requestsAfter = await evaluate(c, `window.__reqs.length`)
  result.clickPhase.newRequests = await evaluate(c, `window.__reqs.slice(${result.clickPhase.requestsBefore}).map((r) => r.m + ' ' + r.u)`)
  result.clickPhase.afterClick = await evaluate(c, `(() => {
    const row = [...document.querySelectorAll('.rlist .ritem')].find((li) => (li.textContent || '').includes('5.0 MB')) || document.querySelector('.rlist .ritem')
    const pill = row && row.querySelector('.ttl')
    return {
      pillText: pill ? pill.textContent.trim() : '',
      pillExpired: pill ? pill.classList.contains('expired') : null,
      rowExpired: row ? row.classList.contains('expired') : null,
      banner: [...document.querySelectorAll('.banner')].map((b) => (b.textContent || '').trim()),
    }
  })()`)

  const pre = result.clickPhase.beforeClick || {}
  const post = result.clickPhase.afterClick || {}
  const newReqs = result.clickPhase.newRequests || []
  if (pre.pillExpired) {
    result.failures.push(`点击前界面已经翻成过期（没造出「界面未过期但服务端已到期」的窗口）：${JSON.stringify(pre)}`)
  }
  const transferReqs = newReqs.filter((u) => /\/v1\/transfers\/[0-9a-f]{32}/.test(u))
  if (transferReqs.length) {
    result.failures.push(`兜底没生效：点击后仍发了传输请求 ${JSON.stringify(transferReqs)}`)
  }
  if (!post.pillExpired || !post.rowExpired) {
    result.failures.push(`点击后没有把行置成过期态：${JSON.stringify(post)}`)
  }
  if ((post.banner || []).some((b) => /410|已过期|过期/.test(b)) && !post.pillExpired) {
    result.failures.push(`吃了 410 的错：banner=${JSON.stringify(post.banner)}`)
  }

  writeFileSync(join(OUT, 'flip.json'), JSON.stringify(result, null, 2))
  if (result.failures.length) {
    exitCode = 1
    console.error('翻转/兜底探针未通过：\n- ' + result.failures.join('\n- '))
  } else {
    console.log(`翻转：pill/row/btn 偏差 ${result.skewRowVsPillMs}/${result.skewBtnVsPillMs}ms；`
      + `相对库内精确到期 ${result.flipVsDbMs >= 0 ? '滞后' : '提前'} ${Math.abs(result.flipVsDbMs)}ms`
      + `（接口秒级值偏差 ${result.flipVsApiMs}ms，库内小数部分 ${result.dbFractionMs}ms）；`
      + `点击兜底：新增传输请求 ${transferReqs.length} 条，行已置过期=${post.pillExpired}`)
  }
} catch (err) {
  exitCode = 1
  result.failures.push(String((err && err.message) || err))
  try { mkdirSync(OUT, { recursive: true }); writeFileSync(join(OUT, 'flip.json'), JSON.stringify(result, null, 2)) } catch {}
  console.error('探针失败：', (err && err.message) || err)
} finally {
  for (const p of procs) { try { p.kill('SIGKILL') } catch {} }
  if (server) server.close()
}
process.exit(exitCode)
