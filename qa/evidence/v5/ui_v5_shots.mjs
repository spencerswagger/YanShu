#!/usr/bin/env node
/**
 * v5 ① / ④ 的界面取证：真服务 + 真前端产物 + 真 Chromium。
 *
 * 为什么要这一层：TTL 胶囊与平台统计是**界面**上的东西，单测只证明函数对，
 * 证明不了「这一屏真的显示出来」。所以这里打开生产构建（dist），
 * 用真 API（`/v1` 反代到真服务）跑一遍，截图 + 抓 DOM 文案，任何一条不满足就 exit 1。
 *
 * 流程：起静态服务（反代 /v1）→ 开 Chromium → 读本机码 → 用 python 造三条真传输
 *      （23h / 42m / 已过期）→ 重载页面 → 截图 → 断言 DOM 文案。
 *
 * 用法：
 *   node qa/evidence/v5/ui_v5_shots.mjs --dist <web/dist> --api http://127.0.0.1:PORT \
 *        --out <out dir> --dsn "$TEST_DATABASE_URL" --schema gate_v5_ui
 *
 * 产物：first-1440x900.png / inbox-1440x900.png / inbox-390x844.png / evidence.json
 */
import { spawn } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { extname, join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const arg = (name, def = '') => {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`))
  if (eq) return eq.split('=').slice(1).join('=')
  const i = process.argv.indexOf(`--${name}`)
  if (i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) return process.argv[i + 1]
  return def
}

const DIST = resolve(arg('dist'))
const API = arg('api')
const OUT = resolve(arg('out', 'results/ui-v5'))
const DSN = arg('dsn')
const SCHEMA = arg('schema', 'gate_v5_ui')
const CHROME = process.env.CHROME || '/usr/lib/chromium/chromium'
const PORT = Number(arg('port', 4183))

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
const shot = async (c, file) => {
  const r = await c.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  writeFileSync(file, Buffer.from(r.data, 'base64'))
  return file
}
const viewport = (c, width, height, mobile) =>
  c.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile, screenWidth: width, screenHeight: height })

const result = { out: OUT, shots: [], ttl: [], stats: null, seeds: null, failures: [] }
let server = null
const procs = []
let exitCode = 0

try {
  mkdirSync(OUT, { recursive: true })
  server = await startStaticServer(DIST)
  const appUrl = `http://127.0.0.1:${PORT}/`

  procs.push(launchChrome(9343, '/tmp/ys-v5-evidence'))
  await sleep(1600)
  const tab = await (await fetch('http://127.0.0.1:9343/json/new?' + encodeURIComponent(appUrl), { method: 'PUT' })).json()
  const c = cdp(tab.webSocketDebuggerUrl)
  await c.ready
  await c.send('Page.enable')
  await viewport(c, 1440, 900, false)
  await sleep(6000)   // 启动：拉 config、生成密钥、注册码、拉统计

  const code = await evaluate(c, `(() => { const el = document.querySelector('.code'); return el ? el.textContent.trim() : '' })()`)
  result.code = code
  if (!code || code === '——') throw new Error('本机码未就绪（前端没连上 API？）')

  // 造三条真传输（TTL 三态）
  const seedPy = join(HERE, 'v5_ui_seed.py')
  const seedArgs = ['python3', seedPy, '--base-url', API, '--schema', SCHEMA, '--recipient', code,
    '--json-out', join(OUT, 'seeds.json')]
  if (DSN) seedArgs.push('--dsn', DSN)
  const seed = await new Promise((ok) => {
    const p = spawn(seedArgs[0], seedArgs.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (err += d))
    p.on('close', (rc) => ok({ rc, out, err }))
  })
  if (seed.rc !== 0) throw new Error(`造数据失败：${seed.err.trim().slice(-300)}`)
  result.seeds = JSON.parse(seed.out.trim().split('\n').pop())

  // 重载 => 重新拉 inbox 与 /v1/stats
  // 注意：`/v1/stats` 服务端内部缓存 60s，必须等过缓存窗，否则截到的是旧数字。
  await sleep(62000)
  await c.send('Page.reload')
  await sleep(6000)
  await viewport(c, 1440, 900, false)
  await sleep(800)

  // 先看「自动加载」是否成立：不点刷新，列表里有没有东西
  result.inboxAuto = await evaluate(c, `document.querySelectorAll('.rlist .ritem').length`)
  if (!result.inboxAuto) {
    // 点一次刷新（aria-label=刷新）——用来区分「没拉到」和「根本没渲染」
    await evaluate(c, `(() => {
      const b = [...document.querySelectorAll('button')].find((x) => x.getAttribute('aria-label') === '刷新');
      if (b) b.click();
      return true;
    })()`)
    await sleep(2000)
    result.inboxAfterRefresh = await evaluate(c, `document.querySelectorAll('.rlist .ritem').length`)
  }
  result.shots.push(await shot(c, join(OUT, 'first-1440x900.png')))

  // 平台统计区块（④）
  result.stats = await evaluate(c, `(() => {
    const card = document.querySelector('.stats-card');
    const rows = card ? [...card.querySelectorAll('.stat')].map((s) => ({
      k: (s.querySelector('.k') || {}).textContent?.trim() || '',
      v: (s.querySelector('.v, .flip, .flip-counter, span:last-child') || {}).textContent?.trim() || '',
    })) : [];
    return { text: card ? card.textContent.replace(/\\s+/g, ' ').trim().slice(0, 240) : '', rows };
  })()`)

  // TTL 胶囊（①）
  await evaluate(c, `(() => {
    const el = [...document.querySelectorAll('*')].find((n) => (n.textContent || '').includes('待接收'));
    if (el) el.scrollIntoView({ block: 'center' });
    window.scrollTo(0, document.body.scrollHeight * 0.35);
    return true;
  })()`)
  await sleep(500)
  result.shots.push(await shot(c, join(OUT, 'inbox-1440x900.png')))
  result.ttl = await evaluate(c, `[...document.querySelectorAll('.ttl')].map((e) => ({
    text: e.textContent.trim(), soon: e.classList.contains('soon'), expired: e.classList.contains('expired'),
  }))`)

  await viewport(c, 390, 844, true)
  await sleep(900)
  await evaluate(c, `window.scrollTo(0, document.body.scrollHeight * 0.35); true`)
  await sleep(400)
  result.shots.push(await shot(c, join(OUT, 'inbox-390x844.png')))

  // ── 断言
  if (!result.inboxAuto) {
    result.failures.push(`首屏未自动加载待收列表（0 行）——点刷新后 ${result.inboxAfterRefresh ?? 0} 行；InboxPanel 在 setup 里 refresh() 时 api 还没就绪`)
  }
  const texts = (result.ttl || []).map((t) => t.text)
  // 想问「文案对不对」：逐字口径由 check_ttl_visible.py 用可控时刻验（那里没有时间漂移）。
  // 这里问的是「界面上三态真的都出现了，且单位/警示态对」。
  const pat = /^(\d+ (分钟|小时|天)后过期|已过期，无法取回)$/
  if (result.ttl.length !== 3) result.failures.push(`待收列表 TTL 胶囊数量 ${result.ttl.length} != 3（实际：${texts.join(' | ') || '无'}）`)
  for (const t of texts) if (!pat.test(t)) result.failures.push(`TTL 文案不合规：${t}`)
  if (!texts.some((t) => t.includes('小时'))) result.failures.push('没有「小时」级 TTL 行')
  if (!texts.some((t) => t.includes('分钟'))) result.failures.push('没有「分钟」级 TTL 行')
  if (!result.ttl.some((t) => t.soon)) result.failures.push('临近过期（≤1h）没有警示态')
  if (!result.ttl.some((t) => t.expired)) result.failures.push('过期行没有 expired 态')
  result.ttlTexts = texts
  const statsText = result.stats?.text || ''
  for (const want of ['今日已取走', '今日流量', '今日新建', '累计已取走', '累计流量', '累计新建']) {
    if (!statsText.includes(want)) result.failures.push(`平台统计区块缺「${want}」`)
  }

  writeFileSync(join(OUT, 'evidence.json'), JSON.stringify(result, null, 2))
  if (result.failures.length) {
    exitCode = 1
    console.error('界面证据未通过：\n- ' + result.failures.join('\n- '))
  } else {
    console.log(`界面证据通过：TTL ${result.ttl.map((t) => t.text).join(' / ')}；平台统计区块 ${result.stats.rows.length} 格`)
  }
} catch (err) {
  exitCode = 1
  result.failures.push(String((err && err.message) || err))
  try {
    mkdirSync(OUT, { recursive: true })
    writeFileSync(join(OUT, 'evidence.json'), JSON.stringify(result, null, 2))
  } catch {}
  console.error('界面证据脚本失败：', (err && err.message) || err)
} finally {
  for (const p of procs) { try { p.kill('SIGKILL') } catch {} }
  if (server) server.close()
}
process.exit(exitCode)
