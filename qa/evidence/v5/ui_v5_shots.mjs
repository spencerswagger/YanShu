#!/usr/bin/env node
/**
 * v5 ①④ 的界面取证：真服务 + 真前端产物 + 真 Chromium。
 *
 * 关键设计（v5/`#49` 之后）：TTL 在**读写路径即时终结**，`/v1/inbox` 永不返回过期行。
 * 所以「已过期」这一态**不能靠种一条过期记录来造**——那种断言在该语义下永远不可能通过。
 * 这里走真实路径：四行都不过期地加载出来 → 其中一行 `expires_at = now()+30s` → **页面内等到点** →
 * 该行必须自己翻成「已过期，无法取回」+ 整行灰化 + 删除线 + 下载置灰，全程**不点刷新、不重载**。
 * 同时再查一次服务端：那一刻该传输必须已是 `EXPIRED`（前后端口径一致）。
 *
 * 用法：
 *   node qa/evidence/v5/ui_v5_shots.mjs --dist <web/dist> --api http://127.0.0.1:PORT \
 *        --out <out dir> --dsn "$TEST_DATABASE_URL" --schema gate_v5_ui [--short-ttl 30]
 *
 * 产物：first-1440x900.png / ttl-after-expiry-1440x900.png / ttl-after-expiry-390x844.png / evidence.json
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
const OUT = resolve(arg('out', 'results/ui-v5'))
const DSN = arg('dsn')
const SCHEMA = arg('schema', 'gate_v5_ui')
const SHORT_TTL = Number(arg('short-ttl', '30'))
const WAIT_EXPIRY_MS = Number(arg('wait-expiry-ms', '90000'))
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

/** 读列表里每一行 TTL 胶囊 + 该行的样式/按钮状态 */
const READ_TTL = `[...document.querySelectorAll('.rlist .ritem')].map((row) => {
  const pill = row.querySelector('.ttl')
  const name = row.querySelector('.rname')
  const btn = row.querySelector('button.icon-btn')
  const cs = getComputedStyle(row)
  return {
    text: pill ? pill.textContent.trim() : '',
    soon: pill ? pill.classList.contains('soon') : null,
    expired: pill ? pill.classList.contains('expired') : null,
    rowOpacity: cs.opacity,
    nameDecoration: name ? getComputedStyle(name).textDecorationLine : null,
    downloadDisabled: btn ? btn.disabled : null,
  }
})`

const result = { out: OUT, shots: [], beforeExpiry: null, afterExpiry: null, serverState: null, failures: [] }
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

  // `/v1/stats` 服务端内部缓存 60s：先等过缓存窗，再种数据，否则统计区截到的是旧数字
  await sleep(62000)

  // 造四条真传输（其中一条 30 秒后到期）
  const seedArgs = ['python3', join(HERE, 'v5_ui_seed.py'), '--base-url', API, '--schema', SCHEMA,
    '--recipient', code, '--short-ttl', String(SHORT_TTL), '--json-out', join(OUT, 'seeds.json')]
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
  const shortId = (result.seeds.seeds || []).find((s) => s.name === 'short')?.transfer_id
  if (!shortId) throw new Error('seeds 里没有 short 那条')

  // 重载 => 重新拉 inbox（不要点刷新：要验的就是首屏自动加载）
  await c.send('Page.reload')
  await sleep(6000)
  await viewport(c, 1440, 900, false)
  await sleep(600)

  result.inboxAuto = await evaluate(c, `document.querySelectorAll('.rlist .ritem').length`)
  result.beforeExpiry = await evaluate(c, READ_TTL)
  result.stats = await evaluate(c, `(() => {
    const card = document.querySelector('.stats-card')
    return card ? card.textContent.replace(/\\s+/g, ' ').trim().slice(0, 240) : ''
  })()`)
  result.shots.push(await shot(c, join(OUT, 'first-1440x900.png')))

  // 页面内等到点：不点刷新、不重载（这才是用户真实遇到的情形）
  const t0 = Date.now()
  let elapsed = 0
  for (;;) {
    const rows = await evaluate(c, READ_TTL)
    if (rows.some((r) => r.expired)) break
    if (Date.now() - t0 > WAIT_EXPIRY_MS) break
    await sleep(1000)
    elapsed = Date.now() - t0
  }
  result.waitMs = elapsed
  // 胶囊（TtlPill 自己的 30s 定时器）与整行状态（InboxPanel 的 30s tick）是两个独立定时器：
  // 先记下「胶囊翻」到「整行翻」的实际间隔，再等整行到位（有界）。
  const tFlip = Date.now()
  let styleLagMs = null
  for (;;) {
    const rows = await evaluate(c, READ_TTL)
    const e = rows.find((r) => r.expired)
    if (e && (e.rowOpacity === '0.55' || String(e.nameDecoration || '').includes('line-through'))) {
      styleLagMs = Date.now() - tFlip
      break
    }
    if (Date.now() - tFlip > 40000) { styleLagMs = Date.now() - tFlip; break }
    await sleep(500)
  }
  result.styleLagMs = styleLagMs
  result.afterExpiry = await evaluate(c, READ_TTL)
  result.rowsStillListed = result.afterExpiry.length

  // 服务端口径：该传输必须 EXPIRED。注意契约里 `expires_at`/`server_time` 都是**秒级**，
  // 前端可能比库内精确时刻早 ≤1s 翻，所以这里给最多 5s 的收敛窗口（并记录等待毫秒数），
  // 而不是"翻的瞬间必须已 EXPIRED"——那会把秒级截断当成缺陷。
  const tSrv = Date.now()
  let st = null
  let body = {}
  for (;;) {
    st = await fetch(`${API}/v1/transfers/${shortId}`)
    body = await st.json().catch(() => ({}))
    if (body.state === 'EXPIRED' || Date.now() - tSrv > 5000) break
    await sleep(100)
  }
  result.serverStateWaitMs = Date.now() - tSrv
  result.serverState = { status: st.status, state: body.state, terminal_reason: body.terminal_reason }

  result.shots.push(await shot(c, join(OUT, 'ttl-after-expiry-1440x900.png')))
  await viewport(c, 390, 844, true)
  await sleep(800)
  result.shots.push(await shot(c, join(OUT, 'ttl-after-expiry-390x844.png')))

  // ── 断言
  const pat = /^(\d+ (分钟|小时|天)后过期|已过期，无法取回)$/
  const textsBefore = (result.beforeExpiry || []).map((r) => r.text)
  const textsAfter = (result.afterExpiry || []).map((r) => r.text)

  if (result.inboxAuto !== 4) {
    result.failures.push(`首屏未自动加载 4 行待收（实际 ${result.inboxAuto}）——InboxPanel 应在 api 注入后自动拉取`)
  }
  if (textsBefore.some((t) => t === '已过期，无法取回')) {
    result.failures.push(`加载时不该有已过期行（种的是 ${SHORT_TTL}s 后到期）：${textsBefore.join(' | ')}`)
  }
  if ((result.beforeExpiry || []).filter((r) => r.expired).length !== 0) {
    result.failures.push('加载时不该有 expired 样式')
  }
  for (const unit of ['小时', '分钟', '天']) {
    if (!textsBefore.some((t) => t.includes(unit))) {
      result.failures.push(`加载时缺「${unit}」级 TTL 行：${textsBefore.join(' | ')}`)
    }
  }

  const expRows = (result.afterExpiry || []).filter((r) => r.expired)
  if (expRows.length !== 1) {
    result.failures.push(`到点后应有且仅有 1 行变「已过期」（实际 ${expRows.length} 行；说明界面没跟时间自翻，或翻错了行）`)
  } else {
    const e = expRows[0]
    if (e.text !== '已过期，无法取回') result.failures.push(`过期行文案不对：${e.text}`)
    if (e.rowOpacity !== '0.55') result.failures.push(`过期行未整行灰化（opacity=${e.rowOpacity}）`)
    if (!String(e.nameDecoration || '').includes('line-through')) {
      result.failures.push(`过期行「发件人名」没有删除线（text-decoration=${e.nameDecoration}）`)
    }
    if (e.downloadDisabled !== true) result.failures.push('过期行下载按钮没有置灰')
  }
  for (const t of textsAfter) if (!pat.test(t)) result.failures.push(`TTL 文案不合规：${t}`)
  for (const unit of ['小时', '分钟', '天']) {
    if (!textsAfter.some((t) => t.includes(unit))) {
      result.failures.push(`到点后的同一屏缺「${unit}」级 TTL 行：${textsAfter.join(' | ')}`)
    }
  }
  if (result.rowsStillListed !== 4) {
    result.failures.push(`到点后行数应为 4（行应留在列表里变灰，而不是消失）：实际 ${result.rowsStillListed}`)
  }
  if (result.serverState?.state !== 'EXPIRED') {
    result.failures.push(`服务端此刻应为 EXPIRED（前后端口径一致）：${JSON.stringify(result.serverState)}`)
  }
  const statsText = result.stats || ''
  for (const want of ['今日已取走', '今日流量', '今日新建', '累计已取走', '累计流量', '累计新建']) {
    if (!statsText.includes(want)) result.failures.push(`平台统计区块缺「${want}」`)
  }

  writeFileSync(join(OUT, 'evidence.json'), JSON.stringify(result, null, 2))
  if (result.failures.length) {
    exitCode = 1
    console.error('界面证据未通过：\n- ' + result.failures.join('\n- '))
  } else {
    console.log(`界面证据通过：首屏自动 ${result.inboxAuto} 行；${SHORT_TTL}s 那条在 ${result.waitMs}ms 后自翻「已过期」，`
      + `服务端 state=${result.serverState.state}；同屏文案 ${textsAfter.join(' / ')}`)
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
