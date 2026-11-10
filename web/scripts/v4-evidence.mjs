#!/usr/bin/env node
/**
 * 界面证据脚本（v4 布局 / 触摸尺寸 / 块矩阵）——可复跑，失败非 0 退出。
 *
 * 用法：
 *   npm run evidence:ui                       # 默认打 http://127.0.0.1:5173（需先起 vite dev）
 *   npm run evidence:ui -- --url=http://127.0.0.1:5173/
 *   npm run evidence:ui -- --serve=dist --api=http://127.0.0.1:18080   # 起静态服务并反代 /v1
 *
 * 产出（默认 `web/results/ui-v4/`，可用 --out 改）：
 *   first-1440x900.png / empty-1440x900.png / transferring-1440x900.png
 *   first-390x844.png  / empty-390x844.png  / transferring-390x844.png
 *   evidence.json（每个可点元素的宽高 + 块矩阵格数 / 单帧最大更新量）
 *
 * 失败条件（任一不满足即 exit 1）：
 *   ① 任一可点元素 < 48×48；
 *   ② 块矩阵 DOM 格数 > 1024；
 *   ③ 块矩阵单帧更新 > 64 格。
 */
import { spawn } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { extname, join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

const arg = (name, def) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`))
  return hit ? hit.split('=').slice(1).join('=') : def
}
const CHROME = process.env.CHROME || '/usr/lib/chromium/chromium'
const OUT = resolve(arg('out', 'results/ui-v4'))
const SERVE = arg('serve', '')
const API = arg('api', 'http://127.0.0.1:18080')
const MIN_TAP = 48
const MAX_CELLS = 1024
const MAX_PER_FRAME = 64

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

/** `--serve=dist`：静态服务 + /v1、/healthz 反代到 --api（不依赖 vite） */
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

/** 极简 CDP 客户端（Node 22 自带 WebSocket） */
function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl)
  let id = 0
  const pending = new Map()
  const ready = new Promise((res, rej) => {
    ws.onopen = () => res()
    ws.onerror = () => rej(new Error('CDP 连接失败'))
  })
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data)
    if (msg.id && pending.has(msg.id)) {
      const { res, rej } = pending.get(msg.id)
      pending.delete(msg.id)
      msg.error ? rej(new Error(msg.error.message)) : res(msg.result)
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

/** 量所有可点元素尺寸 */
const MEASURE = `(() => {
  const sel = 'button, a[href], input, [role="button"]';
  const items = [...document.querySelectorAll(sel)]
    .map((el) => {
      const r = el.getBoundingClientRect();
      const st = getComputedStyle(el);
      return { tag: el.tagName, label: (el.getAttribute('aria-label') || el.textContent || '').trim().slice(0, 18), w: Math.round(r.width), h: Math.round(r.height), hidden: r.width === 0 || r.height === 0 || st.visibility === 'hidden' || st.display === 'none' };
    })
    .filter((i) => !i.hidden);
  return { count: items.length, minW: Math.min(...items.map((i) => i.w)), minH: Math.min(...items.map((i) => i.h)), items };
})()`

/** 装一个 MutationObserver：统计块矩阵每帧改了多少「格」（验证 rAF 批量 ≤64） */
const INSTALL_FRAME_COUNTER = `(() => {
  window.__frames = [];
  const seen = new Set();
  const obs = new MutationObserver((records) => {
    for (const r of records) {
      const el = r.target;
      if (el && el.classList && el.classList.contains('c')) seen.add(el);
    }
  });
  obs.observe(document.body, { attributes: true, subtree: true, attributeFilter: ['class', 'style'] });
  const tick = () => {
    if (seen.size) { window.__frames.push(seen.size); seen.clear(); }
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  window.__obs = obs;
  return true;
})()`

const result = { out: OUT, shots: [], measures: [], matrix: null, frames: null, failures: [] }
let server = null
const procs = []
let exitCode = 0

try {
  mkdirSync(OUT, { recursive: true })
  let appUrl = arg('url', '')
  if (SERVE) {
    const port = Number(arg('port', 4173))
    server = await startStaticServer(SERVE, port)
    appUrl = appUrl || `http://127.0.0.1:${port}/`
  }
  appUrl = appUrl || 'http://127.0.0.1:5173/'
  result.app = appUrl

  procs.push(launchChrome(9333, '/tmp/ys-evidence-a'))
  procs.push(launchChrome(9334, '/tmp/ys-evidence-b'))
  await sleep(1500)

  // B 端：拿一个可用的收件码（用于真跑一次发送 → 传输中截图）
  const tabB = await openTab(9334, appUrl)
  const c2 = cdp(tabB.webSocketDebuggerUrl)
  await c2.ready
  await c2.send('Page.enable')
  await setViewport(c2, 390, 844, true)
  await sleep(4000)
  const peerCode = await evalJs(c2, `(() => { const el = document.querySelector('.code'); return el ? el.textContent.trim() : '' })()`)
  result.peerCode = peerCode
  if (!peerCode || peerCode === '——') result.failures.push('对端码未就绪（需要可用的中转服务：--url 指向已连上 API 的实例，或 --serve=dist --api=…）')
  c2.close()

  const tabA = await openTab(9333, appUrl)
  const c1 = cdp(tabA.webSocketDebuggerUrl)
  await c1.ready
  await c1.send('Page.enable')

  for (const [w, h, mobile, tag] of [
    [1440, 900, false, '1440x900'],
    [390, 844, true, '390x844'],
  ]) {
    await setViewport(c1, w, h, mobile)
    await sleep(2500)
    result.shots.push(await shot(c1, join(OUT, `first-${tag}.png`)))
    const m = await evalJs(c1, MEASURE)
    result.measures.push({ view: tag, phase: 'first', ...m })
    result.shots.push(await shot(c1, join(OUT, `empty-${tag}.png`)))
  }

  // 传输中：真发一个 96 MiB 文件（两身份），并统计矩阵格数 / 单帧更新量
  await setViewport(c1, 1440, 900, false)
  await sleep(600)
  await evalJs(c1, INSTALL_FRAME_COUNTER)
  result.sendStarted = await evalJs(
    c1,
    `(async () => {
      const code = ${JSON.stringify(peerCode)};
      const peer = document.querySelector('#peer');
      if (!peer) return { ok: false, why: 'no code input' };
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      setter.call(peer, code);
      peer.dispatchEvent(new Event('input', { bubbles: true }));
      peer.dispatchEvent(new Event('blur', { bubbles: true }));
      await new Promise((r) => setTimeout(r, 1200));
      const input = document.querySelector('.drop input[type=file]');
      if (!input) return { ok: false, why: 'no file input' };
      const parts = [];
      for (let i = 0; i < 96; i++) parts.push(new Uint8Array(1024 * 1024));
      const dt = new DataTransfer();
      dt.items.add(new File(parts, 'evidence-96m.bin', { type: 'application/octet-stream' }));
      input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
      await new Promise((r) => setTimeout(r, 800));
      const btn = [...document.querySelectorAll('button')].find((b) => (b.textContent || '').includes('发送文件'));
      if (btn) btn.click();
      return { ok: true };
    })()`,
  )
  await sleep(1800)
  // 先让首帧渲染稳定，再清零计数窗口：只量「传输过程中的更新」，不把首次挂载算进去
  await evalJs(c1, `(() => { window.__frames = []; return true })()`)
  await sleep(1600)
  result.matrix = await evalJs(
    c1,
    `(() => {
      const m = document.querySelector('.matrix');
      const cells = m ? m.querySelectorAll('.c').length : 0;
      return { cells, cols: m ? getComputedStyle(m).gridTemplateColumns.split(' ').length : 0 };
    })()`,
  )
  result.frames = await evalJs(
    c1,
    `(() => { const f = window.__frames || []; return { samples: f.length, maxPerFrame: f.length ? Math.max(...f) : 0 }; })()`,
  )
  result.shots.push(await shot(c1, join(OUT, 'transferring-1440x900.png')))
  result.measures.push({ view: '1440x900', phase: 'transferring', ...(await evalJs(c1, MEASURE)) })

  await setViewport(c1, 390, 844, true)
  await sleep(800)
  result.shots.push(await shot(c1, join(OUT, 'transferring-390x844.png')))
  result.measures.push({ view: '390x844', phase: 'transferring', ...(await evalJs(c1, MEASURE)) })
  c1.close()

  // ── 断言（三条，任一不满足即 fail）
  for (const m of result.measures) {
    if (m.minW < MIN_TAP || m.minH < MIN_TAP) {
      result.failures.push(`触摸目标不足：${m.view}/${m.phase} 最小 ${m.minW}×${m.minH}（要求 ≥${MIN_TAP}）`)
    }
  }
  if (!result.matrix || result.matrix.cells === 0) {
    result.failures.push('块矩阵未渲染（无法验证格数/帧预算）')
  } else if (result.matrix.cells > MAX_CELLS) {
    result.failures.push(`块矩阵 DOM 格数 ${result.matrix.cells} > ${MAX_CELLS}`)
  }
  if (!result.frames || result.frames.samples === 0) {
    result.failures.push('未采到块矩阵帧数据（无法验证每帧 ≤64 格）')
  } else if (result.frames.maxPerFrame > MAX_PER_FRAME) {
    result.failures.push(`块矩阵单帧更新 ${result.frames.maxPerFrame} > ${MAX_PER_FRAME}`)
  }

  writeFileSync(join(OUT, 'evidence.json'), JSON.stringify(result, null, 2))
  if (result.failures.length) {
    exitCode = 1
    console.error('界面证据未通过：\n- ' + result.failures.join('\n- '))
  } else {
    console.log(
      `界面证据通过：截图 ${result.shots.length} 张 → ${OUT}；触摸最小 ${Math.min(...result.measures.map((m) => Math.min(m.minW, m.minH)))}px；` +
        `矩阵 ${result.matrix.cells} 格 / 单帧最大 ${result.frames.maxPerFrame} 格`,
    )
  }
} catch (err) {
  exitCode = 1
  result.failures.push(String(err && err.message))
  try {
    mkdirSync(OUT, { recursive: true })
    writeFileSync(join(OUT, 'evidence.json'), JSON.stringify(result, null, 2))
  } catch {}
  console.error('界面证据脚本失败：', err && err.message)
} finally {
  for (const p of procs) {
    try {
      p.kill('SIGKILL')
    } catch {}
  }
  if (server) server.close()
}

process.exit(exitCode)
