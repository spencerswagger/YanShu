#!/usr/bin/env node
/**
 * 负面实测（negative-save）：**写盘失败时，界面不许报成功**。
 *
 * 背景：v0.2.4 的流式接收 `receiveStreaming` 收尾是 `await sink.close()` → `api.ack()` → `return`，
 * 函数里**没有 save()**；headless Chromium 没有 `showSaveFilePicker`，sink 退回内存，
 * `sink.close()` 的返回值被丢掉 → 界面显示「已保存至本机」，磁盘上什么都没有，而 ack 已经把密文删了。
 * 这就是「假绿」。本脚本把这件事做成可复跑的判定。
 *
 * 两个场景（都用 16 MiB，快）：
 *   A. 出厂 sink（headless 下没有 showSaveFilePicker）：断言「界面说保存了」→ 磁盘上必须有文件。
 *      没有文件还报成功 = 假绿 = FAIL。
 *   B. 注入写盘失败（showSaveFilePicker 抛 QuotaExceededError + OPFS getDirectory 抛 QuotaExceededError）：
 *      断言界面**必须**出现错误文案，且**不得**出现「已保存至本机」。
 *
 * 用法：
 *   node negative-save.mjs --url http://127.0.0.1:18080/ --src <16MiB 文件> --evidence <目录> \
 *        [--dl-dir <下载目录>] [--wait-s 180]
 * 退出码：0 = 行为正确（真保存 / 失败可见）；1 = 假绿或失败静默（FAIL）；2 = 用法/环境错误。
 */
import { chromium } from 'playwright-core'
import { mkdirSync, readdirSync, statSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const arg = (k, d = '') => {
  const i = process.argv.indexOf(k)
  return i > 0 ? process.argv[i + 1] : d
}
const url = arg('--url', 'http://127.0.0.1:18080/')
const src = arg('--src')
const ev = arg('--evidence', '.')
const dlDir = arg('--dl-dir', join(ev, 'neg-downloads'))
const waitS = Number(arg('--wait-s', '180'))
const exe = process.env.CHROMIUM_BIN || '/usr/bin/chromium'
if (!src) { console.error('用法：--src <16MiB 文件> [--evidence 目录]'); process.exit(2) }
mkdirSync(ev, { recursive: true }); mkdirSync(dlDir, { recursive: true })
const t0 = Date.now()
const log = []
const say = (s) => { const l = `[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`; log.push(l); console.log(l) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const newFileIn = (dir, before) => readdirSync(dir).filter((f) => !before.has(f))
  .map((f) => join(dir, f)).filter((p) => { try { return statSync(p).isFile() } catch { return false } })

/** 跑一轮：发送端发 src，接收端点下载，观察 UI + 磁盘 */
async function runOnce({ tag, failSink, roDir }) {
  const res = { tag, ui_says_saved: false, error_text: '', files: [], console_errors: [], cdp: '' }
  const profileRoot = join(tmpdir(), `ys-neg-${tag}-${Date.now()}`)
  mkdirSync(profileRoot, { recursive: true })
  const launchOpts = {
    executablePath: exe, headless: true, acceptDownloads: true,
    downloadsPath: dlDir, args: ['--no-sandbox', '--disable-dev-shm-usage']
  }
  let ctxR, ctxS
  try {
    ctxR = await chromium.launchPersistentContext(join(profileRoot, 'recv'), launchOpts)
    const recv = ctxR.pages()[0] || (await ctxR.newPage())
    const cdp = await ctxR.newCDPSession(recv)
    // 场景 C：把下载目标指到**不可写目录**，模拟「浏览器接受了 click 但写不进去」
    const targetDir = roDir || dlDir
    await cdp.send('Browser.setDownloadBehavior',
      { behavior: 'allow', downloadPath: targetDir, eventsEnabled: true })
    if (failSink) {
      // 注入：本次浏览器里所有写盘入口都坏掉（模拟配额打满 / 只读环境）
      await recv.addInitScript(() => {
        window.showSaveFilePicker = async () => {
          throw new DOMException('quota exceeded (injected)', 'QuotaExceededError')
        }
        try {
          Object.defineProperty(navigator, 'storage', {
            configurable: true,
            value: { getDirectory: async () => { throw new DOMException('quota exceeded (injected)', 'QuotaExceededError') } }
          })
        } catch {}
      })
    }
    const ids = new Map()
    let ackSent = 0
    recv.on('request', (rq) => {
      if (rq.method() === 'POST' && /\/ack(?:\?|$)/.test(rq.url())) ackSent += 1
    })
    recv.on('request', (rq) => {
      const m = rq.url().match(/\/v1\/transfers\/([0-9A-Za-z_-]{6,})(?:\/|$)/)
      if (m) ids.set(m[1], (ids.get(m[1]) || 0) + 1)
    })
    recv.on('console', (m) => { if (m.type() === 'error') res.console_errors.push(m.text().slice(0, 160)) })
    await recv.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    await sleep(3000)
    const recvCode = ((await recv.innerText('body')).match(/(?:雁书|雁)\s*([0-9A-HJKMNP-TV-Z]{4})/) || [])[1]
    if (!recvCode) throw new Error('接收端没读出接收码')

    ctxS = await chromium.launchPersistentContext(join(profileRoot, 'send'), launchOpts)
    const send = ctxS.pages()[0] || (await ctxS.newPage())
    await send.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    await sleep(2500)
    await send.fill('#peer', recvCode)
    await send.getByRole('button', { name: '查询接收方' }).click()
    await sleep(1200)
    await send.setInputFiles('input[type=file]', src)
    const sendBtn = send.locator('button.primary.block.lg:not([disabled])').filter({ hasText: '发送文件' }).first()
    await sendBtn.waitFor({ state: 'visible', timeout: 60000 })
    await sendBtn.click()
    say(`[${tag}] 已发送，等发送端完成`)
    await send.waitForFunction(() => /已发送|等待对方接收/.test(document.body.innerText), null, { timeout: 10 * 60 * 1000 })
    say(`[${tag}] 发送端完成`)

    // 接收端：不点刷新就先等 12s（顺带验自动刷新），再点刷新兜底
    const dlBtn = recv.locator('button[aria-label="下载并解密"], button:has-text("下载并解密")').first()
    let auto = false
    try { await dlBtn.waitFor({ state: 'visible', timeout: 12000 }); auto = true } catch {}
    res.auto_refresh = auto
    if (!auto) {
      try { await recv.locator('button[aria-label="刷新"], button:has-text("刷新")').first().click({ timeout: 8000 }) }
      catch { await recv.reload({ waitUntil: 'domcontentloaded' }) }
      await dlBtn.waitFor({ state: 'visible', timeout: 60000 })
    }
    const opfsList = async () => {
      try {
        return await recv.evaluate(async () => {
          const out = []
          try {
            const root = await navigator.storage.getDirectory()
            for await (const [name] of root.entries()) out.push(name)
          } catch (e) { return { err: String(e).slice(0, 120) } }
          return out
        })
      } catch (e) { return { err: String(e).slice(0, 120) } }
    }
    res.opfs_before = await opfsList()
    res.ack_sent = 0
    const before = new Set(readdirSync(targetDir))
    await dlBtn.click()
    say(`[${tag}] 已点下载并解密`)

    // 观察 waitS 秒：等「已保存至本机」/ 错误文案 / 文件出现
    const deadline = Date.now() + waitS * 1000
    let body = ''
    while (Date.now() < deadline) {
      await sleep(2000)
      try { body = await recv.innerText('body') } catch { continue }
      res.files = newFileIn(dlDir, before)
      if (/已保存至本机/.test(body)) { res.ui_says_saved = true; break }
      if (/(本机存储不足|保存失败|落盘失败|存储不足|下载失败|请求失败)/.test(body)) { break }
    }
    if (!res.ui_says_saved) { try { body = await recv.innerText('body') } catch {} }
    const m = body.match(/(本机存储不足[^\n]{0,40}|保存失败[^\n]{0,40}|落盘失败[^\n]{0,40}|存储不足[^\n]{0,40}|请求失败[^\n]{0,40})/)
    if (m) res.error_text = m[1]
    res.files = newFileIn(targetDir, before)
    res.opfs_after = await opfsList()
    res.ack_sent = ackSent
    res.body_tail = body.replace(/\s+/g, ' ').slice(-200)

    // 终态：ack 之后服务端应把传输置为终态（DELETED）；这条是「密文已删」的直接证据
    if (ids.size) {
      const id = [...ids.entries()].sort((a, b) => b[1] - a[1])[0][0]
      res.transfer_id = id
      try {
        const r = await fetch(`${url.replace(/\/$/, '')}/v1/transfers/${id}`)
        const j = await r.json().catch(() => ({}))
        res.transfer_state_after = j.state || j.status || null
        res.transfer_http = r.status
        res.transfer_after_raw = JSON.stringify(j).slice(0, 300)
      } catch (e) { res.transfer_state_after = 'QUERY_FAILED'; res.transfer_after_raw = String(e).slice(0, 120) }
    }
  } finally {
    try { await ctxR?.close() } catch {}
    try { await ctxS?.close() } catch {}
    try { rmSync(profileRoot, { recursive: true, force: true }) } catch {}
  }
  return res
}

const verdicts = []
// ---------- 场景 A：出厂 sink，必须「说保存了就有文件」 ----------
const a = await runOnce({ tag: 'A-no-inject', failSink: false })
a.verdict = a.ui_says_saved && a.files.length > 0 ? 'PASS(真保存)'
  : a.ui_says_saved && a.files.length === 0 ? 'FAIL(假绿：报成功但磁盘无文件)'
  : a.error_text ? (a.ack_sent > 0 ? 'FAIL(报错了却仍 ack，密文已删)' : 'PASS(失败可见且未 ack)')
  : 'FAIL(无结论：既没成功也没报错)'
verdicts.push(a)
say(`场景A：ui_says_saved=${a.ui_says_saved} files=${a.files.length} error=${JSON.stringify(a.error_text)} → ${a.verdict}`)

// ---------- 场景 B：写盘必失败，必须报错、不许报成功 ----------
const b = await runOnce({ tag: 'B-inject-fail', failSink: true })
b.verdict = (!b.ui_says_saved && b.error_text && b.ack_sent === 0) ? 'PASS(失败可见且未 ack)'
  : b.ui_says_saved ? 'FAIL(假绿：写盘注入失败仍报成功)'
  : b.ack_sent > 0 ? `FAIL(报错前已 ack ${b.ack_sent} 次，密文已删)`
  : 'FAIL(静默失败：没有可见错误)'
verdicts.push(b)
say(`场景B：ui_says_saved=${b.ui_says_saved} error=${JSON.stringify(b.error_text)} → ${b.verdict}`)

// ---------- 场景 C：下载目录不可写（click 被接受但写不进去）→ 必须保留 OPFS 副本 + 不报成功 ----------
const roDir = arg('--ro-dir', '')
let c = null
if (roDir) {
  c = await runOnce({ tag: 'C-blocked-download', failSink: false, roDir })
  const opfsKept = Array.isArray(c.opfs_after) && c.opfs_after.length > 0
  c.opfs_kept = opfsKept
  c.verdict = c.ui_says_saved ? 'FAIL(假绿：下载被拦仍报成功)'
    : c.ack_sent > 0 ? `FAIL(下载被拦却已 ack ${c.ack_sent} 次，密文已删)`
    : opfsKept ? 'PASS(未报成功、未 ack、OPFS 副本保留可重下)'
    : 'FAIL(未报成功但副本被删，无法重下)'
  verdicts.push(c)
  say(`场景C：ui_says_saved=${c.ui_says_saved} ack_sent=${c.ack_sent} files=${c.files.length} opfs_after=${JSON.stringify(c.opfs_after).slice(0, 120)} → ${c.verdict}`)
}

const ok = verdicts.every((v) => v.verdict.startsWith('PASS'))
writeFileSync(join(ev, 'negative-save.json'),
  JSON.stringify({ ok, elapsed_s: (Date.now() - t0) / 1000, src, verdicts, log }, null, 2))
console.log(`\n判定：${ok ? 'PASS —— 真保存会落盘、失败会报错' : 'FAIL —— 存在假绿/静默失败'}`)
process.exit(ok ? 0 : 1)
