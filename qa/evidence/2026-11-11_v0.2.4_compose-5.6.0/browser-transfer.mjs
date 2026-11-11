#!/usr/bin/env node
/**
 * 雁书 · 双浏览器真收发（两端各一个独立浏览器实例）
 *
 * 口径：
 *   * **两个独立浏览器实例**（不同 --user-data-dir，等价「两端各一」），不是同一浏览器的两个标签
 *   * 发送端选真文件、点发送；接收端点「下载并解密」，落到磁盘
 *   * 本脚本只负责「传」；算 sha256、判 PASS/FAIL 由 verify-sha256.sh 做（分开才好复验）
 *
 * 用法：
 *   node browser-transfer.mjs --url http://127.0.0.1:18080/ --src /data/ys-fixtures/src.bin \
 *        --out /data/ys-fixtures/landed.bin --evidence <证据目录> [--gib 1] [--executable /usr/bin/chromium]
 *
 * 退出码：0 传完 / 1 任一步失败（含超时）/ 2 用法或环境错误
 */
import { chromium } from 'playwright-core'
import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const arg = (k, d = '') => {
  const i = process.argv.indexOf(k)
  return i > 0 ? process.argv[i + 1] : d
}
const url = arg('--url', 'http://127.0.0.1:18080/')
const src = arg('--src')
const out = arg('--out')
const ev = arg('--evidence', '.')
const gib = Number(arg('--gib', '1'))
const exe = arg('--executable', process.env.CHROMIUM_BIN || '/usr/bin/chromium')
const dlDir = arg('--dl-dir', join(ev, 'downloads'))
if (!src || !out) { console.error('用法：--src <源文件> --out <落地文件>'); process.exit(2) }

mkdirSync(ev, { recursive: true })
mkdirSync(dlDir, { recursive: true })
const t0 = Date.now()
const log = []
const say = (s) => {
  const line = `[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`
  log.push(line); console.log(line)
}
const fail = async (why) => {
  say(`FAIL: ${why}`)
  writeFileSync(join(ev, 'browser-transfer.json'),
    JSON.stringify({ ok: false, why, elapsed_s: (Date.now() - t0) / 1000, log }, null, 2))
  process.exit(1)
}

const expectBytes = Math.round(gib * 1024 * 1024 * 1024)
try {
  const st = statSync(src)
  if (st.size < expectBytes) { console.error(`源文件 ${st.size} B < 要求的 ${expectBytes} B`); process.exit(2) }
} catch { console.error(`源文件不存在：${src}`); process.exit(2) }

const launchOpts = {
  executablePath: exe,
  headless: true,
  downloadsPath: dlDir,
  args: ['--no-sandbox', '--disable-dev-shm-usage']
}

// 两端各自一个独立 profile 目录（=两个浏览器，不是两个标签页）
const profileRoot = join(tmpdir(), `ys-profiles-${Date.now()}`)
mkdirSync(profileRoot, { recursive: true })

let ctxA, ctxB
let ok = false
try {
  // ---------- 接收端先起来：它要在服务器登记自己的码 ----------
  ctxA = await chromium.launchPersistentContext(join(profileRoot, 'recv'), launchOpts)
  const recv = ctxA.pages()[0] || (await ctxA.newPage())
  // 显式打开下载落地（persistent context 上 Playwright 的 downloadsPath 有时不生效，
  // headless 下下载会被**静默丢弃** —— 表现为页面说「已保存至本机」但磁盘上什么都没有）
  try {
    const cdp = await ctxA.newCDPSession(recv)
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dlDir, eventsEnabled: true })
    cdp.on('Browser.downloadProgress', (e) => { if (e.state === 'completed') say(`CDP 下载完成 ${e.receivedBytes} B`) })
    say(`下载落地目录 ${dlDir}（CDP setDownloadBehavior=allow）`)
  } catch (e) { say(`CDP setDownloadBehavior 失败：${String(e).slice(0, 120)}`) }
  await recv.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
  await recv.waitForTimeout(3000)
  const recvText = await recv.innerText('body')
  const recvCode = (recvText.match(/(?:雁书|雁)\s*([0-9A-HJKMNP-TV-Z]{4})/) || [])[1]
  if (!recvCode) await fail(`接收端没读出自己的接收码（页面首屏：${recvText.slice(0, 120).replace(/\s+/g, ' ')}）`)
  say(`接收端已就绪，码 ${recvCode}`)

  // ---------- 发送端 ----------
  ctxB = await chromium.launchPersistentContext(join(profileRoot, 'send'), launchOpts)
  const send = ctxB.pages()[0] || (await ctxB.newPage())
  await send.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
  await send.waitForTimeout(3000)
  const sendText = await send.innerText('body')
  const sendCode = (sendText.match(/(?:雁书|雁)\s*([0-9A-HJKMNP-TV-Z]{4})/) || [])[1]
  say(`发送端已就绪，码 ${sendCode ?? '(未识别)'}`)
  if (sendCode === recvCode) await fail('两端读到的码相同（不是两个独立浏览器）')

  await send.fill('#peer', recvCode)
  say(`填入对方码 ${recvCode}`)
  await send.getByRole('button', { name: '查询接收方' }).click()
  await send.waitForTimeout(1200)

  // 注意：页面上有两个 class 含 primary 的「发送文件」，其中一个是隐藏引导区的禁用桩；
  // 真正的那个在**选完文件之后**才可用 → 选文件，再取「未禁用」的那个。
  await send.setInputFiles('input[type=file]', src)
  say(`已选文件 ${src}（${(expectBytes / 1024 ** 3).toFixed(2)} GiB）`)
  const sendBtn = send.locator('button.primary.block.lg:not([disabled])')
    .filter({ hasText: '发送文件' }).first()
  await sendBtn.waitFor({ state: 'visible', timeout: 60000 })
  await sendBtn.scrollIntoViewIfNeeded()
  await sendBtn.click()
  say('已点发送，等加密+上传完成')

  await send.waitForFunction(
    () => /已发送|等待对方接收/.test(document.body.innerText),
    null, { timeout: 30 * 60 * 1000 })
  say('发送端显示已发送')

  // ---------- 接收端收 ----------
  const dlBtn = recv.locator('button[aria-label="下载并解密"], button:has-text("下载并解密")').first()

  // 观察项：v0.2.4 接收端**不会自动**把新到的文件刷进列表（首屏只拉一次）。
  // 先给 30s 自动出现的机会；没出现就点页面上的「刷新」按钮（真人也是这么点），并把这件事记进证据。
  let autoAppeared = false
  try { await dlBtn.waitFor({ state: 'visible', timeout: 30000 }); autoAppeared = true } catch {}
  if (!autoAppeared) {
    say('30s 内列表未自动出现新文件 → 点「刷新」（记为产品观察项：接收端不自动刷新）')
    try {
      await recv.locator('button[aria-label="刷新"], button:has-text("刷新")').first().click({ timeout: 10000 })
    } catch { await recv.reload({ waitUntil: 'domcontentloaded' }) }
  }
  await dlBtn.waitFor({ state: 'visible', timeout: 60 * 60 * 1000 })
  say(`接收端出现待接收项（自动出现=${autoAppeared}），点「下载并解密」`)

  // 落盘有两条路：① 触发 Playwright download 事件（saveAs 到指定路径）；
  // ② 浏览器自己写 downloadsPath（默认 $HOME/Downloads，目录不存在时**静默失败**）。
  // 两条都盯：先挂事件，同时轮询 dlDir 里新出现的、大小等于源文件的那个。
  const before = new Set(readdirSync(dlDir).map(String))
  const dlPromise = recv.waitForEvent('download', { timeout: 5 * 60 * 1000 }).catch(() => null)
  await dlBtn.click()

  let download = await dlPromise
  if (download) {
    await download.saveAs(out)
    say(`download 事件 → saveAs ${out}`)
  } else {
    say('没收到 download 事件，改盯 downloadsPath 目录')
    const deadline = Date.now() + 40 * 60 * 1000
    let last = -1
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2000))
      const fresh = readdirSync(dlDir).filter((f) => !before.has(f))
        .map((f) => join(dlDir, f))
        .filter((f) => { try { return statSync(f).isFile() } catch { return false } })
      if (!fresh.length) continue
      const f = fresh.map((p) => [p, statSync(p).size]).sort((x, y) => y[1] - x[1])[0]
      if (f[1] === expectBytes && f[1] === last) { copyFileSync(f[0], out); say(`轮询到 ${f[0]} → ${out}`); break }
      last = f[1]
    }
    if (!existsSync(out)) await fail(`下载没落到磁盘（${dlDir} 里没有 ${expectBytes} B 的新文件）`)
  }
  const got = statSync(out).size
  if (got !== expectBytes) await fail(`落地 ${got} B ≠ 源 ${expectBytes} B`)

  ok = true
  writeFileSync(join(ev, 'browser-transfer.json'), JSON.stringify({
    ok, src, out, recv_code: recvCode, send_code: sendCode ?? null, inbox_auto_appeared: autoAppeared,
    bytes: got, elapsed_s: (Date.now() - t0) / 1000, chromium: exe, log
  }, null, 2))
  say('传输完成（sha256 结论由 verify-sha256.sh 给）')
  process.exit(0)
} catch (e) {
  await fail(String(e && e.message ? e.message : e).slice(0, 400))
} finally {
  if (!ok) { try { rmSync(profileRoot, { recursive: true, force: true }) } catch {} }
  try { await ctxA?.close() } catch {}
  try { await ctxB?.close() } catch {}
}
