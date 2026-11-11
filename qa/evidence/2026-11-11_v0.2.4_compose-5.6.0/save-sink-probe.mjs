#!/usr/bin/env node
/**
 * 落盘路径探针（v0.2.4 口径 2 的最后一层：**数据到底有没有写到磁盘**）。
 *
 * 为什么需要它：headless Chromium 没有 `showSaveFilePicker`（实测 `typeof === 'undefined'`），
 * 于是 `defaultSinkFactory` 退回内存 sink；而 `receiveStreaming` 把 `sink.close()` 的返回值
 * **丢掉**（web/src/net/download.js:139），只把 `{name,size}` 返回给 UI → 界面说
 * 「已保存至本机」，磁盘上什么都没有。**这是产品缺陷，不是浏览器下载策略问题。**
 *
 * 本脚本不改产品代码，只在页面里装一个 `showSaveFilePicker` 的**测试替身**：
 * 它把每块写入 POST 给本进程的 HTTP 服务，由 Node 顺序追加到真实文件 →
 * 这样 1 GiB 密文/解密链路、块顺序、完整性校验全部走产品的真实代码，
 * 唯一被替换的是「浏览器把字节写进文件」这一步（产品要修的就是这一步）。
 *
 * 用法：
 *   node save-sink-probe.mjs --url http://127.0.0.1:18080/ --src <1GiB 源> \
 *     --out /data/out.bin --evidence <目录> [--gib 1] [--host 127.0.0.1] [--port 19090]
 * 退出码：0 成功且两侧 sha256 相同；1 失败；2 用法错误。
 */
import { chromium } from 'playwright-core'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { createWriteStream, existsSync, mkdirSync, statSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const arg = (k, d = '') => {
  const i = process.argv.indexOf(k)
  return i > 0 ? process.argv[i + 1] : d
}
const url = arg('--url', 'http://127.0.0.1:18080/')
const src = arg('--src')
const out = arg('--out')
const ev = arg('--evidence', 'results')
const gib = Number(arg('--gib', '1'))
const host = arg('--host', '127.0.0.1')
const port = Number(arg('--port', '19090'))
const exe = arg('--executable', process.env.CHROMIUM_BIN || '/usr/bin/chromium')
if (!src || !out) { console.error('用法：--src <源文件> --out <落地文件>'); process.exit(2) }

mkdirSync(ev, { recursive: true })
const t0 = Date.now()
const log = []
const say = (s) => { const l = `[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`; log.push(l); console.log(l) }
const fail = async (why) => {
  say(`FAIL: ${why}`)
  writeFileSync(join(ev, 'save-sink-probe.json'),
    JSON.stringify({ ok: false, why, elapsed_s: (Date.now() - t0) / 1000, log }, null, 2))
  process.exit(1)
}

const expectBytes = Math.round(gib * 1024 * 1024 * 1024)
try { if (statSync(src).size < expectBytes) { console.error('源文件小于要求'); process.exit(2) } }
catch { console.error(`源文件不存在：${src}`); process.exit(2) }

// ---------- 落地端：把页面写来的块按顺序追加到 out ----------
const fd = createWriteStream(out)
let written = 0
let writes = 0
const server = createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return }
  const parts = []
  req.on('data', (c) => parts.push(c))
  req.on('end', () => {
    const buf = Buffer.concat(parts)
    if (req.url.startsWith('/w')) {
      written += buf.length
      writes += 1
      fd.write(buf)
      res.writeHead(200).end()
    } else if (req.url.startsWith('/close')) {
      fd.end(() => { res.writeHead(200).end() })
    } else { res.writeHead(404).end() }
  })
})
await new Promise((r) => server.listen(port, host, r))
say(`落地服务 ${host}:${port} → ${out}`)

// ---------- 页面里装 showSaveFilePicker 的测试替身 ----------
const sinkStub = () => {
  window.showSaveFilePicker = async (opts) => {
    const name = (opts && opts.suggestedName) || 'out.bin'
    return {
      name,
      kind: 'file',
      async createWritable() {
        return {
          async write(data) {
            const u8 = data instanceof Uint8Array ? data : new Uint8Array(data)
            await fetch(`http://${window.__ysSinkHost}/w`, { method: 'POST', body: u8 })
          },
          async close() { await fetch(`http://${window.__ysSinkHost}/close`, { method: 'POST', body: '' }) },
          async abort() {},
        }
      },
    }
  }
}

const profileRoot = join(tmpdir(), `ys-sink-${Date.now()}`)
mkdirSync(profileRoot, { recursive: true })
let ctxA, ctxB
try {
  ctxA = await chromium.launchPersistentContext(join(profileRoot, 'recv'), {
    executablePath: exe, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'],
  })
  await ctxA.addInitScript(`window.__ysSinkHost = ${JSON.stringify(`${host}:${port}`)}`)
  await ctxA.addInitScript(sinkStub)
  const recv = ctxA.pages()[0] || (await ctxA.newPage())
  recv.on('console', (m) => { if (m.type() === 'error') say(`RECV-CONSOLE(error) ${m.text().slice(0, 160)}`) })
  recv.on('pageerror', (e) => say(`RECV-PAGEERROR ${String(e && e.message || e).slice(0, 160)}`))
  await recv.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
  await recv.waitForTimeout(3000)
  const recvText = await recv.innerText('body')
  const recvCode = (recvText.match(/(?:雁书|雁)\s*([0-9A-HJKMNP-TV-Z]{4})/) || [])[1]
  if (!recvCode) await fail(`接收端没读出码：${recvText.slice(0, 120).replace(/\s+/g, ' ')}`)
  const pickerType = await recv.evaluate(() => typeof window.showSaveFilePicker)
  say(`接收端已就绪，码 ${recvCode}（showSaveFilePicker=${pickerType}）`)

  ctxB = await chromium.launchPersistentContext(join(profileRoot, 'send'), {
    executablePath: exe, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'],
  })
  const send = ctxB.pages()[0] || (await ctxB.newPage())
  await send.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
  await send.waitForTimeout(3000)
  const sendCode = ((await send.innerText('body')).match(/(?:雁书|雁)\s*([0-9A-HJKMNP-TV-Z]{4})/) || [])[1]
  if (!sendCode || sendCode === recvCode) await fail('两端码相同或没读到（不是两个独立浏览器）')
  say(`发送端已就绪，码 ${sendCode}`)

  await send.fill('#peer', recvCode)
  await send.getByRole('button', { name: '查询接收方' }).click()
  await send.waitForTimeout(1200)
  await send.setInputFiles('input[type=file]', src)
  say(`已选文件 ${src}（${(expectBytes / 1024 ** 3).toFixed(2)} GiB）`)
  const sendBtn = send.locator('button.primary.block.lg:not([disabled])').filter({ hasText: '发送文件' }).first()
  await sendBtn.waitFor({ state: 'visible', timeout: 60000 })
  await sendBtn.scrollIntoViewIfNeeded()
  await sendBtn.click()
  await send.waitForFunction(() => /已发送|等待对方接收/.test(document.body.innerText), null,
    { timeout: 30 * 60 * 1000 })
  say('发送端显示已发送')

  const dlBtn = recv.locator('button[aria-label="下载并解密"], button:has-text("下载并解密")').first()
  let autoAppeared = false
  try { await dlBtn.waitFor({ state: 'visible', timeout: 30000 }); autoAppeared = true } catch {}
  if (!autoAppeared) {
    say('30s 内列表未自动出现 → 点「刷新」（产品观察项：接收端不自动刷新）')
    try { await recv.locator('button[aria-label="刷新"], button:has-text("刷新")').first().click({ timeout: 10000 }) }
    catch { await recv.reload({ waitUntil: 'domcontentloaded' }) }
  }
  await dlBtn.waitFor({ state: 'visible', timeout: 60 * 60 * 1000 })
  say(`接收端出现待接收项（自动出现=${autoAppeared}），点「下载并解密」`)

  const tick = setInterval(async () => {
    try {
      const t = (await recv.innerText('body')).replace(/\s+/g, ' ')
      say(`RECV-PROGRESS …${t.slice(-110)}`)
    } catch {}
  }, 15000)
  await dlBtn.click()

  // 成功判据用**产品的 UI 文案**，不是我们自己的下载事件：
  // 如果产品说「已保存至本机」，那磁盘上就必须有对应文件（这就是本轮要证明/证伪的）
  let done = false
  const deadline = Date.now() + 45 * 60 * 1000
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 3000))
    const t = await recv.innerText('body').catch(() => '')
    if (/已保存至本机/.test(t)) { done = true; say(`UI 声称已保存：${(t.match(/已保存至本机[^\n]{0,60}/) || [''])[0]}`); break }
    if (/失败|错误|超时/.test(t) && /下载|接收/.test(t)) { say(`UI 出现错误文案：${t.replace(/\s+/g, ' ').slice(-140)}`); break }
    if (written >= expectBytes) { say(`落地字节已达 ${written}`); break }
  }
  clearInterval(tick)
  if (!done && written < expectBytes) say('UI 未出现「已保存至本机」且字节未到齐（继续等 2 分钟收尾）')
  await new Promise((r) => setTimeout(r, 5000))

  const got = existsSync(out) ? statSync(out).size : 0
  const srcSha = createHash('sha256')
  const srcStream = (await import('node:fs')).createReadStream(src)
  for await (const c of srcStream) srcSha.update(c)
  const outSha = createHash('sha256')
  const outStream = (await import('node:fs')).createReadStream(out)
  for await (const c of outStream) outSha.update(c)
  const a = srcSha.digest('hex')
  const b = outSha.digest('hex')
  say(`src sha256=${a}`)
  say(`out sha256=${b}（${got} B，${writes} 次写入）`)
  if (got !== expectBytes) await fail(`落地 ${got} B ≠ ${expectBytes} B`)
  if (a !== b) await fail('两侧 sha256 不同（内容被改/块序错）')

  writeFileSync(join(ev, 'save-sink-probe.json'), JSON.stringify({
    ok: true, src, out, recv_code: recvCode, send_code: sendCode, inbox_auto_appeared: autoAppeared,
    bytes: got, writes, src_sha256: a, out_sha256: b,
    elapsed_s: (Date.now() - t0) / 1000, chromium: exe, log,
  }, null, 2))
  say('PASS：产品解密链路完整，落盘（用测试替身接住的）两侧 sha256 逐字相同')
  process.exit(0)
} catch (e) {
  await fail(String(e && e.message ? e.message : e).slice(0, 400))
} finally {
  try { await ctxA?.close() } catch {}
  try { await ctxB?.close() } catch {}
  try { server.close() } catch {}
  try { rmSync(profileRoot, { recursive: true, force: true }) } catch {}
}
