#!/usr/bin/env node
/**
 * 侦察脚本：把页面上的可见文案、输入框、按钮、隐藏 file input 全 dump 出来。
 * 目的是让 browser-transfer.mjs 的落点选择器基于**真实 DOM**，不靠猜。
 *
 * 用法：node recon.mjs --url http://127.0.0.1:18080/ [--screenshot x.png]
 */
import { chromium } from 'playwright-core'
import { writeFileSync } from 'node:fs'

const arg = (k, d = '') => {
  const i = process.argv.indexOf(k)
  return i > 0 ? process.argv[i + 1] : d
}
const url = arg('--url', 'http://127.0.0.1:18080/')
const shot = arg('--screenshot', '')
const exe = arg('--executable', process.env.CHROMIUM_BIN || '/usr/bin/chromium')

const b = await chromium.launch({ executablePath: exe, headless: true, args: ['--no-sandbox'] })
const p = await b.newPage()
await p.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
await p.waitForTimeout(2500)

const dump = await p.evaluate(() => {
  const t = (s) => (s || '').replace(/\s+/g, ' ').trim()
  const inputs = [...document.querySelectorAll('input,textarea')].map((e) => ({
    tag: e.tagName, type: e.type || '', id: e.id || '', name: e.name || '',
    placeholder: e.placeholder || '', label: t(e.closest('label')?.textContent || ''),
    visible: !!(e.offsetWidth || e.offsetHeight)
  }))
  const buttons = [...document.querySelectorAll('button,[role=button],a')].map((e) => ({
    tag: e.tagName, text: t(e.textContent).slice(0, 40), id: e.id || '',
    cls: (e.className || '').toString().slice(0, 60), disabled: !!e.disabled
  }))
  return {
    title: document.title,
    bodyText: t(document.body.innerText).slice(0, 3000),
    inputs, buttons,
    hasWasm: !!document.querySelector('script[src*="wasm"],link[href*="wasm"]')
  }
})
writeFileSync(arg('--out', '/tmp/recon.json'), JSON.stringify(dump, null, 2))
console.log('title:', dump.title)
console.log('--- body text ---')
console.log(dump.bodyText)
console.log('--- inputs ---')
for (const i of dump.inputs) console.log(JSON.stringify(i))
console.log('--- buttons ---')
for (const x of dump.buttons) console.log(JSON.stringify(x))
if (shot) { await p.screenshot({ path: shot, fullPage: true }); console.log('shot:', shot) }
await b.close()
