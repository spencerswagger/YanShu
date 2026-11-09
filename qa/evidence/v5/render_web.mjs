#!/usr/bin/env node
/**
 * v5 验收 · 前端逻辑跑分器（不属于产品代码，只 import 被测模块）。
 *
 * 作用：把「后端真数字」塞进前端真实的格式化 / 状态机模块里跑一遍，
 * 避免验收只验后端、界面文案靠肉眼。三个子命令：
 *
 *   node render_web.mjs ttl   --web-dir <web> --json '[{"expiresAt":...,"now":...,"label":"23h"}]'
 *   node render_web.mjs speed --web-dir <web> --samples <samples.json>
 *   node render_web.mjs stats --web-dir <web> --json '{"today":{...},"total":{...}}'
 *
 * 输出：stdout 一行 JSON（供 python 侧断言）；失败 exit 1。
 */
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const arg = (name, def = '') => {
  const eq = process.argv.find((a) => a.startsWith(`--${name}=`))
  if (eq) return eq.split('=').slice(1).join('=')
  const i = process.argv.indexOf(`--${name}`)
  if (i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) return process.argv[i + 1]
  return def
}

const cmd = process.argv[2]
const webDir = resolve(arg('web-dir', '.'))
const load = (rel) => import(pathToFileURL(resolve(webDir, rel)).href)
const readJson = (inline) => JSON.parse(inline || readFileSync(arg('samples'), 'utf8'))

const fail = (msg) => {
  console.error(`render_web: ${msg}`)
  process.exit(1)
}

try {
  if (cmd === 'ttl') {
    const clock = await load('src/lib/serverClock.js')
    const items = JSON.parse(arg('json', '[]'))
    const out = items.map((it) => {
      const ms = clock.remainingMs(it.expiresAt, it.now)
      return {
        label: it.label || '',
        text: clock.formatTtl(ms),
        remainingMs: ms,
        soon: clock.isExpiringSoon(ms),
        expired: clock.isExpired(ms),
      }
    })
    console.log(JSON.stringify({ module: 'serverClock.js', items: out }))
  } else if (cmd === 'speed') {
    const speed = await load('src/lib/speed.js')
    const data = readJson()
    const samples = data.samples || []
    if (!samples.length) fail('no samples')
    let clock = 0
    const meter = speed.createSpeedMeter({ now: () => clock })
    const snaps = []
    for (const [bytes, ms] of samples) {
      clock = ms
      const s = meter.update(bytes, data.total)
      snaps.push({ ms, bytes, ...s, etaText: speed.formatEta(s.etaSec), speedText: speed.formatSpeed(s.speedBps) })
    }
    // 停滞：把时钟再推进 3.2s 且不喂字节
    clock += 3200
    const stalled = meter.snapshot(samples[samples.length - 1][0], data.total)
    console.log(
      JSON.stringify({
        module: 'speed.js',
        samples: snaps.length,
        first: snaps[0],
        half: snaps.find((x) => x.bytes >= data.total / 2) || snaps[snaps.length - 1],
        last: snaps[snaps.length - 1],
        stalled: { ...stalled, etaText: speed.formatEta(stalled.etaSec), label: stalled.label },
        pair: speed.formatBytesPair(samples[samples.length - 1][0], data.total),
      }),
    )
  } else if (cmd === 'stats') {
    const s = await load('src/net/stats.js')
    const json = JSON.parse(arg('json', '{}'))
    const t = json.today || {}
    const tot = json.total || {}
    console.log(
      JSON.stringify({
        module: 'net/stats.js',
        today: {
          consumed: s.formatCount(t.consumed),
          consumed_bytes: s.formatBytesTotal(t.consumed_bytes),
          created: s.formatCount(t.created),
        },
        total: {
          consumed: s.formatCount(tot.consumed),
          consumed_bytes: s.formatBytesTotal(tot.consumed_bytes),
          created: s.formatCount(tot.created),
        },
      }),
    )
  } else {
    fail('用法：render_web.mjs ttl|speed|stats --web-dir <web> …')
  }
} catch (err) {
  fail(String((err && err.stack) || err))
}
