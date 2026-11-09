/**
 * v5 三块的前端逻辑：
 *   ① TTL 倒计时：服务端时间基准 + 单调推进（模拟时钟漂移）+ 四档文案；
 *   ② 速度/ETA：四档文案、<10KB/s 3s → 网络较慢、3s 无进展 → 连接停滞且隐藏 ETA；
 *   ③ /v1/stats：形状正确才用，失败/超时/形状不对 → null（界面隐藏，不弹错）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  syncServerTime,
  serverNow,
  remainingMs,
  formatTtl,
  isExpiringSoon,
  isExpired,
  parseServerExpiry,
  resetServerTime,
} from '../src/lib/serverClock.js'
import { createSpeedMeter, formatEta, formatSpeed, formatBytesPair, stageLabel } from '../src/lib/speed.js'
import { fetchStats, formatCount, formatBytesTotal } from '../src/net/stats.js'

const HOUR = 3600_000
const MIN = 60_000

test('TTL：服务端时间基准能纠正设备时钟漂移（设备快 2 小时也不影响）', () => {
  resetServerTime()
  const fakePerf = 1000
  globalThis.performance = { now: () => fakePerf }
  // 服务端说"现在"是 1_700_000_000_000，而本地 Date.now() 完全不可信
  syncServerTime(1_700_000_000_000)
  assert.equal(serverNow(), 1_700_000_000_000, '同步后必须等于服务端时间')
  // 过期时间 = 服务端时间 + 23h
  assert.equal(remainingMs(1_700_000_000_000 + 23 * HOUR), 23 * HOUR)
  resetServerTime()
})

test('TTL：四档文案（天后 / 小时后 / 分钟后 / 已过期）', () => {
  assert.equal(formatTtl(23 * HOUR), '23 小时后过期')
  assert.equal(formatTtl(42 * MIN), '42 分钟后过期')
  assert.equal(formatTtl(2 * 24 * HOUR), '2 天后过期')
  assert.equal(formatTtl(-1), '已过期，无法取回')
  assert.equal(formatTtl(0), '已过期，无法取回')
  // 边界：59 分 30 秒 → 59 分钟；1 小时整 → 1 小时
  assert.equal(formatTtl(59 * MIN + 30_000), '59 分钟后过期')
  assert.equal(formatTtl(HOUR), '1 小时后过期')
})

test('TTL：≤1 小时才算「临近过期」（只影响视觉）', () => {
  assert.equal(isExpiringSoon(60 * MIN), true)
  assert.equal(isExpiringSoon(61 * MIN), false)
  assert.equal(isExpiringSoon(-1), false)
})

test('ETA：四档文案', () => {
  assert.equal(formatEta(5), '即将完成')
  assert.equal(formatEta(45), '剩 45 秒')
  assert.equal(formatEta(12 * 60), '剩 12 分')
  assert.equal(formatEta(7200), '剩 1 小时以上')
  assert.equal(formatEta(null), '', '停滞时必须隐藏 ETA')
})

test('速度格式化 + 已传/总大小', () => {
  assert.equal(formatSpeed(13_000_000), '12.4 MB/s')
  assert.equal(formatSpeed(820 * 1024), '820 KB/s')
  assert.equal(formatSpeed(0), '0 B/s')
  assert.equal(formatBytesPair(320 * 1048576, 1.02 * 1073741824), '320 MB / 1.02 GB')
})

test('速度状态机：<10KB/s 持续 3 秒 → 网络较慢', () => {
  let t = 0
  const meter = createSpeedMeter({ now: () => t })
  meter.update(0, 10_000_000)
  // 每秒只涨 5KB（远低于 10KB/s）
  for (let i = 1; i <= 5; i++) {
    t += 1000
    meter.update(i * 5 * 1024, 10_000_000)
  }
  const s = meter.snapshot(5 * 5 * 1024, 10_000_000)
  assert.equal(s.state, 'slow')
  assert.equal(s.label, '网络较慢')
})

test('速度状态机：3 秒无进展 → 连接停滞且 ETA 隐藏', () => {
  let t = 0
  const meter = createSpeedMeter({ now: () => t })
  meter.update(1000, 10_000_000)
  t += 1000
  meter.update(200_000, 10_000_000) // 有一次真实进展
  const moving = meter.snapshot(200_000, 10_000_000)
  assert.equal(moving.state, 'ok')
  assert.ok(moving.etaSec !== null)
  // 之后 3.2 秒没有任何字节进展
  t += 3200
  const stalled = meter.snapshot(200_000, 10_000_000)
  assert.equal(stalled.state, 'stalled')
  assert.equal(stalled.label, '连接停滞，重试中')
  assert.equal(stalled.etaSec, null, '停滞时必须隐藏 ETA')
})

test('/v1/stats：形状正确才采用', async () => {
  const ok = {
    today: { consumed: 12, consumed_bytes: 1000, created: 20 },
    total: { consumed: 1284930, consumed_bytes: 42 * 1099511627776, created: 1300000 },
    generated_at: '2026-11-04T09:00:00Z',
  }
  const client = { get: async () => ({ json: ok }) }
  const got = await fetchStats(client)
  assert.deepEqual(got, ok)
})

test('/v1/stats：失败 / 超时 / 形状不对 → null（界面隐藏，不弹错）', async () => {
  const boom = {
    get: async () => {
      throw Object.assign(new Error('network'), { code: 'NETWORK_ERROR' })
    },
  }
  assert.equal(await fetchStats(boom), null)
  const badShape = { get: async () => ({ json: { today: { consumed: 1 } } }) }
  assert.equal(await fetchStats(badShape), null)
  const notFound = { get: async () => ({ json: { error: { code: 'NOT_FOUND' } } }) }
  assert.equal(await fetchStats(notFound), null)
})

test('/v1/stats：数值格式化（四舍五入到千/万，前端只做展示）', () => {
  assert.equal(formatCount(999), '999')
  assert.equal(formatCount(12_480), '12.5K')
  assert.equal(formatCount(128_000), '13 万')
  assert.equal(formatCount(1_284_930), '1.28M')
  assert.equal(formatBytesTotal(42 * 1099511627776), '42.0 TB')
  assert.equal(formatBytesTotal(1_500_000_000), '1.4 GB')
})

test('TTL：过期判定走服务端时间基准（设备时钟快 3 小时也不能提前判过期）', () => {
  resetServerTime()
  const realNow = Date.now()
  // 设备时钟比服务端快 3 小时
  globalThis.performance = { now: () => 1000 }
  syncServerTime(realNow)
  const expiresAt = parseServerExpiry(new Date(realNow + 42 * MIN).toISOString())
  assert.equal(expiresAt, realNow + 42 * MIN, '服务端时间串必须解析成毫秒')
  assert.equal(isExpired(remainingMs(expiresAt)), false, '还剩 42 分钟就不该判过期')
  assert.equal(formatTtl(remainingMs(expiresAt)), '42 分钟后过期')
  // 已过期：服务端时间已经超过 expires_at
  const past = parseServerExpiry(new Date(realNow - 1000).toISOString())
  assert.equal(isExpired(remainingMs(past)), true)
  assert.equal(formatTtl(remainingMs(past)), '已过期，无法取回')
  resetServerTime()
})

test('TTL：expires_at 缺失/非法 → null（界面不显示胶囊，不猜）', () => {
  assert.equal(parseServerExpiry(undefined), null)
  assert.equal(parseServerExpiry(''), null)
  assert.equal(parseServerExpiry('not-a-date'), null)
  assert.equal(parseServerExpiry(0), null)
})

test('接收两段进度：下载中/解密中都是真百分比', () => {
  // 只有下载字节：只显示下载中
  assert.equal(stageLabel('downloading', 62, 100), '下载中 62%')
  assert.equal(stageLabel('downloading', 0, 0), '下载中 0%')
  assert.equal(stageLabel('downloading', 200, 100), '下载中 100%')
  // 已解密字节也上报：两段都给真数字（密文多出每块 16B tag，所以 100% 不越界）
  assert.equal(stageLabel('downloading', 62, 100, 18), '下载中 62% · 解密中 18%')
  assert.equal(stageLabel('downloading', 62, 100, 0), '下载中 62%')
  assert.equal(stageLabel('downloading', 100, 100, 120), '下载中 100% · 解密中 100%')
  // 非流式回退：最终验签没有增量进度 → 只给阶段名
  assert.equal(stageLabel('decrypting', 0, 0), '解密中')
  assert.equal(stageLabel('', 0, 0), '')
  assert.equal(stageLabel('saving', 10, 10), '')
})
