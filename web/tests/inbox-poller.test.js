/**
 * 接收端「不自动刷新」（v0.2.4 现场：16 MB / 1 GiB 都要手点刷新才看得到待收项）。
 * 轮询器必须：立刻拉一次 → 按间隔轮转 → 后台拉稀 → 回来 kick 立刻补 → 不叠加请求。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createPoller } from '../src/lib/poller.js'

function timers() {
  const q = []
  return {
    q,
    setTimer: (fn, ms) => {
      const t = { fn, ms, cancelled: false }
      q.push(t)
      return t
    },
    clearTimer: (t) => {
      if (t) t.cancelled = true
    },
    /** 跑当前待执行的那个定时器 */
    async fire() {
      const t = q.shift()
      if (!t) throw new Error('没有待执行的定时器')
      if (!t.cancelled) await t.fn()
      return t
    },
  }
}

test('启动即拉一次，之后按间隔轮询', async () => {
  const t = timers()
  let runs = 0
  const poller = createPoller({ task: async () => void runs++, intervalMs: 5000, setTimer: t.setTimer, clearTimer: t.clearTimer })
  poller.start()
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 1, '首屏必须自己拉一次（不能等用户点刷新）')
  assert.equal(t.q.length, 1)
  assert.equal(t.q[0].ms, 5000)
  await t.fire()
  assert.equal(runs, 2)
})

test('页面在后台就拉稀（30s），回到前台 kick 立刻补一次', async () => {
  const t = timers()
  let hidden = false
  let runs = 0
  const poller = createPoller({
    task: async () => void runs++,
    intervalMs: 8000,
    hiddenMs: 30000,
    isHidden: () => hidden,
    setTimer: t.setTimer,
    clearTimer: t.clearTimer,
  })
  poller.start()
  await new Promise((r) => setImmediate(r))
  hidden = true
  await t.fire()
  assert.equal(t.q[0].ms, 30000, '后台必须降频，别空烧电')
  hidden = false
  poller.kick()
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 3, '切回页面立刻补一次')
})

test('上一个请求还在飞时，不叠加第二个', async () => {
  const t = timers()
  let started = 0
  let release
  const poller = createPoller({
    task: () => {
      started += 1
      return new Promise((r) => {
        release = r
      })
    },
    intervalMs: 1000,
    setTimer: t.setTimer,
    clearTimer: t.clearTimer,
  })
  poller.start()
  await new Promise((r) => setImmediate(r))
  assert.equal(started, 1)
  poller.kick()
  await new Promise((r) => setImmediate(r))
  assert.equal(started, 1, 'in-flight 未完成时必须直接跳过这一轮')
  release()
})

test('任务抛错不能打断轮询，也不能把异常抛给调用方', async () => {
  const t = timers()
  let runs = 0
  const poller = createPoller({
    task: async () => {
      runs += 1
      throw new Error('boom')
    },
    intervalMs: 1000,
    setTimer: t.setTimer,
    clearTimer: t.clearTimer,
  })
  poller.start()
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 1)
  await t.fire()
  assert.equal(runs, 2, '错误由任务自己显示，轮询要接着来')
})

test('stop 之后不再触发', async () => {
  const t = timers()
  let runs = 0
  const poller = createPoller({ task: async () => void runs++, intervalMs: 1000, setTimer: t.setTimer, clearTimer: t.clearTimer })
  poller.start()
  await new Promise((r) => setImmediate(r))
  poller.stop()
  assert.equal(t.q.every((x) => x.cancelled), true)
  assert.equal(runs, 1)
})
