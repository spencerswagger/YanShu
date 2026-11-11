/**
 * 列表自动刷新（接收端「不自动刷新」的修复）。
 *
 * 规则：
 * - 可见时每 `intervalMs` 拉一次；页面在后台就拉稀（`hiddenMs`），回来立刻补一次（`kick`）；
 * - 同一时刻只有一个请求在飞（`inFlight`），慢请求不会叠成一堆；
 * - 任务抛错不打断轮询（错误由任务自己显示），轮询本身不许把异常往上抛；
 * - 定时器与「是否隐藏」「现在几点」都可注入，便于单测（不依赖真 document / 真时钟）。
 */
export function createPoller({
  task,
  intervalMs = 8000,
  hiddenMs = 30000,
  isHidden = () => Boolean(globalThis.document?.hidden),
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (t) => clearTimeout(t),
  now = () => Date.now(),
  onRun = null,
} = {}) {
  let timer = null
  let stopped = true
  let inFlight = false
  let lastAt = 0

  async function run() {
    if (stopped) return
    if (inFlight) return schedule()
    inFlight = true
    try {
      await task()
      lastAt = now()
      onRun?.(lastAt)
    } catch {
      /* 任务自己负责报错；轮询只保证下一次还会来 */
    } finally {
      inFlight = false
    }
    schedule()
  }

  function schedule() {
    if (stopped) return
    if (timer) clearTimer(timer)
    timer = setTimer(run, isHidden() ? hiddenMs : intervalMs)
  }

  return {
    start() {
      if (!stopped) return
      stopped = false
      run()
    },
    stop() {
      stopped = true
      if (timer) clearTimer(timer)
      timer = null
    },
    /** 立刻补一次（visibilitychange / focus / 发送完成后） */
    kick() {
      if (stopped) return
      if (timer) clearTimer(timer)
      timer = null
      run()
    },
    get lastAt() {
      return lastAt
    },
    get inFlight() {
      return inFlight
    },
  }
}
