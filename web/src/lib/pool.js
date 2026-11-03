/**
 * 有界并发的任务池（上传/下载共用）。
 *
 * 只用最朴素的 "N 个 worker 抢一个队列"，不引第三方库；失败即中断其余 worker（AbortSignal 由调用方管）。
 */
export async function runPool(items, worker, { concurrency = 3, signal, onDone } = {}) {
  const queue = [...items]
  let failed = null
  let index = 0

  async function runOne() {
    for (;;) {
      if (failed) return
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      const i = index++
      if (i >= queue.length) return
      const item = queue[i]
      const result = await worker(item)
      onDone?.(item, result, i)
    }
  }

  const workers = []
  for (let i = 0; i < Math.min(concurrency, queue.length); i++) {
    workers.push(
      runOne().catch((err) => {
        if (!failed) failed = err
        throw err
      }),
    )
  }
  const settled = await Promise.allSettled(workers)
  const rejected = settled.find((s) => s.status === 'rejected')
  if (rejected) throw failed || rejected.reason
}
