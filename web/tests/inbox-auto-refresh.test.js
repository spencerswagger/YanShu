/**
 * 「接收侧来了新文件不自动出现」的回归（#84 里的真缺陷）。
 *
 * v0.2.4 现场：A 发完文件，B 的待收列表**不点刷新就一直不出现**。根因是列表只在
 * `watch(() => props.api)` 注入那一下拉过一次，之后**没有任何轮询或事件**在拉——
 * 发送方在另一台设备/另一个浏览器身份里，接收侧页面没有理由自己知道有新密文。
 *
 * 判据分两层：
 * 1. **接线**（本文件）：`InboxPanel.vue` 真的挂上轮询器（挂载即启动、卸载即停、切回页面立刻补一次），
 *    并且「后台刷新失败」不得把「自动更新 hh:mm:ss」刷成当前时间（假活比不刷新更坏）；
 * 2. **行为**（`inbox-poller.test.js`）：轮询器的间隔、后台降频、in-flight 去重、抛错不打断。
 *
 * 静态读源码是本仓既有做法（`node:test` 里没有 jsdom/Vue 运行时，`ui-copy` / `layout` 同此）。
 * 本文件在**未修复的 main** 上必须红——这是它的存在意义，不是"文档测试"。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createPoller } from '../src/lib/poller.js'
import { bindWakeEvents } from '../src/lib/wakeEvents.js'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const PANEL = resolve(here, '../src/components/InboxPanel.vue')
const src = readFileSync(PANEL, 'utf8')

/** 配平括号：从 `from` 起第一个 `openCh` 出发，返回与之配对的 `closeCh` 下标。 */
function balanced(source, from, openCh, closeCh, label) {
  const begin = source.indexOf(openCh, from)
  assert.notEqual(begin, -1, `${label} 后面找不到 ${openCh}`)
  let depth = 0
  for (let i = begin; i < source.length; i++) {
    if (source[i] === openCh) depth += 1
    else if (source[i] === closeCh) {
      depth -= 1
      if (depth === 0) return i
    }
  }
  throw new Error(`${label} 的 ${openCh}${closeCh} 不配对（源码被改坏了？）`)
}

/** 取 `needle` 之后第一个配平的花括号块（用于 `createPoller({ … })` 的选项对象）。 */
function sliceBraces(source, needle) {
  const start = source.indexOf(needle)
  assert.notEqual(start, -1, `源码里找不到 ${needle}`)
  const open = source.indexOf('{', start)
  assert.notEqual(open, -1, `${needle} 后面没有对象/函数体`)
  return source.slice(open, balanced(source, open, '{', '}', needle) + 1)
}

/** 取某个函数体的源码片段（先跳过参数括号，再取配平的花括号）——比"整文件 grep"更能钉住"这段逻辑在这个函数里"。 */
function sliceFunction(source, signature) {
  const start = source.indexOf(signature)
  assert.notEqual(start, -1, `源码里找不到 ${signature}`)
  const firstParen = source.indexOf('(', start)
  const firstBrace = source.indexOf('{', start)
  const afterParams =
    firstParen !== -1 && (firstBrace === -1 || firstParen < firstBrace)
      ? balanced(source, firstParen, '(', ')', signature)
      : start
  const open = source.indexOf('{', afterParams)
  assert.notEqual(open, -1, `${signature} 后面没有函数体`)
  return source.slice(open, balanced(source, open, '{', '}', signature) + 1)
}

test('待收列表必须自己轮询：挂载即启动，静默刷新走 poller（不是只有手点刷新）', () => {
  assert.match(
    src,
    /import\s*\{\s*createPoller\s*\}\s*from\s*'\.\.\/lib\/poller\.js'/,
    'InboxPanel 必须引入轮询器——没有它，「来了新文件」就只能靠用户手点刷新',
  )

  const pollerCall = sliceBraces(src, 'const poller = createPoller(')
  assert.match(
    pollerCall,
    /task:\s*\(\)\s*=>\s*refresh\(\{\s*quiet:\s*true\s*\}\)/,
    '轮询任务必须是「静默刷新」：后台每 8 秒拉一次不能转圈、不能抹掉用户正在看的错误',
  )
  assert.match(pollerCall, /intervalMs:\s*\d+/, '可见时必须有明确间隔（默认 8s）')
  assert.match(pollerCall, /onRun:\s*\(/, '必须挂 onRun：没有它「自动更新 hh:mm:ss」永不更新（界面看着像没在刷新）')
  assert.match(pollerCall, /hiddenMs:\s*\d+/, '页面在后台必须降频（默认 30s），别空烧电')

  const mounted = sliceBraces(src, 'onMounted(')
  assert.match(mounted, /poller\.start\(\)/, '列表挂载就必须开始轮询（首屏也别等用户点）')

  const unmounted = sliceBraces(src, 'onUnmounted(')
  assert.match(unmounted, /poller\.stop\(\)/, '卸载必须停掉轮询，否则切页面后定时器泄漏、还在打服务端')
})

test('切回页面/聚焦真的唤醒轮询（真事件驱动：EventTarget 派发 → poller.kick → 任务真的跑一次）', async () => {
  // 用 Node 自带的 EventTarget/Event 造真事件源：doc 收 visibilitychange，win 收 focus
  const doc = new EventTarget()
  doc.hidden = false
  const win = new EventTarget()

  let runs = 0
  const listed = [] // 模拟待收列表：任务每跑一次就"拉到"一条
  const timers = []
  const poller = createPoller({
    task: async () => {
      runs += 1
      listed.push(`第 ${runs} 次刷新`)
      return true
    },
    intervalMs: 8000,
    hiddenMs: 30000,
    isHidden: () => doc.hidden,
    setTimer: (fn, ms) => {
      timers.push({ fn, ms })
      return timers.length
    },
    clearTimer: () => {},
  })
  const wake = bindWakeEvents({ poller, doc, win })

  poller.start()
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 1, '挂载即拉一次')
  assert.equal(listed.length, 1, '列表真的被刷新过')

  wake.bind()
  doc.dispatchEvent(new Event('visibilitychange'))
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 2, '页面重新可见必须**真的**把轮询唤醒（不是源码里出现过 kick）')
  assert.equal(listed.length, 2, '唤醒后列表要真的刷新')

  win.dispatchEvent(new Event('focus'))
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 3, '窗口聚焦也要补一次（手机端切回 App 不一定有 visibilitychange）')

  // 后台（hidden）的 visibilitychange 不许补：否则「后台 30s 降频」形同虚设，还在白打服务端
  doc.hidden = true
  doc.dispatchEvent(new Event('visibilitychange'))
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 3, '隐藏状态下的 visibilitychange 不许触发补拉')

  // 卸载后（unbind）事件必须彻底失效：监听没解绑 = 切页面后还在打服务端
  wake.unbind()
  doc.hidden = false
  doc.dispatchEvent(new Event('visibilitychange'))
  win.dispatchEvent(new Event('focus'))
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 3, 'unbind 之后事件不许再唤醒轮询')

  // 幂等：重复 bind 不许叠出两份监听
  wake.bind().bind()
  doc.dispatchEvent(new Event('visibilitychange'))
  await new Promise((r) => setImmediate(r))
  assert.equal(runs, 4, '重复 bind 只允许一份监听（否则一次事件唤醒两次）')
  wake.unbind()
  poller.stop()
})

test('InboxPanel 必须真的接上「唤醒」与「轮询」这两条线（接线守卫，防止逻辑写好但没人调）', () => {
  assert.match(src, /import\s*\{\s*bindWakeEvents\s*\}\s*from\s*'\.\.\/lib\/wakeEvents\.js'/)
  assert.match(src, /bindWakeEvents\(\{\s*poller\s*\}\)/, '必须把轮询器交给唤醒模块')
  const mounted = sliceBraces(src, 'onMounted(')
  assert.match(mounted, /wake\.bind\(\)/, '挂载必须注册唤醒监听')
  const unmounted = sliceBraces(src, 'onUnmounted(')
  assert.match(unmounted, /wake\.unbind\(\)/, '卸载必须解绑（否则切页面后还在打服务端）')
})

test('后台刷新失败不得冒充"刚更新过"（假活比不刷新更坏）', () => {
  const refreshBody = sliceFunction(src, 'async function refresh(')

  assert.match(
    refreshBody,
    /if\s*\(quiet\s*&&\s*activeId\.value\)\s*return false/,
    '正在下载时不打扰（返回 false，让轮询器别推进「自动更新」时间）',
  )

  const catchBlock = sliceBraces(refreshBody, 'catch (')
  assert.match(
    catchBlock,
    /return false/,
    '后台刷新失败时必须返回 false：否则界面写着"自动更新 12:00:00"，其实一次都没拉到（#84 的假成功同源）',
  )

  assert.match(refreshBody, /return true/, '真拉到列表要返回 true，轮询器才更新「自动更新 hh:mm:ss」')
})
