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

test('切回页面/窗口聚焦立刻补一次，且两类监听成对注册与移除', () => {
  assert.match(src, /addEventListener\('visibilitychange'/, '切回页面必须立刻补一次（后台期间是 30s 一轮）')
  assert.match(src, /addEventListener\('focus'/, '窗口聚焦也要补（手机端切 App 回来不一定触发 visibilitychange）')
  assert.match(src, /poller\.kick\(\)/, '补一次要真的触发轮询（kick），不能只是记个时间')
  assert.match(src, /removeEventListener\('visibilitychange'/, 'visibilitychange 监听必须成对移除')
  assert.match(src, /removeEventListener\('focus'/, 'focus 监听必须成对移除')
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
