/**
 * 「页面重新可见 / 窗口聚焦 → 立刻补一次轮询」的接线，抽成独立模块。
 *
 * 为什么抽出来：这段逻辑原来直接写在 `InboxPanel.vue` 的 `onMounted` 里，
 * 而本仓没有 jsdom / Vue 运行时，测试只能读源码断言「出现过 `poller.kick()`」——
 * **同义反复**：把 `visibilitychange` 里的 kick 删掉，`focus` 那行仍然满足断言，用例照样绿
 * （Gate 实测：删掉 kick，3/3 全绿）。逻辑搬到这个模块后，单测可以用 Node 自带的
 * `EventTarget`/`Event` **真的派发事件**，断言轮询真的被唤醒、列表任务真的跑了一次。
 *
 * 规则（都是可观测事实，不是约定）：
 * - 页面**可见**时收到 `visibilitychange` 才补：隐藏状态下补一次等于白打服务端，还会让「后台 30s」失效；
 * - `focus` 无条件补：手机端从别的 App 切回来不一定触发 `visibilitychange`；
 * - 监听成对注册/移除：组件卸载后不许还活着（否则切页面后定时器/监听泄漏，还在打服务端）；
 * - `bind()`/`unbind()` 幂等：重复调用不会叠出两份监听。
 */

/**
 * @param {object}   p
 * @param {{kick:Function}} p.poller  轮询器（只需 `kick()`）
 * @param {EventTarget} [p.doc]       默认 `document`（`visibilitychange` 派发在 document 上）
 * @param {EventTarget} [p.win]       默认 `window`（`focus` 派发在 window 上）
 * @param {() => boolean} [p.isHidden] 默认读 `doc.hidden`；注入后便于单测
 */
export function bindWakeEvents({ poller, doc = globalThis.document, win = globalThis.window, isHidden } = {}) {
  if (!poller || typeof poller.kick !== 'function') {
    throw new Error('bindWakeEvents 需要一个带 kick() 的轮询器')
  }
  const hidden = typeof isHidden === 'function' ? isHidden : () => Boolean(doc?.hidden)
  let bound = false

  const onVisibility = () => {
    if (hidden()) return // 后台不做「立刻补」，交给 poller 自己的 hiddenMs 节流
    poller.kick()
  }
  const onFocus = () => {
    poller.kick()
  }

  return {
    /** 供测试直接驱动（真实浏览器里由事件驱动） */
    onVisibility,
    onFocus,
    bind() {
      if (bound) return this
      doc?.addEventListener?.('visibilitychange', onVisibility)
      win?.addEventListener?.('focus', onFocus)
      bound = true
      return this
    },
    unbind() {
      if (!bound) return this
      doc?.removeEventListener?.('visibilitychange', onVisibility)
      win?.removeEventListener?.('focus', onFocus)
      bound = false
      return this
    },
    get bound() {
      return bound
    },
  }
}
