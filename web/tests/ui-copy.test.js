/**
 * 文案与 `docs/UI-COPY.md` 一致性（防止实现与文档漂移），以及禁止词表。
 * 只做静态断言，不需要内核产物。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const read = (p) => readFileSync(resolve(here, '..', p), 'utf8')
const doc = read('../docs/UI-COPY.md')
const FILES = [
  'src/App.vue',
  'src/components/MyCodeCard.vue',
  'src/components/StatsCard.vue',
  'src/components/SendPanel.vue',
  'src/components/InboxPanel.vue',
  'src/components/DropZone.vue',
  'src/components/RecentList.vue',
]
const sources = FILES.map(read).join('\n')
/** 只扫模板（界面文字）；注释里出现“内核/契约”不算违规 */
const templates = FILES.map((f) => {
  const m = read(f).match(/<template>[\s\S]*?<\/template>/)
  return m ? m[0] : ''
}).join('\n')

/** 11 处 ★ 推荐（与 docs/UI-COPY.md 表格逐字一致） */
/** v4（填充密度改版）定稿文案：与 docs/UI-COPY.md 逐字一致 */
const REQUIRED = [
  '发送文件',
  '接收文件',
  '本机发送',
  '本机接收',
  '成功率',
  '端到端加密 · 私钥仅存本机',
  '把文件拖到这里',
  '暂无待接收文件',
  '最近传输',
  '个文件待接收',
  '昵称已更新',
]

test('UI 文案：11 处推荐文案在文档与代码里都存在', () => {
  for (const text of REQUIRED) {
    assert.ok(doc.includes(text), `docs/UI-COPY.md 缺少：${text}`)
    assert.ok(sources.includes(text), `代码里缺少文案：${text}`)
  }
})

test('UI 文案：禁止口语化/卖萌词', () => {
  const banned = ['我要发', '我要收', '点我', '搞定啦', '么么', '～', 'YSPK', 'sha256', '内核', '契约']
  for (const word of banned) {
    assert.equal(templates.includes(word), false, `界面模板里出现了禁止文案：${word}`)
  }
})

test('UI 文案：安全说明只出现一处（不许散落到卡片）', () => {
  const safetyLine = '私钥仅存本机'
  const hits = sources.split(safetyLine).length - 1
  assert.equal(hits, 1, `安全小字必须全站唯一一处，实际出现 ${hits} 次`)
})

test('UI 文案：昵称失败态必须给出原因（不是"保存失败"）', () => {
  const card = read('src/components/MyCodeCard.vue')
  assert.match(card, /签名挑战已过期/)
  assert.match(card, /昵称过长/)
  // 只看真正的界面标题，注释里说明"不许显示保存失败"不算违规
  assert.equal(/title: *['"]保存失败/.test(card), false, '不允许无原因的“保存失败”')
})
