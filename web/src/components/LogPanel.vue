<script setup>
import { onUnmounted, ref } from 'vue'
import { entriesSnapshot, subscribe } from '../lib/log.js'

const entries = ref(entriesSnapshot())
const open = ref(false)
const unsubscribe = subscribe(() => {
  entries.value = entriesSnapshot()
})
onUnmounted(unsubscribe)

function stamp(t) {
  const d = new Date(t)
  const pad = (x) => String(x).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
</script>

<template>
  <section class="card">
    <div class="row" style="justify-content: space-between">
      <h2 style="margin: 0">运行记录</h2>
      <button type="button" @click="open = !open">{{ open ? '收起' : '展开' }}</button>
    </div>
    <p class="hint">只记方法/路径/状态/大小，不记文件名、明文与密钥。</p>
    <div v-if="open" class="log">
      <div v-for="(entry, i) in entries" :key="i">
        {{ stamp(entry.t) }} · {{ entry.level }} · {{ entry.message }}
      </div>
      <div v-if="!entries.length">（空）</div>
    </div>
  </section>
</template>
