<script setup>
/** 大拖入区：无文件时它就是视觉主体；悬停/拖入变色，落点有一次性动画。 */
import { ref } from 'vue'

const emit = defineEmits(['pick'])
const input = ref(null)
const hot = ref(false)
const landed = ref(false)

function openPicker() {
  input.value?.click()
}

function onPicked(e) {
  const f = e.target.files?.[0]
  if (!f) return
  landed.value = true
  setTimeout(() => (landed.value = false), 460)
  emit('pick', f)
  e.target.value = ''
}

function onDrop(e) {
  e.preventDefault()
  hot.value = false
  const f = e.dataTransfer?.files?.[0]
  if (!f) return
  landed.value = true
  setTimeout(() => (landed.value = false), 460)
  emit('pick', f)
}
</script>

<template>
  <div
    class="drop"
    :class="{ hot, landed }"
    role="button"
    tabindex="0"
    aria-label="选择或拖入文件"
    @click="openPicker"
    @keydown.enter.prevent="openPicker"
    @keydown.space.prevent="openPicker"
    @dragover.prevent="hot = true"
    @dragleave.prevent="hot = false"
    @drop="onDrop"
  >
    <input ref="input" type="file" class="hidden-input" @change="onPicked" />
    <div class="ring" aria-hidden="true"></div>
    <div class="center">
      <svg width="56" height="56" viewBox="0 0 24 24" fill="none" class="drop-icon" aria-hidden="true">
        <path d="M12 16V6m0 0 4 4m-4-4-4 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        <path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
      </svg>
      <div class="title">把文件拖到这里</div>
      <div class="sub">或点击选择</div>
    </div>
  </div>
</template>
