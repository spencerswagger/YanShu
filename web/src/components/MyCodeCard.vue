<script setup>
import { computed } from 'vue'
import { copyText } from '../lib/save.js'

const props = defineProps({
  code: { type: String, default: '' },
  nickname: { type: String, default: '' },
  registered: { type: Boolean, default: false },
  realCrypto: { type: Boolean, default: false },
  kernelMode: { type: String, default: 'loading' },
  kernelLayout: { type: String, default: '' },
})

const display = computed(() => props.code || '——')

async function copy() {
  if (!props.code) return
  await copyText(props.code)
}
</script>

<template>
  <section class="card">
    <h2>我的码</h2>
    <div class="row" style="justify-content: space-between">
      <div class="code">{{ display }} <small v-if="nickname">· {{ nickname }}</small></div>
      <button type="button" :disabled="!code" @click="copy">复制</button>
    </div>
    <p class="hint">
      别人输入这 4 位就能给你发文件；码不是密码，解不开任何东西。
      私钥只存在本机浏览器（IndexedDB），<strong>不上传、不备份</strong>；清缓存等于换人。
    </p>
    <p v-if="!registered" class="hint">正在向中转登记这个码…</p>
    <p v-else-if="kernelMode === 'stub-fake'" class="hint">
      当前是开发桩（未加密），这个码只能用于本地流程联调。
    </p>
    <p v-else-if="!realCrypto" class="hint">端侧加密内核未就绪，码暂时不能用于真实传输。</p>
    <p v-else-if="kernelLayout !== 'contract'" class="hint">
      当前内核是旧布局（非契约），码与加密都真实，但结果不能作为 YSPK/1.0 验收。
    </p>
  </section>
</template>
