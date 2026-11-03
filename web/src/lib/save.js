/** 浏览器落盘：Blob → a[download]（不放第三方库，不经过服务端）。 */
export function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  // 给浏览器一点时间把流接过去，再回收
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

export function copyText(text) {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text)
  const el = document.createElement('textarea')
  el.value = text
  el.style.position = 'fixed'
  el.style.opacity = '0'
  document.body.appendChild(el)
  el.select()
  document.execCommand('copy')
  el.remove()
  return Promise.resolve()
}
