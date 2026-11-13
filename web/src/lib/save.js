/** 浏览器落盘：Blob → a[download]（不放第三方库，不经过服务端）。 */
export class SaveDeliveryError extends Error {
  constructor(message) {
    super(message)
    this.name = 'SaveDeliveryError'
    this.code = 'SAVE_DELIVERY_FAILED'
  }
}

/**
 * 把文件交给浏览器下载。
 *
 * 返回值是 Promise，**失败必须抛出**（`SAVE_DELIVERY_FAILED`）：调用方要 `await` 它，
 * 只有它成功才 ack（ack = 服务端删密文）。这里能判定的是"浏览器接受了这次下载请求"
 * （`a.click()` 同步抛错 = 被拒），下载是否真的写进磁盘浏览器不给回调——所以更严格的口径是：
 * **数据先落进 OPFS/目标文件（sink.close()），再交给浏览器，再 ack**。
 */
export function saveBlob(blob, name) {
  let url
  try {
    url = URL.createObjectURL(blob)
  } catch (err) {
    throw new SaveDeliveryError(`创建下载链接失败：${err?.message || err}`)
  }
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.rel = 'noopener'
  try {
    document.body.appendChild(a)
    a.click()
  } catch (err) {
    URL.revokeObjectURL(url)
    a.remove()
    throw new SaveDeliveryError(`浏览器拒绝这次下载：${err?.message || err}`)
  }
  a.remove()
  // 给浏览器一点时间把流接过去，再回收（OPFS 副本由调用方在 revoke 之后清）
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
  return Promise.resolve({ name, bytes: blob.size })
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
