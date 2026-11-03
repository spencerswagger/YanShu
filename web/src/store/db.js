/**
 * 极简 IndexedDB 封装：只给 store 层用。
 *
 * 为什么用 IndexedDB 而不是 localStorage：私钥是二进制，且 IndexedDB 不受 5MB 限制；
 * 但**两者都不做备份、不上传**——清缓存等于换人（REQUIREMENTS §2 已锁死）。
 *
 * 测试用 `memoryBackend()` 换掉真实 IndexedDB，逻辑不依赖浏览器。
 */

const DB_NAME = 'yanshu'
const DB_VERSION = 1
const STORES = ['identity', 'pending', 'history']

export function hasIndexedDB() {
  return typeof indexedDB !== 'undefined'
}

export function memoryBackend() {
  const map = new Map()
  return {
    kind: 'memory',
    async get(key) {
      return map.has(key) ? structuredCloneSafe(map.get(key)) : null
    },
    async put(key, value) {
      map.set(key, structuredCloneSafe(value))
    },
    async del(key) {
      map.delete(key)
    },
    async all() {
      return [...map.values()].map((v) => structuredCloneSafe(v))
    },
  }
}

function structuredCloneSafe(value) {
  if (typeof structuredClone === 'function') return structuredClone(value)
  return JSON.parse(JSON.stringify(value))
}

/** 打开数据库（每个 store 一个 backend 视图，key 为字符串）。 */
export function openBackend(name) {
  if (!STORES.includes(name)) throw new Error(`unknown store: ${name}`)
  let dbPromise = null

  const open = () => {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION)
        req.onupgradeneeded = () => {
          const db = req.result
          for (const store of STORES) {
            if (!db.objectStoreNames.contains(store)) db.createObjectStore(store)
          }
        }
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
      })
    }
    return dbPromise
  }

  const tx = async (mode, fn) => {
    const db = await open()
    return new Promise((resolve, reject) => {
      const t = db.transaction(name, mode)
      const store = t.objectStore(name)
      let result
      try {
        result = fn(store)
      } catch (err) {
        reject(err)
        return
      }
      t.oncomplete = () => resolve(result && result.__value !== undefined ? result.__value : result)
      t.onerror = () => reject(t.error)
      t.onabort = () => reject(t.error)
    })
  }

  return {
    kind: 'idb',
    async get(key) {
      return tx('readonly', (store) => {
        const req = store.get(key)
        const box = {}
        req.onsuccess = () => {
          box.__value = req.result ?? null
        }
        return box
      })
    },
    async put(key, value) {
      return tx('readwrite', (store) => {
        store.put(value, key)
      })
    },
    async del(key) {
      return tx('readwrite', (store) => {
        store.delete(key)
      })
    },
    async all() {
      return tx('readonly', (store) => {
        const req = store.openCursor()
        const box = { __value: [] }
        req.onsuccess = () => {
          const cursor = req.result
          if (!cursor) return
          box.__value.push(cursor.value)
          cursor.continue()
        }
        return box
      })
    },
  }
}

/** 按运行环境自动选 backend（浏览器 → IndexedDB；其它 → 内存，便于 Node 测试）。 */
export function defaultBackend(name) {
  return hasIndexedDB() ? openBackend(name) : memoryBackend()
}
