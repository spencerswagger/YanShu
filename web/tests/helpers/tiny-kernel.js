/**
 * 手搓一个**极小但合法**的雁书内核形状 wasm（只用于测试 sync/ensure 的核验逻辑）。
 *
 * 为什么不用 `Buffer.alloc(...)`：那些字节不是 wasm，`sync-wasm` 现在会先实例化核验，
 * 拿假字节测"同步成功"等于测了一个不存在的场景。这里生成的是真模块：`memory` +
 * `ys_version` / `ys_header_len` / `ys_unpack_v1`（6 参）/ `ys_sm2_sign_der` / `ys_pack_v1`，
 * 每一项都能单独关掉或改成错值，用来验证门禁**有没有牙**（删掉某条检查必须变红）。
 */

function uleb(n) {
  const out = []
  do {
    let b = n & 0x7f
    n >>>= 7
    if (n) b |= 0x80
    out.push(b)
  } while (n)
  return out
}

function sleb(n) {
  const out = []
  let more = true
  while (more) {
    let b = n & 0x7f
    n >>= 7
    if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) more = false
    else b |= 0x80
    out.push(b)
  }
  return out
}

const str = (s) => [...uleb(s.length), ...Buffer.from(s, 'utf8')]
const vect = (items) => [...uleb(items.length), ...items.flat()]
const section = (id, bytes) => [id, ...uleb(bytes.length), ...bytes]

const T_VOID_I32 = [0x60, 0x00, 0x01, 0x7f]
const T_SIX_I32_I32 = [0x60, 0x06, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f]
const T_VOID_VOID = [0x60, 0x00, 0x00]

/**
 * @param {object} opts
 * @param {number|null} opts.version      ys_version 返回值；null = 不导出该函数
 * @param {number|null} opts.headerLen    ys_header_len 返回值；null = 不导出该函数
 * @param {number} opts.importCount       导入函数个数（内核应为 0）
 * @param {boolean} opts.memory           是否导出 memory
 * @param {boolean} opts.unpackV1         是否导出 6 参的 ys_unpack_v1
 * @param {boolean} opts.signDer          是否导出 ys_sm2_sign_der
 * @param {boolean} opts.packV1           是否导出 ys_pack_v1
 * @returns {Buffer}
 */
export function buildTinyKernel(opts = {}) {
  const {
    version = 0x10000,
    headerLen = 112,
    importCount = 0,
    memory = true,
    unpackV1 = true,
    signDer = true,
    packV1 = true,
  } = opts

  const parts = [section(1, vect([T_VOID_I32, T_SIX_I32_I32, T_VOID_VOID]))]

  if (importCount) {
    const imports = []
    for (let i = 0; i < importCount; i++) imports.push([...str('env'), ...str(`g${i}`), 0x00, ...uleb(2)])
    parts.push(section(2, vect(imports)))
  }

  const funcs = [] // { typeIdx, body: number[] }
  const exports = [] // { name, kind, index }
  if (memory) exports.push({ name: 'memory', kind: 0x02, index: 0 })

  const pushedFns = []
  const addFn = (typeIdx, body, name) => {
    funcs.push({ typeIdx, body })
    const index = importCount + funcs.length - 1
    if (name) exports.push({ name, kind: 0x00, index })
    pushedFns.push(name || '')
  }

  if (version !== null) addFn(0, [0x00, 0x41, ...sleb(version), 0x0b], 'ys_version')
  if (headerLen !== null) addFn(0, [0x00, 0x41, ...sleb(headerLen), 0x0b], 'ys_header_len')
  if (unpackV1) addFn(1, [0x00, 0x41, ...sleb(0), 0x0b], 'ys_unpack_v1')
  if (signDer) addFn(2, [0x00, 0x0b], 'ys_sm2_sign_der')
  if (packV1) addFn(2, [0x00, 0x0b], 'ys_pack_v1')

  // 至少一个函数，否则 code 段为空也没关系；先按需写各段
  if (funcs.length) parts.push(section(3, vect(funcs.map((f) => uleb(f.typeIdx)))))
  if (memory) parts.push(section(5, vect([[0x00, 0x01]])))
  parts.push(section(7, vect(exports.map((e) => [...str(e.name), e.kind, ...uleb(e.index)]))))
  if (funcs.length) parts.push(section(10, vect(funcs.map((f) => [...uleb(f.body.length), ...f.body]))))

  const header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
  return Buffer.from([...header, ...parts.flat()])
}
