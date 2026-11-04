// 流式打包/解包的内存实测：同一进程内逐块喂，wasm 线性内存应基本恒定。
// 用法：node scripts/wasm-smoke/stream-memory.mjs <wasm> <MiB...>

import fs from "node:fs";

const [, , wasmPath, ...sizeArgs] = process.argv;
const sizes = (sizeArgs.length ? sizeArgs : ["64", "256"]).map(Number);

const bytes = fs.readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const e = instance.exports;
const u8 = () => new Uint8Array(e.memory.buffer);
const dv = () => new DataView(e.memory.buffer);

const write = (ptr, buf) => u8().set(buf, ptr);
const read = (ptr, n) => u8().slice(ptr, ptr + n);
const alloc = (n) => {
  const p = e.ys_alloc(n);
  if (!p) throw new Error("ys_alloc failed " + n);
  return p;
};

// 固定密钥材料（只用于测内存，不用于生产）
const seed = new Uint8Array(32).map((_, i) => i);
const seedPtr = alloc(32);
write(seedPtr, seed);
const rsk = alloc(32);
const rpk = alloc(64);
if (e.ys_sm2_keygen(seedPtr, 32, rsk, rpk) !== 0) throw new Error("keygen");
const sseed = new Uint8Array(32).map((_, i) => 255 - i);
const packSeed = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const packSeedPtr = alloc(32);
write(packSeedPtr, packSeed);
const sseedPtr = alloc(32);
write(sseedPtr, sseed);
const ssk = alloc(32);
const spk = alloc(64);
if (e.ys_sm2_keygen(sseedPtr, 32, ssk, spk) !== 0) throw new Error("keygen2");

const name = Buffer.from("stream.bin");
const mime = Buffer.from("application/octet-stream");
const ext = Buffer.from("bin");
const namePtr = alloc(name.length);
const mimePtr = alloc(mime.length);
const extPtr = alloc(ext.length);
write(namePtr, name);
write(mimePtr, mime);
write(extPtr, ext);

const lenPtr = alloc(8);
const CHUNK = 1 << 20;

const results = [];
for (const mib of sizes) {
  const total = mib * 1024 * 1024;
  const chunkCount = Math.ceil(total / CHUNK);
  const buf = new Uint8Array(CHUNK);
  for (let i = 0; i < CHUNK; i++) buf[i] = (i * 31 + 7) & 0xff;
  const bufPtr = alloc(CHUNK);

  // 每个尺寸用不同 seed（内核会拒绝同一 seed 复用）
  const s2 = new Uint8Array(32).map((_, i) => (i * 13 + mib) & 0xff);
  write(packSeedPtr, s2);

  const baseline = e.memory.buffer.byteLength;
  let peak = baseline;

  // ---- 打包（流式）：hash 一遍 + 逐块出记录
  let rc = e.ys_pack_stream_begin(
    rpk, ssk, namePtr, name.length, mimePtr, mime.length, extPtr, ext.length,
    BigInt(1_767_225_600_000), CHUNK, BigInt(total), packSeedPtr, 32,
  );
  if (rc !== 0) throw new Error("pack_stream_begin " + rc);

  for (let i = 0; i < chunkCount; i++) {
    const len = Math.min(CHUNK, total - i * CHUNK);
    if (len !== CHUNK) write(bufPtr, buf.subarray(0, len));
    else write(bufPtr, buf);
    rc = e.ys_pack_hash_update(bufPtr, len);
    if (rc !== 0) throw new Error("hash_update " + rc);
    peak = Math.max(peak, e.memory.buffer.byteLength);
  }

  rc = e.ys_pack_stream_prelude(0, 0, lenPtr);
  if (rc !== -2) throw new Error("prelude probe " + rc);
  const preludeLen = dv().getUint32(lenPtr, true);
  const preludePtr = alloc(preludeLen);
  rc = e.ys_pack_stream_prelude(preludePtr, preludeLen, lenPtr);
  if (rc !== 0) throw new Error("prelude " + rc);
  peak = Math.max(peak, e.memory.buffer.byteLength);

  // ---- 解包（流式）：同一会话里逐块 pack→unpack，验证内存不随文件涨
  const uRc = e.ys_unpack_stream_begin(preludePtr, preludeLen, rsk);
  if (uRc !== 0) throw new Error("unpack_stream_begin " + uRc);

  let outPtr = 0;
  let outCap = 0;
  for (let i = 0; i < chunkCount; i++) {
    const len = Math.min(CHUNK, total - i * CHUNK);
    if (len !== CHUNK) write(bufPtr, buf.subarray(0, len));
    rc = e.ys_pack_stream_chunk(i, bufPtr, len, 0, 0, lenPtr);
    if (rc !== -2) throw new Error("chunk probe " + rc);
    const recLen = dv().getUint32(lenPtr, true);
    if (recLen > outCap) {
      if (outPtr) e.ys_free(outPtr, outCap);
      outPtr = alloc(recLen);
      outCap = recLen;
    }
    rc = e.ys_pack_stream_chunk(i, bufPtr, len, outPtr, outCap, lenPtr);
    if (rc !== 0) throw new Error("pack chunk " + rc);
    const n = dv().getUint32(lenPtr, true);
    rc = e.ys_unpack_stream_chunk(outPtr, n, 0, 0, lenPtr);
    if (rc !== -2) throw new Error("unpack probe " + rc);
    const ptLen = dv().getUint32(lenPtr, true);
    if (ptLen !== len) throw new Error(`pt len ${ptLen} != ${len}`);
    rc = e.ys_unpack_stream_chunk(outPtr, n, outPtr, outCap, lenPtr);
    if (rc !== 0) throw new Error("unpack chunk " + rc);
    peak = Math.max(peak, e.memory.buffer.byteLength);
  }
  const endRc = e.ys_unpack_stream_end();
  if (endRc !== 0) throw new Error("unpack_stream_end " + endRc);
  e.ys_pack_stream_end();

  if (outPtr) e.ys_free(outPtr, outCap);
  e.ys_free(bufPtr, CHUNK);
  e.ys_free(preludePtr, preludeLen);

  results.push({
    mib,
    chunks: chunkCount,
    baselineMiB: +(baseline / 1048576).toFixed(2),
    peakMiB: +(peak / 1048576).toFixed(2),
    growthMiB: +((peak - baseline) / 1048576).toFixed(2),
  });
}

console.log(JSON.stringify(results));
