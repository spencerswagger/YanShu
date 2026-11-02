// wasm32 raw C ABI 冒烟测试（Node，无 wasm-bindgen）
//
// 用法：
//   node scripts/wasm-smoke/smoke.mjs /path/to/yanshu_sm.wasm
//
// 覆盖：内存分配/释放、SM3、SM4-GCM、SM2 密钥对、用户码、打包→解包、篡改拒绝、码规范化。
// 全部通过打印 "SMOKE OK" 并以 0 退出。

import fs from "node:fs";
import crypto from "node:crypto";

const wasmPath = process.argv[2] ||
  "/.cache/rust/wasm32-unknown-unknown/release/yanshu_sm.wasm";
const bytes = fs.readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const e = instance.exports;

const u8 = () => new Uint8Array(e.memory.buffer);
const write = (ptr, data) => {
  u8().set(data, ptr);
};
const read = (ptr, n) => u8().slice(ptr, ptr + n);
const hex = (b) => Buffer.from(b).toString("hex");
const fromHex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

function alloc(n) {
  const p = e.ys_alloc(n);
  if (!p) throw new Error("ys_alloc failed");
  return p;
}
function check(rc, what) {
  if (rc !== 0) throw new Error(`${what} failed: rc=${rc}`);
}

// ---- 内存
const privPtr = alloc(32);
const pubPtr = alloc(64);
const seed = crypto.randomBytes(32);
const seedPtr = alloc(seed.length);
write(seedPtr, seed);

// ---- SM2 密钥对
check(e.ys_sm2_keygen(seedPtr, seed.length, privPtr, pubPtr), "ys_sm2_keygen");
const priv = read(privPtr, 32);
const pub = read(pubPtr, 64);
const priv2Ptr = alloc(32);
check(e.ys_sm2_pubkey(privPtr, priv2Ptr), "ys_sm2_pubkey");
if (hex(read(priv2Ptr, 64)) !== hex(pub)) throw new Error("pubkey mismatch");

// ---- 用户码
const codePtr = alloc(4);
check(e.ys_user_code(pubPtr, codePtr), "ys_user_code");
const code = Buffer.from(read(codePtr, 4)).toString("ascii");
if (!/^[0-9A-HJKMNP-TV-Z]{4}$/.test(code)) throw new Error(`bad code ${code}`);

// ---- 码规范化
const rawIn = Buffer.from("k7-qf");
const inPtr = alloc(rawIn.length);
write(inPtr, rawIn);
const normPtr = alloc(4);
check(e.ys_normalize_code(inPtr, rawIn.length, normPtr), "ys_normalize_code");
const norm = Buffer.from(read(normPtr, 4)).toString("ascii");
if (norm !== "K7QF") throw new Error(`normalize got ${norm}`);

// ---- SM3
const sm3In = alloc(3);
write(sm3In, Buffer.from("abc"));
const sm3Out = alloc(32);
check(e.ys_sm3(sm3In, 3, sm3Out), "ys_sm3");
if (hex(read(sm3Out, 32)) !== "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0") {
  throw new Error("sm3 mismatch");
}

// ---- SM4-GCM
const keyPtr = alloc(16);
write(keyPtr, crypto.randomBytes(16));
const noncePtr = alloc(12);
write(noncePtr, crypto.randomBytes(12));
const aadPtr = alloc(5);
write(aadPtr, Buffer.from("aad!!"));
const pt = crypto.randomBytes(100);
const ptPtr = alloc(pt.length);
write(ptPtr, pt);
const ctPtr = alloc(pt.length);
const tagPtr = alloc(16);
check(
  e.ys_sm4_gcm_encrypt(keyPtr, noncePtr, 12, aadPtr, 5, ptPtr, pt.length, ctPtr, tagPtr),
  "ys_sm4_gcm_encrypt",
);
const backPtr = alloc(pt.length);
check(
  e.ys_sm4_gcm_decrypt(keyPtr, noncePtr, 12, aadPtr, 5, ctPtr, pt.length, tagPtr, backPtr),
  "ys_sm4_gcm_decrypt",
);
if (hex(read(backPtr, pt.length)) !== hex(pt)) throw new Error("gcm roundtrip mismatch");
// 篡改 tag 必须失败（-15 TAG_MISMATCH）
const badTagPtr = alloc(16);
const badTag = read(tagPtr, 16);
badTag[0] ^= 1;
write(badTagPtr, badTag);
const rc = e.ys_sm4_gcm_decrypt(keyPtr, noncePtr, 12, aadPtr, 5, ctPtr, pt.length, badTagPtr, backPtr);
if (rc !== -15) throw new Error(`tampered tag should be -15, got ${rc}`);

// ---- 打包 → 解包
const name = Buffer.from("报告.pdf");
const mime = Buffer.from("application/pdf");
const namePtr = alloc(name.length);
write(namePtr, name);
const mimePtr = alloc(mime.length);
write(mimePtr, mime);
const data = crypto.randomBytes(5000);
const dataPtr = alloc(data.length);
write(dataPtr, data);
const outLenPtr = alloc(8); // usize=4 on wasm32, 8 够用

let rc2 = e.ys_pack(
  pubPtr, privPtr, namePtr, name.length, mimePtr, mime.length, 1024,
  seedPtr, seed.length, dataPtr, data.length, 0, 0, outLenPtr,
);
if (rc2 !== -2) throw new Error(`expected BUFFER_TOO_SMALL(-2), got ${rc2}`);
const need = new DataView(e.memory.buffer).getUint32(outLenPtr, true);
const packPtr = alloc(need);
check(
  e.ys_pack(
    pubPtr, privPtr, namePtr, name.length, mimePtr, mime.length, 1024,
    seedPtr, seed.length, dataPtr, data.length, packPtr, need, outLenPtr,
  ),
  "ys_pack",
);
const packLen = new DataView(e.memory.buffer).getUint32(outLenPtr, true);
const pack = read(packPtr, packLen);

// meta
const metaLenPtr = alloc(8);
let rc3 = e.ys_unpack_meta(packPtr, packLen, privPtr, pubPtr, 0, 0, metaLenPtr);
if (rc3 !== -2) throw new Error(`expected -2 for meta, got ${rc3}`);
const metaNeed = new DataView(e.memory.buffer).getUint32(metaLenPtr, true);
const metaPtr = alloc(metaNeed);
check(e.ys_unpack_meta(packPtr, packLen, privPtr, pubPtr, metaPtr, metaNeed, metaLenPtr), "ys_unpack_meta");
const meta = JSON.parse(Buffer.from(read(metaPtr, metaNeed)).toString("utf8"));
if (meta.name !== "报告.pdf" || meta.size !== data.length) {
  throw new Error(`meta mismatch: ${JSON.stringify(meta)}`);
}

// unpack
let rc4 = e.ys_unpack(packPtr, packLen, privPtr, pubPtr, 0, 0, outLenPtr);
if (rc4 !== -2) throw new Error(`expected -2 for unpack, got ${rc4}`);
const dataNeed = new DataView(e.memory.buffer).getUint32(outLenPtr, true);
const plainPtr = alloc(dataNeed);
check(e.ys_unpack(packPtr, packLen, privPtr, pubPtr, plainPtr, dataNeed, outLenPtr), "ys_unpack");
const plain = read(plainPtr, data.length);
if (hex(plain) !== hex(data)) throw new Error("unpack data mismatch");

// 篡改 1 字节必须失败
const tampered = new Uint8Array(pack);
tampered[Math.floor(pack.length / 2)] ^= 1;
const tamperedPtr = alloc(tampered.length);
write(tamperedPtr, tampered);
const rc5 = e.ys_unpack(tamperedPtr, tampered.length, privPtr, pubPtr, plainPtr, dataNeed, outLenPtr);
if (rc5 === 0) throw new Error("tampered pack must fail");

// ---- 释放
for (const [p, n] of [
  [privPtr, 32], [pubPtr, 64], [seedPtr, seed.length], [priv2Ptr, 32], [codePtr, 4],
  [inPtr, rawIn.length], [normPtr, 4], [sm3In, 3], [sm3Out, 32], [keyPtr, 16],
  [noncePtr, 12], [aadPtr, 5], [ptPtr, pt.length], [ctPtr, pt.length], [tagPtr, 16],
  [badTagPtr, 16], [backPtr, pt.length], [namePtr, name.length], [mimePtr, mime.length],
  [dataPtr, data.length], [outLenPtr, 8], [packPtr, need], [metaLenPtr, 8],
  [metaPtr, metaNeed], [plainPtr, dataNeed], [tamperedPtr, tampered.length],
]) {
  e.ys_free(p, n);
}

console.log(`SMOKE OK (wasm ${bytes.length} bytes, code=${code}, pack=${packLen} bytes, blocks=${meta.block_count})`);
