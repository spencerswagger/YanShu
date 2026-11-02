// wasm32 raw C ABI 冒烟测试（Node，无 wasm-bindgen）
//
// 用法：
//   node scripts/wasm-smoke/smoke.mjs /path/to/yanshu_sm.wasm
//
// 覆盖：内存分配/释放、SM3、SM4-GCM、SM2 密钥对、用户码与校验字符、码规范化、
//       YSPK/1.0 打包→解包（含 sender code 比对）、篡改拒绝。
// 全部通过打印 "SMOKE OK" 并以 0 退出。

import fs from "node:fs";
import crypto from "node:crypto";

const wasmPath = process.argv[2] ||
  "/.cache/rust/wasm32-unknown-unknown/release/yanshu_sm.wasm";
const bytes = fs.readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const e = instance.exports;

const u8 = () => new Uint8Array(e.memory.buffer);
const write = (ptr, data) => u8().set(data, ptr);
const read = (ptr, n) => u8().slice(ptr, ptr + n);
const hex = (b) => Buffer.from(b).toString("hex");
const dv = () => new DataView(e.memory.buffer);

function alloc(n) {
  const p = e.ys_alloc(n);
  if (!p) throw new Error("ys_alloc failed");
  return p;
}
function check(rc, what) {
  if (rc !== 0) throw new Error(`${what} failed: rc=${rc} (${errName(rc)})`);
}
function errName(code) {
  const cap = 64;
  const p = alloc(cap);
  const lp = alloc(8);
  e.ys_error_name(code, p, cap, lp);
  const s = Buffer.from(read(p, dv().getUint32(lp, true))).toString("ascii");
  e.ys_free(p, cap);
  e.ys_free(lp, 8);
  return s;
}

// ---- 密钥对（发送方 / 接收方），seed 由 JS 侧真随机提供
function keygen() {
  const seed = crypto.randomBytes(32);
  const seedPtr = alloc(seed.length);
  write(seedPtr, seed);
  const privPtr = alloc(32);
  const pubPtr = alloc(65);
  check(e.ys_sm2_keygen(seedPtr, seed.length, privPtr, pubPtr), "ys_sm2_keygen");
  const out = { priv: read(privPtr, 32), pub: read(pubPtr, 65) };
  [privPtr, pubPtr, seedPtr].forEach((p, i) => e.ys_free(p, [32, 65, seed.length][i]));
  return out;
}

const sender = keygen();
const recipient = keygen();
if (sender.pub[0] !== 0x04) throw new Error("pubkey must start with 0x04");

// ---- 用户码 + 校验字符
const pubPtr = alloc(65);
write(pubPtr, sender.pub);
const codePtr = alloc(4);
const chkPtr = alloc(1);
check(e.ys_user_code(pubPtr, codePtr), "ys_user_code");
check(e.ys_check_symbol(pubPtr, chkPtr), "ys_check_symbol");
const code = Buffer.from(read(codePtr, 4)).toString("ascii");
const chk = Buffer.from(read(chkPtr, 1)).toString("ascii");
if (!/^[0-9A-HJKMNP-TV-Z]{4}$/.test(code)) throw new Error(`bad code ${code}`);
if (!/^[0-9A-Z*~$=U]$/.test(chk)) throw new Error(`bad check symbol ${chk}`);

// ---- 码规范化
const rawIn = Buffer.from("k7-qf");
const inPtr = alloc(rawIn.length);
write(inPtr, rawIn);
const normPtr = alloc(4);
check(e.ys_normalize_code(inPtr, rawIn.length, normPtr), "ys_normalize_code");
if (Buffer.from(read(normPtr, 4)).toString("ascii") !== "K7QF") throw new Error("normalize");

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
const aad = Buffer.from("YSPK-1.0-aad");
const aadPtr = alloc(aad.length);
write(aadPtr, aad);
const pt = crypto.randomBytes(100);
const ptPtr = alloc(pt.length);
write(ptPtr, pt);
const ctPtr = alloc(pt.length);
const tagPtr = alloc(16);
check(
  e.ys_sm4_gcm_encrypt(keyPtr, noncePtr, 12, aadPtr, aad.length, ptPtr, pt.length, ctPtr, tagPtr),
  "ys_sm4_gcm_encrypt",
);
const backPtr = alloc(pt.length);
check(
  e.ys_sm4_gcm_decrypt(keyPtr, noncePtr, 12, aadPtr, aad.length, ctPtr, pt.length, tagPtr, backPtr),
  "ys_sm4_gcm_decrypt",
);
if (hex(read(backPtr, pt.length)) !== hex(pt)) throw new Error("gcm roundtrip");
// 篡改 tag → CRYPTO_CHUNK_AUTH_FAILED (-17)
const badTagPtr = alloc(16);
const badTag = read(tagPtr, 16);
badTag[0] ^= 1;
write(badTagPtr, badTag);
if (e.ys_sm4_gcm_decrypt(keyPtr, noncePtr, 12, aadPtr, aad.length, ctPtr, pt.length, badTagPtr, backPtr) !== -17) {
  throw new Error("tampered tag should be -17");
}

// ---- 打包
const name = Buffer.from("报告.pdf");
const mime = Buffer.from("application/pdf");
const ext = Buffer.from("pdf");
const namePtr = alloc(name.length);
write(namePtr, name);
const mimePtr = alloc(mime.length);
write(mimePtr, mime);
const extPtr = alloc(ext.length);
write(extPtr, ext);
const data = crypto.randomBytes(5000);
const dataPtr = alloc(data.length);
write(dataPtr, data);
const seed2 = crypto.randomBytes(32);
const seed2Ptr = alloc(seed2.length);
write(seed2Ptr, seed2);
const lenPtr = alloc(8);

const recipientPubPtr = alloc(65);
write(recipientPubPtr, recipient.pub);
const senderPrivPtr = alloc(32);
write(senderPrivPtr, sender.priv);

const packArgs = [
  recipientPubPtr, senderPrivPtr,
  namePtr, name.length, mimePtr, mime.length, extPtr, ext.length,
  BigInt(1_767_225_600_000), 1024,
  seed2Ptr, seed2.length, dataPtr, data.length,
];

let rc = e.ys_pack(...packArgs, 0, 0, lenPtr);
if (rc !== -2) throw new Error(`pack should ask for size (-2), got ${rc}`);
const need = dv().getUint32(lenPtr, true);
const packPtr = alloc(need);
check(e.ys_pack(...packArgs, packPtr, need, lenPtr), "ys_pack");
const packLen = dv().getUint32(lenPtr, true);
const pack = read(packPtr, packLen);

// ---- meta（带 sender code 校验）
const recipPrivPtr = alloc(32);
write(recipPrivPtr, recipient.priv);
const codeBuf = Buffer.from(code, "ascii");
const codePtr2 = alloc(4);
write(codePtr2, codeBuf);

let rc2 = e.ys_unpack_meta(packPtr, packLen, recipPrivPtr, 0, 0, 0, 0, lenPtr);
if (rc2 !== -2) throw new Error(`meta should ask for size (-2), got ${rc2}`);
const metaNeed = dv().getUint32(lenPtr, true);
const metaPtr = alloc(metaNeed);
check(e.ys_unpack_meta(packPtr, packLen, recipPrivPtr, 0, 0, metaPtr, metaNeed, lenPtr), "ys_unpack_meta");
const meta = JSON.parse(Buffer.from(read(metaPtr, metaNeed)).toString("utf8"));
if (meta.name !== "报告.pdf" || meta.size !== data.length) throw new Error(`meta: ${JSON.stringify(meta)}`);
if (meta.sender_code !== code) throw new Error(`sender code mismatch: ${meta.sender_code} vs ${code}`);

// ---- unpack
let rc3 = e.ys_unpack(packPtr, packLen, recipPrivPtr, 0, 0, 0, 0, lenPtr);
if (rc3 !== -2) throw new Error(`unpack should ask for size (-2), got ${rc3}`);
const dataNeed = dv().getUint32(lenPtr, true);
const plainPtr = alloc(dataNeed);
check(e.ys_unpack(packPtr, packLen, recipPrivPtr, codePtr2, 4, plainPtr, dataNeed, lenPtr), "ys_unpack");
if (hex(read(plainPtr, data.length)) !== hex(data)) throw new Error("unpack data mismatch");

// ---- 篡改必须失败；错码必须 CRYPTO_SENDER_MISMATCH(-15)
const tampered = new Uint8Array(pack);
tampered[20] ^= 1; // CHUNK_COUNT 邻域
const tamperedPtr = alloc(tampered.length);
write(tamperedPtr, tampered);
if (e.ys_unpack(tamperedPtr, tampered.length, recipPrivPtr, 0, 0, plainPtr, dataNeed, lenPtr) === 0) {
  throw new Error("tampered pack must fail");
}
const wrongCode = Buffer.from("ZZZZ");
const wrongPtr = alloc(4);
write(wrongPtr, wrongCode);
const rcWrong = e.ys_unpack(packPtr, packLen, recipPrivPtr, wrongPtr, 4, plainPtr, dataNeed, lenPtr);
if (rcWrong !== -15) throw new Error(`wrong sender code should be -15, got ${rcWrong}`);

console.log(
  `SMOKE OK (wasm ${bytes.length}B, code=${code}-${chk}, pack=${packLen}B, chunks=${meta.chunk_count})`,
);
