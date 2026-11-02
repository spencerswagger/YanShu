// wasm32 raw C ABI 冒烟测试（Node，无 wasm-bindgen）
//
// 用法：
//   node scripts/wasm-smoke/smoke.mjs /path/to/yanshu_sm.wasm
//
// 覆盖：内存、SM3、SM4-GCM、SM2（64 字节公钥 / 裸 R‖S，首版 ABI）、用户码与校验字符、
//       码规范化、契约布局 YSPK/1.0 的打包→**离线解包**（来源由包内 SENDER_PUB 自证）、
//       发送方码派生、篡改拒绝、seed 复用拒绝。
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
function check(rc, what) {
  if (rc !== 0) throw new Error(`${what} failed: rc=${rc} (${errName(rc)})`);
}
function expectRc(rc, want, what) {
  if (rc !== want) throw new Error(`${what}: want ${want}, got ${rc} (${errName(rc)})`);
}

function msgPtrConst() {
  const m = alloc(4);
  write(m, Buffer.from("seed"));
  return m;
}

function keygen() {
  const seed = crypto.randomBytes(32);
  const seedPtr = alloc(seed.length);
  write(seedPtr, seed);
  const privPtr = alloc(32);
  const pubPtr = alloc(64);
  check(e.ys_sm2_keygen(seedPtr, seed.length, privPtr, pubPtr), "ys_sm2_keygen");
  const out = { priv: read(privPtr, 32), pub: read(pubPtr, 64) };
  e.ys_free(privPtr, 32);
  e.ys_free(pubPtr, 64);
  e.ys_free(seedPtr, seed.length);
  return out;
}

const sender = keygen();
const recipient = keygen();

// ---- 用户码（64 字节公钥入参，内核补 0x04 后按契约派生）
const pubPtr = alloc(64);
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
const badTagPtr = alloc(16);
const badTag = read(tagPtr, 16);
badTag[0] ^= 1;
write(badTagPtr, badTag);
expectRc(
  e.ys_sm4_gcm_decrypt(keyPtr, noncePtr, 12, aadPtr, aad.length, ctPtr, pt.length, badTagPtr, backPtr),
  -15,
  "tampered tag",
);

// ---- 打包/解包（两种布局）
const name = Buffer.from("报告.pdf");
const mime = Buffer.from("application/pdf");
const namePtr = alloc(name.length);
write(namePtr, name);
const mimePtr = alloc(mime.length);
write(mimePtr, mime);
const data = crypto.randomBytes(5000);
const dataPtr = alloc(data.length);
write(dataPtr, data);
const senderPrivPtr = alloc(32);
write(senderPrivPtr, sender.priv);
const recipientPubPtr = alloc(64);
write(recipientPubPtr, recipient.pub);
const recipientPrivPtr = alloc(32);
write(recipientPrivPtr, recipient.priv);
const senderPubPtr = alloc(64);
write(senderPubPtr, sender.pub);
const lenPtr = alloc(8);
const seed = crypto.randomBytes(32);
const seedPtr = alloc(seed.length);
write(seedPtr, seed);

function packOnce() {
  const args = [
    recipientPubPtr, senderPrivPtr,
    namePtr, name.length, mimePtr, mime.length,
    1024, seedPtr, seed.length, dataPtr, data.length,
  ];
  let rc = e.ys_pack(...args, 0, 0, lenPtr);
  expectRc(rc, -2, "ys_pack probe");
  const need = dv().getUint32(lenPtr, true);
  const p = alloc(need);
  check(e.ys_pack(...args, p, need, lenPtr), "ys_pack");
  const n = dv().getUint32(lenPtr, true);
  return { ptr: p, len: n, bytes: read(p, n) };
}

function unpackCall(fn, extraArg, packPtr, packLen, out, cap) {
  if (extraArg === null) return fn.call(e, packPtr, packLen, recipientPrivPtr, out, cap, lenPtr);
  return fn.call(e, packPtr, packLen, recipientPrivPtr, extraArg, out, cap, lenPtr);
}

function unpackOnce(packPtr, packLen, outCap, useV2 = true, senderArg = null) {
  const fn = useV2 ? e.ys_unpack_v2 : e.ys_unpack;
  const extra = useV2 ? null : senderArg;
  let out = alloc(outCap);
  let rc = unpackCall(fn, extra, packPtr, packLen, out, outCap);
  if (rc === -2) {
    const need = dv().getUint32(lenPtr, true);
    e.ys_free(out, outCap);
    out = alloc(need);
    rc = unpackCall(fn, extra, packPtr, packLen, out, need);
    check(rc, "ys_unpack retry");
    const got = read(out, dv().getUint32(lenPtr, true));
    e.ys_free(out, need);
    return got;
  }
  check(rc, "ys_unpack");
  const got = read(out, dv().getUint32(lenPtr, true));
  e.ys_free(out, outCap);
  return got;
}

// 唯一布局 = 契约 YSPK/1.0
if (e.ys_header_len() !== 112) throw new Error(`header len ${e.ys_header_len()} != 112`);
{
  const pk = packOnce();
  const plain = unpackOnce(pk.ptr, pk.len, 8192);
  if (hex(plain) !== hex(data)) throw new Error("contract unpack mismatch");
  // 首版 7 参原型：传公钥 / 传 NULL 都必须还能用（不能因签名变更静默踩内存）
  if (hex(unpackOnce(pk.ptr, pk.len, 8192, false, senderPubPtr)) !== hex(data)) {
    throw new Error("legacy ys_unpack(pub) mismatch");
  }
  if (hex(unpackOnce(pk.ptr, pk.len, 8192, false, 0)) !== hex(data)) {
    throw new Error("legacy ys_unpack(NULL) mismatch");
  }

  // meta（带发送方公钥）
  // v2（6 参）与首版（7 参，公钥可选）都要能取到元信息
  let rc = e.ys_unpack_meta_v2(pk.ptr, pk.len, recipientPrivPtr, 0, 0, lenPtr);
  expectRc(rc, -2, "meta v2 probe");
  const need = dv().getUint32(lenPtr, true);
  const mp = alloc(need);
  check(e.ys_unpack_meta_v2(pk.ptr, pk.len, recipientPrivPtr, mp, need, lenPtr), "meta v2");
  const mp2 = alloc(need);
  check(e.ys_unpack_meta(pk.ptr, pk.len, recipientPrivPtr, 0, mp2, need, lenPtr), "meta legacy(NULL)");
  const mp3 = alloc(need);
  check(e.ys_unpack_meta(pk.ptr, pk.len, recipientPrivPtr, senderPubPtr, mp3, need, lenPtr), "meta legacy(pub)");
  const meta = JSON.parse(Buffer.from(read(mp, need)).toString("utf8"));
  if (meta.name !== "报告.pdf" || meta.size !== data.length) throw new Error(`meta ${JSON.stringify(meta)}`);
  if (meta.sender_code !== code) throw new Error(`sender_code ${meta.sender_code} != ${code}`);

  // 篡改包内 SENDER_PUB → 验签失败（来源不能冒充）
  const tampered = new Uint8Array(pk.bytes);
  tampered[112 + 3] ^= 0x01;
  const tp = alloc(tampered.length);
  write(tp, tampered);
  const out = alloc(8192);
  if (e.ys_unpack_v2(tp, tampered.length, recipientPrivPtr, out, 8192, lenPtr) === 0) {
    throw new Error("tampered sender pub must fail");
  }
  // 改块密文 → 必失败
  const tampered2 = new Uint8Array(pk.bytes);
  tampered2[tampered2.length - 1] ^= 1;
  write(tp, tampered2);
  if (e.ys_unpack_v2(tp, tampered2.length, recipientPrivPtr, out, 8192, lenPtr) === 0) {
    throw new Error("tampered chunk must fail");
  }
  e.ys_free(tp, tampered.length);
  e.ys_free(out, 8192);
}

// P2：同一 seed 二次使用必须报错
{
  const s2 = crypto.randomBytes(32);
  const sp = alloc(s2.length);
  write(sp, s2);
  const sig1 = alloc(64);
  check(e.ys_sm2_sign(senderPrivPtr, sp, s2.length, msgPtrConst(), 4, sig1), "sign #1");
  expectRc(
    e.ys_sm2_sign(senderPrivPtr, sp, s2.length, msgPtrConst(), 4, sig1),
    -3,
    "reused seed",
  );
}

console.log(
  `SMOKE OK (wasm ${bytes.length}B, code=${code}-${chk}, layout=YSPK/1.0, exports=${Object.keys(e).length})`,
);
