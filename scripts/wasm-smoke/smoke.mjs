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
const fromHex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
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
  -29,
  "tampered tag", // CRYPTO_CHUNK_AUTH_FAILED（首版 -15 的规范值）
);

// ---- 用户码：wasm 两个入口（64B X‖Y / 65B wire）都必须等于原生冻结值
{
  const vecPath = new URL("../../vectors/user-code-vectors.json", import.meta.url);
  const vec = JSON.parse(fs.readFileSync(vecPath, "utf8"));
  for (const v of vec.vectors) {
    const p65 = fromHex(v.pub65);
    const p64 = p65.slice(1);
    const a64 = alloc(64); write(a64, p64);
    const a65 = alloc(65); write(a65, p65);
    const out64 = alloc(4), out65 = alloc(4);
    check(e.ys_user_code(a64, out64), "ys_user_code(64B)");
    check(e.ys_user_code_wire(a65, out65), "ys_user_code_wire(65B)");
    const c64 = Buffer.from(read(out64, 4)).toString("ascii");
    const c65 = Buffer.from(read(out65, 4)).toString("ascii");
    if (c64 !== v.code || c65 !== v.code) {
      throw new Error(`user_code ${v.name}: wasm64=${c64} wasm65=${c65} expect=${v.code}`);
    }
    const s64 = alloc(1), s65 = alloc(1);
    check(e.ys_check_symbol(a64, s64), "ys_check_symbol(64B)");
    check(e.ys_check_symbol_wire(a65, s65), "ys_check_symbol_wire(65B)");
    const k64 = Buffer.from(read(s64, 1)).toString("ascii");
    const k65 = Buffer.from(read(s65, 1)).toString("ascii");
    if (k64 !== v.check || k65 !== v.check) {
      throw new Error(`check_symbol ${v.name}: wasm=${k64}/${k65} expect=${v.check}`);
    }
    [a64, a65, out64, out65, s64, s65].forEach((p, i) => e.ys_free(p, [64, 65, 4, 4, 1, 1][i]));
  }
}

// ---- SM2 DER 验签（服务端/Core 口径）：用 vectors/sm2-verify-vectors.json 驱动
{
  const vecPath = new URL("../../vectors/sm2-verify-vectors.json", import.meta.url);
  const vec = JSON.parse(fs.readFileSync(vecPath, "utf8"));
  for (const v of vec.verify_vectors) {
    // executable:false 表示该条依赖 ABI 不具备的能力（如 userID 入参），不计分
    if (v.executable === false) continue;
    const pub = fromHex(v.pub65).slice(1); // ABI 64 字节 X‖Y
    const msg = fromHex(v.sig_input);
    const sig = fromHex(v.sig_der);
    const pubP = alloc(64); write(pubP, pub);
    const msgP = msg.length ? alloc(msg.length) : 0; // 空消息允许传 NULL
    if (msg.length) write(msgP, msg);
    const sigP = alloc(sig.length); write(sigP, sig);
    const rc = e.ys_sm2_verify_der(pubP, msgP, msg.length, sigP, sig.length);
    const got = rc === 1 ? true : rc === 0 ? false : null;
    if (got !== v.expect_verify) {
      throw new Error(`verify_der ${v.name}: rc=${rc} want ${v.expect_verify}`);
    }
    e.ys_free(pubP, 64);
    if (msg.length) e.ys_free(msgP, msg.length);
    e.ys_free(sigP, sig.length);
  }
}

// ---- 错误名：唯一格式 CRYPTO_*，旧数值能被解析为同一名字
{
  const nPtr = alloc(4);
  const probeName = (code) => {
    e.ys_error_name(code, 0, 0, nPtr); // 先问长度
    const n = dv().getUint32(nPtr, true);
    const buf = alloc(n);
    e.ys_error_name(code, buf, n, nPtr);
    const s = Buffer.from(read(buf, n)).toString("ascii");
    e.ys_free(buf, n);
    return s;
  };
  const expect = {
    "-7": "CRYPTO_TRUNCATED",
    "-18": "CRYPTO_TRAILING_BYTES",
    "-27": "CRYPTO_LENGTH_INCONSISTENT",
    "-28": "CRYPTO_CHUNK_ORDER",
    "-11": "CRYPTO_CHUNK_ORDER", // 首版别名
    "-29": "CRYPTO_CHUNK_AUTH_FAILED",
    "-15": "CRYPTO_CHUNK_AUTH_FAILED", // 首版别名
    "-30": "CRYPTO_CHUNK_MISSING",
    "-19": "CRYPTO_CIPHERTEXT_INVALID",
    "-20": "CRYPTO_CIPHERTEXT_INVALID", // 首版别名
    "-33": "CRYPTO_SENDER_MISMATCH",
    "-34": "CRYPTO_CURVE_INVALID",
  };
  for (const [code, name] of Object.entries(expect)) {
    const got = probeName(Number(code));
    if (got !== name) throw new Error(`error_name(${code}) = ${got}, want ${name}`);
  }
}

// ---- 打包/解包
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

function unpackOnce(packPtr, packLen, outCap, useV1 = true, senderArg = null) {
  const fn = useV1 ? e.ys_unpack_v1 : e.ys_unpack;
  const extra = useV1 ? null : senderArg;
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
  let rc = e.ys_unpack_meta_v1(pk.ptr, pk.len, recipientPrivPtr, 0, 0, lenPtr);
  expectRc(rc, -2, "meta v1 probe");
  const need = dv().getUint32(lenPtr, true);
  const mp = alloc(need);
  check(e.ys_unpack_meta_v1(pk.ptr, pk.len, recipientPrivPtr, mp, need, lenPtr), "meta v1");
  const mp2 = alloc(need);
  check(e.ys_unpack_meta(pk.ptr, pk.len, recipientPrivPtr, 0, mp2, need, lenPtr), "meta legacy(NULL)");
  const mp3 = alloc(need);
  check(e.ys_unpack_meta(pk.ptr, pk.len, recipientPrivPtr, senderPubPtr, mp3, need, lenPtr), "meta legacy(pub)");
  const meta = JSON.parse(Buffer.from(read(mp, need)).toString("utf8"));
  if (meta.name !== "报告.pdf" || meta.size !== data.length) throw new Error(`meta ${JSON.stringify(meta)}`);
  if (meta.sender_code !== code) throw new Error(`sender_code ${meta.sender_code} != ${code}`);

  // 只凭 prelude 取元信息（契约 §4.3/§8.1/§10.2）：应成功且标 scope=prelude / data_verified=false
  {
    const pkBytes = pk.bytes;
    const u64at = (off) => Number(new DataView(pkBytes.buffer, pkBytes.byteOffset + off, 8).getBigUint64(0, false));
    const preludeLen = 112 + 65 + 129 + u64at(40) + u64at(72);
    // 只给前 preludeLen 字节
    let rc = e.ys_unpack_meta_prelude(pk.ptr, preludeLen, recipientPrivPtr, 0, 0, lenPtr);
    expectRc(rc, -2, "meta_prelude probe");
    const need = dv().getUint32(lenPtr, true);
    const mp = alloc(need);
    check(e.ys_unpack_meta_prelude(pk.ptr, preludeLen, recipientPrivPtr, mp, need, lenPtr), "meta_prelude");
    const meta = JSON.parse(Buffer.from(read(mp, need)).toString("utf8"));
    if (meta.scope !== "prelude" || meta.data_verified !== false) {
      throw new Error(`meta_prelude flags: ${JSON.stringify(meta)}`);
    }
    if (meta.sender_code !== code || meta.size !== data.length) {
      throw new Error(`meta_prelude fields: ${JSON.stringify(meta)}`);
    }
    // 整包入口在 prelude-only 时必须拒绝（CRYPTO_TRUNCATED=-7）
    expectRc(
      e.ys_unpack_meta_v1(pk.ptr, preludeLen, recipientPrivPtr, mp, need, lenPtr),
      -7,
      "meta_v1 on prelude-only",
    );
    // prelude 少 1 字节 → 截断
    expectRc(
      e.ys_unpack_meta_prelude(pk.ptr, preludeLen - 1, recipientPrivPtr, mp, need, lenPtr),
      -7,
      "meta_prelude truncated",
    );
    e.ys_free(mp, need);
  }

  // ys_pack_v1：ABI 公钥同样是 64 字节 X‖Y（实现与头文件一致）
  {
    const ext = Buffer.from("bin");
    const extPtr2 = alloc(ext.length);
    write(extPtr2, ext);
    const seedV1 = crypto.randomBytes(32);
    const seedV1Ptr = alloc(seedV1.length);
    write(seedV1Ptr, seedV1);
    const argsV1 = [
      recipientPubPtr, senderPrivPtr,
      namePtr, name.length, mimePtr, mime.length, extPtr2, ext.length,
      BigInt(1_767_225_600_000), 1024,
      seedV1Ptr, seedV1.length, dataPtr, data.length,
    ];
    let rcV1 = e.ys_pack_v1(...argsV1, 0, 0, lenPtr);
    expectRc(rcV1, -2, "ys_pack_v1 probe");
    const needV1 = dv().getUint32(lenPtr, true);
    const outV1 = alloc(needV1);
    check(e.ys_pack_v1(...argsV1, outV1, needV1, lenPtr), "ys_pack_v1(64B pubkey)");
    const nV1 = dv().getUint32(lenPtr, true);
    if (hex(unpackOnce(outV1, nV1, 8192)) !== hex(data)) {
      throw new Error("ys_pack_v1 roundtrip mismatch");
    }
    e.ys_free(extPtr2, ext.length);
    e.ys_free(seedV1Ptr, seedV1.length);
    e.ys_free(outV1, needV1);
  }

  // 篡改包内 SENDER_PUB → 验签失败（来源不能冒充）
  const tampered = new Uint8Array(pk.bytes);
  tampered[112 + 3] ^= 0x01;
  const tp = alloc(tampered.length);
  write(tp, tampered);
  const out = alloc(8192);
  if (e.ys_unpack_v1(tp, tampered.length, recipientPrivPtr, out, 8192, lenPtr) === 0) {
    throw new Error("tampered sender pub must fail");
  }
  // 改块密文 → 必失败
  const tampered2 = new Uint8Array(pk.bytes);
  tampered2[tampered2.length - 1] ^= 1;
  write(tp, tampered2);
  if (e.ys_unpack_v1(tp, tampered2.length, recipientPrivPtr, out, 8192, lenPtr) === 0) {
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
