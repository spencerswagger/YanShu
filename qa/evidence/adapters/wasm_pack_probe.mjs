// Gate 侧 wasm 驱动：直接通过 raw C ABI（生产导出路径）打包 / 解包。
//
// 为什么要这个：Rust 原生 API 只能算"测试入口"，浏览器里真正跑的是 wasm32 + C ABI。
// 这个脚本让证据二能标 `--entry-kind production`：同一个 .wasm 里的 `ys_pack_v1` /
// `ys_unpack` 就是 Web 将来要调的那些导出。
//
// 用法（输出契约与 Rust 探针一致，便于 tamper_probe 直接换驱动）：
//   node wasm_pack_probe.mjs keygen <sk-out> <pk-out>
//   node wasm_pack_probe.mjs pack   <in> <out> --recipient-pk <f> --sender-sk <f>
//                        [--name N] [--mime M] [--ext E] [--created-at-ms N] [--chunk-size N]
//   node wasm_pack_probe.mjs unpack <in> <out> --recipient-sk <f>
//
//   成功 → 写输出文件 + `OK <len> [<块数>]`，退出码 0
//   失败 → 不写输出 + `ERR <错误名>`，退出码 1
//   参数/IO → `probe: <原因>`，退出码 2
//
// wasm 里没有 OS 随机源：密钥与包都用 `crypto.randomBytes(32)` 作 seed（一次性）。

import fs from "node:fs";
import crypto from "node:crypto";

function die(msg) {
  console.error(`probe: ${msg}`);
  process.exit(2);
}

// 全局选项 --wasm <path>（也认 YS_WASM）；其余参数是子命令
let wasmFile = process.env.YS_WASM || "";
const rest = [];
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === "--wasm") { wasmFile = process.argv[++i]; continue; }
  rest.push(process.argv[i]);
}
if (!wasmFile) die("需要 --wasm <path> 或 YS_WASM");

const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmFile), {});
const e = instance.exports;
const u8 = () => new Uint8Array(e.memory.buffer);
const dv = () => new DataView(e.memory.buffer);

function alloc(n) {
  const p = e.ys_alloc(n);
  if (!p) die("ys_alloc failed");
  return p;
}
function write(ptr, data) {
  u8().set(data, ptr);
}
function read(ptr, n) {
  return Buffer.from(u8().slice(ptr, ptr + n));
}
function errName(code) {
  const cap = 64;
  const p = alloc(cap);
  const lp = alloc(8);
  e.ys_error_name(code, p, cap, lp);
  const n = dv().getUint32(lp, true);
  const s = Buffer.from(read(p, n)).toString("ascii");
  e.ys_free(p, cap);
  e.ys_free(lp, 8);
  return s || `rc${code}`;
}

function opt(name) {
  const i = rest.indexOf(name);
  return i >= 0 ? rest[i + 1] : undefined;
}

function readKey(path, len, what) {
  const b = fs.readFileSync(path);
  if (b.length !== len) die(`${what} (${path}) must be ${len} bytes, got ${b.length}`);
  return b;
}

// 调一个「cap 不足返回 -2 且把所需长度写进 out_len」的导出
function callSized(fn, capGuess) {
  let cap = capGuess;
  for (let attempt = 0; attempt < 4; attempt++) {
    const out = alloc(cap);
    const outLenPtr = alloc(8);
    const rc = fn(out, cap, outLenPtr);
    const outLen = dv().getUint32(outLenPtr, true);
    if (rc === 0) {
      const data = read(out, outLen);
      e.ys_free(out, cap);
      e.ys_free(outLenPtr, 8);
      return data;
    }
    e.ys_free(out, cap);
    e.ys_free(outLenPtr, 8);
    if (rc === -2 && outLen > cap) {
      cap = outLen;
      continue;
    }
    throw { code: rc };
  }
  throw { code: -2 };
}

const mode = rest[0];

if (mode === "meta" || mode === "meta-prelude") {
  // meta：整包元信息（_v1 6 参 / 旧 7 参传 0）；meta-prelude：只给 prelude 也要能解
  const inPath = rest[1];
  if (!inPath) die(`${mode} <pack> --recipient-sk <f> [--v1]`);
  const pack = fs.readFileSync(inPath);
  const skBytes = readKey(opt("--recipient-sk"), 32, "recipient-sk");
  const pp = alloc(pack.length || 1), skp = alloc(32);
  write(pp, pack); write(skp, skBytes);
  const wantV1 = rest.includes("--v1");
  let fn;
  if (mode === "meta-prelude") {
    fn = e.ys_unpack_meta_prelude;
    if (typeof fn !== "function") die("内核没有导出 ys_unpack_meta_prelude");
    if (fn.length !== 6) die(`ys_unpack_meta_prelude arity=${fn.length}，期望 6`);
  } else if (wantV1) {
    fn = e.ys_unpack_meta_v1;
    if (typeof fn !== "function") die("内核没有导出 ys_unpack_meta_v1");
    if (fn.length !== 6) die(`ys_unpack_meta_v1 arity=${fn.length}，期望 6`);
  } else {
    fn = e.ys_unpack_meta;
    if (typeof fn !== "function") die("内核没有导出 ys_unpack_meta");
    if (fn.length !== 7) die(`ys_unpack_meta arity=${fn.length}，期望 7`);
  }
  try {
    const out = callSized((buf, cap, lenPtr) =>
      fn.length === 6 ? fn(pp, pack.length, skp, buf, cap, lenPtr)
                      : fn(pp, pack.length, skp, 0, buf, cap, lenPtr), 4096);
    console.log(out.toString("utf8"));
  } catch (err) {
    console.log(`ERR ${errName(err.code)}`);
    process.exit(1);
  }
} else if (mode === "exports") {
  // 打印导出清单：函数数 + 是否有 memory + 名称（供内核同源/完整性二级校验）
  const names = Object.keys(e).sort();
  const funcs = names.filter((n) => typeof e[n] === "function");
  console.log(JSON.stringify({
    count: names.length,
    functions: funcs.length,
    hasMemory: typeof e.memory !== "undefined",
    names,
  }));
} else if (mode === "check-symbol") {
  // ys_check_symbol(pub64, out1) / ys_check_symbol_wire(pub65, out1)
  const raw = Buffer.from((rest[1] || "").trim(), "hex");
  const wire = rest.includes("--wire");
  const fnName = wire ? "ys_check_symbol_wire" : "ys_check_symbol";
  const fn = e[fnName];
  if (typeof fn !== "function") die(`内核没有导出 ${fnName}`);
  if (fn.length !== 2) die(`${fnName} arity=${fn.length}，期望 2`);
  const buf = alloc(wire ? 65 : 64);
  write(buf, wire ? raw : (raw.length === 65 ? raw.subarray(1) : raw));
  const out = alloc(1);
  const rc = fn(buf, out);
  if (rc !== 0) { console.log(`ERR ${errName(rc)}`); process.exit(1); }
  console.log(Buffer.from(read(out, 1)).toString("ascii"));
} else if (mode === "user-code-wrong-width") {
  // **仅供反向用例**：故意把 65 字节（0x04‖X‖Y）喂给只收 64 字节的 `ys_user_code`，
  // 复现"错宽度静默算出另一个码"。生产调用路径绝不走这里。
  const raw = Buffer.from((rest[1] || "").trim(), "hex");
  if (raw.length !== 65) die("user-code-wrong-width 需要 65 字节公钥 hex");
  const fn = e.ys_user_code;
  if (typeof fn !== "function") die("内核没有导出 ys_user_code");
  const buf = alloc(65);
  write(buf, raw);            // 故意 65 字节，不做任何宽度纠正
  const out = alloc(4);
  const rc = fn(buf, out);
  if (rc !== 0) { console.log(`ERR ${errName(rc)}`); process.exit(1); }
  console.log(Buffer.from(read(out, 4)).toString("ascii"));
} else if (mode === "normalize") {
  // ys_normalize_code(input, len, out4)：非法输入返回负错误码（CRYPTO_CODE_INVALID）
  const text = Buffer.from(rest[1] ?? "", "utf8");
  const inp = alloc(text.length || 1);
  write(inp, text);
  const out = alloc(4);
  const rc = e.ys_normalize_code(inp, text.length, out);
  if (rc !== 0) { console.log(`ERR ${errName(rc)}`); process.exit(1); }
  console.log(Buffer.from(read(out, 4)).toString("ascii"));
} else if (mode === "user-code") {
  // 入参 64 字节 X‖Y（前端不用改）；内核内部补 0x04 后按 65 字节算 SM3
  const hexIn = (rest[1] || "").trim();
  const raw = Buffer.from(hexIn, "hex");
  if (raw.length !== 64 && raw.length !== 65) die("user-code 需要 64 或 65 字节公钥 hex");
  const pk = alloc(65);
  if (raw.length === 65) write(pk, raw);
  else { u8()[pk] = 0x04; write(pk + 1, raw); }
  // ys_user_code(pub64, out4) / ys_user_code_wire(pub65, out4)，都是 2 参
  const wire = rest.includes("--wire");
  const fnName = wire ? "ys_user_code_wire" : "ys_user_code";
  const fn = e[fnName];
  if (typeof fn !== "function") die(`内核没有导出 ${fnName}`);
  if (fn.length !== 2) die(`${fnName} arity=${fn.length}，期望 2`);
  if (wire && raw.length !== 65) die("--wire 需要 65 字节公钥 hex");
  // 关键：**按入口的入参宽度准备缓冲区**。
  // 64 字节入口必须拿到纯 X‖Y；把 0x04‖X‖Y 喂给 64 字节入口会整体错位一位，
  // 算出一个不一样的码（X2EH 就是这么来的，不是内核算错）。
  // 规矩：公钥入参一律显式声明字节数并断言，不靠记忆（错一位会静默算出另一个码）
  const wantLen = wire ? 65 : 64;
  if (wire ? raw.length !== 65 : raw.length !== 64) {
    // 允许调用方传 65 给 64 入口（自动去前缀），但**必须显式**记录这一步
    if (!wire && raw.length === 65 && raw[0] === 0x04) {
      // ok：去前缀后是 64
    } else {
      die(`${fnName} 需要 ${wantLen} 字节公钥，收到 ${raw.length}（带 0x04 的 65 字节只能给 _wire 入口）`);
    }
  }
  const buf = alloc(wantLen);
  write(buf, wire ? (raw.length === 65 ? raw : Buffer.concat([Buffer.from([0x04]), raw]))
                  : (raw.length === 65 ? raw.subarray(1) : raw));
  const out = alloc(4);
  const rc = fn(buf, out);
  if (rc !== 0) die(`ys_user_code: ${errName(rc)}`);
  console.log(Buffer.from(read(out, 4)).toString("ascii"));
} else if (mode === "version") {
  // ys_version() 是 u32，按 major.minor.patch(8.8.16) 解
  const v = e.ys_version();
  console.log(`0x${v.toString(16).padStart(8, "0")} ${(v >>> 24)}.${(v >>> 16) & 0xff}.${v & 0xffff}`);
} else if (mode === "keygen") {
  const [skOut, pkOut] = rest.slice(1);
  if (!skOut || !pkOut) die("keygen <sk-out> <pk-out>");
  const seed = crypto.randomBytes(32);
  const sp = alloc(seed.length), priv = alloc(32), pub = alloc(64);
  write(sp, seed);
  const rc = e.ys_sm2_keygen(sp, seed.length, priv, pub);
  if (rc !== 0) die(`ys_sm2_keygen: ${errName(rc)}`);
  fs.writeFileSync(skOut, read(priv, 32));
  fs.writeFileSync(pkOut, read(pub, 64));
  e.ys_free(sp, seed.length); e.ys_free(priv, 32); e.ys_free(pub, 64);
  console.log(`OK 32 64`);
} else if (mode === "pack") {
  const [inPath, outPath] = rest.slice(1, 3);
  if (!inPath || !outPath) die("pack <in> <out> --recipient-pk <f> --sender-sk <f>");
  const data = fs.readFileSync(inPath);
  // ABI 口径（头文件「公钥口径表」）：入参一律 64 字节 X‖Y，**不带 0x04**；
  // 0x04‖X‖Y 只出现在包内 SENDER_PUB。传 65 字节会被当成坐标解析 → CRYPTO_CURVE_INVALID。
  const pkRaw = fs.readFileSync(opt("--recipient-pk") ?? die("--recipient-pk required"));
  const recipientPk = pkRaw.length === 65 && pkRaw[0] === 0x04 ? pkRaw.subarray(1)
    : pkRaw.length === 64 ? pkRaw
    : die(`recipient-pk must be 64 bytes X||Y (or 65 with 0x04 prefix), got ${pkRaw.length}`);
  const senderSk = readKey(opt("--sender-sk"), 32, "sender-sk");
  const name = Buffer.from(opt("--name") ?? "probe.bin", "utf8");
  const mime = Buffer.from(opt("--mime") ?? "application/octet-stream", "ascii");
  const ext = Buffer.from(opt("--ext") ?? "bin", "ascii");
  const createdAt = BigInt(opt("--created-at-ms") ?? "1767225600000");
  const chunkSize = Number(opt("--chunk-size") ?? (1 << 20));
  const seed = crypto.randomBytes(32);

  const pk = alloc(64), sk = alloc(32), nm = alloc(name.length || 1), mi = alloc(mime.length || 1);
  const ex = alloc(ext.length || 1), dt = alloc(data.length || 1), sd = alloc(32);
  write(pk, recipientPk); write(sk, senderSk); write(nm, name); write(mi, mime);
  write(ex, ext); write(dt, data); write(sd, seed);

  try {
    const pack = callSized((out, cap, outLen) =>
      e.ys_pack_v1(pk, sk, nm, name.length, mi, mime.length, ex, ext.length,
        createdAt, chunkSize, sd, 32, dt, data.length, out, cap, outLen),
      data.length + 4096);
    fs.writeFileSync(outPath, pack);
    console.log(`OK ${pack.length} ${data.length}`);
  } catch (err) {
    console.log(`ERR ${errName(err.code)}`);
    process.exit(1);
  }
} else if (mode === "unpack") {
  const [inPath, outPath] = rest.slice(1, 3);
  if (!inPath || !outPath) die("unpack <in> <out> --recipient-sk <f>");
  const pack = fs.readFileSync(inPath);
  const skBytes = readKey(opt("--recipient-sk"), 32, "recipient-sk");
  const pp = alloc(pack.length || 1), skp = alloc(32);
  write(pp, pack); write(skp, skBytes);
  try {
    // 优先用 6 参的 ys_unpack_v2（不需要发送方公钥）；没有就退回 7 参原型并把公钥传 0。
    // 注意：wasm 会静默丢弃多余实参并整体错位（out 收到公钥指针 → 内存踩踏），所以两条路
    // 必须精确匹配各自的原型，不能混传。
    // wasm 导出函数的 .length 就是形参个数：**先断言 arity 再调用**。
    // 踩过的坑：6 参实参去调 7 参的 ys_unpack 不会报错，而是整体错位一位
    //（out 收到公钥指针、out_len 收到容量数字）→ 内存踩踏。这里宁可硬失败。
    const sixAri = (fn, name) => {
      if (fn.length !== 6) die(`${name} arity=${fn.length}，期望 6；拒绝调用（错位会踩内存）`);
      return fn;
    };
    const sevenAri = (fn, name) => {
      if (fn.length !== 7) die(`${name} arity=${fn.length}，期望 7；拒绝调用`);
      return fn;
    };
    let unpackFn;
    // 现行 6 参名是 ys_unpack_v1（曾短暂叫 _v2，保留这一层兼容）
    if (typeof e.ys_unpack_v1 === "function") {
      const f = sixAri(e.ys_unpack_v1, "ys_unpack_v1");
      unpackFn = (out, cap, outLen) => f(pp, pack.length, skp, out, cap, outLen);
    } else if (typeof e.ys_unpack_v2 === "function") {
      const f = sixAri(e.ys_unpack_v2, "ys_unpack_v2");
      unpackFn = (out, cap, outLen) => f(pp, pack.length, skp, out, cap, outLen);
    } else {
      const f = sevenAri(e.ys_unpack, "ys_unpack");
      // 7 参原型：第 4 参 sender_pub_or_0 传 0 = 不与包内公钥比对
      unpackFn = (out, cap, outLen) => f(pp, pack.length, skp, 0, out, cap, outLen);
    }
    const plain = callSized(unpackFn, pack.length);
    fs.writeFileSync(outPath, plain);
    console.log(`OK ${plain.length}`);
  } catch (err) {
    // 失败路径绝不落任何明文
    console.log(`ERR ${errName(err.code)}`);
    process.exit(1);
  }
} else {
  die("subcommand required: keygen | pack | unpack");
}
