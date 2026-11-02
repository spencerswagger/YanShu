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

if (mode === "keygen") {
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
  // 注意：头文件注释写 64，但实现读的是 65 字节并强制 0x04 前缀（见 ffi.rs）
  const pkRaw = fs.readFileSync(opt("--recipient-pk") ?? die("--recipient-pk required"));
  const recipientPk = pkRaw.length === 65 ? pkRaw
    : pkRaw.length === 64 ? Buffer.concat([Buffer.from([0x04]), pkRaw])
    : die(`recipient-pk must be 64 or 65 bytes, got ${pkRaw.length}`);
  const senderSk = readKey(opt("--sender-sk"), 32, "sender-sk");
  const name = Buffer.from(opt("--name") ?? "probe.bin", "utf8");
  const mime = Buffer.from(opt("--mime") ?? "application/octet-stream", "ascii");
  const ext = Buffer.from(opt("--ext") ?? "bin", "ascii");
  const createdAt = BigInt(opt("--created-at-ms") ?? "1767225600000");
  const chunkSize = Number(opt("--chunk-size") ?? (1 << 20));
  const seed = crypto.randomBytes(32);

  const pk = alloc(65), sk = alloc(32), nm = alloc(name.length || 1), mi = alloc(mime.length || 1);
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
    const unpackFn = typeof e.ys_unpack_v2 === "function"
      ? (out, cap, outLen) => e.ys_unpack_v2(pp, pack.length, skp, out, cap, outLen)
      : (out, cap, outLen) => e.ys_unpack(pp, pack.length, skp, 0, out, cap, outLen);
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
