// 只做一件事：加载 wasm，对 vectors/user-code-vectors.json 里的每条公钥调用
// ys_user_code(64B X‖Y) 与 ys_user_code_wire(65B)，把结果打成 JSON 供
// crypto/sm/tests/wasm_user_code.rs 在 cargo test 里断言。
//
// 用法：node scripts/wasm-smoke/user-code-check.mjs <wasm> <vectors.json>

import fs from "node:fs";

const [, , wasmPath, vecPath] = process.argv;
const bytes = fs.readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const e = instance.exports;
const u8 = () => new Uint8Array(e.memory.buffer);

const vec = JSON.parse(fs.readFileSync(vecPath, "utf8"));
const out = [];
for (const v of vec.vectors) {
  const p65 = Uint8Array.from(Buffer.from(v.pub65, "hex"));
  const p64 = p65.slice(1);
  const a64 = e.ys_alloc(64), a65 = e.ys_alloc(65);
  const o64 = e.ys_alloc(4), o65 = e.ys_alloc(4);
  const s64 = e.ys_alloc(1), s65 = e.ys_alloc(1);
  u8().set(p64, a64);
  u8().set(p65, a65);
  const rc = [e.ys_user_code(a64, o64), e.ys_user_code_wire(a65, o65),
              e.ys_check_symbol(a64, s64), e.ys_check_symbol_wire(a65, s65)];
  out.push({
    name: v.name,
    expect_code: v.code,
    expect_check: v.check,
    code64: Buffer.from(u8().slice(o64, o64 + 4)).toString("ascii"),
    code65: Buffer.from(u8().slice(o65, o65 + 4)).toString("ascii"),
    check64: Buffer.from(u8().slice(s64, s64 + 1)).toString("ascii"),
    check65: Buffer.from(u8().slice(s65, s65 + 1)).toString("ascii"),
    rc,
  });
  [a64, a65, o64, o65, s64, s65].forEach((p, i) => e.ys_free(p, [64, 65, 4, 4, 1, 1][i]));
}
console.log(JSON.stringify(out));
