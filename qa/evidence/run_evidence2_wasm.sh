#!/bin/sh
# 一键复跑「证据二：密文篡改必报错」——**生产导出路径**（wasm32 raw C ABI）。
#
# 用法：
#   ./run_evidence2_wasm.sh <path-to-crypto/sm> [workdir]
#
# 与 run_evidence2_contract.sh 的区别：那份走 Rust 原生 API（测试入口），
# 这份直接跑 `yanshu_sm.wasm` 里的 `ys_pack_v1` / `ys_unpack`——就是 Web 将来要调的导出。
#
# 产物（wasm、包、密钥、结果 JSON）都在 workdir，不入仓库。
set -eu

crate="${1:-}"
if [ -z "$crate" ]; then
    echo "usage: $0 <path-to-crypto/sm> [workdir]" >&2
    exit 2
fi
work="${2:-/tmp/ys-ev2-wasm}"
here=$(cd "$(dirname "$0")" && pwd)
driver="$here/adapters/wasm_pack_probe.mjs"

rm -rf "$work"; mkdir -p "$work"

echo "== 1/4 构建 wasm =="
# 只给 host 目标换 linker；wasm 目标必须用 rust-lld，不能被全局 RUSTFLAGS 带偏
if ! command -v cc >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
fi
(cd "$crate" && CARGO_TARGET_DIR="$work/target" cargo build --release \
    --target wasm32-unknown-unknown >"$work/build.log" 2>&1) || {
    echo "[BLOCKED] wasm 构建失败，日志尾部：" >&2; tail -15 "$work/build.log" >&2; exit 2; }
WASM="$work/target/wasm32-unknown-unknown/release/yanshu_sm.wasm"
[ -f "$WASM" ] || { echo "[BLOCKED] 找不到 $WASM" >&2; exit 2; }
echo "wasm: $WASM ($(wc -c <"$WASM") 字节)"

echo "== 2/4 密钥与明文 =="

node "$driver" --wasm "$WASM" keygen "$work/alice.sk" "$work/alice.pk" >/dev/null
node "$driver" --wasm "$WASM" keygen "$work/bob.sk" "$work/bob.pk" >/dev/null
python3 - "$work" <<'PY'
import os, sys, pathlib
w = pathlib.Path(sys.argv[1])
w.joinpath("plain-small.bin").write_bytes(b"yn-shu wasm probe\n" + os.urandom(8).hex().encode() + b"\n")
marker = "鸿雁传书 wasm".encode()
multi = os.urandom(1400) + marker + os.urandom(3072 - 1400 - len(marker))
w.joinpath("plain-multi.bin").write_bytes(multi)      # 3 块等长（1024×3），删块/换序都能构造
w.joinpath("plain-donor.bin").write_bytes(os.urandom(3072))
print(f"明文：单块 {(w/'plain-small.bin').stat().st_size}B / 多块 {len(multi)}B")
PY

echo "== 3/4 打包（wasm C ABI）=="
node "$driver" --wasm "$WASM" pack "$work/plain-small.bin" "$work/a.yspk" \
    --recipient-pk "$work/bob.pk" --sender-sk "$work/alice.sk" \
    --name "验收样本-首夜.txt" --mime text/plain --ext txt --chunk-size 1048576
node "$driver" --wasm "$WASM" pack "$work/plain-multi.bin" "$work/b.yspk" \
    --recipient-pk "$work/bob.pk" --sender-sk "$work/alice.sk" \
    --name "多块样本.bin" --mime application/octet-stream --ext bin --chunk-size 1024
node "$driver" --wasm "$WASM" pack "$work/plain-donor.bin" "$work/c.yspk" \
    --recipient-pk "$work/bob.pk" --sender-sk "$work/alice.sk" \
    --name "donor.bin" --mime application/octet-stream --ext bin --chunk-size 1024

decrypt="node \"$driver\" --wasm \"$WASM\" unpack {in} {out} --recipient-sk \"$work/bob.sk\""

echo "== 4a/4 单块包（只覆盖翻字节类，删块/换序/搬块/截断必然 SKIP → 单块跑批本身 INCONCLUSIVE 属预期）=="
set +e
python3 "$here/tamper_probe.py" --envelope "$work/a.yspk" \
    --backend cmd --entry-kind production --expect-plaintext "$work/plain-small.bin" \
    --extra-cases --error-regex 'ERR [A-Z_]+' \
    --decrypt-cmd "$decrypt" --json-out "$work/result-single.json"
rc_single=$?
set -e

echo "== 4b/4 多块包（3 等长块，含 donor；这一份才是判定依据）=="
set +e
python3 "$here/tamper_probe.py" --envelope "$work/b.yspk" --donor "$work/c.yspk" \
    --backend cmd --entry-kind production --expect-plaintext "$work/plain-multi.bin" \
    --extra-cases --error-regex 'ERR [A-Z_]+' \
    --decrypt-cmd "$decrypt" --json-out "$work/result-multi.json"
rc_multi=$?
set -e

echo "== 结果：单块 exit=$rc_single（2=INCONCLUSIVE 属预期）/ 多块 exit=$rc_multi（0 = 五类篡改全被明确拒绝）=="
# 判定：多块是权威；单块若 FAIL(1) 也必须算 FAIL（结构性缺陷），单块 INCONCLUSIVE(2) 不降级
if [ "$rc_multi" -eq 0 ] && [ "$rc_single" -ne 1 ]; then exit 0; fi
if [ "$rc_single" -eq 1 ] || [ "$rc_multi" -eq 1 ]; then exit 1; fi
exit 2
