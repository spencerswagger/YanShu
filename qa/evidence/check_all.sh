#!/bin/sh
# 内核 head 一变就跑这一套：构建产物 → 证据二（生产路径）→ 用户码一致性。
#
# 用法：
#   ./check_all.sh <rune-crate-dir> [workdir] [--base-url http://127.0.0.1:18080]
#
# 设计意图：把"靠人记得去比"换成"一条命令"。head 前进后重跑本脚本，
# 三份结果都带 head 线索（wasm 字节数 + sha256），不会出现"结果对、产物旧"。
set -eu

crate="${1:-}"
work="${2:-/tmp/ys-checkall}"
base_url="${3:-}"
[ -n "$crate" ] || { echo "usage: $0 <rune-crate-dir> [workdir] [--base-url URL]" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)

rm -rf "$work"; mkdir -p "$work"

echo "== 0/4 构建 wasm + ys-tool =="
if ! command -v cc >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
fi
(cd "$crate" && CARGO_TARGET_DIR="$work/target" cargo build --release --target wasm32-unknown-unknown \
    && CARGO_TARGET_DIR="$work/target" cargo build --release --bin ys-tool) >"$work/build.log" 2>&1 || {
    echo "[BLOCKED] 构建失败，见 $work/build.log"; tail -15 "$work/build.log"; exit 2; }
WASM="$work/target/wasm32-unknown-unknown/release/yanshu_sm.wasm"
TOOL="$work/target/release/ys-tool"
SHA=$(sha256sum "$WASM" | cut -d' ' -f1)
BYTES=$(wc -c <"$WASM")
VER=$(node "$here/adapters/wasm_pack_probe.mjs" --wasm "$WASM" version)
echo "wasm: $BYTES 字节  sha256=$SHA"
echo "ys_version: $VER"

echo "== 1/4 自测（脚本自身）=="
python3 "$here/scan_plaintext.py" --selftest | tail -1
python3 "$here/tamper_probe.py" --selftest | tail -1

echo "== 2/4 用户码一致性（4 入口 + 归一化）=="
set +e
python3 "$here/check_code_consistency.py" --wasm "$WASM" --ys-tool "$TOOL" \
    ${base_url:+--base-url "$base_url"} --json-out "$work/code-consistency.json"
rc_code=$?
set -e

echo "== 3/5 prelude-only 元数据语义 =="
set +e
python3 "$here/check_prelude_meta.py" --wasm "$WASM" --json-out "$work/prelude-meta.json" | tail -4
rc_prelude=$?
set -e

echo "== 4/5 证据二（生产路径，单块 + 多块 + 变体）=="
"$here/run_evidence2_wasm.sh" "$crate" "$work/ev2" | tail -6
rc_ev2=$?

echo "== 5/5 汇总 =="
echo "  head 产物：$BYTES 字节  sha256=$SHA  ys_version=$VER"
echo "  用户码一致性：exit=$rc_code"
echo "  prelude-only 元数据：exit=$rc_prelude"
echo "  证据二：exit=$rc_ev2"
[ "$rc_code" -eq 0 ] && [ "$rc_prelude" -eq 0 ] && [ "$rc_ev2" -eq 0 ]
