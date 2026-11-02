#!/bin/sh
# 构建 Gate 侧驱动 ys_pack_probe（依赖端侧内核 yanshu-sm 的源码）。
#
# 用法：
#   ./build_probe.sh <path-to-crypto/sm>
#
# 例（先把端侧分支取到本地任意目录）：
#   git -C /path/to/YanShu archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune
#   ./build_probe.sh /tmp/rune/crypto/sm
#
# 为什么不在仓库里放 Cargo.toml：`yanshu-sm` 不在 main 上，写死 path 依赖会让
# 本分支单独构建失败。这里改成"复制一份 crate 到临时目录 + 塞进一个 bin"，产物
# 在临时目录，仓库里只有源码，谁都能对着任意 checkout 复跑。
set -eu

crate="${1:-}"
if [ -z "$crate" ] || [ ! -f "$crate/Cargo.toml" ]; then
    echo "usage: $0 <path-to-crypto/sm>（需要能读到 Cargo.toml）" >&2
    exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
work="${YS_PROBE_BUILD_DIR:-/tmp/ys-probe-build}"

rm -rf "$work"
mkdir -p "$work"
# 只复制 crate 本身（不含 target/，避免把别人的构建产物一起搬）
(cd "$crate" && tar -cf - --exclude=target --exclude='*.wasm' .) | (cd "$work" && tar -xf -)
mkdir -p "$work/src/bin"
cp "$here/ys_pack_probe.rs" "$work/src/bin/ys_pack_probe.rs"

# 刻意**不继承** CARGO_TARGET_DIR：多人共用一个沙盒时，共享 target 目录会按
# 包名+版本复用别人编译出的 libyanshu_sm，等于拿别人的源码产出当成自己的证据。
# 要共享请显式给 YS_PROBE_TARGET_DIR。
target_dir="${YS_PROBE_TARGET_DIR:-$work/target}"

# 有些精简环境只有 gcc 没有 cc（rustc 默认调 cc）
if ! command -v cc >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
    RUSTFLAGS="${RUSTFLAGS:-} -C linker=gcc"
    export RUSTFLAGS
fi

CARGO_TARGET_DIR="$target_dir" cargo build --release \
    --manifest-path "$work/Cargo.toml" --bin ys_pack_probe 1>&2

probe="$target_dir/release/ys_pack_probe"
if [ ! -x "$probe" ]; then
    echo "构建失败：找不到 $probe" >&2
    exit 1
fi
echo "$probe"
