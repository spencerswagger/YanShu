#!/bin/sh
# 雁书 YanShu · GmSSL 逐字节交叉验证（一键复跑）
#
# 用法（在仓库任意位置执行）：
#   scripts/crosscheck/run.sh
#
# 前置条件：
#   1. 已编译好的 GmSSL 3.1.1 源码树：
#        <GMSSL_DIR>/include/gmssl/*.h
#        <GMSSL_DIR>/build/bin/libgmssl.a
#        <GMSSL_DIR>/build/bin/gmssl        （命令行，可选但建议有）
#      查找顺序：$GMSSL_DIR → /.cache/ys/GmSSL-3.1.1 → ../GmSSL-3.1.1 → /opt/GmSSL-3.1.1
#   2. Rust 工具链（wasm32 target 不需要，宿主即可）
#   3. python3
#
# 可选环境变量：
#   GMSSL_DIR=/path/to/GmSSL-3.1.1   指定源码树
#   GMSSL_BIN=/path/to/gmssl         指定 GmSSL 命令行
#   GMSSL_AUTOBUILD=1                找不到 GmSSL 时自动下载 v3.1.1 并用 cmake 编译（需要 cmake）
#   YS_TOOL=/path/to/ys-tool         跳过 cargo build，直接用现成二进制
#
# 产物：
#   tmp/crosscheck/oracle    链接 libgmssl.a 的交叉验证 oracle（覆盖 rand_bytes → 固定 k）
#   tmp/crosscheck/ys-tool   本实现的命令行工具
#
# 退出码：0 = 全部 PASS；1 = 有 FAIL；2 = 环境/前置缺失。
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BUILD="$ROOT/tmp/crosscheck"
mkdir -p "$BUILD"

# ---------- 定位 GmSSL
find_gmssl() {
	for cand in "${GMSSL_DIR:-}" "/.cache/ys/GmSSL-3.1.1" "$ROOT/../GmSSL-3.1.1" "/opt/GmSSL-3.1.1"; do
		[ -n "$cand" ] || continue
		if [ -f "$cand/build/bin/libgmssl.a" ] && [ -d "$cand/include/gmssl" ]; then
			printf '%s\n' "$cand"
			return 0
		fi
	done
	return 1
}

if ! GMSSL_DIR=$(find_gmssl); then
	if [ "${GMSSL_AUTOBUILD:-0}" = "1" ]; then
		command -v cmake >/dev/null 2>&1 || {
			echo "GMSSL_AUTOBUILD=1 但沙盒里没有 cmake；请先装 cmake 或手工编译 GmSSL" >&2
			exit 2
		}
		echo "==> 下载并编译 GmSSL v3.1.1 到 $BUILD/GmSSL-3.1.1"
		mkdir -p "$BUILD"
		curl -fsSL -o "$BUILD/gmssl.tar.gz" \
			https://codeload.github.com/guanzhi/GmSSL/tar.gz/refs/tags/v3.1.1
		tar xzf "$BUILD/gmssl.tar.gz" -C "$BUILD"
		(cd "$BUILD/GmSSL-3.1.1" && mkdir -p build && cd build &&
			cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF >/dev/null &&
			make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null)
		GMSSL_DIR="$BUILD/GmSSL-3.1.1"
	else
		echo "找不到编译好的 GmSSL 3.1.1（需要 include/ 与 build/bin/libgmssl.a）。" >&2
		echo "设置 GMSSL_DIR=/path/to/GmSSL-3.1.1，或用 GMSSL_AUTOBUILD=1 自动下载编译。" >&2
		exit 2
	fi
fi

GMSSL_BIN="${GMSSL_BIN:-$GMSSL_DIR/build/bin/gmssl}"
[ -x "$GMSSL_BIN" ] || {
	echo "警告：$GMSSL_BIN 不存在，将跳过命令行路径（只跑 libgmssl oracle）" >&2
	GMSSL_BIN=""
}

echo "==> GmSSL: $GMSSL_DIR"

# ---------- 编译 oracle
echo "==> 编译 oracle（链接 libgmssl.a）"
gcc -O2 -I "$GMSSL_DIR/include" "$SCRIPT_DIR/oracle.c" \
	"$GMSSL_DIR/build/bin/libgmssl.a" -o "$BUILD/oracle"

# ---------- 编译 ys-tool
if [ -z "${YS_TOOL:-}" ]; then
	echo "==> 编译 ys-tool"
	if ! command -v cc >/dev/null 2>&1; then
		# 有的镜像只有 gcc 没有 cc，rustc 默认 linker 是 cc
		CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
		export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
	fi
	(cd "$ROOT/crypto" && cargo build --release --bin ys-tool >/dev/null)
	YS_TOOL="${CARGO_TARGET_DIR:-$ROOT/crypto/target}/release/ys-tool"
fi

[ -x "$YS_TOOL" ] || {
	echo "ys-tool 不可执行：$YS_TOOL" >&2
	exit 2
}

# ---------- 若向量文件缺失，先生成
if [ ! -f "$ROOT/testdata/vectors.json" ]; then
	echo "==> testdata/vectors.json 缺失，重新生成"
	(cd "$ROOT/crypto" && cargo run --release --bin gen-vectors -- "$ROOT/testdata/vectors.json" >/dev/null)
fi

# ---------- 跑比对
GMSSL_ORACLE="$BUILD/oracle" \
GMSSL_BIN="$GMSSL_BIN" \
YS_TOOL="$YS_TOOL" \
	python3 "$SCRIPT_DIR/crosscheck.py"
