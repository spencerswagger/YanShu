#!/bin/sh
# 雁书 YanShu · 测试向量比对（一键复跑）
#
# 用法（在仓库任意位置执行）：
#   scripts/crosscheck/run.sh                      # 有 GmSSL 就本地比，没有就用宿主对照值
#   scripts/crosscheck/run.sh --emit-template      # 生成宿主侧对照值模板
#   scripts/crosscheck/run.sh --no-local           # 只用 testdata/gmssl-expected.json
#
# 对照值来源（两个都支持，有几个比几个）：
#   1. 本机 GmSSL 3.1.1：<GMSSL_DIR>/include/gmssl/*.h + build/bin/libgmssl.a + build/bin/gmssl
#      查找顺序：$GMSSL_DIR → /.cache/ys/GmSSL-3.1.1 → ../GmSSL-3.1.1 → /opt/GmSSL-3.1.1
#      找不到**不算失败**：脚本继续跑，相关条目打印 "SKIP 待宿主对照"。
#   2. 宿主侧对照值：testdata/gmssl-expected.json（先 --emit-template 生成模板再填）
#
# 可选环境变量：
#   GMSSL_DIR=/path/to/GmSSL-3.1.1
#   GMSSL_BIN=/path/to/gmssl
#   GMSSL_AUTOBUILD=1                找不到时自动下载 v3.1.1 并用 cmake 编译（需要 cmake）
#   YS_TOOL=/path/to/ys-tool         跳过 cargo build
#
# 退出码：0 = 无 FAIL（可能全是 SKIP）；1 = 有 FAIL；2 = 环境/前置缺失。
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BUILD="$ROOT/tmp/crosscheck"
mkdir -p "$BUILD"

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

GMSSL_ORACLE=""
GMSSL_BIN=""
if GMSSL_DIR=$(find_gmssl); then
	echo "==> GmSSL: $GMSSL_DIR"
	echo "==> 编译 oracle（链接 libgmssl.a，覆盖 rand_bytes 以固定 SM2 的 k）"
	gcc -O2 -I "$GMSSL_DIR/include" "$SCRIPT_DIR/oracle.c" \
		"$GMSSL_DIR/build/bin/libgmssl.a" -o "$BUILD/oracle"
	GMSSL_ORACLE="$BUILD/oracle"
	GMSSL_BIN="${GMSSL_BIN:-$GMSSL_DIR/build/bin/gmssl}"
	if [ ! -x "$GMSSL_BIN" ]; then
		echo "警告：$GMSSL_BIN 不可用，SM3/SM4-GCM 命令行比对将跳过" >&2
		GMSSL_BIN=""
	fi
elif [ "${GMSSL_AUTOBUILD:-0}" = "1" ]; then
	command -v cmake >/dev/null 2>&1 || {
		echo "GMSSL_AUTOBUILD=1 但没有 cmake；先装 cmake 或手工编译 GmSSL" >&2
		exit 2
	}
	echo "==> 下载并编译 GmSSL v3.1.1 到 $BUILD/GmSSL-3.1.1"
	curl -fsSL -o "$BUILD/gmssl.tar.gz" \
		https://codeload.github.com/guanzhi/GmSSL/tar.gz/refs/tags/v3.1.1
	tar xzf "$BUILD/gmssl.tar.gz" -C "$BUILD"
	(cd "$BUILD/GmSSL-3.1.1" && mkdir -p build && cd build &&
		cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF >/dev/null &&
		make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null)
	gcc -O2 -I "$BUILD/GmSSL-3.1.1/include" "$SCRIPT_DIR/oracle.c" \
		"$BUILD/GmSSL-3.1.1/build/bin/libgmssl.a" -o "$BUILD/oracle"
	GMSSL_ORACLE="$BUILD/oracle"
	GMSSL_BIN="$BUILD/GmSSL-3.1.1/build/bin/gmssl"
else
	echo "==> 未找到本机 GmSSL：本次只用宿主对照值（testdata/gmssl-expected.json）"
	echo "    没有该文件时，相关条目会打印 'SKIP 待宿主对照'，不算失败。"
fi

# ---- ys-tool（反向验证/解包需要；顺带当构建自检）
if [ -z "${YS_TOOL:-}" ]; then
	echo "==> 编译 ys-tool"
	if ! command -v cc >/dev/null 2>&1; then
		CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
		export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
	fi
	# 产物路径以 cargo 自报的为准。不能只用 shell 里的 $CARGO_TARGET_DIR 去拼：
	# 沙盒/CI 的 cargo 包装脚本会把 target 目录挪走（例如 /.cache/rust），而那个变量
	# 只对 cargo 子进程生效 —— 拼出来的路径根本不存在，crosscheck 会在 SM4-GCM 段
	# 以 "No such file or directory: .../crypto/target/release/ys-tool" 中断（退出码 1）。
	build_json="$BUILD/cargo-build.json"
	if ! (cd "$ROOT/crypto" && cargo build --release --bin ys-tool --message-format=json-render-diagnostics >"$build_json"); then
		echo "!! cargo build --release --bin ys-tool 失败（编译错误见上；不静默降级）" >&2
		exit 2
	fi
	YS_TOOL=$(python3 -c 'import json,sys
paths=[]
for line in sys.stdin:
    line=line.strip()
    if not line.startswith("{"):
        continue
    try:
        m=json.loads(line)
    except Exception:
        continue
    if (m.get("reason")=="compiler-artifact" and m.get("executable")
            and m.get("target",{}).get("name")=="ys-tool"):
        paths.append(m["executable"])
print(paths[-1] if paths else "")' <"$build_json")
	if [ -z "$YS_TOOL" ] || [ ! -x "$YS_TOOL" ]; then
		echo "!! 无法确定 ys-tool 产物路径（cargo --message-format=json-render-diagnostics 没有报出 executable）" >&2
		echo "   可显式指定：YS_TOOL=/path/to/ys-tool sh scripts/crosscheck/run.sh" >&2
		exit 2
	fi
	echo "    ys-tool: $YS_TOOL"
fi

# ---- 向量缺失则先生成
if [ ! -f "$ROOT/testdata/vectors.json" ]; then
	echo "==> testdata/vectors.json 缺失，重新生成"
	(cd "$ROOT/crypto" && cargo run --release --bin gen-vectors -- "$ROOT/testdata/vectors.json" >/dev/null)
fi

GMSSL_ORACLE="$GMSSL_ORACLE" \
GMSSL_BIN="$GMSSL_BIN" \
YS_TOOL="$YS_TOOL" \
	python3 "$SCRIPT_DIR/crosscheck.py" "$@"
