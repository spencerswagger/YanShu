#!/bin/sh
# ============================================================================
# 比对的最后一道关：源文件与落地文件的 sha256 必须**逐字相同**（完整 64 位十六进制）
#
# 用法：./verify-sha256.sh <源文件> <落地文件>
#
# 退出码：0 两侧一致 / 1 不一致或算不出 / 2 用法错误
# 说明：同时打印两侧的**字节数**——只比 sha 不比大小会漏掉「文件被截断但哈希巧合」这类事故。
# ============================================================================
set -u
[ $# -eq 2 ] || { echo "[BLOCKED] 用法：$0 <源文件> <落地文件>" >&2; exit 2; }
src="$1"; out="$2"
for f in "$src" "$out"; do
    [ -f "$f" ] || { echo "[FAIL] 文件不存在：$f" >&2; exit 1; }
done

h_src=$(sha256sum "$src" | cut -d' ' -f1)
h_out=$(sha256sum "$out" | cut -d' ' -f1)
b_src=$(wc -c < "$src" | tr -d ' ')
b_out=$(wc -c < "$out" | tr -d ' ')

printf '源文件   %s  %s  %s B\n' "$h_src" "$(basename "$src")" "$b_src"
printf '落地文件 %s  %s  %s B\n' "$h_out" "$(basename "$out")" "$b_out"

if [ "$h_src" = "$h_out" ] && [ "$b_src" = "$b_out" ]; then
    echo "判定：PASS —— sha256 完整 64 位逐字相同，字节数相同"
    exit 0
fi
[ "$h_src" != "$h_out" ] && echo "判定：FAIL —— sha256 不一致（源 ${h_src:0:16}… / 落地 ${h_out:0:16}…）"
[ "$b_src" != "$b_out" ] && echo "判定：FAIL —— 字节数不一致（源 $b_src / 落地 $b_out）"
exit 1
