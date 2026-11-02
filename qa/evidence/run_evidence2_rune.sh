#!/bin/sh
# 一键复跑「证据二：密文篡改必报错」，对象是端侧内核的**真实实现**。
#
# 用法：
#   ./run_evidence2_rune.sh <path-to-crypto/sm> [workdir]
#
# <path-to-crypto/sm> 怎么来（任选）：
#   git -C <YanShu 仓库> archive origin/feat/endcrypto-wasm | tar -x -C /tmp/rune
#   → /tmp/rune/crypto/sm
#
# 做的事：构建探针 → 生成两对密钥 → 产 1 个单块包 + 2 个三块包（含 donor）
#        → 分别跑篡改检查（cmd 后端，baseline 必须解出与原文一致的明文）
# 产物（包、密钥、结果 JSON）都在 workdir，**不进仓库**。
set -eu

crate="${1:-}"
if [ -z "$crate" ]; then
    echo "usage: $0 <path-to-crypto/sm> [workdir]" >&2
    exit 2
fi
work="${2:-/tmp/ys-ev2}"
here=$(cd "$(dirname "$0")" && pwd)

echo "== 1/4 构建探针 =="
probe=$("$here/adapters/build_probe.sh" "$crate")
echo "probe: $probe"

echo "== 2/4 准备密钥与明文 =="
rm -rf "$work"
mkdir -p "$work"
"$probe" keygen "$work/alice.sk" "$work/alice.pk" >/dev/null
"$probe" keygen "$work/bob.sk" "$work/bob.pk" >/dev/null
python3 - "$work" <<'PY'
import os, sys, pathlib
w = pathlib.Path(sys.argv[1])
tok = os.urandom(24).hex()
w.joinpath("plain-small.bin").write_bytes(("yan-shu gate probe\n" + tok + "\n").encode())
multi = os.urandom(600) + ("鸿雁传书 " + tok).encode() + os.urandom(1400)
w.joinpath("plain-multi.bin").write_bytes(multi)
w.joinpath("plain-donor.bin").write_bytes(os.urandom(len(multi)))
print(f"明文：单块 {(w/'plain-small.bin').stat().st_size}B / 多块 {len(multi)}B")
PY

echo "== 3/4 打包 =="
"$probe" pack "$work/plain-small.bin" "$work/a.yspk" --recipient-pk "$work/bob.pk" \
    --sender-sk "$work/alice.sk" --name "验收样本-首夜.txt" --mime "text/plain" --block-size 1048576
"$probe" pack "$work/plain-multi.bin" "$work/b.yspk" --recipient-pk "$work/bob.pk" \
    --sender-sk "$work/alice.sk" --name "多块样本.bin" --mime "application/octet-stream" --block-size 1024
"$probe" pack "$work/plain-donor.bin" "$work/c.yspk" --recipient-pk "$work/bob.pk" \
    --sender-sk "$work/alice.sk" --name "donor.bin" --mime "application/octet-stream" --block-size 1024

decrypt="\"$probe\" unpack {in} {out} --recipient-sk \"$work/bob.sk\" --sender-pk \"$work/alice.pk\""

echo "== 4a/4 单块包 =="
python3 "$here/tamper_probe.py" --envelope "$work/a.yspk" --layout rune-v1 \
    --backend cmd --expect-plaintext "$work/plain-small.bin" --extra-cases \
    --decrypt-cmd "$decrypt" --error-regex 'ERR [A-Z_]+' \
    --json-out "$work/result-single.json"
rc_single=$?

echo "== 4b/4 多块包（3 块，含 donor）=="
python3 "$here/tamper_probe.py" --envelope "$work/b.yspk" --donor "$work/c.yspk" \
    --layout rune-v1 --backend cmd --expect-plaintext "$work/plain-multi.bin" --extra-cases \
    --decrypt-cmd "$decrypt" --error-regex 'ERR [A-Z_]+' \
    --json-out "$work/result-multi.json"
rc_multi=$?

echo "== 结果：单块 exit=$rc_single / 多块 exit=$rc_multi（0 = 全部篡改都被明确拒绝）=="
[ "$rc_single" -eq 0 ] && [ "$rc_multi" -eq 0 ]
