#!/bin/sh
# 内核 head 一变就跑这一套：构建产物 → 自测 → 用户码一致性 → 契约一致性 → prelude 元数据 → 证据二。
#
# 用法：
#   ./check_all.sh <rune-crate-dir> [workdir] [--base-url http://127.0.0.1:18080]
#   ./check_all.sh --selftest          # 只验聚合逻辑（不需要 crate）
#
# 设计意图：把"靠人记得去比"换成"一条命令"。head 前进后重跑本脚本，
# 三份结果都带 head 线索（wasm 字节数 + sha256），不会出现"结果对、产物旧"。
#
# 退出码（三态，别把"没跑"当"通过"）：
#   0  PASS          —— 所有步骤都真跑且全部通过
#   1  FAIL          —— 任一步判定失败
#   2  INCONCLUSIVE  —— 有步骤**没跑**（缺参数/被跳过）或自身判不出结论；**绝不当 PASS**
#   4  PENDING       —— 参数/依赖缺失，连一步都跑不起来（与单脚本语义一致）
# CI 环境下：出现 INCONCLUSIVE 一律非 0（即 2），不会因为"跳过"而绿。
#
# 示例：
#   YS_OLD_BINARY=… YS_NEW_BINARY=… YS_BASE_DSN=… YS_SERVER_DIR=… ./check_all.sh <crate>
set -eu

EXIT_PASS=0
EXIT_FAIL=1
EXIT_INCONCLUSIVE=2
EXIT_PENDING=4

ci_mode=0
if [ -n "${CI:-}" ]; then ci_mode=1; fi

# 每步的输出先落文件、再 tail 展示；rc 取**命令本身**的。
# 反面教材：`python3 x.py | tail -5` 之后 $? 是 tail 的（恒 0）——真 FAIL 会被吞成 PASS。
# 这里选"落文件再 tail"（不依赖 bash 的 pipefail/PIPESTATUS，/bin/sh 也能用）。
run_step() {          # run_step <行数> <日志文件> <命令...>
    rs_lines=$1; rs_log=$2; shift 2
    "$@" >"$rs_log" 2>&1
    rs_rc=$?
    tail -n "$rs_lines" "$rs_log" 2>/dev/null || true
    return $rs_rc
}

not_run=""           # 空格分隔的"未跑步骤名"，汇总时点名

mark_not_run() {     # mark_not_run <名称>
    if [ -z "$not_run" ]; then not_run="$1"; else not_run="$not_run $1"; fi
}

# 三态聚合：FAIL > INCONCLUSIVE > PASS。结果写进全局 $verdict（函数恒返回 0，避免 set -e 误退）。
# 入参：若干 "名称:rc" 项；未跑/未判定步骤写进 $not_run 并点名打印。
aggregate() {
    has_fail=0
    has_incon=0
    for item in "$@"; do
        name=${item%:*}
        rc=${item##*:}
        case "$rc" in
            0) ;;
            2) mark_not_run "$name"; has_incon=1 ;;
            *) has_fail=1 ;;
        esac
    done
    if [ "$has_fail" -eq 1 ]; then worst=1
    elif [ "$has_incon" -eq 1 ]; then worst=2
    else worst=0
    fi
    if [ "$worst" -eq 0 ]; then
        echo "结论：PASS —— 所有步骤都真跑且全部通过"
        verdict=$EXIT_PASS
        return 0
    fi
    if [ "$worst" -eq 1 ]; then
        echo "结论：FAIL —— 至少一步判定失败"
        if [ -n "$not_run" ]; then echo "  （另有未跑/未判定步骤：$not_run —— 它们不计入 PASS）"; fi
        verdict=$EXIT_FAIL
        return 0
    fi
    echo "结论：INCONCLUSIVE —— 以下步骤未跑或判不出结论：$not_run"
    echo "      未跑 ≠ 通过；补参数后重跑，或改用 --selftest 单独验聚合逻辑"
    if [ "$ci_mode" -eq 1 ]; then echo "      （CI 环境：未跑一律非 0）"; fi
    verdict=$EXIT_INCONCLUSIVE
    return 0
}

# ---------------------------------------------------------------- 自测
if [ "${1:-}" = "--selftest" ]; then
    echo "== check_all.sh --selftest（只验聚合三态，不需要 crate）=="
    rc_all=0

    not_run=""; verdict=-1
    aggregate "code:0" "prelude:0" "ev2:0" "kernel:0" "upgrade:0" "parity:0" >/tmp/ca-1.txt 2>&1
    if [ "$verdict" -ne 0 ]; then echo "  FAIL 全跑全过应 exit 0，实得 $verdict"; rc_all=1
    else echo "  PASS 全跑全过 → exit 0"; fi

    not_run=""; verdict=-1
    aggregate "code:0" "prelude:0" "ev2:0" "kernel:2" "upgrade:2" "parity:0" >/tmp/ca-2.txt 2>&1
    if [ "$verdict" -ne 2 ]; then echo "  FAIL upgrade/kernel 未跑应 exit 2，实得 $verdict"; rc_all=1
    else
        if grep -q "kernel" /tmp/ca-2.txt && grep -q "upgrade" /tmp/ca-2.txt; then
            echo "  PASS upgrade/kernel 未跑 → exit 2，且点名两步：$(grep '结论：INCONCLUSIVE' /tmp/ca-2.txt)"
        else echo "  FAIL exit 2 但没点名未跑的步骤"; rc_all=1; fi
    fi

    not_run=""; verdict=-1
    aggregate "code:0" "prelude:0" "ev2:1" "kernel:2" "upgrade:2" "parity:0" >/tmp/ca-3.txt 2>&1
    if [ "$verdict" -ne 1 ]; then echo "  FAIL 有 FAIL 又有未跑应 exit 1（FAIL 优先），实得 $verdict"; rc_all=1
    else echo "  PASS FAIL 优先于 INCONCLUSIVE → exit 1"; fi

    not_run=""; verdict=-1
    aggregate "code:0" "prelude:0" "ev2:0" "kernel:2" "upgrade:2" "parity:0" >/tmp/ca-4.txt 2>&1
    case "$verdict" in
        0) echo "  FAIL 未跑却 exit 0（正是要被堵掉的行为）"; rc_all=1 ;;
        2) echo "  PASS 未跑不计入 PASS（exit 2，非 0）" ;;
        *) echo "  FAIL 未跑应 exit 2，实得 $verdict"; rc_all=1 ;;
    esac

    # 管道不吞退出码：run_step 必须拿到命令自身的 rc（而不是 tail 的 0）
    set +e
    run_step 1 /tmp/ca-5.log sh -c 'echo pipeline-demo; exit 7' >/dev/null 2>&1
    rc_demo=$?
    set -e
    if [ "$rc_demo" -ne 7 ]; then
        echo "  FAIL run_step 应取到 rc=7，实得 $rc_demo（管道吞退出码的回归又回来了）"; rc_all=1
    else
        echo "  PASS run_step 取命令自身 rc=7（不被 tail 吞）"
    fi

    # 某步真 FAIL → 聚合 1（只有这一条 FAIL，其余全过）
    not_run=""; verdict=-1
    aggregate "selftest-scan:0" "selftest-tamper:0" "selftest-all:0" \
              "code:1" "parity:0" "kernel:0" "upgrade:0" "prelude:0" "ev2:0" >/tmp/ca-6.txt 2>&1
    if [ "$verdict" -ne 1 ]; then
        echo "  FAIL 单步 FAIL 应聚合为 exit 1，实得 $verdict"; rc_all=1
    else
        echo "  PASS 单步 FAIL → exit 1：$(grep '结论：FAIL' /tmp/ca-6.txt)"
    fi

    echo "自测：$([ "$rc_all" -eq 0 ] && echo PASS || echo FAIL)"
    exit "$rc_all"
fi

crate="${1:-}"
work="${2:-/tmp/ys-checkall}"
base_url="${3:-}"
[ -n "$crate" ] || { echo "usage: $0 <rune-crate-dir> [workdir] [--base-url URL] | --selftest" >&2; exit $EXIT_PENDING; }
here=$(cd "$(dirname "$0")" && pwd)

rm -rf "$work"; mkdir -p "$work"

echo "== 0/5 构建 wasm + ys-tool =="
if ! command -v cc >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
fi
(cd "$crate" && CARGO_TARGET_DIR="$work/target" cargo build --release --target wasm32-unknown-unknown \
    && CARGO_TARGET_DIR="$work/target" cargo build --release --bin ys-tool) >"$work/build.log" 2>&1 || {
    echo "[BLOCKED] 构建失败，见 $work/build.log"; tail -15 "$work/build.log"; exit $EXIT_INCONCLUSIVE; }
WASM="$work/target/wasm32-unknown-unknown/release/yanshu_sm.wasm"
TOOL="$work/target/release/ys-tool"
SHA=$(sha256sum "$WASM" | cut -d' ' -f1)
BYTES=$(wc -c <"$WASM")
VER=$(node "$here/adapters/wasm_pack_probe.mjs" --wasm "$WASM" version)
echo "wasm: $BYTES 字节  sha256=$SHA"
echo "ys_version: $VER"

echo "== 1/5 自测（脚本自身；解释器与调用方式都要对，否则自测等于没跑）=="
set +e
run_step 1 "$work/selftest-scan.log" python3 "$here/scan_plaintext.py" --selftest
rc_st1=$?
run_step 1 "$work/selftest-tamper.log" python3 "$here/tamper_probe.py" --selftest
rc_st2=$?
# 本脚本是 POSIX sh：自测必须用 sh 调（用 python3 调只会 SyntaxError，且被管道吞掉看不见）
run_step 6 "$work/selftest-all.log" sh "$here/check_all.sh" --selftest
rc_st3=$?
set -e
echo "  自测退出码：scan=$rc_st1 tamper=$rc_st2 check_all=$rc_st3"

echo "== 2/5 用户码一致性（4 入口 + 归一化）=="
set +e
run_step 8 "$work/code-consistency.log" python3 "$here/check_code_consistency.py" \
    --wasm "$WASM" --ys-tool "$TOOL" ${base_url:+--base-url "$base_url"} \
    --json-out "$work/code-consistency.json"
rc_code=$?
set -e

echo "== 3/5 契约字面 vs 实现（双向一致性）=="
set +e
run_step 6 "$work/parity.log" python3 "$here/check_contract_impl_parity.py" ${YS_PARITY_ARGS:-}
rc_parity=$?
set -e

if [ -n "${YS_OLD_BINARY:-}" ] && [ -n "${YS_NEW_BINARY:-}" ] && [ -n "${YS_BASE_DSN:-}" ]; then
    echo "== 4b/5 升级路径（老库 → 新库）=="
    set +e
    run_step 6 "$work/upgrade.log" python3 "$here/check_upgrade_path.py" \
        --old-binary "$YS_OLD_BINARY" --new-binary "$YS_NEW_BINARY" --dsn "$YS_BASE_DSN"
    rc_upgrade=$?
    set -e
else
    rc_upgrade=$EXIT_INCONCLUSIVE
    echo "== 4b/5 升级路径：**未跑**（需设 YS_OLD_BINARY / YS_NEW_BINARY / YS_BASE_DSN）=="
fi

if [ -n "${YS_SERVER_DIR:-}" ]; then
    echo "== 4a/5 服务端内嵌内核 sha256 =="
    set +e
    run_step 8 "$work/kernel.log" python3 "$here/check_server_kernel.py" --server-dir "$YS_SERVER_DIR" \
        ${YS_REPO_DIR:+--repo "$YS_REPO_DIR"} ${YS_GIT_REF:+--git-ref "$YS_GIT_REF"} \
        ${YS_VECTORS_DIR:+--vectors-dir "$YS_VECTORS_DIR"}
    rc_kernel=$?
    set -e
else
    rc_kernel=$EXIT_INCONCLUSIVE
    echo "== 4a/5 服务端内嵌内核 sha256：**未跑**（未设 YS_SERVER_DIR）=="
fi

echo "== 5/5 prelude-only 元数据语义 =="
set +e
run_step 4 "$work/prelude.log" python3 "$here/check_prelude_meta.py" --wasm "$WASM" \
    --json-out "$work/prelude-meta.json"
rc_prelude=$?
set -e

echo "== 5b/5 证据二（生产路径，单块 + 多块 + 变体）=="
set +e
run_step 6 "$work/ev2.log" "$here/run_evidence2_wasm.sh" "$crate" "$work/ev2"
rc_ev2=$?
set -e

echo "== 汇总 =="
echo "  head 产物：$BYTES 字节  sha256=$SHA  ys_version=$VER"
echo "  脚本自测：scan=$rc_st1 tamper=$rc_st2 check_all=$rc_st3"
echo "  用户码一致性：exit=$rc_code"
echo "  契约/实现一致性：exit=$rc_parity"
echo "  服务端内嵌内核 sha：exit=$rc_kernel${YS_SERVER_DIR:+（$YS_SERVER_DIR）}"
echo "  升级路径：exit=$rc_upgrade"
echo "  prelude-only 元数据：exit=$rc_prelude"
echo "  证据二：exit=$rc_ev2"
if [ "$ci_mode" -eq 1 ]; then echo "  （CI 模式：任何未跑/未判定都非 0）"; fi

verdict=$EXIT_PASS
aggregate "selftest-scan:$rc_st1" "selftest-tamper:$rc_st2" "selftest-all:$rc_st3" \
          "code:$rc_code" "parity:$rc_parity" "kernel:$rc_kernel" \
          "upgrade:$rc_upgrade" "prelude:$rc_prelude" "ev2:$rc_ev2"
exit "$verdict"
