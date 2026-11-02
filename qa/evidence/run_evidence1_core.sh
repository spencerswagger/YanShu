#!/bin/sh
# 一键复跑「证据一：服务端存储 / 数据库 / 日志三处都查不到文件名与明文」。
#
# 用法：
#   YS_BASE_DSN='postgres://…' ./run_evidence1_core.sh <core-src-dir> <rune-crate-dir> [workdir]
#
#   <core-src-dir>  服务端源码根（含 server/），例如 git archive origin/feat/server-skeleton
#   <rune-crate-dir> 端侧 crate（crypto/sm），用来打包真密文 + 派生用户码
#   YS_BASE_DSN     PostgreSQL 基础连接串（默认取 $PG_TEST_DSN）；口令不落任何文件
#
# 做的事：
#   1. 编译服务端、端侧工具（ys-tool / ys_pack_probe）——产物全在 workdir，isolated target
#   2. 建独立 schema（默认 gate_ev1），起服务（stub-allow 验签 + 独立 blob 目录 + 日志重定向）
#   3. 生成投递样本（高熵串 + 中文短句 + 有辨识度的文件名/主干/扩展名）
#   4. 用端侧内核把样本打成**真 .yspk**，按 API 走完整投递（注册→建包→prelude→块→complete→取件）
#   5. 对存储目录 / PG / 日志三处跑检索
#   6. 收工杀服务
#
# 判定：三处都无强信号命中 → 退出码 0；命中 → 1；参数缺失 → 4；空语料 → 3。
set -eu

core="${1:-}"
rune="${2:-}"
if [ -z "$core" ] || [ -z "$rune" ]; then
    echo "usage: YS_BASE_DSN=… $0 <core-src-dir> <rune-crate-dir> [workdir]" >&2
    exit 2
fi
work="${3:-/tmp/ys-ev1}"
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

base_dsn="${YS_BASE_DSN:-${PG_TEST_DSN:-}}"
if [ -z "$base_dsn" ]; then
    echo "[PENDING] 没有 YS_BASE_DSN / PG_TEST_DSN —— 缺数据库连接串，不跑，也不伪造 PASS" >&2
    exit 4
fi
schema="${YS_EV1_SCHEMA:-gate_ev1}"
# 端口按 PID 派生：沙盒里上一轮的服务可能还没退干净，固定端口会导致
# "healthz 通但其实是别人的服务"，把密文写到别的目录里去（已踩过一次）
port="${YS_EV1_PORT:-$((18080 + ($$ % 500)))}"
dsn="$base_dsn&search_path=$schema"

# 只允许跑在约定的库上（默认 yanshu_test）：不扫别人的库、不互相污染
dbname=$(python3 -c 'import sys,urllib.parse as u; p=u.urlparse(sys.argv[1]); print(p.path.lstrip("/"))' "$base_dsn")
expect_db="${YS_EXPECT_DB:-yanshu_test}"
if [ "$dbname" != "$expect_db" ]; then
    echo "[BLOCKED] 证据一必须跑在库 '$expect_db' 上，当前 DSN 指向 '${dbname:-?}'；" \
         "不扫别人的库（口令与 DSN 原文不落任何文件）" >&2
    exit 2
fi
echo "db: $dbname / schema: $schema（DSN 从环境取，不落文件）"

rm -rf "$work"
mkdir -p "$work/bin" "$work/blobs" "$work/logs" "$work/sample"

echo "== 1/6 编译 =="
(cd "$core/server" && go build -o "$work/bin/yanshu-server" ./cmd/yanshu-server)
cp -R "$rune/." "$work/crate/"
mkdir -p "$work/crate/src/bin"
cp "$here/adapters/ys_pack_probe.rs" "$work/crate/src/bin/ys_pack_probe.rs"
# 有些精简环境只有 gcc 没有 cc（rustc 默认调 cc）
if ! command -v cc >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
fi
(cd "$work/crate" && CARGO_TARGET_DIR="$work/target" cargo build --release \
    --bin ys-tool --bin ys_pack_probe >"$work/logs/build.log" 2>&1) || {
    echo "[BLOCKED] 端侧工具编译失败，日志尾部：" >&2; tail -15 "$work/logs/build.log" >&2; exit 2; }
BIN="$work/target/release"
echo "server: $work/bin/yanshu-server"
echo "tool:   $BIN/ys-tool"

echo "== 2/6 建 schema 并起服务 =="
psql -X -q "$base_dsn" -c "create schema if not exists $schema" >/dev/null
log_mode="${YS_EV1_LOG_MODE:-stdout}"    # stdout = 重定向；dir = 服务端内建按日滚动
if [ "$log_mode" = "dir" ]; then
    YANSHU_LOG_DIR="$work/logs" \
    YANSHU_DATABASE_URL="$dsn" YANSHU_BLOB_DIR="$work/blobs" YANSHU_ADDR="127.0.0.1:$port" \
    YANSHU_VERIFIER=stub-allow \
    YANSHU_TOKEN_SECRET="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    "$work/bin/yanshu-server" >"$work/stdout.log" 2>&1 &
    LOG_SCAN="$work/logs/yanshu-server-$(date -u +%F).log"
else
    YANSHU_DATABASE_URL="$dsn" YANSHU_BLOB_DIR="$work/blobs" YANSHU_ADDR="127.0.0.1:$port" \
    YANSHU_VERIFIER=stub-allow \
    YANSHU_TOKEN_SECRET="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    "$work/bin/yanshu-server" >"$work/logs/server.log" 2>&1 &
    LOG_SCAN="$work/logs"
fi
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM

i=0
while [ $i -lt 60 ]; do
    if curl -fsS --max-time 2 "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then break; fi
    i=$((i+1)); sleep 0.2
done
# 启动检查要看**真正的日志落点**：stdout 模式是重定向文件，dir 模式是当日滚动文件
LOG_CHECK="${LOG_SCAN:-$work/logs/server.log}"
[ -d "$LOG_CHECK" ] && LOG_CHECK="$LOG_CHECK/server.log"
for _i in $(seq 1 20); do [ -s "$LOG_CHECK" ] && break; sleep 0.2; done

# 必须是**我们自己起的**那个进程在服务：进程活着、日志里有 listening、没有 bind 失败
if ! kill -0 "$SRV" 2>/dev/null; then
    echo "[BLOCKED] 服务进程已退出，日志尾部：" >&2
    tail -20 "$LOG_CHECK" >&2
    exit 2
fi
if grep -q "bind: address already in use" "$LOG_CHECK" 2>/dev/null; then
    echo "[BLOCKED] 端口 $port 被占（可能是上一轮没退干净的服务）：换 YS_EV1_PORT 重跑" >&2
    tail -5 "$LOG_CHECK" >&2
    exit 2
fi
if ! grep -q "listening" "$LOG_CHECK" 2>/dev/null; then
    echo "[BLOCKED] 日志里没有 listening，服务未就绪（日志落点：$LOG_CHECK）：" >&2
    tail -20 "$LOG_CHECK" >&2
    exit 2
fi
echo "healthz OK（port $port，pid $SRV）"

echo "== 3/6 投递样本 =="
python3 "$here/scan_plaintext.py" --emit-sample "$work/sample" | sed 's/^/  /'

echo "== 4/6 打包 + 投递 =="
"$BIN/ys_pack_probe" keygen "$work/alice.sk" "$work/alice.pk" >/dev/null
"$BIN/ys_pack_probe" keygen "$work/bob.sk" "$work/bob.pk" >/dev/null
ALICE_PUB65="04$(od -An -tx1 -v "$work/alice.pk" | tr -d ' \n')"
BOB_PUB65="04$(od -An -tx1 -v "$work/bob.pk" | tr -d ' \n')"
ALICE_CODE=$("$BIN/ys-tool" user-code "$ALICE_PUB65")
BOB_CODE=$("$BIN/ys-tool" user-code "$BOB_PUB65")
SAMPLE_NAME=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["file_name"])' "$work/sample/sample.json")
"$BIN/ys_pack_probe" pack "$work/sample/sample.bin" "$work/sample.yspk" \
    --recipient-pk "$work/bob.pk" --sender-sk "$work/alice.sk" \
    --name "$SAMPLE_NAME" --mime application/octet-stream --ext txt --chunk-size 1024

b64() { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).decode().rstrip("="))' "$1"; }

# 扫描目标：默认用本次 work 目录；若投递驱动报了路径就用它的
SCAN_BLOB="$work/blobs"; SCAN_DSN="$base_dsn"; SCAN_LOG="$work/logs"

if [ -n "${YS_DELIVER_BIN:-}" ]; then
    # Core 的投递驱动：入参是 .yspk（不是明文），stdout 给五个标识
    echo "  投递驱动：$YS_DELIVER_BIN"
    dargs=$(printf '%s' "${YS_DELIVER_ARGS:-}" | sed "s#{pack}#$work/sample.yspk#g")
    set +e
    # shellcheck disable=SC2086
    DELIVER_OUT=$("$YS_DELIVER_BIN" $dargs 2>&1)
    rc_deliver=$?
    set -e
    printf '%s\n' "$DELIVER_OUT" | sed 's/^/  /'
    if [ "$rc_deliver" -ne 0 ]; then
        echo "[BLOCKED] 投递驱动退出码 $rc_deliver" >&2
        exit 2
    fi
    IDS_JSON=$(printf '%s' "$DELIVER_OUT" | python3 -c '
import json, sys
sys.path.insert(0, sys.argv[1])
from scan_plaintext import parse_deliver_output
print(json.dumps(parse_deliver_output(sys.stdin.read()), ensure_ascii=False))
' "$here")
    SCAN_BLOB=$(printf '%s' "$IDS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("blob_dir",""))')
    SCAN_DSN=$(printf '%s' "$IDS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("db_url",""))')
    SCAN_LOG=$(printf '%s' "$IDS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("log_path",""))')
    SCAN_BLOB=${SCAN_BLOB:-$work/blobs}
    SCAN_DSN=${SCAN_DSN:-$base_dsn}
    SCAN_LOG=${SCAN_LOG:-$work/logs}
    echo "  驱动报出的扫描目标：blob=$SCAN_BLOB db=$(python3 -c 'import sys,urllib.parse as u;print(u.urlparse(sys.argv[1]).path.lstrip("/") or "(none)")' "$SCAN_DSN") log=$SCAN_LOG"
else
    python3 "$here/adapters/core_delivery.py" --base-url "http://127.0.0.1:$port" \
        --yspk "$work/sample.yspk" \
        --sender-code "$ALICE_CODE" --sender-pk-b64 "$(b64 "$ALICE_PUB65")" --sender-nickname 甲 \
        --recipient-code "$BOB_CODE" --recipient-pk-b64 "$(b64 "$BOB_PUB65")" --recipient-nickname 乙 \
        --sm3-cmd "$BIN/ys-tool sm3" --no-ack \
        --json-out "$work/delivery.json" | sed 's/^/  /'
fi

if [ -z "$(find "$SCAN_BLOB" -type f 2>/dev/null | head -1)" ]; then
    echo "[BLOCKED] 投递后存储目录是空的：$SCAN_BLOB" >&2
    echo "          说明密文没落到这个目录（端口被占 / 路径不对），此时'扫不到明文'不能算证据" >&2
    exit 2
fi
echo "  存储里已有 $(find "$SCAN_BLOB" -type f | wc -l) 个文件，可以扫了"

if [ "$log_mode" = "dir" ]; then
    if [ ! -s "$LOG_SCAN" ]; then
        echo "[BLOCKED] 内建日志当日文件不存在或为空：$LOG_SCAN（跨天会换名，按投递时间选文件）" >&2
        exit 2
    fi
    echo "  内建日志：$LOG_SCAN（$(wc -c <"$LOG_SCAN") 字节）"
fi

echo "== 5/6 三处检索 =="
set +e
python3 "$here/scan_plaintext.py" --profile core-skeleton \
    --storage-root "$SCAN_BLOB" --dsn "$SCAN_DSN" --pg-schema "$schema" --log-path "${LOG_SCAN:-$SCAN_LOG}" \
    --sample "$work/sample/sample.json" \
    --json-out "$work/scan.json"
SCAN_RC=$?
set -e
echo "  scan exit=$SCAN_RC"

if [ "${YS_EV1_CONTROLS:-1}" = "1" ]; then
    echo "== 5b/6 阳性对照（证明检测器不是瞎的）=="
    NAME=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["file_name"])' "$work/sample/sample.json")
    scan() {
        python3 "$here/scan_plaintext.py" --profile core-skeleton \
            --storage-root "$SCAN_BLOB" --dsn "$SCAN_DSN" --pg-schema "$schema" \
            --log-path "${LOG_SCAN:-$SCAN_LOG}" --sample "$work/sample/sample.json" >/dev/null 2>&1
    }
    # ① 存储：把明文样本塞进 blob 目录
    cp "$work/sample/sample.bin" "$work/blobs/_control_plaintext.bin"
    set +e; scan; rc_store=$?; set -e
    rm -f "$work/blobs/_control_plaintext.bin"
    # ② 日志：追加一行带文件名的请求日志
    LOG_CTL="${LOG_SCAN:-$work/logs/server.log}"
    [ -d "$LOG_CTL" ] && LOG_CTL="$LOG_CTL/server.log"
    cp "$LOG_CTL" "$LOG_CTL.bak"
    printf '%s\n' "2026-01-01T00:00:00Z level=INFO msg=\"upload name=$NAME\"" >> "$LOG_CTL"
    set +e; scan; rc_log=$?; set -e
    mv "$LOG_CTL.bak" "$LOG_CTL"
    # ③ 数据库：把文件名写进 nickname 列
    psql -X -q "$base_dsn" -c "set search_path=$schema; update codes set nickname='$NAME' where code=(select code from codes limit 1)" >/dev/null
    set +e; scan; rc_db=$?; set -e
    psql -X -q "$base_dsn" -c "set search_path=$schema; update codes set nickname='gate'" >/dev/null

    echo "  存储注入 → exit=$rc_store（期望 1）"
    echo "  日志注入 → exit=$rc_log（期望 1）"
    echo "  DB 注入  → exit=$rc_db（期望 1）"
    set +e; scan; rc_clean=$?; set -e
    echo "  复原后   → exit=$rc_clean（期望 0）"
    if [ "$rc_store" -ne 1 ] || [ "$rc_log" -ne 1 ] || [ "$rc_db" -ne 1 ] || [ "$rc_clean" -ne 0 ]; then
        echo "[BLOCKED] 阳性对照不成立：检测器可能失效，本轮 PASS 不可信" >&2
        kill "$SRV" 2>/dev/null || true
        exit 2
    fi
    echo "  阳性对照全部成立"
fi

echo "== 6/6 收工 =="
kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
trap - EXIT INT TERM
echo "服务端日志：$work/logs/server.log"
echo "扫描明细：$work/scan.json"
exit "$SCAN_RC"
