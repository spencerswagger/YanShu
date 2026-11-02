#!/bin/sh
# token 轮换三组对照（给验收用，自动跑、不靠手工记录）。
#
# 用法：
#   scripts/token-rotation-check.sh \
#     --bin      <server 二进制> \
#     --deliver  <deliver 二进制> \
#     --yspk     <样本 .yspk> \
#     --dsn      "<PG DSN，含 search_path>" \
#     --blob     <blob 目录> \
#     [--port 18099] [--schema 已建好]
#
# 前置：schema 已存在（本脚本只跑 -migrate-only，不建库）。
# 验签用 stub-allow（本对照只验证 token 语义，与 SM2 无关）。
#
# 输出：四行 PASS/FAIL，退出码 0 表示全部通过。
set -eu

BIN=""; DELIVER=""; YSPK=""; DSN=""; BLOB=""; PORT="${PORT:-18099}"
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        --deliver) DELIVER="$2"; shift 2 ;;
        --yspk) YSPK="$2"; shift 2 ;;
        --dsn) DSN="$2"; shift 2 ;;
        --blob) BLOB="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
for v in BIN DELIVER YSPK DSN BLOB; do
    eval "val=\$$v"
    [ -n "$val" ] || { echo "missing --$(echo $v | tr 'A-Z' 'a-z')" >&2; exit 2; }
done

WORK=$(mktemp -d)
SRV_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

BASE="http://127.0.0.1:$PORT"
FAILS=0

start_server() { # $1=secret $2=kid
    YANSHU_DATABASE_URL="$DSN" YANSHU_BLOB_DIR="$BLOB" YANSHU_ADDR="127.0.0.1:$PORT" \
    YANSHU_VERIFIER=stub-allow YANSHU_TOKEN_SECRET="$1" YANSHU_TOKEN_KID="$2" \
        "$BIN" >"$WORK/server-$2.log" 2>&1 &
    SRV_PID=$!
    i=0
    while [ $i -lt 80 ]; do
        if curl -fsS --max-time 2 "$BASE/healthz" >/dev/null 2>&1; then return 0; fi
        i=$((i+1)); sleep 0.15
    done
    echo "server did not start (kid=$2)，日志尾部：" >&2
    tail -5 "$WORK/server-$2.log" >&2
    return 1
}

stop_server() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
}

new_transfer() { # 输出 "<package_id> <token>"
    "$DELIVER" --base-url "$BASE" --yspk "$YSPK" --no-ack --print-upload-token \
        >"$WORK/out.json" 2>"$WORK/err.txt" || return 1
    pkg=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["package_id"])' "$WORK/out.json")
    tok=$(sed -n 's/^upload_token=//p' "$WORK/err.txt" | head -1)
    [ -n "$pkg" ] && [ -n "$tok" ] || return 1
    echo "$pkg $tok"
}

status_of() { # $1=package_id $2=token → 输出 "<http_code> <error_code>"
    code=$(curl -s -o "$WORK/body" -w '%{http_code}' -H "X-YS-Upload-Token: $2" "$BASE/v1/transfers/$1/status")
    err=$(python3 -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(d.get("error",{}).get("code",""))
except Exception:
    print("")' "$WORK/body")
    echo "$code $err"
}

check() { # $1=label $2=want_status $3=want_err $4=got
    got_status=$(echo "$4" | cut -d' ' -f1)
    got_err=$(echo "$4" | cut -d' ' -f2)
    if [ "$got_status" = "$2" ] && [ "$got_err" = "$3" ]; then
        echo "PASS  $1 → $got_status ${got_err:-(ok)}"
    else
        echo "FAIL  $1 → $got_status ${got_err:-(ok)}（期望 $2 ${3:-(ok)}）"
        FAILS=$((FAILS+1))
    fi
}

echo "== 0) 迁移 =="
YANSHU_DATABASE_URL="$DSN" "$BIN" -migrate-only >/dev/null 2>&1 || { echo "migrate 失败" >&2; exit 1; }

echo "== 1) 基线：kid=k1 签发并可用 =="
start_server "rotation-secret-0001" "k1"
set -- $(new_transfer)
PKG1=$1; TOK1=$2
check "baseline status" 200 "" "$(status_of "$PKG1" "$TOK1")"
stop_server

echo "== 2) 只改 secret（kid 仍 k1） =="
start_server "rotation-secret-0002" "k1"
check "only-secret: 旧 token" 401 "AUTH_TOKEN_INVALID" "$(status_of "$PKG1" "$TOK1")"
set -- $(new_transfer); PKG2=$1; TOK2=$2
check "only-secret: 新 token" 200 "" "$(status_of "$PKG2" "$TOK2")"
stop_server

echo "== 3) 只改 kid（secret 不变） =="
start_server "rotation-secret-0002" "k2"
check "only-kid: 旧 token" 401 "AUTH_TOKEN_STALE" "$(status_of "$PKG2" "$TOK2")"
set -- $(new_transfer); PKG3=$1; TOK3=$2
check "only-kid: 新 token" 200 "" "$(status_of "$PKG3" "$TOK3")"
stop_server

echo "== 4) 两个都换 =="
start_server "rotation-secret-0003" "k3"
check "both: 旧 token" 401 "AUTH_TOKEN_STALE" "$(status_of "$PKG3" "$TOK3")"
set -- $(new_transfer); PKG4=$1; TOK4=$2
check "both: 新 token" 200 "" "$(status_of "$PKG4" "$TOK4")"
stop_server

echo
if [ "$FAILS" -eq 0 ]; then
    echo "全部通过（3 组轮换 × 旧拒/新可用）"
    exit 0
fi
echo "有 $FAILS 项失败"
exit 1
