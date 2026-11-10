#!/bin/sh
# 契约 §0.2 覆盖率验收：**每一个**非 2xx 响应都必须是错误信封（ADR-0003）。
#
# 背景：路由层（http.ServeMux）对"路径不存在"和"方法未定义"会自己抢答 text/plain，
# 绕过 writeError。这类响应没有 `error.code`、没有 `request_id`，客户端按 code 分支直接失效。
# 本脚本把它变成可复跑门禁：真起二进制 → 真打请求 → 断言 status + Content-Type + code。
#
# 用法：
#   sh qa/evidence/check_unrouted_envelope.sh --binary <yanshu-server> --dsn "<PG_TEST_DSN>" \
#       [--schema ark_envelope] [--port 18160]
#
# 退出码：0 全 PASS；1 有 FAIL（修前版本会在这里 FAIL）；2 起不来（BLOCKED）。
# 依赖：curl、psql（凭据只从环境读，脚本不打印 DSN）。
set -u

BIN=""; DSN=""; SCHEMA=ark_envelope; PORT=18160
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BIN="$2"; shift 2 ;;
    --dsn)    DSN="$2"; shift 2 ;;
    --schema) SCHEMA="$2"; shift 2 ;;
    --port)   PORT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$BIN" ] && [ -n "$DSN" ] || { echo "usage: $0 --binary <bin> --dsn <dsn> [--schema s] [--port p]" >&2; exit 2; }
[ -x "$BIN" ] || { echo "[BLOCKED] 二进制不可执行：$BIN" >&2; exit 2; }

WORK="${TMPDIR:-/tmp}/ys-envelope-$$"
mkdir -p "$WORK/blobs" || exit 2

psql "$DSN" -qc "drop schema if exists $SCHEMA cascade; create schema $SCHEMA;" >/dev/null 2>&1 \
  || { echo "[BLOCKED] 建 schema 失败（DSN/权限？）" >&2; exit 2; }

SEP='?'; case "$DSN" in *\?*) SEP='&' ;; esac
YANSHU_DATABASE_URL="$DSN$SEP""search_path=$SCHEMA" \
YANSHU_BLOB_DIR="$WORK/blobs" \
YANSHU_ADDR="127.0.0.1:$PORT" \
YANSHU_ENV=test \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET=0123456789abcdef0123456789abcdef \
  "$BIN" >"$WORK/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$WORK"' EXIT INT TERM

i=0
while [ $i -lt 60 ]; do
  curl -fsS -m 1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  i=$((i+1)); sleep 0.3
done
curl -fsS -m 1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 \
  || { echo "[BLOCKED] 服务端没起来，见 $WORK/server.log" >&2; sed -n '1,5p' "$WORK/server.log" >&2; exit 2; }

B="http://127.0.0.1:$PORT"
PASS=0; FAIL=0

# check <描述> <期望状态> <期望 code> <方法> <路径>
check() {
  desc=$1; want_status=$2; want_code=$3; method=$4; path=$5
  code=$(curl -sS -m 3 -o "$WORK/body" -D "$WORK/hdr" -w '%{http_code}' -X "$method" "$B$path" 2>/dev/null)
  ctype=$(tr -d '\r' <"$WORK/hdr" | sed -n 's/^[Cc]ontent-[Tt]ype: //p' | head -1)
  got_code=$(sed -n 's/.*"code":"\([A-Z_]*\)".*/\1/p' "$WORK/body" | head -1)
  case "$ctype" in application/json*) json=1 ;; *) json=0 ;; esac
  if [ "$code" = "$want_status" ] && [ "$json" = 1 ] && [ "$got_code" = "$want_code" ]; then
    PASS=$((PASS+1)); printf 'PASS  %-42s %s %s -> %s %s\n' "$desc" "$method" "$path" "$code" "$got_code"
  else
    FAIL=$((FAIL+1))
    printf 'FAIL  %-42s %s %s -> status=%s content-type=%s code=%s (want %s %s JSON)\n' \
      "$desc" "$method" "$path" "$code" "${ctype:-<none>}" "${got_code:-<none>}" "$want_status" "$want_code"
  fi
}

echo "======================================================================"
echo "契约 §0.2 覆盖率（ADR-0003）：非 2xx 必须是信封"
echo "binary: $BIN"
echo "date  : $(date -u +%FT%TZ)"
echo "======================================================================"
check "未知路径 -> 404 信封"        404 ROUTE_NOT_FOUND   GET    /v1/nope
check "未知路径（深一层）"           404 ROUTE_NOT_FOUND   GET    /v1/codes/AWQW/x
check "根路径 -> 404 信封"           404 ROUTE_NOT_FOUND   GET    /
check "未定义方法 DELETE /config"    405 METHOD_NOT_ALLOWED DELETE /v1/config
check "未定义方法 POST /stats"       405 METHOD_NOT_ALLOWED POST   /v1/stats
check "未定义方法 GET /transfers"    405 METHOD_NOT_ALLOWED GET    /v1/transfers
echo "----------------------------------------------------------------------"
echo "阴性对照（对象级语义不许被顶替 / 真路由不许被吞）"
check "未注册码仍 CODE_NOT_FOUND"    404 CODE_NOT_FOUND     GET    /v1/codes/AWQW
check "坏 transfer_id 仍 TRANSFER_NOT_FOUND" 404 TRANSFER_NOT_FOUND GET /v1/transfers/ZZZZ
curl -sS -m 3 -o /dev/null -w '' "http://127.0.0.1:$PORT/healthz" 2>/dev/null
hstatus=$(curl -sS -m 3 -o "$WORK/h" -w '%{http_code}' "http://127.0.0.1:$PORT/healthz")
if [ "$hstatus" = "200" ] && grep -q '"api_version"' "$WORK/h"; then
  PASS=$((PASS+1)); echo "PASS  /healthz 真路由仍 200"
else
  FAIL=$((FAIL+1)); echo "FAIL  /healthz 被兜底抢答：status=$hstatus"
fi
echo "----------------------------------------------------------------------"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
