#!/bin/sh
# 合并期逐张回归：给一个 ref，只跑「这张 PR 守的那条」最小回归（也可 --only all 跑全套）。
#
# 用法：
#   TEST_DATABASE_URL=... qa/evidence/release/merge_regression.sh --ref <ref> --only 56|57|58|59|60|61|all
#
# 为什么每项都自己建隔离库：httpapi 夹具用固定 schema 名（yanshu_core_test_httpapi），
# 与别人同时跑会互删 schema，冒出 "no schema has been selected"（假失败）。
#
# 退出码：0 全 PASS（SKIP 不算失败但要打印）；1 有 FAIL；2 环境不成立（BLOCKED）。
set -u

REF=origin/main
ONLY=all
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF=$2; shift 2 ;;
    --only) ONLY=$2; shift 2 ;;
    -h|--help) sed -n '1,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
[ -n "${TEST_DATABASE_URL:-}" ] || { echo "[BLOCKED] 需要 TEST_DATABASE_URL" >&2; exit 2; }
command -v git >/dev/null && command -v go >/dev/null && command -v psql >/dev/null || {
  echo "[BLOCKED] 缺 git/go/psql" >&2; exit 2; }

REV=$(git -C "$REPO" rev-parse "$REF") || { echo "[BLOCKED] 取不到 $REF" >&2; exit 2; }
WORK=${WORK:-${TMPDIR:-/tmp}/yanshu-mr-$$}
rm -rf "$WORK"; mkdir -p "$WORK/src" "$WORK/bin"
git -C "$REPO" archive "$REV" | tar -x -C "$WORK/src" || { echo "[BLOCKED] archive 失败" >&2; exit 2; }
SRC=$WORK/src
BIN=$WORK/bin/yanshu-server

echo "== 合并期回归 @ $(date -u +%Y-%m-%dT%H:%M:%SZ)  ref=$REF ($REV)  only=$ONLY"
echo "   work=$WORK"

ADMIN_DSN=$TEST_DATABASE_URL
mkdb() { # $1=名字后缀 -> echo DSN
  local db="yanshu_mr_$(date -u +%Y%m%dt%H%M%S)_$1"
  psql -X -q "$ADMIN_DSN" -c "CREATE DATABASE \"$db\"" >/dev/null 2>&1 || return 1
  python3 - "$ADMIN_DSN" "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
print(urllib.parse.urlunsplit((u.scheme, u.netloc, "/" + sys.argv[2], u.query, "")))
PY
}
dropdb() { psql -X -q "$ADMIN_DSN" -c "DROP DATABASE IF EXISTS \"$1\" WITH (FORCE)" >/dev/null 2>&1 || true; }

RC=0
ok()   { echo "[PASS] $1"; }
bad()  { echo "[FAIL] $1"; RC=1; }
skip() { echo "[SKIP] $1"; }

want() { [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }

# ---------- 通用：构建 / vet / gofmt（每次都跑，任何一张合入后都不许退化）
echo "--- build ---"
if ( cd "$SRC/server" && go build ./... && go vet ./... && test -z "$(gofmt -l .)" ); then
  ok "build+vet+gofmt"
else
  bad "build+vet+gofmt"
fi
( cd "$SRC/server" && go build -o "$BIN" ./cmd/yanshu-server ) || bad "编 yanshu-server"

DB_T=$(mkdb test) || { echo "[BLOCKED] 建隔离库失败" >&2; exit 2; }
echo "   test db = ${DB_T##*/}"
cleanup() { dropdb "${DB_T##*/}"; [ -n "${DB_M:-}" ] && dropdb "${DB_M##*/}"; }
trap cleanup EXIT INT TERM

# ---------- #57 建索引门禁（store 单测 + 迁移跑两遍）
if want 57; then
  echo "--- #57 建索引锁写门禁 ---"
  if ( cd "$SRC/server" && TEST_DATABASE_URL="$DB_T" go test ./internal/store \
        -run 'TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex' -v 2>&1 ) \
       | tail -5 | grep -q '^ok'; then
    ok "#57 store 门禁（两条）"
  else
    bad "#57 store 门禁"
  fi
  DB_M=$(mkdb migrate) || bad "#57 migrate-only 建库"
  if [ -n "${DB_M:-}" ]; then
    out1=$( cd "$SRC/server" && YANSHU_DATABASE_URL="$DB_M" "$BIN" -migrate-only 2>&1 ); r1=$?
    out2=$( cd "$SRC/server" && YANSHU_DATABASE_URL="$DB_M" "$BIN" -migrate-only 2>&1 ); r2=$?
    n=$(psql -X -A -t "$DB_M" -c "select count(*) from schema_migrations" 2>/dev/null | tr -d ' ')
    if [ "$r1" -eq 0 ] && [ "$r2" -eq 0 ] && [ "${n:-0}" -ge 9 ]; then
      ok "#57 迁移跑两遍幂等（schema_migrations=$n）"
    else
      bad "#57 迁移幂等（rc=$r1/$r2 rows=${n:-?}）"
      echo "$out1" | tail -3; echo "$out2" | tail -3
    fi
  fi
fi

# ---------- #56 终结态 410 门禁
if want 56; then
  echo "--- #56 终结态 410 先于凭据 ---"
  if ( cd "$SRC/server" && TEST_DATABASE_URL="$DB_T" go test ./internal/httpapi \
        -run 'Terminal|NonTerminal' -v 2>&1 ) | tee "$WORK/56.log" | grep -q '^ok'; then
    ok "#56 httpapi 门禁（Terminal + 阴性对照）"
  else
    bad "#56 httpapi 门禁"
    tail -5 "$WORK/56.log"
  fi
fi

# ---------- #58 未路由路径信封
if want 58; then
  echo "--- #58 契约 §0.2 路由信封 ---"
  if [ -x "$SRC/qa/evidence/check_unrouted_envelope.sh" ]; then
    if ( cd "$SRC" && sh qa/evidence/check_unrouted_envelope.sh \
          --binary "$BIN" --dsn "$DB_T" --schema mr_envelope 2>&1 ) | tee "$WORK/58.log" | tail -3 | grep -q 'PASS'; then
      ok "#58 未路由信封（脚本自检）"
    else
      bad "#58 未路由信封"
    fi
  else
    skip "#58 脚本不在该 ref 上"
  fi
fi

# ---------- #59 A/B 证据脚本仍可跑（信封一侧，快）
if want 59; then
  echo "--- #59 A/B 证据脚本 ---"
  if [ -f "$SRC/qa/evidence/fix-ab/ab_contract_envelope.py" ]; then
    if python3 "$SRC/qa/evidence/fix-ab/ab_contract_envelope.py" \
         --binary "$BIN" --dsn "$DB_T" --expect after --work "$WORK/ab59" >"$WORK/59.log" 2>&1; then
      ok "#59 ab_contract_envelope --expect after"
    else
      bad "#59 ab_contract_envelope"; tail -4 "$WORK/59.log"
    fi
  else
    skip "#59 脚本不在该 ref 上"
  fi
fi

# ---------- #60 crosscheck 裸跑
if want 60; then
  echo "--- #60 crosscheck 裸跑 ---"
  if [ -f "$SRC/scripts/crosscheck/run.sh" ]; then
    if ( cd "$SRC" && timeout 600 sh scripts/crosscheck/run.sh --no-local >"$WORK/60.log" 2>&1 ); then
      line=$(grep -E '^PASS [0-9]+ / FAIL' "$WORK/60.log" | tail -1)
      ok "#60 crosscheck（${line:-无汇总行}）"
    else
      bad "#60 crosscheck"; tail -5 "$WORK/60.log"
    fi
  else
    skip "#60 脚本不在该 ref 上"
  fi
fi

# ---------- #61 wasm 溯源门禁（node --test）
if want 61; then
  echo "--- #61 wasm:sync 溯源门禁 ---"
  if [ -f "$SRC/web/tests/wasm-sync-provenance.test.js" ]; then
    if ( cd "$SRC" && timeout 300 node --test web/tests/wasm-sync-provenance.test.js >"$WORK/61.log" 2>&1 ); then
      s=$(grep -E '^# (pass|fail|skipped) ' "$WORK/61.log" | tr '\n' ' ')
      ok "#61 node --test（$s）"
    else
      bad "#61 node --test"; tail -5 "$WORK/61.log"
    fi
  else
    skip "#61 测试不在该 ref 上"
  fi
fi

echo
if [ "$RC" -eq 0 ]; then echo "结论：本轮回归无 FAIL（SKIP 项见上，不算通过）"; else echo "结论：有 FAIL"; fi
exit "$RC"
