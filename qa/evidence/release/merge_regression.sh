#!/bin/sh
# 合并期逐张回归：给一个 ref，只跑「这张 PR 守的那条」最小回归（也可 --only all 跑全套）。
#
# 用法：
#   TEST_DATABASE_URL=... qa/evidence/release/merge_regression.sh --ref <ref> --only 56|57|58|59|60|61|all
#
# 判据原则（复审 P0/P1 后改的）：
#   - 不信「退出码 0」也不信「有 PASS 字样」：go 门禁要求 `--- PASS` **条数达标**且没有
#     `no tests to run`（`-run` 匹配不到会静默 exit 0，末行还印 `ok`）；
#   - #58 要求内层脚本的 `PASS=n FAIL=0` 且 rc=0（它末行永远含 "PASS="，grep PASS 会恒真）；
#   - 该项被 SKIP（树里没有这条）/`--only` 非法 → 退出码 2，不能算"跑过"。
#
# 为什么每项都自己建隔离库：httpapi 夹具用固定 schema 名（yanshu_core_test_httpapi），
# 与别人同时跑会互删 schema，冒出 "no schema has been selected"（假失败）。
#
# 退出码：0 所有"要求跑的"都真跑了且 PASS；1 有 FAIL；2 环境不成立或该项没跑（BLOCKED）。
set -u

REF=origin/main
ONLY=all
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF=$2; shift 2 ;;
    --only) ONLY=$2; shift 2 ;;
    -h|--help) sed -n '1,16p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
case "$ONLY" in 56|57|58|59|60|61|all) ;; *) echo "[BLOCKED] --only 只接受 56|57|58|59|60|61|all" >&2; exit 2 ;; esac

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
[ -n "${TEST_DATABASE_URL:-}" ] || { echo "[BLOCKED] 需要 TEST_DATABASE_URL" >&2; exit 2; }
command -v git >/dev/null && command -v go >/dev/null && command -v psql >/dev/null || {
  echo "[BLOCKED] 缺 git/go/psql" >&2; exit 2; }

REV=$(git -C "$REPO" rev-parse "$REF") || { echo "[BLOCKED] 取不到 $REF" >&2; exit 2; }
WORK=${WORK:-${TMPDIR:-/tmp}/yanshu-mr-$$-$(date -u +%H%M%S)}
rm -rf "$WORK"; mkdir -p "$WORK/src" "$WORK/bin"
git -C "$REPO" archive "$REV" | tar -x -C "$WORK/src" || { echo "[BLOCKED] archive 失败" >&2; exit 2; }
SRC=$WORK/src
BIN=$WORK/bin/yanshu-server

echo "== 合并期回归 @ $(date -u +%Y-%m-%dT%H:%M:%SZ)  ref=$REF ($REV)  only=$ONLY"
echo "   work=$WORK"

ADMIN_DSN=$TEST_DATABASE_URL
mkdb() { # $1=后缀 -> echo DSN
  local db="yanshu_mr_$(date -u +%Y%m%dt%H%M%S)_$1"
  psql -X -q "$ADMIN_DSN" -c "CREATE DATABASE \"$db\"" >/dev/null 2>&1 || return 1
  python3 - "$ADMIN_DSN" "$db" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
print(urllib.parse.urlunsplit((u.scheme, u.netloc, "/" + sys.argv[2], u.query, "")))
PY
}
dropdb() { psql -X -q "$ADMIN_DSN" -c "DROP DATABASE IF EXISTS \"$1\" WITH (FORCE)" >/dev/null 2>&1 || true; }

RC=0; DID=0
ok()   { echo "[PASS] $1"; DID=$((DID+1)); }
bad()  { echo "[FAIL] $1"; RC=1; DID=$((DID+1)); }
skip() { echo "[SKIP] $1（该项没跑，不算通过）"; RC=2; }

want() { [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }

# go 门禁：必须 rc=0 + `--- PASS` 条数 >= 期望 + 没有 "no tests to run"
go_gate() { # $1=包 $2=-run 正则 $3=最少 PASS 条数 $4=日志
  ( cd "$SRC/server" && TEST_DATABASE_URL="$DB_T" go test "$1" -run "$2" -v ) >"$4" 2>&1
  rc=$?
  n=$(grep -c '^--- PASS' "$4" 2>/dev/null || true)
  [ -z "$n" ] && n=0
  if [ "$rc" -ne 0 ]; then echo "  rc=$rc"; tail -4 "$4"; return 1; fi
  if grep -q 'no tests to run' "$4"; then echo "  测试名没命中（no tests to run）"; return 1; fi
  if [ "$n" -lt "$3" ]; then echo "  --- PASS 只有 $n 条（期望 >= $3）"; return 1; fi
  echo "  --- PASS $n 条"
  return 0
}

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
  if go_gate ./internal/store 'TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex' 2 "$WORK/57.log"; then
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
  if go_gate ./internal/httpapi 'Terminal|NonTerminal' 2 "$WORK/56.log"; then
    ok "#56 httpapi 门禁（Terminal + 阴性对照）"
  else
    bad "#56 httpapi 门禁"
  fi
fi

# ---------- #58 未路由路径信封
if want 58; then
  echo "--- #58 契约 §0.2 路由信封 ---"
  if [ -f "$SRC/qa/evidence/check_unrouted_envelope.sh" ]; then
    ( cd "$SRC" && sh qa/evidence/check_unrouted_envelope.sh \
        --binary "$BIN" --dsn "$DB_T" --schema mr_envelope ) >"$WORK/58.log" 2>&1
    rc=$?
    summary=$(grep -E '^PASS=[0-9]+ FAIL=[0-9]+$' "$WORK/58.log" | tail -1)
    fails=$(printf '%s' "$summary" | sed -n 's/.*FAIL=\([0-9]*\).*/\1/p')
    passes=$(printf '%s' "$summary" | sed -n 's/^PASS=\([0-9]*\).*/\1/p')
    if [ "$rc" -eq 0 ] && [ -n "$summary" ] && [ "${fails:-1}" -eq 0 ] && [ "${passes:-0}" -ge 4 ]; then
      ok "#58 未路由信封（$summary）"
    else
      bad "#58 未路由信封（rc=$rc summary=${summary:-无}）"
      tail -4 "$WORK/58.log"
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

# ---------- #60 crosscheck 裸跑（要求汇总行 FAIL 0 且至少跑了几条）
if want 60; then
  echo "--- #60 crosscheck 裸跑 ---"
  if [ -f "$SRC/scripts/crosscheck/run.sh" ]; then
    ( cd "$SRC" && timeout 600 sh scripts/crosscheck/run.sh --no-local ) >"$WORK/60.log" 2>&1
    rc=$?
    summary=$(grep -E '^PASS [0-9]+ / FAIL [0-9]+' "$WORK/60.log" | tail -1)
    fails=$(printf '%s' "$summary" | sed -n 's/.*FAIL \([0-9]*\).*/\1/p')
    passes=$(printf '%s' "$summary" | sed -n 's/^PASS \([0-9]*\).*/\1/p')
    if [ "$rc" -eq 0 ] && [ -n "$summary" ] && [ "${fails:-1}" -eq 0 ] && [ "${passes:-0}" -ge 1 ]; then
      ok "#60 crosscheck（$summary）"
    else
      bad "#60 crosscheck（rc=$rc summary=${summary:-无}）"; tail -4 "$WORK/60.log"
    fi
  else
    skip "#60 脚本不在该 ref 上"
  fi
fi

# ---------- #61 wasm 溯源门禁（node --test，要求 fail 0 且至少 pass 1）
if want 61; then
  echo "--- #61 wasm:sync 溯源门禁 ---"
  if [ -f "$SRC/web/tests/wasm-sync-provenance.test.js" ]; then
    ( cd "$SRC" && timeout 300 node --test web/tests/wasm-sync-provenance.test.js ) >"$WORK/61.log" 2>&1
    rc=$?
    npass=$(sed -n 's/^# pass \([0-9]*\)$/\1/p' "$WORK/61.log" | tail -1)
    nfail=$(sed -n 's/^# fail \([0-9]*\)$/\1/p' "$WORK/61.log" | tail -1)
    nskip=$(sed -n 's/^# skipped \([0-9]*\)$/\1/p' "$WORK/61.log" | tail -1)
    if [ "$rc" -eq 0 ] && [ "${nfail:-1}" -eq 0 ] && [ "${npass:-0}" -ge 1 ] && [ "${nskip:-9}" -le 2 ]; then
      ok "#61 node --test（pass=${npass} fail=${nfail} skipped=${nskip}）"
    else
      bad "#61 node --test（rc=$rc pass=${npass:-?} fail=${nfail:-?} skipped=${nskip:-?}）"
      tail -4 "$WORK/61.log"
    fi
  else
    skip "#61 测试不在该 ref 上"
  fi
fi

echo
if [ "$RC" -eq 0 ]; then
  echo "结论：本轮要求的 $DID 项全部真跑且 PASS"
elif [ "$RC" -eq 2 ]; then
  echo "结论：有项没跑（SKIP/环境），不能算通过（见上）"
else
  echo "结论：有 FAIL"
fi
exit "$RC"
