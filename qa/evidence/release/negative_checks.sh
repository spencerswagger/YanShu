#!/bin/sh
# 反向验证：把门禁守的规则**故意破坏**，两条门禁必须变红（红不了就是假绿）。
#
#   基线   ：未变异的树必须绿，而且**真跑了**（-run 匹配不到会静默 exit 0）
#   1) #57-a：往迁移目录塞一条普通 CREATE INDEX（事务迁移里）→ store 门禁必须 FAIL
#   2) #57-b：删掉 0010 文件头的 `-- yanshu:no-transaction` → store 门禁必须 FAIL
#   3) #56  ：把「终结态预判」挪到「凭据存在性」之后（还原修前顺序）→ httpapi 门禁必须 FAIL
#
# 用法：TEST_DATABASE_URL=... qa/evidence/release/negative_checks.sh [ref] [workdir]
# 退出码：0 基线与三处变异都符合预期；1 门禁没牙；2 环境不成立（连不上库/并发踩踏，别当结论）。
set -e

REF=${1:-origin/main}
WORK=${2:-/tmp/yanshu-negative}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)

command -v git >/dev/null && command -v go >/dev/null || { echo "[BLOCKED] 缺 git/go" >&2; exit 2; }
# httpapi 门禁要连库；没 DSN 时用例会 SKIP（exit 0），看起来跟"绿"一样，必须先挡住
[ -n "${TEST_DATABASE_URL:-}" ] || { echo "[BLOCKED] 需要 TEST_DATABASE_URL（门禁要连真 PG）" >&2; exit 2; }
REV=$(git -C "$REPO" rev-parse "$REF") || { echo "[BLOCKED] 取不到 $REF" >&2; exit 2; }

# 用独立数据库：不碰共享库里的既有数据/schema，跑完即删。
# 并发互删 schema 的根因已由 #68 消除（testutil 每次 NewStore 用唯一 schema），
# 这里不再为"夹具撞名"重试。
ADMIN_DSN=$TEST_DATABASE_URL
NEGDB="yanshu_neg_$(date -u +%Y%m%dt%H%M%Sz | tr 'A-Z' 'a-z')"
psql -X -q "$ADMIN_DSN" -c "CREATE DATABASE \"$NEGDB\"" >/dev/null 2>&1 || {
  echo "[BLOCKED] 建隔离库失败（角色要能 CREATE DATABASE）" >&2; exit 2; }
drop_db() { psql -X -q "$ADMIN_DSN" -c "DROP DATABASE IF EXISTS \"$NEGDB\" WITH (FORCE)" >/dev/null 2>&1 || true; }
trap drop_db EXIT INT TERM
TEST_DATABASE_URL=$(python3 - "$ADMIN_DSN" "$NEGDB" <<'PYEOF'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
print(urllib.parse.urlunsplit((u.scheme, u.netloc, "/" + sys.argv[2], u.query, "")))
PYEOF
)
export TEST_DATABASE_URL
echo "[iso] 隔离库：$NEGDB"

rm -rf "$WORK"; mkdir -p "$WORK"
git -C "$REPO" archive "$REV" | tar -x -C "$WORK"
SRC=$WORK/server

echo "反向验证 @ $(date -u +%Y-%m-%dT%H:%M:%SZ)  ref=$REF ($REV)"

run_store() { ( cd "$SRC" && go test ./internal/store -v \
  -run 'TestMigrationsCreateIndexesWithoutBlockingWrites' 2>&1 ); }
run_http()  { ( cd "$SRC" && go test ./internal/httpapi -v -run 'Terminal|NonTerminal' 2>&1 ); }

count_pass() { grep -c '^--- PASS' "$1" 2>/dev/null || true; }

# 单次执行；输出落 $2。返回 0/1。
attempt() { # $1=命令函数 $2=日志
  "$1" > "$2" 2>&1 && return 0 || return 1
}

rc_all=0

# ---- 基线：必须绿且真跑（单次；#68 之后夹具 schema 唯一，不需要为并发重试）
rs=0; attempt run_store "$WORK/base-store.log" || rs=$?
rh=0; attempt run_http  "$WORK/base-http.log"  || rh=$?
ns=$(count_pass "$WORK/base-store.log"); nh=$(count_pass "$WORK/base-http.log")
if [ "$rs" -eq 0 ] && [ "$rh" -eq 0 ] && [ "$ns" -ge 1 ] && [ "${nh:-0}" -ge 2 ]; then
  echo "[PASS] 基线：两条门禁都绿且真跑（store PASS=$ns / httpapi PASS=$nh）"
else
  echo "[BLOCKED] 基线跑不绿（rc=$rs/$rh PASS=${ns:-0}/${nh:-0}）：环境/DSN 问题，不能据此判门禁好坏" >&2
  exit 2
fi

# 变异必须红在**那条断言的消息**上：只要求"有 --- FAIL"会把
# "no schema has been selected / migrate: …" 这种环境炸库也当成门禁有牙（假绿）。
expect_fail() { # $1=名字 $2=输出文件 $3=命令函数 $4=必须出现的断言消息（固定串）
  if "$3" > "$2" 2>&1; then
    echo "[FAIL] $1：变异后测试仍然绿（门禁没牙）"; rc_all=1; return
  fi
  if grep -q 'no schema has been selected' "$2"; then
    echo "[BLOCKED] $1：连库/夹具异常（no schema selected），不是门禁结论" >&2; rc_all=2; return
  fi
  if grep -q -- "$4" "$2"; then
    echo "[PASS] $1：变异后测试红在预期断言上（门禁有牙）"
    grep -E '^(--- FAIL|    )' "$2" | head -3 | sed 's/^/        /'
    return
  fi
  echo "[BLOCKED] $1：非 0 但没出现预期断言「$4」，无法判定" >&2
  rc_all=2
}

# 1) 普通 CREATE INDEX 塞回事务迁移
M1=$SRC/internal/store/migrations/0011_mutant_plain_index.sql
printf -- '-- mutant: 事务迁移里用普通 CREATE INDEX（必须被抓住）\nCREATE INDEX IF NOT EXISTS mutant_idx ON transfers (created_at);\n' > "$M1"
expect_fail "#57-a 普通 CREATE INDEX 回归" "$WORK/mutant-plain-index.log" run_store \
  "0011_mutant_plain_index.sql"
rm -f "$M1"

# 2) 去掉 0010 的 no-transaction 头
M2=$SRC/internal/store/migrations/0010_indexes_concurrently.sql
cp "$M2" "$WORK/0010.bak"
grep -v '^-- yanshu:no-transaction$' "$WORK/0010.bak" > "$M2"
expect_fail "#57-b CONCURRENTLY 缺 no-transaction 头" "$WORK/mutant-no-tx-header.log" run_store \
  "文件头没有"
cp "$WORK/0010.bak" "$M2"

# 3) 还原修前的判定顺序：凭据存在性排到终结态之前
F=$SRC/internal/httpapi/handlers_transfers.go
cp "$F" "$WORK/handlers.bak"
python3 - "$F" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding='utf-8').read()
anchor = '''	if spec.IsTerminalState(t.State) {
		fail(w, r, spec.TerminalErrorCode(t.State))
		return store.Transfer{}, false
	}
'''
mut = '''	if uploadToken(r) == "" { // mutant: 还原修前顺序——凭据存在性先于终结态
		fail(w, r, spec.ErrAuthMissing)
		return store.Transfer{}, false
	}
	if spec.IsTerminalState(t.State) {
		fail(w, r, spec.TerminalErrorCode(t.State))
		return store.Transfer{}, false
	}
'''
assert s.count(anchor) == 1, "锚点不唯一，拒绝盲改"
open(p, 'w', encoding='utf-8').write(s.replace(anchor, mut))
PY
expect_fail "#56 终结态被凭据存在性顶掉" "$WORK/mutant-410-order.log" run_http \
  "§1.7.4 被违反"
cp "$WORK/handlers.bak" "$F"

echo
case "$rc_all" in
  0) echo "结论：三处变异全部被抓 → 两道门禁有牙" ;;
  2) echo "结论：有变异无法判定（环境问题），别当成「门禁有牙」或「没牙」"; exit 2 ;;
  *) echo "结论：有变异没被抓 → 门禁存在假绿" ;;
esac
exit "$rc_all"
