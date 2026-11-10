#!/bin/sh
# 反向验证：把门禁守的规则**故意破坏**，两条门禁必须变红（红不了就是假绿）。
#
#   1) #57-a：往迁移目录塞一条普通 CREATE INDEX（事务迁移里）→ store 门禁必须 FAIL
#   2) #57-b：删掉 0010 文件头的 `-- yanshu:no-transaction` → store 门禁必须 FAIL
#   3) #56  ：把「终结态预判」挪到「凭据存在性」之后（还原修前的顺序）→ httpapi 门禁必须 FAIL
#
# 用法：qa/evidence/release/negative_checks.sh [ref] [workdir]
# 退出码：0 三个变异都被抓住；1 有变异没被抓住；2 前置失败。
set -e

REF=${1:-origin/main}
WORK=${2:-/tmp/yanshu-negative}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)

command -v git >/dev/null && command -v go >/dev/null || { echo "[BLOCKED] 缺 git/go" >&2; exit 2; }
REV=$(git -C "$REPO" rev-parse "$REF") || { echo "[BLOCKED] 取不到 $REF" >&2; exit 2; }

rm -rf "$WORK"; mkdir -p "$WORK"
git -C "$REPO" archive "$REV" | tar -x -C "$WORK"
SRC=$WORK/server

echo "反向验证 @ $(date -u +%Y-%m-%dT%H:%M:%SZ)  ref=$REF ($REV)"

run_store() { ( cd "$SRC" && go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites' 2>&1 ); }
run_http()  { ( cd "$SRC" && go test ./internal/httpapi -run 'Terminal|NonTerminal' 2>&1 ); }

rc_all=0
expect_fail() { # $1=名字 $2=输出文件
  if "$3" > "$2" 2>&1; then
    echo "[FAIL] $1：变异后测试仍然绿（门禁没牙）"
    rc_all=1
  else
    echo "[PASS] $1：变异后测试变红（门禁有牙）"
    grep -E '^(--- FAIL|FAIL|    )' "$2" | head -3 | sed 's/^/        /'
  fi
}

# 基线：未变异的树必须绿（否则下面的"变红"没有意义）
if run_store > "$WORK/base-store.log" 2>&1 && run_http > "$WORK/base-http.log" 2>&1; then
  echo "[PASS] 基线：未变异的 main 上两条门禁都是绿的"
else
  echo "[FAIL] 基线就不绿，反向验证无意义（先修基线）"
  rc_all=1
fi

# 1) 普通 CREATE INDEX 塞回事务迁移
M1=$SRC/internal/store/migrations/0011_mutant_plain_index.sql
printf -- '-- mutant: 事务迁移里用普通 CREATE INDEX（必须被抓住）\nCREATE INDEX IF NOT EXISTS mutant_idx ON transfers (created_at);\n' > "$M1"
expect_fail "#57-a 普通 CREATE INDEX 回归" "$WORK/mutant-plain-index.log" run_store
rm -f "$M1"

# 2) 去掉 0010 的 no-transaction 头
M2=$SRC/internal/store/migrations/0010_indexes_concurrently.sql
cp "$M2" "$WORK/0010.bak"
grep -v '^-- yanshu:no-transaction$' "$WORK/0010.bak" > "$M2"
expect_fail "#57-b CONCURRENTLY 缺 no-transaction 头" "$WORK/mutant-no-tx-header.log" run_store
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
expect_fail "#56 终结态被凭据存在性顶掉" "$WORK/mutant-410-order.log" run_http
cp "$WORK/handlers.bak" "$F"

echo
[ "$rc_all" -eq 0 ] && echo "结论：三处变异全部被抓 → 两道门禁有牙" || echo "结论：有变异没被抓 → 门禁存在假绿"
exit "$rc_all"
