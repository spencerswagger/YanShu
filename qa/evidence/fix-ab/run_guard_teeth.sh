#!/bin/sh
# 防回退门禁有牙吗？（PR #57 的三条断言 + 反向验证）
#
#   1) 修后树：`go test ./internal/store -run ...` → PASS
#   2) 反向验证：往迁移目录塞一条普通 CREATE INDEX → 同一测试必须 FAIL
#   3) 修前树：同一测试不存在（"no tests to run"）→ 这条规则当时**没有任何门禁**
#
# 用法：qa/evidence/fix-ab/run_guard_teeth.sh <修后树根> <修前树根>
# 例：  qa/evidence/fix-ab/run_guard_teeth.sh /tmp/fix-ab-run/trees/after /tmp/fix-ab-run/trees/before
set -e
AFTER=$1
BEFORE=$2
[ -d "$AFTER/server" ] && [ -d "$BEFORE/server" ] || {
  echo "用法：$0 <修后树根> <修前树根>" >&2; exit 2; }

GUARD='TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex'
MUTANT="$AFTER/server/internal/store/migrations/0011_mutant.sql"
rc=0

echo "===== 1) 修后树：门禁本体 ====="
( cd "$AFTER/server" && go test ./internal/store -run "$GUARD" -v 2>&1 | tail -6 )
if ( cd "$AFTER/server" && go test ./internal/store -run "$GUARD" -v 2>&1 \
     | grep -q -- '--- PASS: TestMigrationsCreateIndexesWithoutBlockingWrites' ); then
  echo "[PASS] 修后树门禁真跑了且绿"
else
  echo "[FAIL] 修后树门禁红，或压根没跑（no tests to run）"; rc=1
fi

echo
echo "===== 2) 反向验证：塞一条普通 CREATE INDEX（模拟有人写回去）====="
printf -- '-- mutant: 在事务迁移里用普通 CREATE INDEX（必须被门禁抓住）\nCREATE INDEX IF NOT EXISTS mutant_idx ON transfers (created_at);\n' > "$MUTANT"
set +e
( cd "$AFTER/server" && go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites' 2>&1 | tail -8 )
( cd "$AFTER/server" && go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites' >/dev/null 2>&1 )
mut_rc=$?
set -e
rm -f "$MUTANT"
if [ "$mut_rc" -ne 0 ]; then echo "[PASS] 门禁抓住变异体（测试红）"; else echo "[FAIL] 门禁没抓住变异体"; rc=1; fi

echo
echo "===== 3) 修前树：同一条规则有没有门禁？ ====="
set +e
( cd "$BEFORE/server" && go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites' -v 2>&1 | tail -4 )
set -e
if ( cd "$BEFORE/server" && go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites' -v 2>&1 | grep -q 'no tests to run' ); then
  echo "[PASS] 修前树确实没有这条门禁（规则当时无人守）"
else
  echo "[FAIL] 修前树已有门禁？树选错了"
  rc=1
fi

echo
[ "$rc" -eq 0 ] && echo "结论：门禁有牙（PASS→变异体红→修前无门禁）" || echo "结论：不成立"
exit "$rc"
