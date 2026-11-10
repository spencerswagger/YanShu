#!/bin/sh
# 定序仲裁：把 #57 / #58 / #56 三个 head 按两种顺序真合到同一个基线，各跑 build/vet/全包测试，
# 并打两序合并后的 tree SHA（相同就说明"顺序不影响结果"）。
#
# 用法： TEST_DATABASE_URL=... qa/evidence/release/order_ab.sh [workdir]
# 退出码：0 两序皆可行；1 有一序冲突/构建/测试失败；2 环境不成立。
set -u

WORK=${1:-/tmp/ys-order}
BASE=${BASE:-bf84457}   # v0.2.0 digest 合并点：#56/#57 都还没进
P57=${P57:-f941589}
P58=${P58:-760dfdb}
P56=${P56:-884fbe4}

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
[ -n "${TEST_DATABASE_URL:-}" ] || { echo "[BLOCKED] 需要 TEST_DATABASE_URL" >&2; exit 2; }
GITDIR=$(git -C "$REPO" rev-parse --git-common-dir) || { echo "[BLOCKED] 不在 git 仓库里" >&2; exit 2; }

rm -rf "$WORK"; mkdir -p "$WORK"
git clone -q "$GITDIR" "$WORK/repo" || { echo "[BLOCKED] clone 失败" >&2; exit 2; }
cd "$WORK/repo" || exit 2

run_order() { # $1=名字 $2..=三个 head
  name=$1; shift
  git checkout -q -B "$name" "$BASE"
  echo "===== ORDER $name base=$BASE  $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
  for c in "$@"; do
    out=$(git -c user.name=order-test -c user.email=ot@local merge --no-ff --no-edit "$c" 2>&1)
    rc=$?
    unmerged=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
    echo "--- merge $c rc=$rc unmerged=[${unmerged}]"
    if [ "$rc" -ne 0 ]; then
      echo "$out" | grep -E "CONFLICT|Auto-merging|error:" | head -6
      for f in $(git diff --name-only --diff-filter=U); do
        echo "  file: $f"
        git diff --no-color "$f" | grep -nE '^(\+\+\+|---|@@|<<<<<<<|=======|>>>>>>>)' | head -12
      done
      return 1
    fi
  done
  echo "--- tree SHA: $(git rev-parse HEAD^{tree}) ---"
  echo "--- 合后 build/vet ---"
  ( cd server && go build ./... && go vet ./... ) && echo "BUILD_VET_OK" || { echo "BUILD_VET_FAIL"; return 1; }
  echo "--- 合后 go test -count=1 ./...（$(cd server && go list ./... | wc -l) 包，-count=1 跳过缓存）---"
  # 不能 `go test | tail`：管道状态是 tail 的，测试红了也会被当成成功（复审 P1）。
  ( cd server && TEST_DATABASE_URL="$TEST_DATABASE_URL" go test -count=1 ./... ) >"$WORK/$name-test.log" 2>&1
  trc=$?
  tail -20 "$WORK/$name-test.log"
  if [ "$trc" -ne 0 ]; then
    echo "GO_TEST_FAIL rc=$trc（完整日志 $WORK/$name-test.log）"
    return 1
  fi
  return 0
}

rc_all=0
for spec in "A_57_58_56:$P57 $P58 $P56" "B_57_56_58:$P57 $P56 $P58"; do
  name=${spec%%:*}; refs=${spec#*:}
  if run_order "$name" $refs; then echo "ORDER $name: OK"; else echo "ORDER $name: FAIL"; rc_all=1; fi
  echo
done

A_TREE=$(git rev-parse A_57_58_56^{tree} 2>/dev/null || echo "?")
B_TREE=$(git rev-parse B_57_56_58^{tree} 2>/dev/null || echo "?")
echo "== 结论 =="
echo "A tree=$A_TREE"
echo "B tree=$B_TREE"
if [ "$A_TREE" = "$B_TREE" ]; then
  echo "两序合并结果完全相同（tree SHA 一致）"
else
  echo "两序结果不同（需人工看）"; rc_all=1
fi
[ "$rc_all" -eq 0 ] && echo "两序皆可行" || echo "至少一序有问题（见上）"
exit "$rc_all"
