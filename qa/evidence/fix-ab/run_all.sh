#!/bin/sh
# 一条命令跑完两处修复的独立 A/B（三组实验）。不动工作树、不切分支：
# 用 `git archive <ref>` 把两版代码取到临时目录再编二进制。
#
# 用法：
#   qa/evidence/fix-ab/run_all.sh \
#     --before-ref bf84457 \                  # 修前基线：必须写死"合入前"的 sha（见下）
#     --after-ref  7385f8b \                  # #56 合入点（终结态 410）
#     [--envelope-after-ref 760dfdb] \        # #58 分支 head（合入后换成合入点 sha）
#     [--guard-ref 9efc88f] \                 # #57 合入点（建索引门禁）
#     [--rows 600000] [--work /tmp/fix-ab-run] [--dsn "$TEST_DATABASE_URL"]
#
# 关于 --before-ref：**不要用 origin/main**。#56/#57 已合入，main 本身就是"修后"，
# 拿它当 before 会让 A/B 反着判。合入前的最后一个 main 是 bf84457（#55 合入点），
# 也是本脚本的默认值；脚本会拦住"before 与任一 after 指向同一 commit"的调用。
#
# 退出码：0 全部符合预期；1 有不符合；2 环境失败（BUILD/PG/ref）。
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
# 修前基线不是 origin/main：#56（7385f8b）/ #57（9efc88f）已合入，main 本身已是"修后"。
# bf84457 = #55 合入点 = 这两张合入前的最后一个 main。
BEFORE=bf84457
AFTER=
ENV_AFTER=
GUARD_REF=
ROWS=600000
WORK=${TMPDIR:-/tmp}/fix-ab-run
DSN=${TEST_DATABASE_URL:-}

while [ $# -gt 0 ]; do
  case "$1" in
    --before-ref) BEFORE=$2; shift 2 ;;
    --after-ref) AFTER=$2; shift 2 ;;
    --envelope-after-ref) ENV_AFTER=$2; shift 2 ;;
    --guard-ref) GUARD_REF=$2; shift 2 ;;
    --rows) ROWS=$2; shift 2 ;;
    --work) WORK=$2; shift 2 ;;
    --dsn) DSN=$2; shift 2 ;;
    -h|--help) sed -n '/^set -e$/q;p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$HERE/results
mkdir -p "$OUT" "$WORK/trees" "$WORK/bin"

[ -n "$DSN" ] || { echo "[BLOCKED] 需要 --dsn 或 TEST_DATABASE_URL（真 PG）" >&2; exit 2; }

resolve() { # $1=ref → 打印 commit sha；解析不到就 BLOCKED
  git -C "$REPO" rev-parse --verify --quiet "$1^{commit}" 2>/dev/null || {
    echo "[BLOCKED] 解析不到 ref/commit：$1" >&2; exit 2; }
}
BEFORE_SHA=$(resolve "$BEFORE")
AFTER_SHA=
ENV_AFTER_SHA=
GUARD_SHA=
if [ -n "$AFTER" ]; then AFTER_SHA=$(resolve "$AFTER"); fi
if [ -n "$ENV_AFTER" ]; then ENV_AFTER_SHA=$(resolve "$ENV_AFTER"); fi
if [ -n "$GUARD_REF" ]; then GUARD_SHA=$(resolve "$GUARD_REF"); fi

# 防呆（复审要求）：before 与任一 after 指向同一 commit 时，A/B 就是拿一份树自证，直接停。
for pair in "after=$AFTER_SHA" "envelope-after=$ENV_AFTER_SHA" "guard=$GUARD_SHA"; do
  name=${pair%%=*}; sha=${pair#*=}
  if [ -n "$sha" ] && [ "$sha" = "$BEFORE_SHA" ]; then
    echo "[BLOCKED] --before-ref 与 --$name 指向同一 commit（$BEFORE_SHA）→ A/B 无意义" >&2
    echo "           before 必须是修复合入前的树，例如 bf84457（#55 合入点）" >&2
    exit 2
  fi
done
echo "[refs] before=$BEFORE($BEFORE_SHA) after=${AFTER_SHA:--} envelope-after=${ENV_AFTER_SHA:--} guard=${GUARD_SHA:--}"

build() { # $1=ref  $2=name
  local ref=$1 name=$2 dir=$WORK/trees/$2
  rm -rf "$dir"; mkdir -p "$dir"
  git -C "$REPO" archive "$ref" | tar -x -C "$dir"
  ( cd "$dir/server" && go build -o "$WORK/bin/$name" ./cmd/yanshu-server )
  echo "[build] $name ← $ref ($(sha256sum "$WORK/bin/$name" | cut -d' ' -f1))"
}

mask() { # 结果文件要入库：把 DSN 里的口令打码
  printf '%s' "$*" | sed -E 's#://([^:/@]+):[^@]*@#://\1:***@#g'
}

RC_TOTAL=0
run() { # $1=name  $2...=command
  local name=$1; shift
  local log=$OUT/$STAMP-$name.txt
  local tmp=$OUT/.$STAMP-$name.out
  echo "===== $name @ $(date -u +%Y-%m-%dT%H:%M:%SZ) =====" | tee "$log"
  echo "[cmd] $(mask "$@")" | tee -a "$log"
  # 关键：不能 `"$@" | tee`，那样 $? 是 tee 的退出码（复审 P0-1 实测：全挂也 rc=0）
  set +e
  "$@" >"$tmp" 2>&1
  local rc=$?
  set -e
  cat "$tmp" >>"$log"
  rm -f "$tmp"
  echo "[exit=$rc] $name" | tee -a "$log"
  echo "$rc" > "$OUT/$STAMP-$name.rc"
  [ "$rc" -eq 0 ] || RC_TOTAL=1
}

set -- 
build "$BEFORE" before
run envelope-before python3 "$HERE/ab_contract_envelope.py" \
  --binary "$WORK/bin/before" --dsn "$DSN" --expect before --work "$WORK/env-before" \
  --json-out "$OUT/$STAMP-envelope-before.json"

rc_env=0
if [ -n "$ENV_AFTER" ]; then
  build "$ENV_AFTER" env-after
  run envelope-after python3 "$HERE/ab_contract_envelope.py" \
    --binary "$WORK/bin/env-after" --dsn "$DSN" --expect after --work "$WORK/env-after" \
    --json-out "$OUT/$STAMP-envelope-after.json" || rc_env=$?
else
  echo "===== envelope-after SKIP（未给 --envelope-after-ref：只跑信封修前基线，出不了 A/B 结论）=====" | \
    tee "$OUT/$STAMP-envelope-after.txt"
fi

if [ -n "$AFTER" ]; then
  build "$AFTER" after
  run terminal-before python3 "$HERE/ab_terminal_410.py" \
    --binary "$WORK/bin/before" --dsn "$DSN" --expect before --work "$WORK/term-before" \
    --json-out "$OUT/$STAMP-terminal-before.json"
  run terminal-after python3 "$HERE/ab_terminal_410.py" \
    --binary "$WORK/bin/after" --dsn "$DSN" --expect after --work "$WORK/term-after" \
    --json-out "$OUT/$STAMP-terminal-after.json"
fi

if [ -n "$GUARD_REF" ]; then
  rm -rf "$WORK/trees/guard"; mkdir -p "$WORK/trees/guard"
  git -C "$REPO" archive "$GUARD_REF" | tar -x -C "$WORK/trees/guard"
  run guard-teeth sh "$HERE/run_guard_teeth.sh" "$WORK/trees/guard" "$WORK/trees/before"
fi

run index-lock python3 "$HERE/ab_index_lock_write.py" --dsn "$DSN" --rows "$ROWS" \
  --json-out "$OUT/$STAMP-index-lock.json"

echo "结果目录：$OUT（前缀 $STAMP）"
[ "$RC_TOTAL" -eq 0 ] || { echo "[FAIL] 有实验不符合预期（见上面 exit!=0 的项与 .rc 文件）" >&2; exit 1; }
exit 0
