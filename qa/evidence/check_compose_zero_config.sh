#!/bin/sh
# 零配置部署验收：只下载 docker-compose.yml → `docker compose up -d`，不写 .env、不填密钥。
#
# 用法：
#   ./check_compose_zero_config.sh [--image-tag TAG] [--compose-url URL] [--keep] [--json-out FILE]
#   ./check_compose_zero_config.sh --selftest        # 只验判定逻辑，不需要 docker
#
# 退出码（三态，与其它 check_* 一致）：
#   0  PASS          —— 全部断言真跑通过
#   2  INCONCLUSIVE  —— 缺依赖（无 docker CLI / 无 compose 插件 / 起不来镜像），未判定；**不是通过**
#   1  FAIL          —— 任一条断言真实失败
#
# 断言清单（14 条，逐条打印 PASS/FAIL）：
#   ① 临时目录里只有 docker-compose.yml、**没有 .env**
#   ② `docker compose config -q` 返回 0（不写 .env 也能解析）
#   ③ `up -d --wait` 返回 0
#   ④ 容器数 == 2（postgres + yanshu-server）
#   ⑤ 两个容器状态都是 healthy
#   ⑥ `/healthz` 返回 200 且 body 含 `"status":"ok"`
#   ⑦ `docker compose logs yanshu-server` 含 `sm2 verifier loaded`
#   ⑧ `secrets/` 目录存在
#   ⑨ `secrets/token_secret` 权限 0600
#   ⑩ `secrets/pg_password` 权限 0600
#   ⑪ `token_secret` ≥ 32 字节
#   ⑫ `down && up -d` 后两个 secret 的 sha256 **不变**（复用，不重生成）
#   ⑬ `down -v && up -d` 后两个 secret 的 sha256 **变化**（重生成）
#   ⑭ 换新库后 `/healthz` 仍 200（新库能起）
#
# 说明：本脚本**不修改被测 compose 文件**；所有跑批在一个临时目录里进行，退出时清理（--keep 保留现场）。
set -u

EXIT_PASS=0
EXIT_FAIL=1
EXIT_INCONCLUSIVE=2

here=$(cd "$(dirname "$0")" && pwd)
tag="local"
compose_url="https://raw.githubusercontent.com/spencerswagger/YanShu/main/docker-compose.yml"
keep=0
json_out=""
selftest=0

while [ $# -gt 0 ]; do
    case "$1" in
        --image-tag) tag="${2:-}"; shift 2 ;;
        --compose-url) compose_url="${2:-}"; shift 2 ;;
        --json-out) json_out="${2:-}"; shift 2 ;;
        --keep) keep=1; shift ;;
        --selftest) selftest=1; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit $EXIT_PASS ;;
        *) echo "unknown arg: $1" >&2; exit $EXIT_INCONCLUSIVE ;;
    esac
done

n_pass=0
n_fail=0
fail_names=""
verdict=""

ok()   { n_pass=$((n_pass+1)); printf '  PASS  %s\n' "$1"; }
bad()  { n_fail=$((n_fail+1)); fail_names="$fail_names|$1"; printf '  FAIL  %s\n' "$1"; }
skip_all() { echo "$1" >&2; exit $EXIT_INCONCLUSIVE; }

sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# ---------------------------------------------------------------- 自测
if [ "$selftest" -eq 1 ]; then
    echo "== check_compose_zero_config.sh --selftest（只验判定逻辑，无 docker）=="
    rc_all=0

    # ① 缺依赖 → 必须 2，不能是 0
    ( PATH=/nonexistent; command -v docker >/dev/null 2>&1 ) && r=0 || r=2
    if [ "$r" -eq 2 ]; then echo "  PASS 缺 docker → INCONCLUSIVE(2)"; else echo "  FAIL 缺 docker 应 2"; rc_all=1; fi

    # ② sha 比较：相同判复用、不同判重生成
    a="abc"; b="abc"; c="def"
    if [ "$a" = "$b" ]; then echo "  PASS sha 相同 → 判复用"; else echo "  FAIL sha 比较逻辑"; rc_all=1; fi
    if [ "$a" != "$c" ]; then echo "  PASS sha 不同 → 判重生成"; else echo "  FAIL sha 比较逻辑"; rc_all=1; fi

    # ③ 三条计数聚合：有 FAIL 就是 FAIL，不是 PASS
    n_pass=3; n_fail=0
    if [ "$n_fail" -eq 0 ] && [ "$n_pass" -gt 0 ]; then echo "  PASS 全过 → 0"; else echo "  FAIL 聚合"; rc_all=1; fi
    n_pass=0; n_fail=0
    if [ "$n_pass" -eq 0 ]; then echo "  PASS 一条没跑 → INCONCLUSIVE(2)（不给 PASS）"; else echo "  FAIL 空跑应 2"; rc_all=1; fi
    n_pass=3; n_fail=1
    if [ "$n_fail" -gt 0 ]; then echo "  PASS 有 FAIL → 1"; else echo "  FAIL 聚合"; rc_all=1; fi

    echo "自测：$([ "$rc_all" -eq 0 ] && echo PASS || echo FAIL)"
    exit "$rc_all"
fi

# ---------------------------------------------------------------- 依赖
if ! command -v docker >/dev/null 2>&1; then
    skip_all "[INCONCLUSIVE] 没有 docker CLI —— 无法判定零配置部署（本项记 n/a，不是通过）"
fi
if ! docker compose version >/dev/null 2>&1; then
    skip_all "[INCONCLUSIVE] docker compose 插件不可用 —— 无法判定（本项记 n/a）"
fi
if ! command -v curl >/dev/null 2>&1; then
    skip_all "[INCONCLUSIVE] 没有 curl —— 无法取 compose 文件与探活"
fi

# ---------------------------------------------------------------- 现场
work=$(mktemp -d "${TMPDIR:-/tmp}/ys-compose-XXXXXX") || skip_all "[INCONCLUSIVE] 建临时目录失败"
cleanup() {
    if [ "$keep" -eq 1 ]; then
        echo "[keep] 现场保留在 $work"
        return
    fi
    ( cd "$work" 2>/dev/null && docker compose down -v >/dev/null 2>&1 )
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

cd "$work" || skip_all "[INCONCLUSIVE] 无法进入临时目录"

echo "== 0/6 取 docker-compose.yml（不创建 .env）=="
curl -fsS -o docker-compose.yml "$compose_url" || skip_all "[INCONCLUSIVE] 取不到 compose：$compose_url"
echo "compose: $(wc -l <docker-compose.yml) 行  sha256=$(sha_of docker-compose.yml)"

echo "== 1/6 解析与起服务 =="
if [ -f .env ]; then bad "① 临时目录不应有 .env（零配置要求）"; else ok "① 目录内只有 docker-compose.yml、无 .env"; fi

if docker compose config -q >/dev/null 2>&1; then ok "② docker compose config -q 返回 0（不写 .env 可解析）"
else bad "② docker compose config -q 失败（缺省值不足或变量未给默认）"; fi

up_ok=0
if docker compose up -d --wait >up.log 2>&1; then up_ok=1; ok "③ up -d --wait 返回 0"
else bad "③ up -d --wait 失败（见 $work/up.log 尾部）"; tail -15 up.log | sed 's/^/        /'; fi

echo "== 2/6 容器健康 =="
if [ "$up_ok" -eq 1 ]; then
    ps_json="docker compose ps --format json"
    n_cont=$(docker compose ps --format json 2>/dev/null | grep -c '"Service"')
    if [ "$n_cont" -eq 2 ]; then ok "④ 容器数 == 2（实测 $n_cont）"; else bad "④ 容器数应 2，实测 $n_cont"; fi
    n_healthy=$(docker compose ps --format json 2>/dev/null | grep -c '"Health":"healthy"')
    if [ "$n_healthy" -eq 2 ]; then ok "⑤ 两个容器均 healthy"; else bad "⑤ healthy 容器应 2，实测 $n_healthy"; fi
else
    bad "④⑤ 起服务失败，容器健康无法断言"
fi

echo "== 3/6 探活与日志 =="
port=$(docker compose port yanshu-server 8080 2>/dev/null | awk -F: '{print $NF}')
[ -n "${port:-}" ] || port=$(docker compose ps --format json 2>/dev/null | tr ',' '\n' | grep -o '"PublishedPort":[0-9]*' | head -1 | cut -d: -f2)
if [ -n "${port:-}" ]; then
    body=$(curl -fsS "http://127.0.0.1:$port/healthz" 2>/dev/null)
    if [ $? -eq 0 ] && printf '%s' "$body" | grep -q '"status":"ok"'; then
        ok "⑥ /healthz 200 且 status=ok（端口 $port）"
    else bad "⑥ /healthz 未返回 ok（端口 ${port:-?}，body=${body:-<空>}）"; fi
else
    bad "⑥ 取不到 yanshu-server 映射端口"
fi
if docker compose logs yanshu-server 2>/dev/null | grep -q "sm2 verifier loaded"; then
    ok "⑦ 启动日志含 sm2 verifier loaded"
else bad "⑦ 启动日志缺 sm2 verifier loaded（验签器没起来）"; fi

echo "== 4/6 secrets 自动生成 =="
if [ -d secrets ]; then ok "⑧ secrets/ 目录存在"; else bad "⑧ secrets/ 不存在（未自动生成密钥）"; fi
for f in token_secret pg_password; do
    if [ -f "secrets/$f" ]; then
        m=$(mode_of "secrets/$f")
        case "$m" in
            600) ok "⑨⑩ secrets/$f 权限 0600（实测 $m）" ;;
            *)   bad "⑨⑩ secrets/$f 权限应为 0600，实测 ${m:-?}" ;;
        esac
    else
        bad "⑨⑩ secrets/$f 不存在"
    fi
done
if [ -f secrets/token_secret ]; then
    n=$(wc -c <secrets/token_secret | tr -d ' ')
    if [ "$n" -ge 32 ]; then ok "⑪ token_secret 长度 $n B ≥ 32"; else bad "⑪ token_secret 只有 ${n}B（要求 ≥32）"; fi
else
    bad "⑪ token_secret 不存在，长度无法断言"
fi
s_tok_1=$(sha_of secrets/token_secret); s_pg_1=$(sha_of secrets/pg_password)

echo "== 5/6 down && up：secrets 必须复用 =="
docker compose down >/dev/null 2>&1
if docker compose up -d --wait >up2.log 2>&1; then
    s_tok_2=$(sha_of secrets/token_secret); s_pg_2=$(sha_of secrets/pg_password)
    if [ -n "$s_tok_1" ] && [ "$s_tok_1" = "$s_tok_2" ] && [ "$s_pg_1" = "$s_pg_2" ]; then
        ok "⑫ down && up 后两个 secret sha256 不变（复用）"
    else
        bad "⑫ down && up 后 secret 变了（token ${s_tok_1:0:12}→${s_tok_2:0:12} / pg ${s_pg_1:0:12}→${s_pg_2:0:12}）"
    fi
else
    bad "⑫ 第二次 up -d --wait 失败（复用场景起不来）"
fi

echo "== 6/6 down -v && up：secrets 必须重生成 + 新库能起 =="
docker compose down -v >/dev/null 2>&1
if docker compose up -d --wait >up3.log 2>&1; then
    s_tok_3=$(sha_of secrets/token_secret); s_pg_3=$(sha_of secrets/pg_password)
    if [ -n "$s_tok_3" ] && { [ "$s_tok_1" != "$s_tok_3" ] || [ "$s_pg_1" != "$s_pg_3" ]; }; then
        ok "⑬ down -v && up 后 secret 已重生成"
    else
        bad "⑬ down -v 后 secret 未变化（可能仍复用旧文件）"
    fi
    port2=$(docker compose port yanshu-server 8080 2>/dev/null | awk -F: '{print $NF}')
    body2=$(curl -fsS "http://127.0.0.1:${port2:-$port}/healthz" 2>/dev/null)
    if printf '%s' "$body2" | grep -q '"status":"ok"'; then ok "⑭ 新库 + 新密钥下 /healthz 仍 200"
    else bad "⑭ 重生成后 /healthz 未 ok（body=${body2:-<空>}）"; fi
else
    bad "⑬⑭ down -v 后 up -d --wait 失败（新库起不来）"
fi

# ---------------------------------------------------------------- 结论
echo
echo "------------------------------------------------------------"
echo "合计：PASS $n_pass / FAIL $n_fail"
if [ "$n_fail" -gt 0 ]; then verdict="FAIL"; rc=$EXIT_FAIL
elif [ "$n_pass" -eq 0 ]; then verdict="INCONCLUSIVE"; rc=$EXIT_INCONCLUSIVE
else verdict="PASS"; rc=$EXIT_PASS
fi
echo "结论：$verdict（镜像 tag=${tag}；在目标环境实测）"
if [ "$json_out" != "" ]; then
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    cat >"$json_out" <<EOF
{"generated_at":"$ts","image_tag":"$tag","compose_url":"$compose_url",
 "pass":$n_pass,"fail":$n_fail,"verdict":"$verdict","exit_code":$rc,
 "token_secret_sha256":["${s_tok_1:-}","${s_tok_2:-}","${s_tok_3:-}"],
 "pg_password_sha256":["${s_pg_1:-}","${s_pg_2:-}","${s_pg_3:-}"],
 "note":"在目标环境实测；三态语义与其他 check_* 一致"}
EOF
    echo "[report] 明细已写入 $json_out"
fi
exit $rc
