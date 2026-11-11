#!/bin/sh
# ============================================================================
# 雁书 v0.2.4 · 干净环境真收发 一键验收（Gate / 2026-11-11）
#
# 用法（在一台**有 docker + 至少一个 chromium** 的机器上，非 root 亦可，需在 docker 组）：
#   ./run.sh preflight        # 只做前置检查，不落地任何东西
#   ./run.sh up               # 干净目录 → 官方 compose → SWR 官方镜像 → 起服务 → 探活
#   ./run.sh transfer         # 双浏览器 ≥1 GiB 真收发 + 两侧 sha256（需要 browser-transfer.mjs）
#   ./run.sh secrets          # down && up -d 后 ./secrets 两个密钥 sha256 必须不变
#   ./run.sh negative-save    # 写盘失败必须可见（16 MiB，验「假绿」：报成功但无文件 = FAIL）
#   ./run.sh all              # 顺序跑 up → transfer → secrets，任何一步 FAIL 即停
#
# 铁律（脚本会自己断言，不许改参数绕过）：
#   * 工作目录必须是**新建的空目录**，里面只放官方 docker-compose.yml（+ 可选 .env，默不写）
#   * 镜像只从华为云 SWR 拉；**禁止本地 build**；**禁止改 compose 里的 tag**
#   * compose 文件 sha256 必须是已知值（见 COMPOSE_SHA），否则判 FAIL（防止有人偷偷改 compose）
#   * 任一不通过 → FAIL → 当场修 → 出 v0.2.5；不许留到第二天
#
# 退出码：0 PASS / 1 FAIL / 2 INCONCLUSIVE（缺依赖或环境不满足 —— **不算通过**）
# ============================================================================
set -u

# ---- 被测对象的已知指纹（改这里等于改验收口径，必须走 PR）----
TAG_DEFAULT="v0.2.4"
COMPOSE_SHA="16baed7e89f848386edfa00da9f0fcc4f48f43103ef0cab86ea8d5689a76884d"
COMPOSE_URL_TMPL="https://raw.githubusercontent.com/spencerswagger/YanShu/%s/docker-compose.yml"
REG="swr.cn-east-5.myhuaweicloud.com/spencerswagger"
DIG_SERVER="sha256:e253e71ee238fec49bf0e0eff84dcfa126241d608bc708e3865a1be79a677370"
DIG_WEB="sha256:ee3c8e7a085cb3974374b704c44a92467c7416be73ebb494443fd35705f3a6e0"
DIG_ALPINE="sha256:ec7ca0b6e94fe97eacac06ae7c8a5c20fca978adb4446af4abf1d46b7cdc818c"
DIG_PG="sha256:14f55ab28d36faa81870fdb6d182677caf2729a2330bd5be84afecc77d1c9601"
PORT_DEFAULT=18080
FILE_GIB=1

TAG="$TAG_DEFAULT"
WORK=""
PORT="$PORT_DEFAULT"
EV=""
JSON_OUT=""
EV_OVERRIDE=""
NEG_FRESH=0
NEG_KEEP=0

n_pass=0; n_fail=0; n_skip=0; fail_names=""

ok()   { n_pass=$((n_pass+1)); printf '  PASS  %s\n' "$1" | tee -a "$EV/summary.txt"; }
bad()  { n_fail=$((n_fail+1)); fail_names="$fail_names|$1"; printf '  FAIL  %s\n' "$1" | tee -a "$EV/summary.txt"; }
skip() { n_skip=$((n_skip+1)); printf '  SKIP  %s\n' "$1" | tee -a "$EV/summary.txt"; }
die2() { printf '[INCONCLUSIVE] %s\n' "$1" | tee -a "$EV/summary.txt"; exit 2; }

# 记一步的原始输出 + 真实退出码（**不要** `cmd | tee log; rc=$?` —— 取到的是 tee 的码）
step() {
    name="$1"; shift
    log="$EV/logs/$name.log"
    printf '\n$ %s\n' "$*" > "$log"
    ( "$@" ) >> "$log" 2>&1
    rc=$?
    printf '[rc=%s] %s\n' "$rc" "$name"
    printf '$ %s\nrc=%s\n' "$*" "$rc" >> "$EV/logs/index.txt"
    cat "$log" | sed 's/^/      /' | tail -25
    return $rc
}

sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# 密钥文件是 0600 且属主 10001（compose 里故意这么设的）→ 宿主用户读不了，
# 必须借助容器算 sha256（这也顺带证明「容器视角能读到、权限没跑偏」）
sec_sha() {
    docker run --rm -v "$WORK/secrets:/s:ro" "$REG/library-alpine:3.20" \
        sha256sum "/s/$1" 2>/dev/null | cut -d' ' -f1
}

# ------------------------------------------------------------------ 参数
while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --work) WORK="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --gib) FILE_GIB="$2"; shift 2 ;;
        --json-out) JSON_OUT="$2"; shift 2 ;;
        --ev) EV_OVERRIDE="$2"; shift 2 ;;
        --fresh-stack) NEG_FRESH=1; shift ;;
        --keep-stack) NEG_KEEP=1; shift ;;
        preflight|up|transfer|secrets|negative-save|all) CMD="$1"; shift ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
: "${CMD:=all}"

# ------------------------------------------------------------------ 证据目录
ROOT=$(cd "$(dirname "$0")" && pwd)
if [ -n "${EV_OVERRIDE:-}" ]; then EV="$EV_OVERRIDE"; else EV="$ROOT/results/$(date +%Y%m%dT%H%M%S)-$TAG"; fi
mkdir -p "$EV/logs" || { echo "无法建证据目录" >&2; exit 2; }

# ------------------------------------------------------------------ preflight
cmd_preflight() {
    echo "== preflight =="
    echo "host=$(hostname) user=$(id -un) uid=$(id -u) date=$(date -Is)"

    command -v docker >/dev/null 2>&1 || die2 "没有 docker CLI"
    step 01-docker-version docker info --format 'server={{.ServerVersion}} driver={{.Driver}} cgroup={{.CgroupDriver}}' || die2 "docker 不可用"
    step 02-compose-version docker compose version || die2 "docker compose 插件不可用"
    ok "docker + compose 可用"

    # 必须真能 run 容器（只有 socket 不算）
    if step 03-docker-run docker run --rm "$REG/library-alpine:3.20" /bin/sh -c 'echo container-ok'; then
        grep -q container-ok "$EV/logs/03-docker-run.log" && ok "docker run 真能起容器" || bad "docker run 无预期输出"
    else
        bad "docker run 起不了容器（有 socket 但跑不了容器 = 不可用）"
    fi

    command -v curl >/dev/null 2>&1 || die2 "没有 curl"
    command -v sha256sum >/dev/null 2>&1 || die2 "没有 sha256sum"

    # 磁盘：源文件 + 落地文件 + 卷，留 ≥ 3× 文件大小余量
    need=$((FILE_GIB * 3 + 3))
    if [ -n "$WORK" ] && [ -d "$(dirname "$WORK")" ]; then dfdir=$(dirname "$WORK"); else dfdir=$(pwd); fi
    avail=$(df -Pk "$dfdir" | awk 'NR==2{printf "%d", $4/1024/1024}')
    if [ "${avail:-0}" -ge "$need" ]; then ok "磁盘余量 ${avail} GiB ≥ ${need} GiB（$dfdir）"; else bad "磁盘余量 ${avail} GiB < ${need} GiB（$dfdir）"; fi

    # SWR 可达
    code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "https://${REG%%/*}/v2/" 2>/dev/null || echo 000)
    case "$code" in 200|401|403) ok "SWR 可达（/v2/ HTTP $code）" ;; *) bad "SWR 不可达（HTTP $code）" ;; esac

    # 端口必须空闲：上一个栈没 down 就再跑一次，会卡在 port already allocated 上，
    # 表现为「up 失败但 healthz 还 ok」（其实是旧栈在应答）—— 这种假绿必须在这里挡掉
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$PORT\$"; then
            bad "端口 $PORT 已被占用（先 down 掉上一个栈；否则 up 会失败而 healthz 仍由旧栈应答）"
        else ok "端口 $PORT 空闲"; fi
    else
        skip "没有 ss，跳过端口占用检查（请自行确认 $PORT 空闲）"
    fi

    # 浏览器连接方式：脚本打的是本机回环，浏览器必须与 docker 同机
    echo "      浏览器入口约定：http://127.0.0.1:$PORT/ （chromium 必须与本机 docker 同机）"

    # 浏览器（只在 transfer 阶段必需）
    if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 \
       || command -v google-chrome >/dev/null 2>&1; then
        ok "找到 chromium/chrome"
    else
        skip "没找到 chromium（transfer 阶段必需；up/secrets 不受影响）"
    fi
}

# ------------------------------------------------------------------ up
cmd_up() {
    echo "== 干净目录 =="
    [ -n "$WORK" ] || WORK=$(mktemp -d "${TMPDIR:-/tmp}/ys-clean-$TAG-XXXXXX")
    mkdir -p "$WORK"
    if [ -n "$(ls -A "$WORK" 2>/dev/null)" ]; then
        printf 'notempty=%s\n' "$(ls -A "$WORK")" > "$EV/logs/04-workdir.log"
        bad "工作目录不是空的：$WORK（口径要求新空目录）"
        return 1
    fi
    ok "工作目录是新建空目录：$WORK"
    echo "$WORK" > "$EV/workdir.txt"

    echo "== 只放官方 docker-compose.yml =="
    url=$(printf "$COMPOSE_URL_TMPL" "$TAG")
    step 05-fetch-compose curl -fsS -o "$WORK/docker-compose.yml" "$url" || { bad "取不到 compose：$url"; return 1; }
    got=$(sha_of "$WORK/docker-compose.yml")
    echo "$got" > "$EV/compose.sha256"
    if [ "$got" = "$COMPOSE_SHA" ]; then ok "compose sha256 = $got（与已知值一致）"
    else bad "compose sha256 = $got ≠ 已知 $COMPOSE_SHA（compose 被改过，禁跑）"; fi

    if grep -qE '^[[:space:]]*build:' "$WORK/docker-compose.yml"; then bad "compose 里出现 build: 段（禁本地构建）"; else ok "compose 无 build: 段"; fi

    ( cd "$WORK" && docker compose config > "$EV/logs/06-compose-config.log" 2>&1 )
    if [ $? -eq 0 ]; then ok "docker compose config 解析通过"; else bad "docker compose config 失败"; fi
    ( cd "$WORK" && docker compose config | grep -E '^\s+image:' | sed 's/^ *//' ) > "$EV/images-resolved.txt"
    cat "$EV/images-resolved.txt" | sed 's/^/      /'
    if grep -q "yanshu-server:$TAG" "$EV/images-resolved.txt" && grep -q "yanshu-web:$TAG" "$EV/images-resolved.txt"; then
        ok "镜像 tag 解析为 $TAG（未被改写）"
    else bad "解析出的镜像 tag 不含 $TAG"; fi

    echo "== 拉镜像（只用 SWR）=="
    ( cd "$WORK" && docker compose pull ) > "$EV/logs/07-pull.log" 2>&1
    rc=$?
    tail -6 "$EV/logs/07-pull.log" | sed 's/^/      /'
    [ $rc -eq 0 ] && ok "docker compose pull 成功" || bad "docker compose pull 失败（见 logs/07-pull.log）"

    ( cd "$WORK" && for img in yanshu-server yanshu-web library-alpine library-postgres; do
        t=$TAG; case $img in library-alpine) t=3.20 ;; library-postgres) t=16-alpine ;; esac
        printf '%s:%s %s\n' "$img" "$t" "$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$REG/$img:$t" 2>/dev/null | tr '\n' ' ')"
      done ) > "$EV/image-digests.txt"
    cat "$EV/image-digests.txt" | sed 's/^/      /'
    if grep -q "${DIG_SERVER#sha256:}" "$EV/image-digests.txt" && grep -q "${DIG_WEB#sha256:}" "$EV/image-digests.txt" \
       && grep -q "${DIG_ALPINE#sha256:}" "$EV/image-digests.txt" && grep -q "${DIG_PG#sha256:}" "$EV/image-digests.txt"; then
        ok "四个镜像 digest 全与登记值一致（内容未被替换，等价「按 digest 固定」）"
    else bad "镜像 digest 与登记值不一致（见 image-digests.txt）"; fi

    echo "== 起服务 =="
    ( cd "$WORK" && docker compose up -d --wait ) > "$EV/logs/08-up.log" 2>&1
    rc=$?
    tail -10 "$EV/logs/08-up.log" | sed 's/^/      /'
    [ $rc -eq 0 ] && ok "docker compose up -d --wait 返回 0" || bad "up -d --wait 失败"

    ( cd "$WORK" && docker compose ps ) > "$EV/logs/09-ps.log" 2>&1
    cat "$EV/logs/09-ps.log" | sed 's/^/      /'
    nrun=$(cd "$WORK" && docker compose ps --status running --format '{{.Service}}' | wc -l | tr -d ' ')
    if [ "${nrun:-0}" -ge 3 ]; then ok "running 服务数 $nrun ≥ 3（postgres/server/web）"; else bad "running 服务数 ${nrun:-0} < 3"; fi

    body=$(curl -fsS -m 15 "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo '')
    printf 'GET /healthz -> %s\n' "${body:-<空>}" > "$EV/logs/10-healthz.log"
    case "$body" in *'"status":"ok"'*) ok "web 18080 /healthz 返回 status=ok" ;; *) bad "/healthz 未返回 ok（body=${body:-<空>}）" ;; esac

    ( cd "$WORK" && docker compose logs --tail=50 yanshu-server ) > "$EV/logs/11-server-logs.log" 2>&1
    if grep -q 'sm2 verifier loaded' "$EV/logs/11-server-logs.log"; then ok "server 日志含 sm2 verifier loaded"; else bad "server 日志缺 sm2 verifier loaded"; fi

    if [ -f "$WORK/secrets/token_secret" ] && [ -f "$WORK/secrets/pg_password" ]; then
        ok "首次启动自动生成 ./secrets/{token_secret,pg_password}"
        sec_sha token_secret > "$EV/secrets-before.txt"
        sec_sha pg_password >> "$EV/secrets-before.txt"
    else bad "./secrets 下两个密钥文件缺失"; fi
}

# ------------------------------------------------------------------ transfer
cmd_transfer() {
    echo "== 双浏览器真收发 =="
    [ -f "$EV/workdir.txt" ] && WORK=$(cat "$EV/workdir.txt")
    [ -n "$WORK" ] || die2 "还没跑 up（找不到 workdir.txt）"
    if ! command -v node >/dev/null 2>&1; then die2 "没有 node，无法跑浏览器自动化（可改手工步骤，见 README）"; fi
    # 测试文件放在**干净目录之外**（干净目录只能有 compose），且不能放 /tmp（可能太小）
    FIXDIR="${FIXDIR:-$(dirname "$WORK")/ys-fixtures}"
    mkdir -p "$FIXDIR"
    src="$FIXDIR/src-$TAG-$FILE_GIB-GiB.bin"
    if [ ! -f "$src" ] || [ "$(wc -c < "$src")" -lt "$((FILE_GIB * 1073741824))" ]; then
        echo "      生成 $FILE_GIB GiB 随机文件：$src"
        head -c "$((FILE_GIB * 1073741824))" /dev/urandom > "$src" || { bad "生成测试文件失败"; return 1; }
    fi
    printf '%s  %s\n' "$(sha_of "$src")" "$src" > "$EV/source.sha256"
    echo "      源文件 $(ls -l "$src" | awk '{print $5}') B  sha256=$(cat "$EV/source.sha256")"

    out="$WORK/landed-$TAG.bin"
    step 21-browser-transfer node "$ROOT/browser-transfer.mjs" \
        --url "http://127.0.0.1:$PORT/" --src "$src" --out "$out" --gib "$FILE_GIB" \
        --evidence "$EV" --dl-dir "$FIXDIR/downloads"
    rc=$?
    if [ $rc -ne 0 ]; then bad "浏览器双端收发失败（rc=$rc，见 logs/21-browser-transfer.log）"; return 1; fi
    ok "双浏览器收发完成"

    step 22-verify-sha256 sh "$ROOT/verify-sha256.sh" "$src" "$out"
    if [ $? -eq 0 ]; then ok "源/落地 sha256 逐字一致"; else bad "源/落地 sha256 不一致"; fi

    # 块覆盖判定（不看进度条）：把上轮「1024/707」的争议钉死
    if [ -f "$EV/chunk-coverage.json" ]; then
        cov=$(python3 - "$EV/chunk-coverage.json" <<'PYEOF'
import json,sys
d=json.load(open(sys.argv[1]))
print(d.get("unique_200",-1), d.get("missing_count",-1), d.get("min_index",-1), d.get("max_index",-1), d.get("retries",-1))
PYEOF
)
        set -- $cov
        cov_ok=$1; cov_miss=$2; cov_min=$3; cov_max=$4; cov_retry=$5
        if [ "${cov_miss:-1}" = "0" ] && [ "${cov_ok:-0}" -gt 0 ]; then
            ok "块覆盖完整：$cov_ok 个 index 有 200，index [${cov_min}..${cov_max}]，0 缺口（重试 $cov_retry 次）"
        else
            bad "块覆盖有缺口：$cov_ok 个 200 / 缺 ${cov_miss} 个（index [${cov_min}..${cov_max}]）"
        fi
    else
        skip "没有 chunk-coverage.json（块覆盖未判）"
    fi
}

# ------------------------------------------------------------------ secrets
cmd_secrets() {
    echo "== down && up -d 后密钥必须不变 =="
    [ -f "$EV/workdir.txt" ] && WORK=$(cat "$EV/workdir.txt")
    [ -n "$WORK" ] || die2 "还没跑 up（找不到 workdir.txt）"
    b_tok=$(sec_sha token_secret); b_pg=$(sec_sha pg_password)
    if [ -z "$b_tok" ] || [ -z "$b_pg" ]; then bad "重启前算不出密钥 sha256（容器内读取失败）"; return 1; fi

    ( cd "$WORK" && docker compose down ) > "$EV/logs/30-down.log" 2>&1
    rc=$?; [ $rc -eq 0 ] && ok "docker compose down 返回 0" || bad "docker compose down 失败（rc=$rc）"
    [ -d "$WORK/secrets" ] && ok "down 之后 ./secrets 仍在（未删密钥）" || bad "down 之后 ./secrets 不见了"

    ( cd "$WORK" && docker compose up -d --wait ) > "$EV/logs/31-up-again.log" 2>&1
    rc=$?; [ $rc -eq 0 ] && ok "再次 up -d --wait 返回 0" || bad "第二次 up 失败（rc=$rc）"

    a_tok=$(sec_sha token_secret); a_pg=$(sec_sha pg_password)
    { printf 'token_secret %s\npg_password  %s\n' "$b_tok" "$b_pg"; } > "$EV/secrets-compare.txt"
    { printf 'token_secret %s\npg_password  %s\n' "$a_tok" "$a_pg"; } >> "$EV/secrets-compare.txt"
    printf -- '--- 重启前 / 重启后 ---\n' >> "$EV/secrets-compare.txt"
    cat "$EV/secrets-compare.txt" | sed 's/^/      /'

    if [ -n "$b_tok" ] && [ "$b_tok" = "$a_tok" ] && [ -n "$b_pg" ] && [ "$b_pg" = "$a_pg" ]; then
        ok "重启前后两个密钥 sha256 完全一致（token 与 pg 都复用）"
    else
        bad "重启前后密钥不一致（token $(printf %s "$b_tok" | cut -c1-12)→$(printf %s "$a_tok" | cut -c1-12) / pg $(printf %s "$b_pg" | cut -c1-12)→$(printf %s "$a_pg" | cut -c1-12)）"
    fi

    body=$(curl -fsS -m 15 "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo '')
    case "$body" in *'"status":"ok"'*) ok "重启后 /healthz 仍 ok（旧密钥能开旧库）" ;; *) bad "重启后 /healthz 不 ok（旧密钥开不了旧库）" ;; esac
}

# ------------------------------------------------------------------ negative-save
# 负面实测：**报成功就必须有文件；写盘失败必须可见**。
# v0.2.4 判据：这条 FAIL（假绿 + 已 ack = 数据丢失）；v0.2.5 必须 PASS 才允许发版。
#   ./run.sh negative-save --tag v0.2.4 --ev <证据目录>   # 自动为该 tag 起独立干净栈
#   ./run.sh negative-save --work <已存在的栈> --ev <证据目录>
cmd_negative_save() {
    echo "== negative-save：假绿判定（tag=$TAG）=="
    command -v node >/dev/null 2>&1 || die2 "没有 node"

    # 给了非默认 tag（或显式 --fresh-stack）就为该 tag 起一条独立的干净栈
    if [ "${NEG_FRESH:-0}" = "1" ] || [ "$TAG" != "$TAG_DEFAULT" ] || [ -z "${WORK:-}" ]; then
        base=$(dirname "${WORK:-/data/x}")
        [ -d "$base" ] || base=/data
        STACK="$base/clean-$TAG"
        if [ -n "$(ls -A "$STACK" 2>/dev/null)" ]; then
            # 已被别的 tag 用过 → 重建，避免镜像混用
            ( cd "$STACK" && docker compose down -v >/dev/null 2>&1 ); rm -rf "$STACK"
        fi
        mkdir -p "$STACK"
        url=$(printf "$COMPOSE_URL_TMPL" "$TAG")
        step 41-neg-fetch-compose curl -fsS -o "$STACK/docker-compose.yml" "$url" || { bad "取不到 $TAG 的 compose"; return 1; }
        got=$(sha_of "$STACK/docker-compose.yml")
        if [ "$got" = "$COMPOSE_SHA" ]; then ok "compose sha256 与已知值一致（$got）"
        elif [ "$TAG" = "$TAG_DEFAULT" ]; then bad "compose sha256 不一致：$got"
        else skip "老 tag 的 compose 与已知值不同（$got）—— 只做记录，不判 FAIL"; fi
        if grep -qE '^[[:space:]]*build:' "$STACK/docker-compose.yml"; then bad "compose 含 build: 段"; else ok "compose 无 build 段"; fi
        ( cd "$STACK" && YANSHU_IMAGE_TAG="$TAG" docker compose pull ) > "$EV/logs/42-neg-pull-$TAG.log" 2>&1 \
            && ok "拉取 $TAG 镜像成功" || bad "拉取 $TAG 镜像失败（见 logs/42-neg-pull-$TAG.log）"
        ( cd "$STACK" && docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
            "$REG/yanshu-server:$TAG" ) > "$EV/neg-image-digest-$TAG.txt" 2>/dev/null
        ( cd "$STACK" && YANSHU_IMAGE_TAG="$TAG" docker compose up -d --wait ) > "$EV/logs/43-neg-up-$TAG.log" 2>&1 \
            && ok "$TAG 栈起来（up -d --wait）" || { bad "$TAG 栈起不来"; return 1; }
        WORK="$STACK"; echo "$WORK" > "$EV/workdir.txt"
    else
        ok "复用现有栈：$WORK"
    fi

    FIXDIR="${FIXDIR:-$(dirname "$WORK")/ys-fixtures}"; mkdir -p "$FIXDIR"
    src="$FIXDIR/neg-16MiB.bin"
    [ -f "$src" ] || head -c $((16 * 1024 * 1024)) /dev/urandom > "$src"
    printf '%s  %s\n' "$(sha_of "$src")" "$src" > "$EV/negative-save-src-$TAG.sha256"

    ack_before=$( ( cd "$WORK" && docker compose logs yanshu-server 2>/dev/null ) | grep -c 'ack' || true)
    step "40-negative-save-$TAG" node "$ROOT/negative-save.mjs" \
        --url "http://127.0.0.1:$PORT/" --src "$src" --evidence "$EV" \
        --dl-dir "$FIXDIR/neg-downloads-$TAG" --wait-s 180
    rc=$?
    ack_after=$( ( cd "$WORK" && docker compose logs yanshu-server 2>/dev/null ) | grep -c 'ack' || true)
    ack_delta=$((ack_after - ack_before))

    # 四项现象落一张表（谁都能一眼看完）
    sum="$EV/negative-save-summary-$TAG.txt"
    {
        printf '镜像 tag        : %s\n' "$TAG"
        printf '镜像 digest     : %s\n' "$(head -1 "$EV/neg-image-digest-$TAG.txt" 2>/dev/null)"
        printf '界面「已保存至本机」: %s\n' "$(python3 -c "import json;d=json.load(open('$EV/negative-save.json'));print(','.join(str(v['ui_says_saved']) for v in d['verdicts']))" 2>/dev/null)"
        printf '下载目录文件数  : %s\n' "$(python3 -c "import json;d=json.load(open('$EV/negative-save.json'));print(','.join(str(len(v['files'])) for v in d['verdicts']))" 2>/dev/null)"
        printf 'ack 计数        : 前 %s → 后 %s（delta=%s）\n' "$ack_before" "$ack_after" "$ack_delta"
        printf 'ack 原始行      : %s\n' "$( ( cd "$WORK" && docker compose logs --tail=200 yanshu-server 2>/dev/null ) | grep -i 'ack' | tail -2 | tr '\n' '|')"
        printf '页面可见报错    : %s\n' "$(python3 -c "import json;d=json.load(open('$EV/negative-save.json'));print(';'.join(v['error_text'] or '-' for v in d['verdicts']))" 2>/dev/null)"
        printf '场景判定        : %s\n' "$(python3 -c "import json;d=json.load(open('$EV/negative-save.json'));print('; '.join(v['tag']+'='+v['verdict'] for v in d['verdicts']))" 2>/dev/null)"
    } | tee "$sum"
    cat "$sum" >> "$EV/summary.txt"

    if [ $rc -eq 0 ]; then
        ok "[$TAG] 真保存会落盘、写盘失败必报错（无假绿）"
    else
        bad "[$TAG] 假绿或静默失败（见 negative-save.json）"
    fi
    if [ "$ack_delta" -gt 0 ] && grep -q '假绿' "$EV/logs/40-negative-save-$TAG.log" 2>/dev/null; then
        bad "[$TAG] 假成功且已 ack（delta=$ack_delta）：密文已删、文件从未写出 = 数据丢失"
    fi

    # 该 tag 的栈用完就停，避免下一个 tag 抢 18080
    if [ "${NEG_KEEP:-0}" != "1" ]; then
        ( cd "$WORK" && docker compose down ) > "$EV/logs/44-neg-down-$TAG.log" 2>&1 && ok "[$TAG] 栈已停（释放 $PORT）"
    fi
}

# ------------------------------------------------------------------ main
case "$CMD" in
    preflight) cmd_preflight ;;
    up)        cmd_up ;;
    transfer)  cmd_transfer ;;
    secrets)   cmd_secrets ;;
    negative-save) cmd_negative_save ;;
    all)
        cmd_preflight
        if [ "$n_fail" -eq 0 ]; then
            cmd_up && cmd_transfer && cmd_secrets
        fi
        ;;
esac

echo
echo "== 汇总 =="
printf 'PASS=%s FAIL=%s SKIP=%s\n' "$n_pass" "$n_fail" "$n_skip" | tee -a "$EV/summary.txt"
[ -n "$fail_names" ] && echo "失败项：$(printf '%s' "$fail_names" | tr '|' '\n' | sed '/^$/d' | tr '\n' ';')" | tee -a "$EV/summary.txt"
echo "证据目录：$EV"
[ -n "$JSON_OUT" ] && printf '{"pass":%s,"fail":%s,"skip":%s,"evidence":"%s","tag":"%s"}\n' \
    "$n_pass" "$n_fail" "$n_skip" "$EV" "$TAG" > "$JSON_OUT"

if [ "$n_fail" -gt 0 ]; then echo "判定：FAIL —— 当场修，出下一版（不许留到第二天）"; exit 1; fi
if [ "$n_pass" -eq 0 ]; then echo "判定：INCONCLUSIVE —— 一条都没跑成，不算通过"; exit 2; fi
echo "判定：PASS"
exit 0
