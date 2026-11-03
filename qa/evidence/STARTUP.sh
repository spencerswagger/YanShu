#!/bin/sh
# 雁书服务端 · 常驻实例启动脚本（可直接粘走 / 直接执行）
#
# 用法：
#   1) 改下面"配置区"四个值（其余不用动）
#   2) sh yanshu-start.sh            # 起服务
#      sh yanshu-start.sh stop       # 停服务
#      sh yanshu-start.sh status     # 看状态
#
# 纪律：凭据只从 /.keys/pg.env 读，脚本里不出现任何 DSN/口令原文。
set -eu

# ── 配置区 ─────────────────────────────────────────────────────────────
SRC=${YANSHU_SRC:-/srv/yanshu/src}        # 仓库源码根（含 server/）
PREFIX=${YANSHU_PREFIX:-/srv/yanshu}      # 二进制/数据/日志根
SCHEMA=${YANSHU_SCHEMA:-gate_ev1}         # 独立 schema，不动 public
ADDR=${YANSHU_ADDR:-127.0.0.1:8080}       # spencer 用 8080
PG_ENV=${YS_PG_ENV:-/.keys/pg.env}        # 凭据来源（只读，不落任何文件）
DSN_VAR=${YS_DSN_VAR:-PG_TEST_DSN}        # 用哪个库：PG_TEST_DSN=yanshu_test
# ──────────────────────────────────────────────────────────────────────

BIN="$PREFIX/bin/yanshu-server"
DELIVER="$PREFIX/bin/deliver"
BLOB="$PREFIX/blobs"
LOGS="$PREFIX/logs"
SECRETS="$PREFIX/secrets"
PIDFILE="$PREFIX/yanshu.pid"
LOGFILE="$LOGS/server-file.log"

log() { printf '%s\n' "$*"; }

need_src() {
    [ -d "$SRC/server" ] || { log "[BLOCKED] 找不到源码：$SRC/server"; exit 2; }
}

cmd_build() {
    need_src
    mkdir -p "$PREFIX/bin" "$BLOB" "$LOGS" "$SECRETS"
    chmod 0750 "$BLOB"; chmod 0700 "$LOGS" "$SECRETS"
    ( cd "$SRC/server" && go build -o "$BIN" ./cmd/yanshu-server && go build -o "$DELIVER" ./cmd/deliver )
    if [ ! -s "$SECRETS/token_secret" ]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SECRETS/token_secret"
        chmod 600 "$SECRETS/token_secret"
    fi
    log "built: $BIN / $DELIVER"
}

dsn() {
    # 从 pg.env 读 DSN（不打印），拼上 search_path
    set -a; . "$PG_ENV"; set +a
    eval "base=\${$DSN_VAR}"
    [ -n "${base:-}" ] || { log "[BLOCKED] $PG_ENV 里没有 $DSN_VAR"; exit 2; }
    printf '%s&search_path=%s' "$base" "$SCHEMA"
}

cmd_start() {
    [ -x "$BIN" ] || cmd_build
    D=$(dsn)
    # 1) schema
    psql "${D%%&search_path=*}" -c "create schema if not exists $SCHEMA" >/dev/null
    # 2) migrations（启动时也会跑，这里先自检一次）
    YANSHU_DATABASE_URL="$D" "$BIN" -migrate-only
    # 3) 起服务：日志走 YANSHU_LOG_FILE（正式文件），stdout 也留一份
    YANSHU_DATABASE_URL="$D" \
    YANSHU_BLOB_DIR="$BLOB" \
    YANSHU_ADDR="$ADDR" \
    YANSHU_VERIFIER=stub-allow \
    YANSHU_TOKEN_SECRET="$(cat "$SECRETS/token_secret")" \
    YANSHU_LOG_FILE="$LOGFILE" \
    setsid "$BIN" >>"$LOGS/stdout.log" 2>&1 </dev/null &
    echo $! > "$PIDFILE"
    # 4) 健康检查（进程 + listening + 无 bind 失败，不只看 healthz）
    i=0
    while [ $i -lt 50 ]; do
        curl -fsS --max-time 1 "http://$ADDR/healthz" >/dev/null 2>&1 && break
        i=$((i+1)); sleep 0.2
    done
    kill -0 "$(cat "$PIDFILE")" 2>/dev/null || { log "[BLOCKED] 进程已退出，见 $LOGS/stdout.log"; exit 2; }
    grep -q listening "$LOGFILE" 2>/dev/null || { log "[BLOCKED] 日志里没有 listening"; exit 2; }
    grep -q "bind: address already in use" "$LOGFILE" 2>/dev/null && { log "[BLOCKED] 端口被占"; exit 2; }
    log "started: $(curl -sS --max-time 2 "http://$ADDR/healthz")"
    log "log: $LOGFILE"
}

cmd_stop() {
    if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; rm -f "$PIDFILE"; fi
    pkill -f yanshu-server 2>/dev/null || true
    log "stopped"
}

cmd_status() {
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        log "running pid=$(cat "$PIDFILE")"
    else
        log "not running"
    fi
    curl -sS --max-time 2 "http://$ADDR/healthz" 2>/dev/null || true; echo
}

case "${1:-start}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    build)  cmd_build ;;
    *) log "usage: $0 start|stop|status|build"; exit 2 ;;
esac
