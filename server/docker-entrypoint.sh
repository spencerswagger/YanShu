#!/bin/sh
# 容器入口：以 root 修正命名卷权限，然后**降权**到 10001 运行所有业务进程。
#
# 背景：docker 新建的命名卷属主是 root:root，而镜像以非 root 运行，
# 首次 `compose up` 会因写不了日志/密文块而崩溃（permission denied）。
# 这里只在启动瞬间用 root 做 chown，业务进程始终是非 root（su-exec 降权）。
set -eu

blob="${YANSHU_BLOB_DIR:-/app/data/blobs}"
logs="${YANSHU_LOG_DIR:-/app/data/logs}"

# 零配置：密钥来自挂载的 /run/secrets（由 init 服务生成），无需用户 export。
# 显式设置的 YANSHU_* 环境变量优先，便于高级用法覆盖。
token_file="${YANSHU_TOKEN_SECRET_FILE:-/run/secrets/token_secret}"
pg_file="${YANSHU_PG_PASSWORD_FILE:-/run/secrets/pg_password}"

if [ -z "${YANSHU_TOKEN_SECRET:-}" ] && [ -s "$token_file" ]; then
    YANSHU_TOKEN_SECRET="$(cat "$token_file")"
    export YANSHU_TOKEN_SECRET
fi
if [ -z "${YANSHU_DATABASE_URL:-}" ] && [ -s "$pg_file" ]; then
    YANSHU_DATABASE_URL="postgres://yanshu:$(cat "$pg_file")@postgres:5432/yanshu?sslmode=disable"
    export YANSHU_DATABASE_URL
fi

if [ -z "${YANSHU_TOKEN_SECRET:-}" ]; then
    echo "entrypoint: no upload-token secret (set YANSHU_TOKEN_SECRET or mount /run/secrets/token_secret)" >&2
    exit 1
fi
if [ -z "${YANSHU_DATABASE_URL:-}" ]; then
    echo "entrypoint: no database url (set YANSHU_DATABASE_URL or mount /run/secrets/pg_password)" >&2
    exit 1
fi

mkdir -p "$blob" "$logs"

# 快速失败：chown 失败（只读挂载、SELinux 拒绝等）继续启动只会变成 permission denied 崩溃循环，
# 且日志难定位；这里直接报明确错误并退出。
if ! chown -R 10001:10001 "$blob" "$logs"; then
    echo "entrypoint: cannot fix ownership of $blob / $logs" \
         "(check volume mount and permissions; need writable dirs owned by 10001)" >&2
    exit 1
fi

# 迁移也以非 root 身份执行
su-exec yanshu:yanshu /app/yanshu-server -migrate-only

exec su-exec yanshu:yanshu /app/yanshu-server "$@"
