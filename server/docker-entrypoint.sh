#!/bin/sh
# 容器入口：以 root 修正命名卷权限，然后**降权**到 10001 运行所有业务进程。
#
# 背景：docker 新建的命名卷属主是 root:root，而镜像以非 root 运行，
# 首次 `compose up` 会因写不了日志/密文块而崩溃（permission denied）。
# 这里只在启动瞬间用 root 做 chown，业务进程始终是非 root（su-exec 降权）。
set -eu

blob="${YANSHU_BLOB_DIR:-/app/data/blobs}"
logs="${YANSHU_LOG_DIR:-/app/data/logs}"

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
