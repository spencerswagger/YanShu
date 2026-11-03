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
# 幂等：属主已正确或卷只读时 chown 可能失败，不阻塞启动（真正写不进去会在业务层报错）
chown -R 10001:10001 "$blob" "$logs" 2>/dev/null || true

# 迁移也以非 root 身份执行
su-exec 10001:10001 /app/yanshu-server -migrate-only

exec su-exec 10001:10001 /app/yanshu-server "$@"
