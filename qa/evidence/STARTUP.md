# 雁书服务端 · 常驻实例启动配方（沙盒实测原文）

> 这份是**实际跑通过**的命令原文，不是"见 README"。
> 实测环境：`core` @ `2bc7dae`（`feat/server-skeleton`）、PostgreSQL `yanshu_test`、
> schema `gate_ev1`、监听 `127.0.0.1:8099`（换成 8080 只需改 `YANSHU_ADDR`，无其他依赖）。
> 口令与 DSN 只从密钥文件读取，**任何一步都不打印它们**。

## 0. 前置

```sh
# 编译（一次性）
cd <YANSHU_SRC>/server && go build -o /srv/yanshu/bin/yanshu-server ./cmd/yanshu-server

# 凭据：从密钥文件读，不落仓库/日志
set -a; . /.keys/pg.env; set +a          # 提供 PG_TEST_DSN / PG_TEST_PASSWORD
export PGPASSWORD="$PG_TEST_PASSWORD"     # 只给 psql 用
```

## 1. 目录与权限

```sh
install -d -m 0750 /srv/yanshu/blobs      # 与 Core 的 blob 实现一致：目录 0750、块文件 0640
install -d -m 0700 /srv/yanshu/logs
install -d -m 0700 /srv/yanshu/secrets

# upload_token 的 HMAC 密钥：生成一次，重启后旧 token 才继续有效
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /srv/yanshu/secrets/token_secret
chmod 600 /srv/yanshu/secrets/token_secret
```

## 2. schema 与迁移

```sh
# 独立 schema，不动 public（换成你自己的名字即可）
psql "$PG_TEST_DSN" -c 'create schema if not exists gate_ev1'

# 迁移：-migrate-only 跑完即退出（起常驻实例前自检用）
YANSHU_DATABASE_URL="$PG_TEST_DSN&search_path=gate_ev1" \
  /srv/yanshu/bin/yanshu-server -migrate-only
# 期望输出：level=INFO msg="migrations applied"；退出码 0
```

## 3. 起服务（stdout 重定向版——本轮证据用的就是这套）

```sh
YANSHU_DATABASE_URL="$PG_TEST_DSN&search_path=gate_ev1" \
YANSHU_BLOB_DIR=/srv/yanshu/blobs \
YANSHU_ADDR=127.0.0.1:8080 \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET="$(cat /srv/yanshu/secrets/token_secret)" \
setsid /srv/yanshu/bin/yanshu-server >>/srv/yanshu/logs/server.log 2>&1 </dev/null &
```

- `YANSHU_VERIFIER` 三个值：`sm2`（真实验签，尚未接入）/ `stub-deny`（**默认**，一律拒绝）/
  `stub-allow`（**仅测试**，只做形状检查，启动时打 WARN）。
  要让投递能跑通必须显式写 `stub-allow`；不写就是 fail-closed，投递会被拒。
- `setsid ... &` + 两个重定向是必须的：沙盒里直接 `&` 会挂在当前 shell 的 stdout 上，
  进程随 shell 退出而断。
- 不用 `setsid` 的话，systemd 单元里用 `StandardOutput=append:/srv/yanshu/logs/server.log` 等效。

## 4. 健康检查

```sh
curl -fsS http://127.0.0.1:8080/healthz
# 期望：HTTP 200，body = {"status":"ok","api_version":"v1","contract":"v1"}
```

判活不要只看端口有没有人听：上一轮我就吃过"旧进程占着同一端口、healthz 通但其实是别人的服务"
的亏。严格一点可以加：

```sh
pid=$(pgrep -f 'yanshu-server' | head -1)
kill -0 "$pid"                       # 进程还在
grep -q listening /srv/yanshu/logs/server.log
! grep -q 'address already in use' /srv/yanshu/logs/server.log
```

## 5. 日志（两套写法，二选一）

| 方式 | 写法 | 说明 |
|---|---|---|
| **stdout 重定向**（本轮证据用的） | 见上面第 3 步的 `>>/srv/yanshu/logs/server.log 2>&1` | 扫日志就扫这个文件；跨天不会换名 |
| 服务端内建滚动（`2bc7dae` 起支持） | 加 `YANSHU_LOG_DIR=/srv/yanshu/logs`（可选 `YANSHU_LOG_RETENTION_DAYS=7`） | 按 UTC 日期写 `yanshu-server-YYYY-MM-DD.log`，0640，跨天换文件；同时仍写 stdout |

> 扫日志时的坑：**跨天滚动会换文件名**，取证要按投递时间戳选当日文件（
> `yanshu-server-$(date -u +%F).log`），不要硬编码某一天的文件名——否则会扫到空文件还判 PASS。

## 6. 收工

```sh
pkill -f 'yanshu-server'    # 或 systemctl stop yanshu-server
```

## 7. 这套配方与证据的关系

用这套配方起的实例 + `qa/evidence/run_evidence1_core.sh` 的投递/扫描流程，
产出的就是 `results/contract-v1/2026-11-02-evidence1-core-c3c2fc9.md` 那份"初步证据"。
**换了真实验签（`YANSHU_VERIFIER=sm2`）或改用内建日志滚动后，必须用同一流程重跑一次**，
两次分开留档（本次标"初步证据"，下次标"复扫"），文件名可区分。
