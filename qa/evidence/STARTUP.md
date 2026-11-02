# 雁书服务端 · 常驻实例启动配方（沙盒实测原文）

> 这份是**实际跑通过**的命令原文，不是"见 README"。
> 实测环境：`core` @ `28d75b0`（`feat/server-skeleton`）、PostgreSQL `yanshu_test`、
> schema `gate_ev1`；命令里的端口统一按 8080 写（我沙盒实测用动态空闲端口，只改 `YANSHU_ADDR`）。
> 口令与 DSN 只从密钥文件读取，**任何一步都不打印它们**。


> **想要一条命令搞定的版本**：直接用可执行脚本 `qa/evidence/STARTUP.sh`
> （`sh STARTUP.sh build|start|status|stop`，配置区四个变量改完即用，已实测跑通）。

## TL;DR · 可直接粘走（整段）

```sh
# ── 0) 凭据：只从密钥文件读，不落仓库/日志 ───────────────────────────
set -a; . /.keys/pg.env; set +a          # 提供 PG_TEST_DSN / PG_TEST_PASSWORD
export PGPASSWORD="$PG_TEST_PASSWORD"

# ── 1) 编译 + 目录（目录 0750、块文件 0640，与 Core 实现一致）─────────
cd <YANSHU_SRC>/server && go build -o /srv/yanshu/bin/yanshu-server ./cmd/yanshu-server
cd <YANSHU_SRC>/server && go build -o /srv/yanshu/bin/deliver       ./cmd/deliver
install -d -m 0750 /srv/yanshu/blobs
install -d -m 0700 /srv/yanshu/logs /srv/yanshu/secrets
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /srv/yanshu/secrets/token_secret
chmod 600 /srv/yanshu/secrets/token_secret

# ── 2) schema + migrations（服务端启动时也会自动跑；先自检一次）────────
psql "$PG_TEST_DSN" -c 'create schema if not exists gate_ev1'
YANSHU_DATABASE_URL="$PG_TEST_DSN&search_path=gate_ev1" \
  /srv/yanshu/bin/yanshu-server -migrate-only      # 期望 "migrations applied"，退出码 0

# ── 3) 起服务（stdout 重定向；日志另可走 YANSHU_LOG_FILE）──────────────
YANSHU_DATABASE_URL="$PG_TEST_DSN&search_path=gate_ev1" \
YANSHU_BLOB_DIR=/srv/yanshu/blobs \
YANSHU_ADDR=127.0.0.1:8080 \
YANSHU_VERIFIER=stub-allow \
YANSHU_TOKEN_SECRET="$(cat /srv/yanshu/secrets/token_secret)" \
setsid /srv/yanshu/bin/yanshu-server >>/srv/yanshu/logs/server.log 2>&1 </dev/null &

# ── 4) 健康检查 ────────────────────────────────────────────────────
curl -fsS http://127.0.0.1:8080/healthz
# 期望：{"status":"ok","api_version":"v1","contract":"v1"}
# 判活别只看端口：kill -0 <pid> && grep listening /srv/yanshu/logs/server.log

# ── 5) 投递一条（--no-ack 必带：ack 会删密文，删完就没法扫"无明文"了）──
/srv/yanshu/bin/deliver \
  --base-url http://127.0.0.1:8080 \
  --yspk /path/to/<包>.yspk \
  --no-ack \
  --blob-dir /srv/yanshu/blobs \
  --json-out /srv/yanshu/deliver.json

# ── 6) 收工 ────────────────────────────────────────────────────────
pkill -f yanshu-server
```

env 一览（凭据不写明文，一律从 `/.keys/pg.env` 读）：

| 变量 | 值 |
|---|---|
| `YANSHU_DATABASE_URL` | `"$PG_TEST_DSN&search_path=<你的 schema>"` |
| `YANSHU_BLOB_DIR` | `/srv/yanshu/blobs` |
| `YANSHU_ADDR` | `127.0.0.1:8080` |
| `YANSHU_VERIFIER` | `stub-allow`（仅联调；默认是 fail-closed 的 `stub-deny`） |
| `YANSHU_TOKEN_SECRET` | 从 `/srv/yanshu/secrets/token_secret` 读（重启不换才不丢 token） |
| `YANSHU_LOG_FILE` | 可选：`/srv/yanshu/logs/server-file.log`（推荐；与 stdout 并行） |

> 下面第 0～8 节是同一套命令的展开说明（含权限、日志三种写法、判活细节、故障排查）。

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

## 5. 日志（三种写法，推荐第一种）

| 方式 | 写法 | 说明 |
|---|---|---|
| **`YANSHU_LOG_FILE`（推荐，Core 交付清单里的正式方式）** | `YANSHU_LOG_FILE=/srv/yanshu/logs/server-file.log` | 单文件、不换名，取证最省事；仍是 stdout 之外的第二份 |
| stdout 重定向 | `… >>/srv/yanshu/logs/server.log 2>&1` | 部署方接管，跨天不换名 |
| `YANSHU_LOG_DIR` 按日滚动 | `YANSHU_LOG_DIR=/srv/yanshu/logs` | 写 `yanshu-server-YYYY-MM-DD.log`、0640、保留 7 天；**跨天换文件名**，取证要按投递时间戳选文件，别硬编码 |

> `YANSHU_LOG_DIR` 与 `YANSHU_LOG_FILE` 同时给时，Core 的实现以 `YANSHU_LOG_FILE` 优先。
> 扫日志一律扫**实际落盘的那个文件**；扫不到就 BLOCKED，不许当 PASS。

## 6. 投递一条命令（Core 的 `deliver`）

```sh
# 先编译（一次性）
cd <YANSHU_SRC>/server && go build -o /srv/yanshu/bin/deliver ./cmd/deliver

/srv/yanshu/bin/deliver \
  --base-url http://127.0.0.1:8080 \
  --yspk /path/to/<包>.yspk \
  --no-ack \
  --blob-dir /srv/yanshu/blobs \
  --dsn "${PG_TEST_DSN}&search_path=gate_ev1" \
  --json-out /srv/yanshu/deliver.json
```

> `--dsn` 只用于打印 database/schema（Core 的实现用 pgx 解析）。
> 若 DSN 里带 `search_path` 连不上，就把 `--dsn` 去掉，schema 用服务端启动时那份。
> stdout 固定字段：`code` / `package_id` / `chunks` / `blob_dir` / `db_url`（脱敏）/ `log_path`，
> 另含 `schema` 与 `storage_path`；退出码 0 即成功。

- **`--no-ack` 必须带**：ack 会按策略删密文，删完再"扫不到明文"就是空语料，不构成证据。
- `--blob-dir` 只是打印/校验用；`--dsn` 可选（仅用于打印 database/schema）。
  若它带 `search_path` 参数而 pgx 拒绝，去掉 `--dsn` 即可——扫描脚本自己用 `--pg-schema` 指定 schema。
- 输出里 `storage_path` / `schema` / `transfer_id` 就是要交给扫描脚本的标识；
  `--json-out` 写成文件后可直接喂给 `scan_plaintext.py --deliver-json`。
- 服务端必须是 `YANSHU_VERIFIER=stub-allow`，否则 `deliver` 退出码 4（fail-closed）。
- **端口**：上面写的是 spencer 要用的 8080；我沙盒实测用的是动态空闲端口（18080+/随机），
  只影响 `--base-url` 和 `YANSHU_ADDR` 两处，其他不变。

## 7. 收工

```sh
pkill -f 'yanshu-server'    # 或 systemctl stop yanshu-server
```

## 8. 这套配方与证据的关系

用这套配方起的实例 + `qa/evidence/run_evidence1_core.sh` 的投递/扫描流程，
产出的就是 `results/contract-v1/2026-11-02-evidence1-core-c3c2fc9.md` 那份"初步证据"。
**换了真实验签（`YANSHU_VERIFIER=sm2`）或改用内建日志滚动后，必须用同一流程重跑一次**，
两次分开留档（本次标"初步证据"，下次标"复扫"），文件名可区分。
