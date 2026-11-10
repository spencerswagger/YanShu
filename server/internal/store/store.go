// Package store 是 PostgreSQL 持久层。
//
// 设计红线（与 migrations/0001_init.sql 顶部注释一致）：
// 库里只有白名单字段——码、公钥、昵称、尺寸、计数、状态、时间、密文摘要。
// 没有文件名、没有 MIME、没有任何明文片段、没有任何密钥材料。
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// 语义化错误，handler 据此映射对外错误码。
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// Store 持有连接池。
type Store struct {
	pool *pgxpool.Pool
}

// Open 建立连接池并探活。
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	// 单实例骨架的保守池大小；扩到多实例时按 DB 连接上限调。
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close 关闭连接池。
func (s *Store) Close() { s.pool.Close() }

// Ping 探活（/healthz 用）。
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Pool 暴露底层池给测试与运维脚本，业务代码不要直接用。
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Migrate 顺序应用 migrations/*.sql，用 advisory lock 防并发迁移。
//
// 全程**固定一条连接**：`pg_advisory_lock` 是会话级锁，如果加锁与解锁落到池里不同的连接，
// 锁会永远挂在那条连接上（并发迁移直接死锁 —— 测试并行跑各包迁移时就踩到过）。
// 顺带也保证 `CREATE INDEX CONCURRENTLY` 这类不能进事务块的语句在同一条会话里串行执行。
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire migration conn: %w", err)
	}
	defer conn.Release()

	// 先拿锁**再**建表：反过来会在并发迁移时死锁 —— 一个会话持锁去要 schema_migrations 的
	// 表级/目录锁，另一个会话正持着那些锁等这把 advisory lock。
	const lockKey int64 = 0x59616e536875 // "YanShu"
	if err := acquireMigrationLock(ctx, conn, lockKey); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text        PRIMARY KEY,
		applied_at timestamptz NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	applied := map[string]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("store: read applied migrations: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, name := range names {
		if applied[name] {
			continue
		}
		sqlBytes, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: read %s: %w", name, err)
		}
		if err := s.applyMigration(ctx, conn, name, string(sqlBytes)); err != nil {
			return err
		}
	}
	return nil
}

// migrationLockTimeout 是等待迁移锁的上限。
const migrationLockTimeout = 2 * time.Minute

// acquireMigrationLock **轮询**拿 advisory lock，而不是阻塞等 `pg_advisory_lock`。
//
// 原因（实测踩到）：阻塞的 `SELECT pg_advisory_lock(...)` 会让等待方**一直开着一个事务/快照**，
// 而持锁方正在跑 `CREATE INDEX CONCURRENTLY` —— CIC 要等所有并发事务结束才能收尾，
// 于是"持锁方等等待方结束、等待方等持锁方放锁" → PostgreSQL 直接报 deadlock detected。
// 改成每次 `pg_try_advisory_lock` 都是一个立即结束的语句，等待期间不持有任何快照。
func acquireMigrationLock(ctx context.Context, conn *pgxpool.Conn, key int64) error {
	deadline := time.Now().Add(migrationLockTimeout)
	for {
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
			return fmt.Errorf("store: advisory lock: %w", err)
		}
		if got {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("store: migration lock timeout after %s (另一个实例正在迁移？)", migrationLockTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// migrationNoTxDirective 让一个迁移**不在事务里**执行。
//
// 为什么需要：`CREATE INDEX CONCURRENTLY` 不能在事务块内执行（会报
// "CREATE INDEX CONCURRENTLY cannot run inside a transaction block"）。而 transfers 从 v5 起
// 元数据永久保留、表只会变大，建索引必须并发做，否则建索引期间 `SHARE` 锁把写入全挡住。
const migrationNoTxDirective = "yanshu:no-transaction"

// applyMigration 应用一个迁移：默认整文件包在一个事务里（失败即整体回滚）；
// 文件里出现 `-- yanshu:no-transaction` 时改为**逐条语句自动提交**（每条各自一个隐式事务）。
//
// ⚠ 改这里要同步改 `migrations_lock_guard_test.go`：那条门禁的前提就是"整文件一个事务"——
// 普通 `CREATE INDEX` 的 `SHARE` 锁会一直持到提交，所以事务迁移里不许建阻塞索引。
// 如果哪天改成逐句提交，断言会变成误报（不是漏洞），改之前先读那段注释。
func (s *Store) applyMigration(ctx context.Context, conn *pgxpool.Conn, name, src string) error {
	if !isNoTxMigration(src) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, src); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`, name, time.Now().UTC()); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: commit %s: %w", name, err)
		}
		return nil
	}

	// no-transaction：必须一条一条发。整段 SQL 作为单个简单查询发出去时，PostgreSQL 会把
	// 多语句包在**同一个隐式事务**里，CONCURRENTLY 照样报错。
	stmts := splitSQLStatements(src)
	if len(stmts) == 0 {
		return fmt.Errorf("store: apply %s: no statements", name)
	}
	for i, stmt := range stmts {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store: apply %s (statement %d/%d): %w", name, i+1, len(stmts), err)
		}
	}
	if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`, name, time.Now().UTC()); err != nil {
		return fmt.Errorf("store: record %s: %w", name, err)
	}
	return nil
}

// isNoTxMigration 判断迁移头部（第一条语句之前）是否有**独占一行**的 no-transaction 指令。
//
// 只认"整行就是指令"。早先是"注释里出现这个字样就算"，后果是**反向的**：一份普通事务迁移
// 只要在说明文字里提一句 `-- yanshu:no-transaction`，就会静默变成逐条自动提交——
// 中途失败留下半截 schema，而事务原子性没了谁也没提示。
func isNoTxMigration(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "--") {
			return false // 已经进入第一条语句，指令只能写在文件头
		}
		if strings.TrimSpace(strings.TrimPrefix(trimmed, "--")) == migrationNoTxDirective {
			return true
		}
	}
	return false
}

// splitSQLStatements 按分号切分 SQL，跳过字符串、引号标识符、`$tag$` 块与注释里的分号。
// 只用于 no-transaction 迁移（本仓库的迁移里没有函数体以外的复杂语法）。
func splitSQLStatements(src string) []string {
	var out []string
	var cur strings.Builder
	var quote byte       // ' 或 "
	var dollarTag string // 非空表示在 $tag$ 块里
	inLineComment := false
	inBlockComment := false
	// hasCode 区分"真语句"与"只剩注释的碎片"：文件末尾的注释不该被当成一条语句执行。
	hasCode := false

	for i := 0; i < len(src); i++ {
		ch := src[i]

		switch {
		case inLineComment:
			cur.WriteByte(ch)
			if ch == '\n' {
				inLineComment = false
			}
			continue
		case inBlockComment:
			cur.WriteByte(ch)
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				cur.WriteByte('/')
				i++
				inBlockComment = false
			}
			continue
		case dollarTag != "":
			if ch == '$' {
				if end := strings.Index(src[i:], dollarTag); end == 0 {
					cur.WriteString(dollarTag)
					i += len(dollarTag) - 1
					dollarTag = ""
					continue
				}
			}
			cur.WriteByte(ch)
			continue
		case quote != 0:
			cur.WriteByte(ch)
			if ch == quote {
				// 连续两个引号是转义，不算结束
				if i+1 < len(src) && src[i+1] == quote {
					cur.WriteByte(src[i+1])
					i++
					continue
				}
				quote = 0
			}
			continue
		}

		// 正常状态
		switch {
		case ch == '-' && i+1 < len(src) && src[i+1] == '-':
			cur.WriteString("--")
			i++
			inLineComment = true
		case ch == '/' && i+1 < len(src) && src[i+1] == '*':
			cur.WriteString("/*")
			i++
			inBlockComment = true
		case ch == '\'' || ch == '"':
			quote = ch
			hasCode = true
			cur.WriteByte(ch)
		case ch == '$':
			// 可能是 $tag$ 美元引用；$1 这类参数占位不是
			j := i + 1
			for j < len(src) && (isIdentByte(src[j])) {
				j++
			}
			if j < len(src) && src[j] == '$' {
				dollarTag = src[i : j+1]
				hasCode = true
				cur.WriteString(dollarTag)
				i = j
			} else {
				cur.WriteByte(ch)
			}
		case ch == ';':
			if stmt := strings.TrimSpace(cur.String()); stmt != "" && hasCode {
				out = append(out, stmt)
			}
			cur.Reset()
			hasCode = false
		default:
			if ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
				hasCode = true
			}
			cur.WriteByte(ch)
		}
	}
	if stmt := strings.TrimSpace(cur.String()); stmt != "" && hasCode {
		out = append(out, stmt)
	}
	return out
}

// isIdentByte 判断是否可组成 $tag$ 中 tag 的字符。
func isIdentByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// isUniqueViolation 判断是否 23505 唯一键冲突。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isNoRows 是 pgx.ErrNoRows 的短别名。
func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
