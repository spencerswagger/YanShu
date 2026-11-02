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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// 语义化错误，handler 据此映射对外错误码。
var (
	ErrNotFound        = errors.New("store: not found")
	ErrCodeTaken       = errors.New("store: code taken")
	ErrConflict        = errors.New("store: conflict")
	ErrPackageLocked   = errors.New("store: package locked")
	ErrChunkConflict   = errors.New("store: chunk conflict")
	ErrPreludeConflict = errors.New("store: prelude conflict")
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
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text        PRIMARY KEY,
		applied_at timestamptz NOT NULL
	)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	const lockKey int64 = 0x59616e536875 // "YanShu"
	if _, err := s.pool.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return fmt.Errorf("store: advisory lock: %w", err)
	}
	defer func() { _, _ = s.pool.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey) }()

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
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
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
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
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
	}
	return nil
}

// isUniqueViolation 判断是否 23505 唯一键冲突。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isNoRows 是 pgx.ErrNoRows 的短别名。
func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
