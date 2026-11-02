// Package testutil 提供集成测试用的 PG 夹具。
//
// 隔离方式：每个测试包用自己的 schema（search_path），互不踩踏，也不污染
// Gate 使用的 yanshu_test 默认 schema。
package testutil

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/store"
)

// NewStore 建一个干净的测试库 schema 并返回 Store。没有 TEST_DATABASE_URL 时 skip。
func NewStore(t *testing.T, name string) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	schema := "yanshu_core_test_" + sanitize(name)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Open(ctx, dsn+sep+"search_path="+schema)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)

	if _, err := st.Pool().Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := st.Pool().Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// Reset 清空全部业务表，供同包内多个用例复用同一个 schema。
func Reset(t *testing.T, st *store.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tables := []string{
		"package_chunks", "packages", "package_tombstones",
		"sessions", "auth_challenges", "codes", "audit_events",
	}
	for _, tbl := range tables {
		if _, err := st.Pool().Exec(ctx, "TRUNCATE TABLE "+tbl+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
