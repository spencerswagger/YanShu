// Package testutil 提供集成测试用的 PG 夹具。
//
// 隔离方式：**每次 NewStore 调用**用一个唯一的 schema（search_path），互不踩踏，
// 也不污染 Gate 使用的 yanshu_test 默认 schema。
//
// 为什么必须唯一（而不是"每个测试包一个固定名"）：两个进程（验收与回归、或两个 CI job）
// 同时在同一库上跑同一个包时，固定名会让它们互相把对方的 schema `DROP ... CASCADE` 掉，
// 症状是 `drop schema: deadlock detected` / `schema already exists` /
// `relation schema_migrations does not exist` —— 同一份代码连跑三次可以 0 绿。
// 这是"假红"，但它顺带让"这次绿"证明不了"这份代码绿"，所以必须从根上消除。
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/store"
)

// runID 标识"这一次进程"：pid + 4 字节随机。同一进程内再叠一个自增序号，
// 于是「并发进程 × 同进程内多次调用」都不会撞名。
var (
	runID   = newRunID()
	schemaN atomic.Uint64
)

func newRunID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.Itoa(os.Getpid())
	}
	return strconv.Itoa(os.Getpid()) + hex.EncodeToString(b[:])
}

// SchemaName 生成一次运行内唯一的测试 schema 名。
// 前缀固定为 yanshu_core_test_，便于运维按前缀清理孤儿 schema。
func SchemaName(name string) string {
	return "yanshu_core_test_" + sanitize(name) + "_" + runID + "_" +
		strconv.FormatUint(schemaN.Add(1), 10)
}

// NewStore 建一个干净的测试库 schema 并返回 Store。没有 TEST_DATABASE_URL 时 skip。
func NewStore(t *testing.T, name string) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	schema := SchemaName(name)
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
	// 注意顺序：Cleanup 是后进先出，先注册 Close、再注册 DROP，
	// 才能保证 DROP 用的是还没关的连接池。
	t.Cleanup(st.Close)
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := st.Pool().Exec(dropCtx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Logf("清理测试 schema %s 失败（不影响结论，可手动删）：%v", schema, err)
		}
	})

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
		"transfer_chunks", "transfer_downloads", "transfers",
		"idempotency_keys", "auth_challenges", "codes", "audit_events",
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
