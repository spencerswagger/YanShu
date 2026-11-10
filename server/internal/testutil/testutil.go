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
//
// 进程被 `kill -9` 时可能留下孤儿 schema；人工清理（按前缀，注意别在别人正在跑的时候执行）：
//
//	DO $$ DECLARE r record; BEGIN
//	  FOR r IN SELECT nspname FROM pg_namespace WHERE nspname LIKE 'yanshu_core_test_%'
//	  LOOP EXECUTE format('DROP SCHEMA %I CASCADE', r.nspname); END LOOP; END $$;
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

// SchemaName 生成一次运行内唯一的测试 schema 名（测试专用 API，产品代码不要用）。
//
// 名字结构：`yanshu_core_test_<pid+随机>_<序号>_<夹具名>`
//
// 为什么唯一段要放**前面**：PostgreSQL 对超过 63 字节的标识符是**静默截断**而不是报错。
// 早先是 `<前缀><夹具名>_<唯一段>`，夹具名一长（实测 pid 6 位时夹具名 ≥ 29 字符），
// 被截掉的正好是 `_<序号>`，于是同进程多次 NewStore 又撞回同一个名字 —— 这个 PR 要修的
// 那类 bug 会从这条缝里原样回来。唯一段提前 + 夹具名按预算截断，截断就只影响可读性。
//
// 前缀固定为 yanshu_core_test_，便于运维按前缀清理孤儿 schema（见包注释里的清理 SQL）。
func SchemaName(name string) string {
	head := "yanshu_core_test_" + runID + "_" + strconv.FormatUint(schemaN.Add(1), 10) + "_"
	budget := maxSchemaNameLen - len(head)
	fixture := sanitize(name)
	if len(fixture) > budget {
		// 按字节截断可能切坏多字节字符，退化成按 rune 截；夹具名都是 ASCII，够用。
		runes := []rune(fixture)
		if len(runes) > budget {
			runes = runes[:budget]
		}
		fixture = string(runes)
	}
	return head + fixture
}

// maxSchemaNameLen 是 PostgreSQL 标识符的硬上限（NAMEDATALEN-1）。
const maxSchemaNameLen = 63

// dropSchemaQuietly 尽力清掉测试 schema，绝不把一次绿的测试变红。
//
// 并发跑同一个包时，两个进程同时 DROP/CREATE 不同 schema 仍可能在 PG 的命名空间目录锁上
// 撞一次 `deadlock detected`（实测偶发，约 1/6 进程）。所以重试一次（换个时间点就过去了），
// 仍失败才打到 **stderr** —— `go test` 不开 `-v` 时 t.Logf 完全不可见，残留会悄悄攒。
// DropSchemaQuietly 供其它包的测试夹具复用（清自己的 schema，失败不致命）。
func DropSchemaQuietly(schema string, st *store.Store) {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = st.Pool().Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		cancel()
		if err == nil {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "testutil: 清理测试 schema %s 失败（不影响结论，可按包注释的 SQL 清）：%v\n", schema, err)
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
	t.Cleanup(func() { DropSchemaQuietly(schema, st) })

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
