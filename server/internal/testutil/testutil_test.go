package testutil

import (
	"strings"
	"testing"
)

// TestSchemaNameIsUniquePerCall 钉住"每次调用都拿到新名字"这条性质。
//
// 这条断言的意义：并发跑同一个包的两个进程如果再共用 schema 名，就会互相
// `DROP ... CASCADE` 对方正在用的 schema（`deadlock detected` / `schema already exists` /
// `relation schema_migrations does not exist`），同一份代码能连跑三次 0 绿。
// 所以"唯一"不是洁癖，是门禁可信度的前提。
func TestSchemaNameIsUniquePerCall(t *testing.T) {
	const n = 200
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		s := SchemaName("httpapi")
		if seen[s] {
			t.Fatalf("第 %d 次拿到重复的 schema 名：%s", i, s)
		}
		seen[s] = true
		if !strings.HasPrefix(s, "yanshu_core_test_") {
			t.Fatalf("schema 名丢了固定前缀（运维要按前缀清孤儿）：%s", s)
		}
		if len(s) > 63 {
			t.Fatalf("schema 名超过 PostgreSQL 标识符上限 63 字节：%s (%d)", s, len(s))
		}
		if strings.ContainsAny(s, `"' ;-`) {
			t.Fatalf("schema 名含不安全字符（要直接拼进 SQL）：%s", s)
		}
	}
}

// TestSchemaNameKeepsFixtureName 保证名字里还能看出是哪个夹具（排障用）。
func TestSchemaNameKeepsFixtureName(t *testing.T) {
	if s := SchemaName("httpapi"); !strings.Contains(s, "httpapi") {
		t.Fatalf("schema 名里应保留夹具名，实际：%s", s)
	}
	if s := SchemaName("tz_atomic"); !strings.Contains(s, "tz_atomic") {
		t.Fatalf("schema 名里应保留夹具名，实际：%s", s)
	}
}
