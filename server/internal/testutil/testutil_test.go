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
		if len(s) > maxSchemaNameLen {
			t.Fatalf("schema 名超过 PostgreSQL 标识符上限 %d 字节：%s (%d)", maxSchemaNameLen, s, len(s))
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

// TestSchemaNameSurvivesTruncationBoundary 打长度边界。
//
// PostgreSQL 对超长标识符是**静默截断**（只 `NOTICE` 一下），截掉的若是唯一段，
// 同进程多次调用就会撞回同名 —— 正是本 PR 要修的那类 bug。所以这里用足够长的夹具名
// 逼到截断区，断言：仍 ≤ 63 字节、唯一段（runID + 序号）没被截掉、两次调用仍然不同。
func TestSchemaNameSurvivesTruncationBoundary(t *testing.T) {
	long := strings.Repeat("a", 60) // 远超剩余预算，必然触发截断
	first := SchemaName(long)
	second := SchemaName(long)

	if len(first) > maxSchemaNameLen {
		t.Fatalf("截断后仍超上限 %d：%s (%d)", maxSchemaNameLen, first, len(first))
	}
	if !strings.HasPrefix(first, "yanshu_core_test_"+runID+"_") {
		t.Fatalf("唯一段被截掉了（截断后会同名相撞）：%s", first)
	}
	if first == second {
		t.Fatalf("长夹具名下两次调用拿到同一个名字（唯一段被截断的典型症状）：%s", first)
	}

	// 短夹具名不该被截断（可读性不能无谓损失）。
	if s := SchemaName("tz_atomic"); !strings.HasSuffix(s, "tz_atomic") {
		t.Fatalf("短夹具名被截断了：%s", s)
	}
}
