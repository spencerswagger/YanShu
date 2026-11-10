package store

import (
	"strings"
	"testing"
)

// no-transaction 迁移要逐条执行（CONCURRENTLY 不能在事务块里），所以切句必须稳：
// 拆分错了会把一条语句劈成两半 —— 建索引失败是一回事，劈坏数据定义是另一回事。
func TestSplitSQLStatements(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "普通多语句",
			src:  "CREATE INDEX a ON t (x);\nCREATE INDEX b ON t (y);\n",
			want: []string{"CREATE INDEX a ON t (x)", "CREATE INDEX b ON t (y)"},
		},
		{
			name: "行注释里的分号不切",
			src:  "-- 说明；这里有个分号\nSELECT 1;\n-- 末尾注释；\n",
			want: []string{"-- 说明；这里有个分号\nSELECT 1"},
		},
		{
			name: "块注释里的分号不切",
			src:  "/* a; b; */ SELECT 2;",
			want: []string{"/* a; b; */ SELECT 2"},
		},
		{
			name: "单引号字符串里的分号不切",
			src:  "INSERT INTO t VALUES ('a;b'); SELECT 3;",
			want: []string{"INSERT INTO t VALUES ('a;b')", "SELECT 3"},
		},
		{
			name: "单引号里的转义引号",
			src:  "INSERT INTO t VALUES ('it''s; ok');",
			want: []string{"INSERT INTO t VALUES ('it''s; ok')"},
		},
		{
			name: "双引号标识符里的分号不切",
			src:  `CREATE INDEX "weird;name" ON t (x);`,
			want: []string{`CREATE INDEX "weird;name" ON t (x)`},
		},
		{
			name: "美元引用块里的分号不切",
			src:  "CREATE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;",
			want: []string{"CREATE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql"},
		},
		{
			name: "带 tag 的美元引用",
			src:  "DO $body$ BEGIN PERFORM 1; END $body$;SELECT 4;",
			want: []string{"DO $body$ BEGIN PERFORM 1; END $body$", "SELECT 4"},
		},
		{
			name: "参数占位不是美元引用",
			src:  "SELECT $1; SELECT 5;",
			want: []string{"SELECT $1", "SELECT 5"},
		},
		{
			name: "末尾没有分号",
			src:  "SELECT 6",
			want: []string{"SELECT 6"},
		},
		{
			name: "空文件与纯注释",
			src:  "-- 只有注释；\n\n",
			want: nil,
		},
	}
	for _, c := range cases {
		got := splitSQLStatements(c.src)
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %d statements %q, want %d", c.name, len(got), got, len(c.want))
		}
		for i := range got {
			if strings.TrimSpace(got[i]) != strings.TrimSpace(c.want[i]) {
				t.Fatalf("%s: statement %d = %q, want %q", c.name, i, got[i], c.want[i])
			}
		}
	}
}

// 指令只认文件头：写在语句中间的 `-- yanshu:no-transaction` 不该改变执行方式。
func TestIsNoTxMigration(t *testing.T) {
	if !isNoTxMigration("-- yanshu:no-transaction\nCREATE INDEX CONCURRENTLY i ON t (x);") {
		t.Fatal("头部指令未被识别")
	}
	if !isNoTxMigration("\n-- 说明\n-- yanshu:no-transaction\nALTER TABLE t ADD COLUMN c int;") {
		t.Fatal("注释行中的指令未被识别")
	}
	if isNoTxMigration("ALTER TABLE t ADD COLUMN c int;\n-- yanshu:no-transaction\n") {
		t.Fatal("语句之后的指令不该生效")
	}
	if isNoTxMigration("CREATE TABLE t (id int);") {
		t.Fatal("无指令时不该判成 no-transaction")
	}
}
