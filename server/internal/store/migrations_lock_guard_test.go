package store

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// 迁移里"建索引"的写法必须是**不阻塞写入**的。
//
// 为什么要有这条门禁：v5 的 0008 / 0009 曾把 `CREATE INDEX` 写在事务迁移里 —— 普通
// `CREATE INDEX` 取 `SHARE` 锁，而迁移器把整份文件包在一个事务里，锁一直持到提交，
// 于是**建索引期间 transfers 的写入被整体挡住**。实测（PG 17.11，150 万行 transfers，
// 迁移期间另开一路 300 条 UPDATE）：单条写入最长阻塞 **1215.8 ms**、2 条 ≥1 s，
// 并在 `pg_locks` 里看得到 `transfers|ShareLock`。
// 修法是 `0010_indexes_concurrently.sql`：文件头 `-- yanshu:no-transaction` 让迁移器逐条
// 自动提交，索引一律 `CREATE INDEX CONCURRENTLY`（锁模式只剩 `ShareUpdateExclusiveLock`，
// 同一条件下最长阻塞 **13.0 ms**、0 条 ≥1 s）。
//
// 但"修过一次"不等于"以后不会写回去"：仓库没有 test CI，只能靠人记。所以把规则落成断言。
// 这两条断言不碰数据库（读的是编译进二进制的 migrations/*.sql），任何 `go test ./...` 都会跑。

// indexStatementRe 匹配一条语句是否**以** `create [unique] index` 开头。
var indexStatementRe = regexp.MustCompile(`(?is)^\s*create\s+(unique\s+)?index\s+`)

// concurrentlyRe 匹配 `create [unique] index concurrently`。
var concurrentlyRe = regexp.MustCompile(`(?is)^\s*create\s+(unique\s+)?index\s+concurrently\b`)

// createTableRe 用来取"本文件自己建了哪些表"（表名小写）。
var createTableRe = regexp.MustCompile(`(?is)^\s*create\s+table\s+(if\s+not\s+exists\s+)?([a-z_][a-z0-9_]*)`)

// indexTargetRe 取 `create index ... on <table>` 的表名。
var indexTargetRe = regexp.MustCompile(`(?is)\bon\s+([a-z_][a-z0-9_]*)\s*\(`)

// TestMigrationsCreateIndexesWithoutBlockingWrites 守住两条规则：
//
//  1. 事务迁移里不许用普通 `CREATE INDEX`：它会取 `SHARE` 锁挡住写入（线上就是写不可用窗口）。
//     唯一例外是**同一份迁移里刚建出来的表** —— 那时表必为空，建索引不产生任何写入等待。
//  2. 文件里只要出现 `CONCURRENTLY`，就必须带 `-- yanshu:no-transaction` 头；
//     否则它在事务块里执行会直接报 "cannot run inside a transaction block"（部署即挂）。
func TestMigrationsCreateIndexesWithoutBlockingWrites(t *testing.T) {
	names := migrationFileNames(t)
	if len(names) == 0 {
		t.Fatal("没有找到任何迁移文件")
	}

	for _, name := range names {
		src := readMigration(t, name)
		noTx := isNoTxMigration(src)
		stmts := splitSQLStatements(src)

		tablesCreatedHere := map[string]bool{}
		for _, s := range stmts {
			if m := createTableRe.FindStringSubmatch(stripLeadingComments(s)); m != nil {
				tablesCreatedHere[strings.ToLower(m[2])] = true
			}
		}

		for i, s := range stmts {
			s = stripLeadingComments(s)
			if concurrentlyRe.MatchString(s) {
				if !noTx {
					t.Errorf("%s 第 %d 条语句用了 CONCURRENTLY，但文件头没有 `-- %s`：\n"+
						"它会跑在事务块里，PostgreSQL 直接拒绝执行。\n语句：%s",
						name, i+1, migrationNoTxDirective, firstLine(s))
				}
				continue
			}
			if !indexStatementRe.MatchString(s) {
				continue
			}
			m := indexTargetRe.FindStringSubmatch(s)
			if m == nil {
				t.Errorf("%s 第 %d 条语句是 CREATE INDEX 但解析不出表名，无法判定是否阻塞写入：%s",
					name, i+1, firstLine(s))
				continue
			}
			target := strings.ToLower(m[1])
			if tablesCreatedHere[target] {
				// 表在本文件里刚建出来 → 必为空 → 普通 CREATE INDEX 不会等待任何写入。
				continue
			}
			t.Errorf("%s 第 %d 条语句在事务迁移里用普通 CREATE INDEX 建 %s 的索引：\n"+
				"`CREATE INDEX` 取 SHARE 锁、迁移器把整份文件包在一个事务里，锁持到提交 ——\n"+
				"这期间 %s 的写入全被挡住（实测 150 万行时单条写最长阻塞 1215.8 ms）。\n"+
				"改法：把索引挪进一个文件头带 `-- %s` 的迁移，并用 `CREATE INDEX CONCURRENTLY`。\n语句：%s",
				name, i+1, target, target, migrationNoTxDirective, firstLine(s))
		}
	}
}

// TestNoTxMigrationHasConcurrentIndex 保证"非事务迁移"这个机制本身还在被用：
// 如果哪天有人把 0010 合并回事务迁移、或删掉 CONCURRENTLY 关键字，上面那条断言会变绿
// （没有 CONCURRENTLY 就没有违规），但阻塞写入的写法又回来了。所以这里正面要求：
// 至少有一份非事务迁移里真的在用 `CREATE INDEX CONCURRENTLY`。
func TestNoTxMigrationHasConcurrentIndex(t *testing.T) {
	found := ""
	for _, name := range migrationFileNames(t) {
		src := readMigration(t, name)
		if !isNoTxMigration(src) {
			continue
		}
		for _, s := range splitSQLStatements(src) {
			if concurrentlyRe.MatchString(s) {
				found = name
				break
			}
		}
		if found != "" {
			break
		}
	}
	if found == "" {
		t.Fatalf("没有任何非事务迁移在用 `CREATE INDEX CONCURRENTLY`：\n"+
			"索引类迁移必须写成 文件头 `-- %s` + CONCURRENTLY，否则建索引期间写入会被 SHARE 锁挡住。",
			migrationNoTxDirective)
	}
	t.Logf("非事务 + CONCURRENTLY 的迁移：%s", found)
}

func migrationFileNames(t *testing.T) []string {
	t.Helper()
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		t.Fatalf("读 migrations 目录失败：%v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	return names
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	b, err := migrationFS.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatalf("读迁移 %s 失败：%v", name, err)
	}
	return string(b)
}

// stripLeadingComments 去掉语句前面的整行 `--` 注释：迁移里每条语句都带大段说明，
// 不剥掉的话 `^create ...` 这类行首锚点永远匹配不上。
// （splitSQLStatements 保留了注释，是为了让执行时上下文完整；这里只做判定用。）
func stripLeadingComments(s string) string {
	for {
		trimmed := strings.TrimLeft(s, " \t\r\n")
		if !strings.HasPrefix(trimmed, "--") {
			return trimmed
		}
		if i := strings.IndexByte(trimmed, '\n'); i >= 0 {
			s = trimmed[i+1:]
			continue
		}
		return ""
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
