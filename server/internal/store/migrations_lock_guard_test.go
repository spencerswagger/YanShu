package store

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 迁移里"建索引"的写法必须是**不阻塞写入**的。
//
// 为什么要有这条门禁：v5 的 0008 / 0009 曾把 `CREATE INDEX` 写在事务迁移里 —— 普通
// `CREATE INDEX` 取 `SHARE` 锁，而 `applyMigration` 把整份文件包在一个事务里，锁一直持到提交，
// 于是**建索引期间 transfers 的写入被整体挡住**。实测（PG 17.11，150 万行 transfers，
// 迁移期间另开一路 300 条 UPDATE）：单条写入最长阻塞 **1215.8 ms**、2 条 ≥1 s，
// 并在 `pg_locks` 里看得到 `transfers|ShareLock`。
// 修法是 `0010_indexes_concurrently.sql`：文件头 `-- yanshu:no-transaction` 让迁移器逐条
// 自动提交，索引一律 `CREATE INDEX CONCURRENTLY`（锁模式只剩 `ShareUpdateExclusiveLock`，
// 同一条件下最长阻塞 **13.0 ms**、0 条 ≥1 s）。
//
// 但"修过一次"不等于"以后不会写回去"：仓库没有 test CI，只能靠人记。所以把规则落成断言。
// 断言不碰数据库（读的是编译进二进制的 migrations/*.sql），任何 `go test ./...` 都会跑。
//
// 已知盲区（写在这里是为了下一个改迁移的人能看见）：
//   - `ALTER TABLE ... ADD CONSTRAINT ... UNIQUE / PRIMARY KEY` 也会取 `ACCESS EXCLUSIVE`
//     并顺手建索引，比普通 `CREATE INDEX` 更狠，本文件不管它（仓里没有这种写法）；
//   - 第 1 条断言的成立前提是"`applyMigration` 把整份文件包在一个事务里"。
//     改 store.go 的迁移执行方式（例如改成逐句提交）时，要同步改这条断言，否则它会变成误报。
//     store.go 的 `applyMigration` 上留了对应的注释锚点。

// indexAtStartRe 匹配一条语句是否**以** `create [unique] index` 开头。
var indexAtStartRe = regexp.MustCompile(`(?is)^\s*create\s+(unique\s+)?index\b`)

// indexAnywhereRe 匹配语句里**任意位置**出现 `create [unique] index`（词边界）。
// 用来做 fail-closed：不以它开头却包含了它（`DO $$ ... EXECUTE 'CREATE INDEX ...' $$`、
// 拼接出来的动态 SQL 等），一律当"无法判定"报错，而不是静默放过。
var indexAnywhereRe = regexp.MustCompile(`(?is)(^|[^a-z0-9_$])create\s+(unique\s+)?index\b`)

// concurrentlyRe 匹配 `create [unique] index concurrently`。
var concurrentlyRe = regexp.MustCompile(`(?is)^\s*create\s+(unique\s+)?index\s+concurrently\b`)

// createTableRe 取"这条语句建了哪张表"（可能是 `IF NOT EXISTS`、可能带引号）。
var createTableRe = regexp.MustCompile(`(?is)^\s*create\s+(?:temp\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:"?[a-z_][a-z0-9_]*"?\.)?"?[a-z_][a-z0-9_]*"?)\s*\(`)

// indexTargetRe 取 `create index ... on [only] <table> [using <method>] (` 里的表名。
// `ON ONLY`（分区表）与 `USING <method>` 都是合法写法，必须认出来，否则误报成"解析不出表名"。
var indexTargetRe = regexp.MustCompile(`(?is)\bon\s+(?:only\s+)?((?:"?[a-z_][a-z0-9_]*"?\.)?"?[a-z_][a-z0-9_]*"?)\s*(?:using\s+[a-z_][a-z0-9_]*\s*)?\(`)

// TestMigrationsCreateIndexesWithoutBlockingWrites 守住三条规则：
//
//  1. 事务迁移里不许用普通 `CREATE INDEX`：它取 `SHARE` 锁，锁持到事务提交（线上就是写不可用窗口）。
//     唯一豁免是**该表在全仓迁移里第一次被创建就是本文件** —— 那时表必为空，建索引不产生任何
//     写入等待。豁免按"首次创建者"判定，不看"本文件出现过 CREATE TABLE"：后者能被
//     `CREATE TABLE IF NOT EXISTS <已存在的热表>` 伪造（对已有表是 no-op，索引照样建在热表上）。
//  2. 文件里只要出现 `CONCURRENTLY`，就必须带 `-- yanshu:no-transaction` 头；
//     否则它在事务块里执行会直接报 "cannot run inside a transaction block"（部署即挂）。
//  3. 不以 `CREATE INDEX` 开头、却包含它（动态 SQL）→ 报错，不猜。
func TestMigrationsCreateIndexesWithoutBlockingWrites(t *testing.T) {
	names := migrationFileNames(t)
	if len(names) == 0 {
		t.Fatal("没有找到任何迁移文件")
	}
	firstCreator := tableFirstCreators(t, names)

	for _, name := range names {
		src := readMigration(t, name)
		noTx := isNoTxMigration(src)
		stmts := splitSQLStatements(src)

		for i, raw := range stmts {
			s := strings.TrimSpace(stripSQLComments(raw))
			if s == "" {
				continue
			}

			if !indexAtStartRe.MatchString(s) {
				if indexAnywhereRe.MatchString(s) && !strings.HasPrefix(strings.ToUpper(s), "DROP ") {
					t.Errorf("%s 第 %d 条语句里出现了 CREATE INDEX，但不在语句开头（动态 SQL / `DO` 块 / `EXECUTE` 字符串）：\n"+
						"这种写法没法静态判定它会不会阻塞写入，一律不放行。\n语句：%s",
						name, i+1, firstLine(s))
				}
				continue
			}

			if concurrentlyRe.MatchString(s) {
				if !noTx {
					t.Errorf("%s 第 %d 条语句用了 CONCURRENTLY，但文件头没有 `-- %s`：\n"+
						"它会跑在事务块里，PostgreSQL 直接拒绝执行。\n语句：%s",
						name, i+1, migrationNoTxDirective, firstLine(s))
				}
				continue
			}

			m := indexTargetRe.FindStringSubmatch(s)
			if m == nil {
				t.Errorf("%s 第 %d 条语句是 CREATE INDEX 但解析不出表名，无法判定是否阻塞写入：%s",
					name, i+1, firstLine(s))
				continue
			}
			target := normalizeIdent(m[1])
			if firstCreator[target] == name {
				// 这张表第一次被创建就在本文件 → 建索引时表必为空 → 不会等待任何写入。
				continue
			}
			if noTx {
				t.Errorf("%s 第 %d 条语句是非事务迁移里的普通 CREATE INDEX（目标表 %s）：\n"+
					"逐条提交只是去掉了「锁持到提交」那一段，单条 CREATE INDEX 本身仍取 SHARE 锁、\n"+
					"在整个建索引时长内挡住 %s 的写入。索引类迁移一律用 `CREATE INDEX CONCURRENTLY`。\n语句：%s",
					name, i+1, target, target, firstLine(s))
				continue
			}
			t.Errorf("%s 第 %d 条语句在事务迁移里用普通 CREATE INDEX 建 %s 的索引：\n"+
				"`CREATE INDEX` 取 SHARE 锁、applyMigration 把整份文件包在一个事务里，锁持到提交 ——\n"+
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
		for _, raw := range splitSQLStatements(src) {
			if concurrentlyRe.MatchString(strings.TrimSpace(stripSQLComments(raw))) {
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

// TestNoTxDirectiveMustBeItsOwnLine 钉住指令的识别口径。
//
// `isNoTxMigration` 只认"整行就是指令"：如果只要注释里提到这个字样就算，那么一份普通事务迁移
// 只要在说明里写一句 "本文件没用 -- yanshu:no-transaction"，就会**静默丢掉事务原子性**
// （每条语句各自提交，中途失败留下半截 schema）。
func TestNoTxDirectiveMustBeItsOwnLine(t *testing.T) {
	prose := "-- 说明：这个文件不需要 -- yanshu:no-transaction，整份包在事务里\n" +
		"ALTER TABLE transfers ADD COLUMN x int;"
	if isNoTxMigration(prose) {
		t.Fatalf("注释里提到指令字样不该被当成指令：事务迁移会静默变成逐条提交")
	}
	for _, ok := range []string{
		"-- yanshu:no-transaction\nCREATE INDEX CONCURRENTLY i ON t (x);",
		"\n\n-- yanshu:no-transaction\nDROP INDEX CONCURRENTLY IF EXISTS i;",
	} {
		if !isNoTxMigration(ok) {
			t.Fatalf("整行指令没被认出来：%q", ok)
		}
	}
}

// tableFirstCreators 返回"每张表在全仓迁移里第一次被谁创建"（文件名升序）。
func tableFirstCreators(t *testing.T, names []string) map[string]string {
	t.Helper()
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	first := map[string]string{}
	for _, name := range sorted {
		for _, raw := range splitSQLStatements(readMigration(t, name)) {
			s := strings.TrimSpace(stripSQLComments(raw))
			if m := createTableRe.FindStringSubmatch(s); m != nil {
				tbl := normalizeIdent(m[1])
				if _, seen := first[tbl]; !seen {
					first[tbl] = name
				}
			}
		}
	}
	return first
}

// stripSQLComments 去掉 SQL 注释（`--` 到行尾、`/* */` 可嵌套），其余原样保留。
//
// 两条注意：
//   - 块注释必须一起剥。只剥 `--` 的话，`/* 说明 */` 开头的语句会让行首锚点 `^create` 失配，
//     于是被当成"不是建索引语句"静默放过 —— 正是这条门禁要防的写法。
//   - 引号/`$tag$` 里的内容**不剥**（保留原文）：`DO $$ ... EXECUTE 'CREATE INDEX ...' $$`
//     这类动态 SQL 就是要靠"字符串里也看得见 CREATE INDEX"来 fail-closed 拦住的。
func stripSQLComments(s string) string {
	var b strings.Builder
	i, n := 0, len(s)
	inSingle, inDouble := false, false
	dollarTag := ""

	for i < n {
		ch := s[i]

		if dollarTag != "" {
			if strings.HasPrefix(s[i:], dollarTag) {
				b.WriteString(dollarTag)
				i += len(dollarTag)
				dollarTag = ""
				continue
			}
			b.WriteByte(ch)
			i++
			continue
		}
		if inSingle {
			b.WriteByte(ch)
			if ch == '\'' {
				if i+1 < n && s[i+1] == '\'' { // '' 转义
					b.WriteByte('\'')
					i += 2
					continue
				}
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			b.WriteByte(ch)
			if ch == '"' {
				if i+1 < n && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				inDouble = false
			}
			i++
			continue
		}

		switch {
		case ch == '-' && i+1 < n && s[i+1] == '-':
			for i < n && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case ch == '/' && i+1 < n && s[i+1] == '*':
			depth := 1
			i += 2
			for i < n && depth > 0 {
				if s[i] == '/' && i+1 < n && s[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if s[i] == '*' && i+1 < n && s[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
			b.WriteByte(' ') // 用空格代替，别把前后两个 token 粘在一起
		case ch == '\'':
			inSingle = true
			b.WriteByte(ch)
			i++
		case ch == '"':
			inDouble = true
			b.WriteByte(ch)
			i++
		case ch == '$':
			if tag, ok := dollarTagAt(s[i:]); ok {
				dollarTag = tag
				b.WriteString(tag)
				i += len(tag)
				continue
			}
			b.WriteByte(ch)
			i++
		default:
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}

// dollarTagAt 识别 `$$` / `$tag$` 形式的起始定界符。
func dollarTagAt(s string) (string, bool) {
	if len(s) < 2 || s[0] != '$' {
		return "", false
	}
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '$':
			return s[:i+1], true
		case s[i] == '_' || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
			(s[i] >= '0' && s[i] <= '9' && i > 1):
			continue
		default:
			return "", false
		}
	}
	return "", false
}

// normalizeIdent 把 `public.transfers` / `"transfers"` 归一成 `transfers`。
func normalizeIdent(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.Trim(s, `"`)
	return strings.ToLower(s)
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
