package store_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

// expectedColumns 是**白名单**：库里允许出现的全部列。
//
// 加列必须同时改这里和迁移文件，并在 PR 里说明"为什么这条元数据不违反
// 不存文件名/不存明文的约束"。这条断言是 Gate「库里 grep 不到文件名」的结构性保证。
var expectedColumns = map[string][]string{
	"codes": {
		"code", "created_at", "expires_at", "last_seen_at",
		"nickname", "pubkey", "updated_at",
	},
	"auth_challenges": {
		"code", "created_at", "expires_at", "id", "message", "pubkey", "purpose", "used_at",
	},
	"sessions": {
		"code", "created_at", "expires_at", "token_hash",
	},
	"packages": {
		"chunk_count", "chunk_size", "committed_at", "created_at", "delete_on_ack",
		"downloads_used", "expires_at", "id", "max_downloads", "plaintext_size",
		"prelude_digest", "prelude_len", "received_count", "recipient_code",
		"sender_code", "state", "terminal_at", "terminal_reason",
	},
	"package_chunks": {
		"chunk_index", "ct_digest", "ct_len", "package_id", "received_at",
	},
	"package_tombstones": {
		"created_at", "id", "purged_at", "recipient_code", "sender_code", "state", "terminal_at",
	},
	"audit_events": {
		"at", "bytes", "code", "id", "ip", "kind", "outcome", "package_id",
	},
}

func TestSchemaColumnWhitelist(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()

	var schema string
	if err := st.Pool().QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatalf("current schema: %v", err)
	}
	rows, err := st.Pool().Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = $1 AND table_name <> 'schema_migrations'`, schema)
	if err != nil {
		t.Fatalf("list columns: %v", err)
	}
	defer rows.Close()

	got := map[string][]string{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		got[table] = append(got[table], column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for table, cols := range got {
		sort.Strings(cols)
		want, ok := expectedColumns[table]
		if !ok {
			t.Fatalf("unexpected table %q (add it to the whitelist or remove it)", table)
		}
		sorted := append([]string(nil), want...)
		sort.Strings(sorted)
		if strings.Join(cols, ",") != strings.Join(sorted, ",") {
			t.Fatalf("table %s columns = %v, want %v", table, cols, sorted)
		}
	}
	for table := range expectedColumns {
		if _, ok := got[table]; !ok {
			t.Fatalf("missing table %q", table)
		}
	}
}

// TestNoContentBearingColumns 是白名单之外的第二道闸：
// 列名里不允许出现"内容/明文/文件名"这类语义，防止有人"顺手"加个大字段。
func TestNoContentBearingColumns(t *testing.T) {
	for table, cols := range expectedColumns {
		for _, c := range cols {
			name := strings.ToLower(c)
			for _, forbidden := range []string{"filename", "file_name", "mime", "content", "body", "blob", "plaintext_data"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("column %s.%s looks content-bearing (%q)", table, c, forbidden)
				}
			}
		}
	}
}
