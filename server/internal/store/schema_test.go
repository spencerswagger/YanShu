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
// 依据 docs/API.md §2.1 的元数据白名单，加上迁移文件里逐条注明理由的
// 「派生/内部」列（prelude_received / received_chunks / updated_at /
// upload_token_sm3 / uploader_ip / 租约与幂等表）。
// 加列必须同时改这里与迁移文件，并在 PR 里说明为什么不违反「不落明文」。
var expectedColumns = map[string][]string{
	"codes":           {"code", "nickname", "public_key", "registered_at", "updated_at"},
	"auth_challenges": {"challenge_id", "expires_at", "nonce", "purpose", "used"},
	"transfers": {
		"chunk_count", "chunk_size", "created_at", "download_count", "expires_at",
		"max_downloads", "plaintext_size", "prelude_len", "prelude_received",
		"prelude_sm3", "received_chunks", "recipient_code", "sender_code", "state",
		"terminal_at", "terminal_reason", "total_ciphertext_bytes", "transfer_id",
		"updated_at", "upload_token_sm3", "upload_token_kid", "uploader_ip",
	},
	"transfer_chunks":    {"chunk_index", "ciphertext_sm3", "length", "stored_at", "transfer_id"},
	"transfer_downloads": {"acked_at", "created_at", "download_id", "lease_expires_at", "transfer_id"},
	"idempotency_keys":   {"created_at", "expires_at", "key_hash", "request_fingerprint", "sender_code", "transfer_id"},
	"audit_events":       {"bytes", "id", "ip", "method", "path", "request_id", "status", "ts"},
	"token_kid_state":    {"id", "kid", "updated_at"},
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

// 白名单之外的第二道闸：列名里不允许出现「内容/明文/文件名」这类语义。
func TestNoContentBearingColumns(t *testing.T) {
	for table, cols := range expectedColumns {
		for _, c := range cols {
			name := strings.ToLower(c)
			for _, forbidden := range []string{"filename", "file_name", "mime", "content", "body", "blob", "plaintext_data", "extension"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("column %s.%s looks content-bearing (%q)", table, c, forbidden)
				}
			}
		}
	}
}
