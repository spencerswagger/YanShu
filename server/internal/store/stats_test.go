package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

// 脱敏：终结满 30 天的行保留，身份列与**内容指纹列**（含块级 ciphertext_sm3）置 NULL；幂等（第二次 0 行）。
func TestRedactOldTerminal(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()
	now := time.Now().UTC()

	insert := func(id string, terminalAt *time.Time) {
		t.Helper()
		_, err := st.Pool().Exec(ctx, `INSERT INTO transfers
			(transfer_id,sender_code,recipient_code,plaintext_size,chunk_size,chunk_count,prelude_len,
			 prelude_sm3,state,max_downloads,created_at,updated_at,expires_at,upload_token_sm3,upload_token_kid,
			 uploader_ip,terminal_reason,terminal_at)
			VALUES ($1,'AWQW','X2EH',1024,1024,1,100,decode(repeat('00',32),'hex'),
			 'CONSUMED',1,now(),now(),now(),decode(repeat('11',32),'hex'),'1','203.0.113.9','CONSUMED',$2)`,
			id, terminalAt)
		if err != nil {
			t.Fatal(err)
		}
	}

	old := now.Add(-40 * 24 * time.Hour)
	recent := now.Add(-1 * 24 * time.Hour)
	insert("0123456789abcdef0123456789abcdef", &old)
	insert("fedcba9876543210fedcba9876543210", &recent)

	// 两条块级指纹：老的那条要脱敏，近的那条不动。
	for _, tc := range []struct{ tid string }{
		{"0123456789abcdef0123456789abcdef"}, {"fedcba9876543210fedcba9876543210"},
	} {
		if _, err := st.Pool().Exec(ctx, `INSERT INTO transfer_chunks
			(transfer_id, chunk_index, length, ciphertext_sm3, stored_at)
			VALUES ($1, 0, 64, decode(repeat('ab',32),'hex'), now())`, tc.tid); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.RedactOldTerminal(ctx, now.Add(-30*24*time.Hour), 200)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 { // 1 条 transfers 行 + 1 条块级指纹
		t.Fatalf("redacted = %d, want 2", n)
	}

	var chunkSM3 *string
	if err := st.Pool().QueryRow(ctx, `SELECT ciphertext_sm3::text FROM transfer_chunks
		WHERE transfer_id = '0123456789abcdef0123456789abcdef'`).Scan(&chunkSM3); err != nil {
		t.Fatal(err)
	}
	if chunkSM3 != nil {
		t.Fatalf("transfer_chunks.ciphertext_sm3 should be NULL after redact, got %v", *chunkSM3)
	}
	var recentChunk *string
	if err := st.Pool().QueryRow(ctx, `SELECT ciphertext_sm3::text FROM transfer_chunks
		WHERE transfer_id = 'fedcba9876543210fedcba9876543210'`).Scan(&recentChunk); err != nil {
		t.Fatal(err)
	}
	if recentChunk == nil {
		t.Fatal("recent chunk digest must not be redacted")
	}

	var ip, sm3, tok *string
	if err := st.Pool().QueryRow(ctx, `SELECT uploader_ip, prelude_sm3::text, upload_token_sm3::text
		FROM transfers WHERE transfer_id = '0123456789abcdef0123456789abcdef'`).Scan(&ip, &sm3, &tok); err != nil {
		t.Fatal(err)
	}
	if ip != nil || sm3 != nil || tok != nil {
		t.Fatalf("columns should be NULL after redact: ip=%v sm3=%v tok=%v", ip, sm3, tok)
	}

	// 行还在（永久保留），大小/时间/状态都在。
	var size int64
	var state string
	if err := st.Pool().QueryRow(ctx, `SELECT plaintext_size, state FROM transfers
		WHERE transfer_id = '0123456789abcdef0123456789abcdef'`).Scan(&size, &state); err != nil {
		t.Fatal(err)
	}
	if size != 1024 || state != "CONSUMED" {
		t.Fatalf("row should be kept: size=%d state=%s", size, state)
	}

	// 幂等：再跑一次 0 行；最近的行不受影响。
	if n, err = st.RedactOldTerminal(ctx, now.Add(-30*24*time.Hour), 200); err != nil || n != 0 {
		t.Fatalf("second run: n=%d err=%v", n, err)
	}
	var ip2 *string
	if err := st.Pool().QueryRow(ctx, `SELECT uploader_ip FROM transfers
		WHERE transfer_id = 'fedcba9876543210fedcba9876543210'`).Scan(&ip2); err != nil {
		t.Fatal(err)
	}
	if ip2 == nil {
		t.Fatal("recent row must not be redacted")
	}
}

// 脱敏列必须可空（0007 放开 transfers 两列，0009 放开 transfer_chunks.ciphertext_sm3）。
func TestRedactionColumnsNullable(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()
	for _, tc := range []struct{ table, col string }{
		{"transfers", "prelude_sm3"},
		{"transfers", "upload_token_sm3"},
		{"transfer_chunks", "ciphertext_sm3"}, // 0009 起可空（块级内容指纹也要能脱敏）
	} {
		var nullable string
		if err := st.Pool().QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name=$1 AND column_name=$2`,
			tc.table, tc.col).Scan(&nullable); err != nil {
			t.Fatalf("%s.%s: %v", tc.table, tc.col, err)
		}
		if nullable != "YES" {
			t.Fatalf("%s.%s must be nullable, got %s", tc.table, tc.col, nullable)
		}
	}
}
