package cleanup_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/cleanup"
	"github.com/spencerswagger/YanShu/server/internal/store"
	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

func newSweeper(t *testing.T, now time.Time) (*cleanup.Sweeper, *store.Store) {
	t.Helper()
	st := testutil.NewStore(t, "cleanup")
	testutil.Reset(t, st)
	blobs, err := blob.NewDisk(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatalf("blob disk: %v", err)
	}
	sw := cleanup.New(st, blobs, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sw.Now = func() time.Time { return now }
	return sw, st
}

// 审计保留期（ADR-0002 §2.4）：90 天前的行必须被删，近期的留下。
func TestSweeperPurgesOldAudit(t *testing.T) {
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	sw, st := newSweeper(t, now)
	ctx := context.Background()

	insert := func(ts time.Time) {
		t.Helper()
		if err := st.Audit(ctx, store.AuditEvent{
			TS: ts, Method: "POST", Path: "/v1/transfers", Status: 201, Bytes: 10,
			IP: "203.0.113.9", RequestID: "req",
		}); err != nil {
			t.Fatalf("audit: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		insert(now.Add(-91 * 24 * time.Hour))
	}
	for i := 0; i < 2; i++ {
		insert(now.Add(-24 * time.Hour))
	}

	stats, err := sw.Once(ctx)
	if err != nil {
		t.Fatalf("once: %v", err)
	}
	if stats.AuditPurged != 3 {
		t.Fatalf("auditPurged = %d, want 3", stats.AuditPurged)
	}
	var left int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&left); err != nil {
		t.Fatalf("count: %v", err)
	}
	if left != 2 {
		t.Fatalf("audit rows left = %d, want 2", left)
	}
}

// 每日对账 + 告警出口（ADR-0002 §2.3）：计数器与真实行分叉时，Once 里必须
// 跑出 Reconcile 结果并调用 OnDrift（默认还会落 `alert=stats_drift` 的 ERROR 日志）。
func TestSweeperReconcileRaisesDrift(t *testing.T) {
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	sw, st := newSweeper(t, now)
	ctx := context.Background()
	yesterday := now.AddDate(0, 0, -1)

	// 真实行：昨天 2 条 CONSUMED；计数器只记了 1 条（漏加）。
	for i, id := range []string{
		"55555555555555555555555555555555",
		"66666666666666666666666666666666",
	} {
		if _, err := st.CreateTransfer(ctx, store.Transfer{
			ID: id, SenderCode: "AAAA", RecipientCode: "BBBB",
			PlaintextSize: 10, ChunkSize: 32, ChunkCount: 1, PreludeLen: 300,
			PreludeSM3: make([]byte, 32), TotalCiphertextBytes: 506, MaxDownloads: 1,
			CreatedAt: yesterday, UpdatedAt: yesterday, ExpiresAt: yesterday.Add(24 * time.Hour),
			UploadTokenSM3: make([]byte, 32), UploadTokenKID: "1",
		}); err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := st.Pool().Exec(ctx, `UPDATE transfers SET state='CONSUMED',
			terminal_reason='CONSUMED', terminal_at=$2, download_count=1 WHERE transfer_id=$1`,
			id, yesterday.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("mark consumed: %v", err)
		}
	}
	if _, err := st.Pool().Exec(ctx, `UPDATE stats_counters SET consumed = 1, consumed_bytes = 10
		WHERE day = $1::date`, yesterday.Format("2006-01-02")); err != nil {
		t.Fatalf("seed counters: %v", err)
	}

	var got *cleanup.DayDrift
	sw.OnDrift = func(d cleanup.DayDrift) { got = &d }

	stats, err := sw.Once(ctx)
	if err != nil {
		t.Fatalf("once: %v", err)
	}
	if stats.Reconcile == nil {
		t.Fatal("reconcile 没跑")
	}
	if got == nil {
		t.Fatalf("偏差未触发告警：%+v", *stats.Reconcile)
	}
	if got.Deviation <= sw.DriftThreshold {
		t.Fatalf("deviation = %v, threshold = %v", got.Deviation, sw.DriftThreshold)
	}
	if got.Actual.Consumed != 2 || got.Counters.Consumed != 1 {
		t.Fatalf("告警载荷不对：%+v", got)
	}

	// 限频：同一轮内再跑一次不应重复对账。
	sw.Now = func() time.Time { return now.Add(time.Minute) }
	stats2, err := sw.Once(ctx)
	if err != nil {
		t.Fatalf("once2: %v", err)
	}
	if stats2.Reconcile != nil {
		t.Fatal("对账未按 ReconcileInterval 限频")
	}
}

// P0 回归：兜底删密文必须**逐批推进**。
//
// 旧实现用 `ORDER BY terminal_at LIMIT batch`：终结行永久保留后，每个 tick 都拿回同一批
// 最老的行，更晚终结的行永远轮不到（密文永久残留），日志里的 purged 还是常量。
// 现在按 `ciphertext_purged_at` 水位推进，两轮必须处理不同行、最终密文文件数为 0。
func TestSweeperPurgeAdvancesWatermark(t *testing.T) {
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	_, st := newSweeper(t, now) // 只借它的 store（干净的 schema）
	ctx := context.Background()
	blobRoot := filepath.Join(t.TempDir(), "blobs2")
	blobs, err := blob.NewDisk(blobRoot)
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}
	sw2 := cleanup.New(st, blobs, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sw2.Now = func() time.Time { return now }
	sw2.AuditRetention = 0 // 只测密文水位
	sw2.ReconcileInterval = 0

	const total = 250 // > 默认批大小 200

	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("%032x", i+1)
		ids = append(ids, id)
		if _, err := st.CreateTransfer(ctx, store.Transfer{
			ID: id, SenderCode: "AAAA", RecipientCode: "BBBB",
			PlaintextSize: 10, ChunkSize: 32, ChunkCount: 1, PreludeLen: 8,
			PreludeSM3: make([]byte, 32), TotalCiphertextBytes: 40, MaxDownloads: 1,
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(-time.Minute), UploadTokenSM3: make([]byte, 32), UploadTokenKID: "1",
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		if _, err := st.Pool().Exec(ctx, `UPDATE transfers SET state='CONSUMED',
			terminal_reason='CONSUMED', terminal_at=$2, download_count=1 WHERE transfer_id=$1`,
			id, now.Add(-time.Duration(total-i)*time.Second)); err != nil {
			t.Fatalf("terminalize: %v", err)
		}
		if _, err := blobs.PutPrelude(id, []byte("ciphertx")); err != nil {
			t.Fatalf("put prelude: %v", err)
		}
	}

	countFiles := func() int {
		n := 0
		_ = filepath.Walk(blobRoot, func(_ string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() {
				n++
			}
			return nil
		})
		return n
	}
	if got := countFiles(); got != total {
		t.Fatalf("blob files before sweep = %d, want %d", got, total)
	}

	round1, err := sw2.Once(ctx)
	if err != nil {
		t.Fatalf("round1: %v", err)
	}
	if round1.Purged != 200 || round1.PurgeRemaining != int64(total-200) {
		t.Fatalf("round1 purged=%d remaining=%d, want 200/%d", round1.Purged, round1.PurgeRemaining, total-200)
	}
	if got := countFiles(); got != total-200 {
		t.Fatalf("blob files after round1 = %d, want %d（旧实现会一直是 50 个残留被反复处理）", got, total-200)
	}

	round2, err := sw2.Once(ctx)
	if err != nil {
		t.Fatalf("round2: %v", err)
	}
	if round2.Purged != total-200 || round2.PurgeRemaining != 0 {
		t.Fatalf("round2 purged=%d remaining=%d, want %d/0（未推进到新行）",
			round2.Purged, round2.PurgeRemaining, total-200)
	}
	if got := countFiles(); got != 0 {
		t.Fatalf("blob files after round2 = %d, want 0", got)
	}
	if round1.Purged == round2.Purged {
		t.Fatalf("两轮处理数相同（%d），日志计数仍是常量", round1.Purged)
	}
}
