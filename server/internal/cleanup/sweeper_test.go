package cleanup_test

import (
	"context"
	"io"
	"log/slog"
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
