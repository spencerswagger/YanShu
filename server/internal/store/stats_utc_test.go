package store_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/store"
)

// openWithSessionTZ 用**非 UTC 的会话时区**打开一个干净 schema。
//
// 这是 ADR-0002 §2.2 的可测形态：`timestamptz → date` 的截断吃会话 `TimeZone`，
// 部署环境只要不是 UTC，日界就会错桶；用 `timezone=Asia/Shanghai` 起一个 Store 就能暴露。
func openWithSessionTZ(t *testing.T, name, tz string) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	schema := "yanshu_core_test_tz_" + name
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Open(ctx, dsn+sep+"search_path="+schema+"&timezone="+tz)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool().Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := st.Pool().Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var got string
	if err := st.Pool().QueryRow(ctx, "SHOW TimeZone").Scan(&got); err != nil {
		t.Fatalf("show timezone: %v", err)
	}
	if got != tz {
		t.Fatalf("session timezone = %q, want %q", got, tz)
	}
	return st
}

// seedTransfer 造一条传输（默认 UPLOADING，created_at 由调用方给）。
func seedTransfer(t *testing.T, st *store.Store, id string, createdAt time.Time, plaintextSize int64) {
	t.Helper()
	ctx := context.Background()
	_, err := st.CreateTransfer(ctx, store.Transfer{
		ID:                   id,
		SenderCode:           "AAAA",
		RecipientCode:        "BBBB",
		PlaintextSize:        plaintextSize,
		ChunkSize:            32,
		ChunkCount:           1,
		PreludeLen:           300,
		PreludeSM3:           make([]byte, 32),
		TotalCiphertextBytes: 506,
		MaxDownloads:         1,
		CreatedAt:            createdAt,
		UpdatedAt:            createdAt,
		ExpiresAt:            createdAt.Add(24 * time.Hour),
		UploadTokenSM3:       make([]byte, 32),
		UploadTokenKID:       "1",
	})
	if err != nil {
		t.Fatalf("create transfer: %v", err)
	}
}

// markConsumed 把一条传输改成 CONSUMED（模拟 ack 达上限后的终态）。
func markConsumed(t *testing.T, st *store.Store, id string, terminalAt time.Time) {
	t.Helper()
	_, err := st.Pool().Exec(context.Background(), `UPDATE transfers
		SET state = 'CONSUMED', terminal_reason = 'CONSUMED', terminal_at = $2,
		    download_count = 1, updated_at = $2
		WHERE transfer_id = $1`, id, terminalAt)
	if err != nil {
		t.Fatalf("mark consumed: %v", err)
	}
}

// addCounter 直接写一行计数器（模拟运行时累加的结果，用于比对读取侧）。
func addCounter(t *testing.T, st *store.Store, day string, consumed, bytes, created int64) {
	t.Helper()
	_, err := st.Pool().Exec(context.Background(), `INSERT INTO stats_counters (day, consumed, consumed_bytes, created)
		VALUES ($1::date, $2, $3, $4)
		ON CONFLICT (day) DO UPDATE SET consumed = stats_counters.consumed + EXCLUDED.consumed,
		    consumed_bytes = stats_counters.consumed_bytes + EXCLUDED.consumed_bytes,
		    created = stats_counters.created + EXCLUDED.created`, day, consumed, bytes, created)
	if err != nil {
		t.Fatalf("add counter: %v", err)
	}
}

// TestStatsDayBoundaryIsUTC：非 UTC 会话下，23:30Z 仍须落 UTC 日桶
// （2026-11-09），不能落成上海日（2026-11-10）。
func TestStatsDayBoundaryIsUTC(t *testing.T) {
	st := openWithSessionTZ(t, "utc", "Asia/Shanghai")
	ctx := context.Background()

	edge := time.Date(2026, 11, 9, 23, 30, 0, 0, time.UTC) // = 上海 2026-11-10 07:30
	addCounter(t, st, "2026-11-09", 1, 5, 0)

	consumed, bytes, created, err := st.DayStats(ctx, edge)
	if err != nil {
		t.Fatalf("day stats: %v", err)
	}
	if consumed != 1 || bytes != 5 || created != 0 {
		t.Fatalf("UTC 日界取错桶：consumed=%d bytes=%d created=%d（应按会话时区落到 11-10 才算 bug）",
			consumed, bytes, created)
	}

	// 写路径同样按 UTC 落桶：created_at = 23:30Z 的建包要加在 11-09。
	seedTransfer(t, st, "11111111111111111111111111111111", edge, 5)
	_, _, created, err = st.DayStats(ctx, edge)
	if err != nil {
		t.Fatalf("day stats after create: %v", err)
	}
	if created != 1 {
		t.Fatalf("created 写到了错误的桶：created=%d（want 1 on 2026-11-09）", created)
	}
	// 上海日桶必须是空的：那才说明没有按会话时区分桶。
	_, _, shanghaiDayCreated, err := st.DayStats(ctx, edge.Add(8*time.Hour))
	if err != nil {
		t.Fatalf("day stats shanghai bucket: %v", err)
	}
	if shanghaiDayCreated != 0 {
		t.Fatalf("计数器按本地日界分了桶：上海日 created=%d", shanghaiDayCreated)
	}
}

// TestReconcileDayMatchesCounters：计数器与真实行一致时偏差为 0（含 23:30Z 边界行）。
func TestReconcileDayMatchesCounters(t *testing.T) {
	st := openWithSessionTZ(t, "recon", "Asia/Shanghai")
	ctx := context.Background()
	edge := time.Date(2026, 11, 9, 23, 30, 0, 0, time.UTC)

	seedTransfer(t, st, "22222222222222222222222222222222", edge, 7) // created 由建包路径自己累加
	markConsumed(t, st, "22222222222222222222222222222222", edge)
	addCounter(t, st, "2026-11-09", 1, 7, 0) // consumed/bytes 与真实行一致

	rec, err := st.ReconcileDay(ctx, edge)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if rec.Day != "2026-11-09" {
		t.Fatalf("reconcile day = %s, want 2026-11-09", rec.Day)
	}
	if rec.Actual.Consumed != 1 || rec.Actual.ConsumedBytes != 7 || rec.Actual.Created != 1 {
		t.Fatalf("actual 落桶错误：%+v", rec.Actual)
	}
	if dev := rec.Deviation(); dev != 0 {
		t.Fatalf("counters 与真实行一致却报偏差 %v（%+v vs %+v）", dev, rec.Counters, rec.Actual)
	}
}

// TestReconcileDayDetectsDrift：计数器少记 10% → 偏差 0.1 > 0.001 阈值。
func TestReconcileDayDetectsDrift(t *testing.T) {
	st := openWithSessionTZ(t, "drift", "UTC")
	ctx := context.Background()
	day := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	for i, id := range []string{
		"33333333333333333333333333333333",
		"44444444444444444444444444444444",
	} {
		seedTransfer(t, st, id, day, 10)
		markConsumed(t, st, id, day.Add(time.Duration(i)*time.Minute))
	}
	addCounter(t, st, "2026-11-09", 2, 20, 2)

	// 人为把计数器打少一条（模拟漏加）。
	if _, err := st.Pool().Exec(ctx, `UPDATE stats_counters SET consumed = consumed - 1, consumed_bytes = consumed_bytes - 10
		WHERE day = '2026-11-09'`); err != nil {
		t.Fatalf("break counter: %v", err)
	}

	rec, err := st.ReconcileDay(ctx, day)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if rec.Counters.Consumed != 1 || rec.Actual.Consumed != 2 {
		t.Fatalf("unexpected reconcile: %+v", rec)
	}
	if dev := rec.Deviation(); dev < 0.4 || dev > 0.6 {
		t.Fatalf("deviation = %v, want ≈0.5（|1-2|/2）", rec.Deviation())
	}
}
