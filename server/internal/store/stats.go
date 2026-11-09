package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// execer 同时由 *pgxpool.Pool 与 pgx.Tx 实现，统计累加可复用同一段 SQL。
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// statDay 把时间点换算成**UTC 日界**的日期字符串。
//
// 为什么不把 time.Time 直接 `$1::date`：`timestamptz → date` 的截断吃会话 `TimeZone`，
// 部署环境一旦不是 UTC，同一个"今天"就会被分到两个桶（回填与运行时各错各的，ADR-0002 §2.2）。
// 这里先在 Go 侧按 UTC 折成 `YYYY-MM-DD` 字面量，SQL 只做文本→date，与会话时区无关。
func statDay(t time.Time) string { return t.UTC().Format("2006-01-02") }

// AddCreatedStat 在建包事务内累加当日 created 计数。
func addCreatedStat(ctx context.Context, tx execer, day time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO stats_counters (day, created) VALUES ($1::date, 1)
		ON CONFLICT (day) DO UPDATE SET created = stats_counters.created + 1`, statDay(day))
	return err
}

// addConsumedStat 在 ack 事务内累加当日 consumed / consumed_bytes。
func addConsumedStat(ctx context.Context, tx execer, day time.Time, bytes int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO stats_counters (day, consumed, consumed_bytes) VALUES ($1::date, 1, $2)
		ON CONFLICT (day) DO UPDATE
		SET consumed = stats_counters.consumed + 1,
		    consumed_bytes = stats_counters.consumed_bytes + EXCLUDED.consumed_bytes`, statDay(day), bytes)
	return err
}

// DayStats 返回某日（**UTC 日界**）的聚合计数（没有当天行为零值）。
func (s *Store) DayStats(ctx context.Context, day time.Time) (consumed, consumedBytes, created int64, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT consumed, consumed_bytes, created FROM stats_counters WHERE day = $1::date`, statDay(day)).
		Scan(&consumed, &consumedBytes, &created)
	if err != nil {
		if isNoRows(err) {
			return 0, 0, 0, nil
		}
		return 0, 0, 0, fmt.Errorf("store: day stats: %w", err)
	}
	return consumed, consumedBytes, created, nil
}

// TotalStats 返回累计聚合计数（对计数器表求和：一年只有 365 行，不碰 transfers）。
func (s *Store) TotalStats(ctx context.Context) (consumed, consumedBytes, created int64, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT COALESCE(sum(consumed),0), COALESCE(sum(consumed_bytes),0), COALESCE(sum(created),0)
		FROM stats_counters`).Scan(&consumed, &consumedBytes, &created)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("store: total stats: %w", err)
	}
	return consumed, consumedBytes, created, nil
}

// StatBucket 是一档聚合计数（与 spec.StatsBucket 同口径；刻意不反向依赖 spec）。
type StatBucket struct {
	Consumed      int64
	ConsumedBytes int64
	Created       int64
}

// DayReconcile 是一天的对账结果：计数器（派生）vs transfers 真实行（事实）。
type DayReconcile struct {
	Day      string
	Counters StatBucket
	Actual   StatBucket
}

// Deviation 返回三项指标里的**最大相对偏差**。
// 两边都为 0 记 0；只有一侧为 0 记 1（完全偏离），避免除零。
func (r DayReconcile) Deviation() float64 {
	pairs := [][2]int64{
		{r.Counters.Consumed, r.Actual.Consumed},
		{r.Counters.ConsumedBytes, r.Actual.ConsumedBytes},
		{r.Counters.Created, r.Actual.Created},
	}
	var worst float64
	for _, p := range pairs {
		c, a := p[0], p[1]
		if c == 0 && a == 0 {
			continue
		}
		base := c
		if a > base {
			base = a
		}
		dev := float64(c-a) / float64(base)
		if dev < 0 {
			dev = -dev
		}
		if dev > worst {
			worst = dev
		}
	}
	return worst
}

// ReconcileDay 对账某一天（**UTC 日界**）：计数器 vs `transfers` 真实行。
//
// 口径（ADR-0002 §2.1/§2.3）：`consumed`/`consumed_bytes` 按 `terminal_at` 落桶，
// `created` 按 `created_at` 落桶；两者都用半开区间 [00:00Z, 次日 00:00Z)，走索引、不做函数截断。
func (s *Store) ReconcileDay(ctx context.Context, day time.Time) (DayReconcile, error) {
	start := time.Date(day.UTC().Year(), day.UTC().Month(), day.UTC().Day(), 0, 0, 0, 0, time.UTC)
	out := DayReconcile{Day: start.Format("2006-01-02")}

	consumed, bytes, created, err := s.DayStats(ctx, start)
	if err != nil {
		return DayReconcile{}, err
	}
	out.Counters = StatBucket{Consumed: consumed, ConsumedBytes: bytes, Created: created}

	end := start.AddDate(0, 0, 1)
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'CONSUMED'),
		       COALESCE(sum(plaintext_size) FILTER (WHERE state = 'CONSUMED'), 0)
		FROM transfers WHERE terminal_at >= $1 AND terminal_at < $2`, start, end).
		Scan(&out.Actual.Consumed, &out.Actual.ConsumedBytes); err != nil {
		return DayReconcile{}, fmt.Errorf("store: reconcile consumed: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM transfers WHERE created_at >= $1 AND created_at < $2`, start, end).
		Scan(&out.Actual.Created); err != nil {
		return DayReconcile{}, fmt.Errorf("store: reconcile created: %w", err)
	}
	return out, nil
}

// RedactOldTerminal 把终结超过 before 的行的敏感列置 NULL（幂等、分批）。// 返回本次处理的批次数与总行数，供 sweeper 循环调用。
func (s *Store) RedactOldTerminal(ctx context.Context, before time.Time, batch int) (int64, error) {
	var total int64
	for {
		tag, err := s.pool.Exec(ctx, `
			UPDATE transfers
			SET uploader_ip = NULL, prelude_sm3 = NULL, upload_token_sm3 = NULL
			WHERE transfer_id IN (
				SELECT transfer_id FROM transfers
				WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED')
				  AND terminal_at IS NOT NULL AND terminal_at < $1
				  AND (uploader_ip IS NOT NULL OR prelude_sm3 IS NOT NULL OR upload_token_sm3 IS NOT NULL)
				ORDER BY terminal_at
				LIMIT $2
			)`, before, batch)
		if err != nil {
			return total, fmt.Errorf("store: redact terminal: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			return total, nil
		}
	}
}
