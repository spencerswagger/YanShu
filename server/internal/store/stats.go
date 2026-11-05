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

// AddCreatedStat 在建包事务内累加当日 created 计数。
func addCreatedStat(ctx context.Context, tx execer, day time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO stats_counters (day, created) VALUES ($1::date, 1)
		ON CONFLICT (day) DO UPDATE SET created = stats_counters.created + 1`, day)
	return err
}

// addConsumedStat 在 ack 事务内累加当日 consumed / consumed_bytes。
func addConsumedStat(ctx context.Context, tx execer, day time.Time, bytes int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO stats_counters (day, consumed, consumed_bytes) VALUES ($1::date, 1, $2)
		ON CONFLICT (day) DO UPDATE
		SET consumed = stats_counters.consumed + 1,
		    consumed_bytes = stats_counters.consumed_bytes + EXCLUDED.consumed_bytes`, day, bytes)
	return err
}

// DayStats 返回某日的聚合计数（没有当天行为零值）。
func (s *Store) DayStats(ctx context.Context, day time.Time) (consumed, consumedBytes, created int64, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT consumed, consumed_bytes, created FROM stats_counters WHERE day = $1::date`, day).
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

// RedactOldTerminal 把终结超过 before 的行的敏感列置 NULL（幂等、分批）。
// 返回本次处理的批次数与总行数，供 sweeper 循环调用。
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
