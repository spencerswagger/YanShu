// Package cleanup 是 TTL / 终结态的清道夫。
//
// 三条终结路径（ack 达上限、revoke、TTL）都必须**物理删除**密文（API.md §2.3）；
// 本包是兜底重试：即使请求路径里删除失败，也会被周期任务补上。
package cleanup

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// Sweeper 周期清理。
type Sweeper struct {
	store    *store.Store
	blobs    blob.Store
	log      *slog.Logger
	interval time.Duration
	batch    int
	// RedactAfter 是终结元数据**脱敏**时限（v5：30 天）；元数据本身永久保留。
	RedactAfter time.Duration
	// ChallengeRetention 是挑战记录保留时长（API.md §1.2：10 分钟）。
	ChallengeRetention time.Duration
	// AuditRetention 是审计行保留期（ADR-0002 §2.4：默认 90 天；没有保留期的审计表
	// 迟早变成第二张大表，而且带 IP）。
	AuditRetention time.Duration
	// ReconcileInterval 是统计对账间隔（ADR-0002 §2.3：每日一次）。
	ReconcileInterval time.Duration
	// DriftThreshold 是对账偏差告警阈值（0.1%）。
	DriftThreshold float64
	// OnDrift 是告警出口：为 nil 时只写 ERROR 日志（`alert=stats_drift`，运维按此抓）。
	OnDrift func(DayDrift)
	// Now 可被测试替换。
	Now func() time.Time

	lastReconcile time.Time
}

// New 构造 Sweeper。
func New(st *store.Store, blobs blob.Store, interval time.Duration, log *slog.Logger) *Sweeper {
	if log == nil {
		log = slog.Default()
	}
	return &Sweeper{
		store:              st,
		blobs:              blobs,
		log:                log,
		interval:           interval,
		batch:              200,
		RedactAfter:        spec.RedactAfter,
		ChallengeRetention: spec.ChallengeRetention,
		AuditRetention:     spec.AuditRetention,
		ReconcileInterval:  spec.ReconcileInterval,
		DriftThreshold:     spec.DriftThreshold,
		Now:                func() time.Time { return time.Now().UTC() },
	}
}

// Stats 是一轮清理的结果。
type Stats struct {
	Expired     int
	Purged      int
	PurgeErrors int
	// PurgeRemaining 是本轮结束后**仍未确认删除密文**的终结行数（真实值，不是批次大小）。
	PurgeRemaining int64
	Challenges     int64
	Idempotency    int64
	Redacted       int64
	AuditPurged    int64
	// Reconcile 是本次真正跑过的对账结果（未到期则为 nil）。
	Reconcile *store.DayReconcile
}

// DayDrift 是一次对账越阈值的结果（告警载荷）。
type DayDrift struct {
	Day       string
	Deviation float64
	Threshold float64
	Counters  store.StatBucket
	Actual    store.StatBucket
}

// Run 阻塞运行，直到 ctx 取消。
func (s *Sweeper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		if _, err := s.Once(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Warn("sweep failed", "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Once 跑一轮清理。
func (s *Sweeper) Once(ctx context.Context) (Stats, error) {
	now := s.Now()
	var stats Stats

	// 1) TTL 到期 → EXPIRED。
	expired, err := s.store.TerminalizeExpired(ctx, now)
	if err != nil {
		return stats, err
	}
	stats.Expired = len(expired)
	purgedIDs := make([]string, 0, len(expired)+s.batch)
	for _, id := range expired {
		if err := s.blobs.Purge(id); err != nil {
			s.log.Error("purge expired ciphertext failed", "transferId", id, "err", err.Error())
			stats.PurgeErrors++
			continue
		}
		stats.Purged++
		purgedIDs = append(purgedIDs, id)
	}

	// 2) 兜底删密文：按 `ciphertext_purged_at` 水位推进。
	//    终结行永久保留后，"ORDER BY terminal_at LIMIT n" 每 tick 都返回同一批最老的行，
	//    更晚终结的行永远轮不到（密文永久残留）。这里每删成功一批就写水位，下一批自然推进。
	unpurged, err := s.store.ListUnpurgedTerminal(ctx, s.batch)
	if err != nil {
		return stats, err
	}
	for _, row := range unpurged {
		if err := s.blobs.Purge(row.ID); err != nil {
			s.log.Error("purge terminal ciphertext failed", "transferId", row.ID, "err", err.Error())
			stats.PurgeErrors++
			continue
		}
		stats.Purged++
		purgedIDs = append(purgedIDs, row.ID)
	}
	if len(purgedIDs) > 0 {
		if _, err := s.store.MarkCiphertextPurged(ctx, purgedIDs, now); err != nil {
			s.log.Warn("mark ciphertext purged failed", "count", len(purgedIDs), "err", err.Error())
		}
	}
	// 真实剩余量（不是常量 200）：运维据此判断兜底是否跟上。
	if remaining, err := s.store.CountUnpurgedTerminal(ctx); err == nil {
		stats.PurgeRemaining = remaining
	} else {
		s.log.Warn("count unpurged terminal failed", "err", err.Error())
	}

	// 3) 过期挑战（10 分钟）。
	if n, err := s.store.DeleteExpiredChallenges(ctx, now.Add(-s.ChallengeRetention)); err == nil {
		stats.Challenges = n
	} else {
		s.log.Warn("delete challenges failed", "err", err.Error())
	}

	// 4) 幂等记录。
	if n, err := s.store.DeleteExpiredIdempotency(ctx, now); err == nil {
		stats.Idempotency = n
	} else {
		s.log.Warn("delete idempotency failed", "err", err.Error())
	}

	// 5) 终结元数据**永久保留**；终结满 30 天后把三个关联性字段置 NULL（脱敏，幂等分批）。
	if n, err := s.store.RedactOldTerminal(ctx, now.Add(-s.RedactAfter), s.batch); err == nil {
		stats.Redacted = n
	} else {
		s.log.Warn("redact terminal transfers failed", "err", err.Error())
	}

	// 6) 审计保留期（ADR-0002 §2.4）：90 天前的审计行分批删除。
	if s.AuditRetention > 0 {
		if n, err := s.store.DeleteOldAudit(ctx, now.Add(-s.AuditRetention), s.batch); err == nil {
			stats.AuditPurged = n
		} else {
			s.log.Warn("delete old audit failed", "err", err.Error())
		}
	}

	// 7) 每日对账（ADR-0002 §2.3）：计数器是派生值，与 transfers 事实行比对，
	//    偏差 > 0.1% 走告警出口。按 ReconcileInterval 限频，重启后会立刻补跑一次。
	if s.ReconcileInterval > 0 && (s.lastReconcile.IsZero() || now.Sub(s.lastReconcile) >= s.ReconcileInterval) {
		day := now.UTC().AddDate(0, 0, -1) // 对账「昨天」：那一天已经不会再变
		rec, err := s.store.ReconcileDay(ctx, day)
		if err != nil {
			s.log.Warn("stats reconcile failed", "day", day.Format("2006-01-02"), "err", err.Error())
		} else {
			s.lastReconcile = now
			stats.Reconcile = &rec
			if dev := rec.Deviation(); dev > s.DriftThreshold {
				drift := DayDrift{Day: rec.Day, Deviation: dev, Threshold: s.DriftThreshold,
					Counters: rec.Counters, Actual: rec.Actual}
				// 告警路径：默认落 ERROR 日志（`alert=stats_drift`，运维按此关键字抓/转发）；
				// 部署方可用 OnDrift 接自己的告警通道。
				s.log.Error("stats drift alert",
					"alert", "stats_drift",
					"day", rec.Day,
					"deviation", dev,
					"threshold", s.DriftThreshold,
					"countersConsumed", rec.Counters.Consumed,
					"actualConsumed", rec.Actual.Consumed,
					"countersBytes", rec.Counters.ConsumedBytes,
					"actualBytes", rec.Actual.ConsumedBytes,
					"countersCreated", rec.Counters.Created,
					"actualCreated", rec.Actual.Created,
				)
				if s.OnDrift != nil {
					s.OnDrift(drift)
				}
			} else {
				s.log.Info("stats reconcile ok", "day", rec.Day, "deviation", dev,
					"countersConsumed", rec.Counters.Consumed, "actualConsumed", rec.Actual.Consumed,
					"countersCreated", rec.Counters.Created, "actualCreated", rec.Actual.Created)
			}
		}
	}

	if stats.Expired > 0 || stats.Purged > 0 || stats.Redacted > 0 || stats.AuditPurged > 0 ||
		stats.PurgeRemaining > 0 || stats.PurgeErrors > 0 {
		s.log.Info("sweep",
			"expired", stats.Expired,
			"purged", stats.Purged,
			"purgeErrors", stats.PurgeErrors,
			"purgeRemaining", stats.PurgeRemaining,
			"redacted", stats.Redacted,
			"auditPurged", stats.AuditPurged,
		)
	}
	return stats, nil
}
