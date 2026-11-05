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
	// Now 可被测试替换。
	Now func() time.Time
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
		Now:                func() time.Time { return time.Now().UTC() },
	}
}

// Stats 是一轮清理的结果。
type Stats struct {
	Expired     int
	Purged      int
	PurgeErrors int
	Challenges  int64
	Idempotency int64
	Redacted    int64
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
	for _, id := range expired {
		if err := s.blobs.Purge(id); err != nil {
			s.log.Error("purge expired ciphertext failed", "transferId", id, "err", err.Error())
			stats.PurgeErrors++
		}
	}

	// 2) 所有终结态再兜底删一次密文（删除幂等）。
	terminal, err := s.store.ListTerminal(ctx, s.batch)
	if err != nil {
		return stats, err
	}
	for _, t := range terminal {
		if err := s.blobs.Purge(t.ID); err != nil {
			s.log.Error("purge terminal ciphertext failed", "transferId", t.ID, "err", err.Error())
			stats.PurgeErrors++
			continue
		}
		stats.Purged++
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

	if stats.Expired > 0 || stats.Purged > 0 || stats.Redacted > 0 {
		s.log.Info("sweep",
			"expired", stats.Expired,
			"purged", stats.Purged,
			"purgeErrors", stats.PurgeErrors,
			"redacted", stats.Redacted,
		)
	}
	return stats, nil
}
