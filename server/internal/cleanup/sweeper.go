// Package cleanup 是 TTL / 终结态的清道夫。
//
// 三件事：把到期包置终结 → **真删**磁盘密文与元数据 → 清理过期的挑战/会话/码。
// 删除是真删（RemoveAll + DELETE），不是软删、不是改状态了事。
package cleanup

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// Sweeper 周期清理。
type Sweeper struct {
	store    *store.Store
	blobs    blob.Store
	log      *slog.Logger
	interval time.Duration
	batch    int
	// CodeGrace 是码过期后仍保留多久（保留期内查询返回 code_expired，之后是 code_not_found）。
	CodeGrace time.Duration
	// TombstoneTTL 是墓碑保留时长（只留终结原因，便于排障）。
	TombstoneTTL time.Duration
	// Now 可被测试替换，生产用 time.Now。
	Now func() time.Time
}

// New 构造 Sweeper。
func New(st *store.Store, blobs blob.Store, interval time.Duration, log *slog.Logger) *Sweeper {
	if log == nil {
		log = slog.Default()
	}
	return &Sweeper{
		store:        st,
		blobs:        blobs,
		log:          log,
		interval:     interval,
		batch:        200,
		CodeGrace:    7 * 24 * time.Hour,
		TombstoneTTL: 30 * 24 * time.Hour,
		Now:          func() time.Time { return time.Now().UTC() },
	}
}

// Stats 是一轮清理的结果。
type Stats struct {
	Terminalized int64
	Purged       int
	PurgeErrors  int
	Challenges   int64
	Sessions     int64
	Codes        int64
	Tombstones   int64
}

// Run 阻塞运行，直到 ctx 取消。启动立即跑一轮，之后按 interval 跑。
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

	n, err := s.store.TerminalizeExpired(ctx, now)
	if err != nil {
		return stats, err
	}
	stats.Terminalized = n

	for i := 0; i < s.batch; i++ {
		list, err := s.store.ListPurgeable(ctx, now, 1)
		if err != nil {
			return stats, err
		}
		if len(list) == 0 {
			break
		}
		p := list[0]
		// 先删密文再删元数据：即使元数据删除失败，下一轮还能重试，不会留下"可下载但已标记删除"的窗口。
		if err := s.blobs.Purge(p.ID); err != nil {
			s.log.Error("purge blobs failed", "packageId", p.ID, "err", err.Error())
			stats.PurgeErrors++
			break
		}
		if err := s.store.PurgePackage(ctx, p.ID, now); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			s.log.Error("purge package failed", "packageId", p.ID, "err", err.Error())
			stats.PurgeErrors++
			break
		}
		_ = s.store.Audit(ctx, store.AuditEvent{
			At: now, Kind: store.AuditPackagePurge, PackageID: p.ID,
			Outcome: p.State, Bytes: int64(p.PreludeLen),
		})
		stats.Purged++
	}

	if n, err := s.store.DeleteExpiredChallenges(ctx, now); err == nil {
		stats.Challenges = n
	} else {
		s.log.Warn("delete challenges failed", "err", err.Error())
	}
	if n, err := s.store.DeleteExpiredSessions(ctx, now); err == nil {
		stats.Sessions = n
	} else {
		s.log.Warn("delete sessions failed", "err", err.Error())
	}
	if n, err := s.store.DeleteExpiredCodes(ctx, now.Add(-s.CodeGrace)); err == nil {
		stats.Codes = n
	} else {
		s.log.Warn("delete codes failed", "err", err.Error())
	}
	if n, err := s.store.DeleteOldTombstones(ctx, now.Add(-s.TombstoneTTL)); err == nil {
		stats.Tombstones = n
	} else {
		s.log.Warn("delete tombstones failed", "err", err.Error())
	}

	if stats.Purged > 0 || stats.Terminalized > 0 {
		s.log.Info("sweep",
			"terminalized", stats.Terminalized,
			"purged", stats.Purged,
			"purgeErrors", stats.PurgeErrors,
			"challenges", stats.Challenges,
			"sessions", stats.Sessions,
			"codes", stats.Codes,
		)
	}
	return stats, nil
}
