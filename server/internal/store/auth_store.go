package store

import (
	"context"
	"fmt"
	"time"
)

// Challenge 是一次性签名挑战（API.md §1.2 / §2.1）。
type Challenge struct {
	ID        string
	Purpose   string
	Nonce     []byte
	ExpiresAt time.Time
	Used      bool
}

// InsertChallenge 落一个挑战。
func (s *Store) InsertChallenge(ctx context.Context, id, purpose string, nonce []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO auth_challenges (challenge_id, purpose, nonce, expires_at, used)
		VALUES ($1, $2, $3, $4, false)`, id, purpose, nonce, expiresAt)
	if err != nil {
		return fmt.Errorf("store: insert challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge 原子地作废挑战并返回它。
//
// 语义按 API.md §1.2：**成功或失败都作废**（防爆破）。因此 handler 必须在验签
// *之前* 调用它；未过期、未用过才返回记录，否则 ErrNotFound（统一映射
// AUTH_CHALLENGE_INVALID，不区分原因）。
func (s *Store) ConsumeChallenge(ctx context.Context, id string, now time.Time) (Challenge, error) {
	var c Challenge
	err := s.pool.QueryRow(ctx, `UPDATE auth_challenges SET used = true
		WHERE challenge_id = $1 AND used = false AND expires_at > $2
		RETURNING challenge_id, purpose, nonce, expires_at, used`, id, now).
		Scan(&c.ID, &c.Purpose, &c.Nonce, &c.ExpiresAt, &c.Used)
	if err != nil {
		if isNoRows(err) {
			return Challenge{}, ErrNotFound
		}
		return Challenge{}, fmt.Errorf("store: consume challenge: %w", err)
	}
	return c, nil
}

// DeleteExpiredChallenges 清理过期挑战（API.md §1.2：10 分钟后失效）。
func (s *Store) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM auth_challenges WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}
