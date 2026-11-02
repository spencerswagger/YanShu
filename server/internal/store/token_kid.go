package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrTokenKIDLower 表示传入的 kid 小于已记录的最大值（拒绝调小）。
var ErrTokenKIDLower = errors.New("store: token kid is lower than the recorded maximum")

// EnsureTokenKID 记录并返回当前最大的 kid。
//
// 语义：kid 只能单调递增。相等 → 幂等通过；更大 → 更新；更小 → ErrTokenKIDLower。
func (s *Store) EnsureTokenKID(ctx context.Context, kid int64, now time.Time) (int64, error) {
	if kid <= 0 {
		return 0, fmt.Errorf("store: token kid must be positive")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var stored int64
	err = tx.QueryRow(ctx, `SELECT kid FROM token_kid_state WHERE id = true FOR UPDATE`).Scan(&stored)
	switch {
	case isNoRows(err):
		if _, err := tx.Exec(ctx, `INSERT INTO token_kid_state (id, kid, updated_at) VALUES (true, $1, $2)`, kid, now); err != nil {
			return 0, fmt.Errorf("store: insert token kid: %w", err)
		}
		stored = kid
	case err != nil:
		return 0, fmt.Errorf("store: read token kid: %w", err)
	case kid < stored:
		return stored, ErrTokenKIDLower
	case kid > stored:
		if _, err := tx.Exec(ctx, `UPDATE token_kid_state SET kid = $1, updated_at = $2 WHERE id = true`, kid, now); err != nil {
			return 0, fmt.Errorf("store: update token kid: %w", err)
		}
		stored = kid
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return stored, nil
}
