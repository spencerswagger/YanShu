package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrTokenEpochLower 表示传入的 KID 小于库里记录的当前值（拒绝调小）。
var ErrTokenEpochLower = errors.New("store: token epoch is lower than the recorded value")

// CurrentTokenEpoch 读当前 KID。
func (s *Store) CurrentTokenEpoch(ctx context.Context) (int64, error) {
	var kid int64
	err := s.pool.QueryRow(ctx, `SELECT kid FROM token_kid_state WHERE id = true`).Scan(&kid)
	if err != nil {
		if isNoRows(err) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("store: read token epoch: %w", err)
	}
	return kid, nil
}

// EnsureTokenEpoch 启动期同步 KID：库里没有就写入；**等于**允许（重启幂等）；
// 大于则更新；**小于 → ErrTokenEpochLower**（拒绝启动，防止把 KID 调小让旧凭据复活）。
func (s *Store) EnsureTokenEpoch(ctx context.Context, kid int64, now time.Time) (int64, error) {
	if kid <= 0 {
		return 0, fmt.Errorf("store: token epoch must be positive")
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
			return 0, fmt.Errorf("store: insert token epoch: %w", err)
		}
		stored = kid
	case err != nil:
		return 0, fmt.Errorf("store: read token epoch: %w", err)
	case kid < stored:
		return stored, ErrTokenEpochLower
	case kid > stored:
		if _, err := tx.Exec(ctx, `UPDATE token_kid_state SET kid = $1, updated_at = $2 WHERE id = true`, kid, now); err != nil {
			return 0, fmt.Errorf("store: update token epoch: %w", err)
		}
		stored = kid
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return stored, nil
}
