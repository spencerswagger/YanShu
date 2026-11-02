package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrTokenEpochLower 表示传入的 EPOCH 小于库里记录的当前值（拒绝调小）。
var ErrTokenEpochLower = errors.New("store: token epoch is lower than the recorded value")

// 说明：表名沿用 `token_kid_state`（历史命名），存的是**当前 token EPOCH**。
// 单一一行 id=true；递增 = 一键吊销（不删库、不重启，运行中的进程每次请求读这张表）。

// CurrentTokenEpoch 读当前 EPOCH。
func (s *Store) CurrentTokenEpoch(ctx context.Context) (int64, error) {
	var epoch int64
	err := s.pool.QueryRow(ctx, `SELECT kid FROM token_kid_state WHERE id = true`).Scan(&epoch)
	if err != nil {
		if isNoRows(err) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("store: read token epoch: %w", err)
	}
	return epoch, nil
}

// EnsureTokenEpoch 在启动时同步 EPOCH：库里没有就写入；比库里大就更新；比库里小就拒绝。
// 运行期吊销用运维侧的 `UPDATE token_kid_state SET kid = kid + 1`（无需重启）。
func (s *Store) EnsureTokenEpoch(ctx context.Context, epoch int64, now time.Time) (int64, error) {
	if epoch <= 0 {
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
		if _, err := tx.Exec(ctx, `INSERT INTO token_kid_state (id, kid, updated_at) VALUES (true, $1, $2)`, epoch, now); err != nil {
			return 0, fmt.Errorf("store: insert token epoch: %w", err)
		}
		stored = epoch
	case err != nil:
		return 0, fmt.Errorf("store: read token epoch: %w", err)
	case epoch < stored:
		return stored, ErrTokenEpochLower
	case epoch > stored:
		if _, err := tx.Exec(ctx, `UPDATE token_kid_state SET kid = $1, updated_at = $2 WHERE id = true`, epoch, now); err != nil {
			return 0, fmt.Errorf("store: update token epoch: %w", err)
		}
		stored = epoch
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return stored, nil
}
