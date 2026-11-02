package store

import (
	"context"
	"fmt"
	"time"
)

// Code 是一条用户码记录。服务端只存公钥与昵称，不存任何私钥相关物。
type Code struct {
	Code       string
	PubKey     []byte
	Nickname   string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

const codeColumns = `code, pubkey, nickname, created_at, updated_at, last_seen_at, expires_at`

func scanCode(row interface{ Scan(...any) error }) (Code, error) {
	var c Code
	err := row.Scan(&c.Code, &c.PubKey, &c.Nickname, &c.CreatedAt, &c.UpdatedAt, &c.LastSeenAt, &c.ExpiresAt)
	return c, err
}

// InsertCode 注册新码。码已被占用 → ErrCodeTaken（不自动改码）。
func (s *Store) InsertCode(ctx context.Context, code string, pubKey []byte, nickname string, now, expiresAt time.Time) (Code, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO codes (`+codeColumns+`)
		VALUES ($1, $2, $3, $4, $4, $4, $5)
		RETURNING `+codeColumns,
		code, pubKey, nickname, now, expiresAt)
	c, err := scanCode(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Code{}, ErrCodeTaken
		}
		return Code{}, fmt.Errorf("store: insert code: %w", err)
	}
	return c, nil
}

// GetCode 按码取记录（过期与否由调用方判断，保证「不存在」与「已过期」可区分）。
func (s *Store) GetCode(ctx context.Context, code string) (Code, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+codeColumns+` FROM codes WHERE code = $1`, code)
	c, err := scanCode(row)
	if err != nil {
		if isNoRows(err) {
			return Code{}, ErrNotFound
		}
		return Code{}, fmt.Errorf("store: get code: %w", err)
	}
	return c, nil
}

// TouchCode 刷新 last_seen_at，并按需续期（expires_at 只前推不后退）。
func (s *Store) TouchCode(ctx context.Context, code string, now, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE codes
		SET last_seen_at = $2,
		    expires_at = GREATEST(expires_at, $3),
		    updated_at = CASE WHEN expires_at < $3 THEN $2 ELSE updated_at END
		WHERE code = $1`, code, now, expiresAt)
	if err != nil {
		return fmt.Errorf("store: touch code: %w", err)
	}
	return nil
}

// UpdateNickname 改昵称（需先过签名挑战）。
func (s *Store) UpdateNickname(ctx context.Context, code, nickname string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE codes SET nickname = $2, updated_at = $3 WHERE code = $1`, code, nickname, now)
	if err != nil {
		return fmt.Errorf("store: update nickname: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredCodes 删除过期超过保留期的码（清理由 sweeper 触发）。
func (s *Store) DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM codes WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete expired codes: %w", err)
	}
	return tag.RowsAffected(), nil
}
