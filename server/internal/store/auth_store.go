package store

import (
	"context"
	"fmt"
	"time"
)

// Challenge 是一次性签名挑战。nonce 只用一次。
type Challenge struct {
	ID        string
	Purpose   string
	Code      string
	PubKey    []byte
	Message   []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// InsertChallenge 落一个挑战。
func (s *Store) InsertChallenge(ctx context.Context, c Challenge) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO auth_challenges
		(id, purpose, code, pubkey, message, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ID, c.Purpose, c.Code, c.PubKey, c.Message, c.ExpiresAt, c.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: insert challenge: %w", err)
	}
	return nil
}

// GetChallenge 取挑战（含是否已用）。
func (s *Store) GetChallenge(ctx context.Context, id string) (Challenge, error) {
	var c Challenge
	err := s.pool.QueryRow(ctx, `SELECT id, purpose, code, pubkey, message, expires_at, used_at, created_at
		FROM auth_challenges WHERE id = $1`, id).
		Scan(&c.ID, &c.Purpose, &c.Code, &c.PubKey, &c.Message, &c.ExpiresAt, &c.UsedAt, &c.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Challenge{}, ErrNotFound
		}
		return Challenge{}, fmt.Errorf("store: get challenge: %w", err)
	}
	return c, nil
}

// UseChallenge 原子地把挑战标记为已用。返回 false 表示已被用过（防重放）。
func (s *Store) UseChallenge(ctx context.Context, id string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE auth_challenges SET used_at = $2 WHERE id = $1 AND used_at IS NULL`, id, now)
	if err != nil {
		return false, fmt.Errorf("store: use challenge: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteExpiredChallenges 清理过期挑战。
func (s *Store) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM auth_challenges WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Session 是已认证的会话；库里只有令牌的 SHA-256。
type Session struct {
	TokenHash []byte
	Code      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// InsertSession 落会话。
func (s *Store) InsertSession(ctx context.Context, tokenHash []byte, code string, now, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (token_hash, code, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`, tokenHash, code, now, expiresAt)
	if err != nil {
		return fmt.Errorf("store: insert session: %w", err)
	}
	return nil
}

// GetSession 取会话；码已过期或会话过期都视为无效。
func (s *Store) GetSession(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `SELECT s.token_hash, s.code, s.created_at, s.expires_at
		FROM sessions s JOIN codes c ON c.code = s.code
		WHERE s.token_hash = $1 AND s.expires_at > $2 AND c.expires_at > $2`,
		tokenHash, now).
		Scan(&sess.TokenHash, &sess.Code, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		if isNoRows(err) {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("store: get session: %w", err)
	}
	return sess, nil
}

// DeleteExpiredSessions 清理过期会话。
func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
