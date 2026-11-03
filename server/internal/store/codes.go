package store

import (
	"context"
	"fmt"
	"time"
)

// Code 是一条用户码记录（API.md §2.1 白名单字段）。
type Code struct {
	Code         string
	PublicKey    []byte
	Nickname     string
	RegisteredAt time.Time
	UpdatedAt    time.Time
}

const codeColumns = `code, public_key, nickname, registered_at, updated_at`

func scanCode(row interface{ Scan(...any) error }) (Code, error) {
	var c Code
	err := row.Scan(&c.Code, &c.PublicKey, &c.Nickname, &c.RegisteredAt, &c.UpdatedAt)
	return c, err
}

// InsertCode 注册新码：码被占 → ErrCodeTaken；公钥已在别的码下 → ErrPubkeyTaken。
func (s *Store) InsertCode(ctx context.Context, code string, publicKey []byte, nickname string, now time.Time) (Code, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO codes (`+codeColumns+`)
		VALUES ($1, $2, $3, $4, $4)
		RETURNING `+codeColumns, code, publicKey, nickname, now)
	c, err := scanCode(row)
	if err != nil {
		if isUniqueViolation(err) {
			// 区分是码冲突还是公钥冲突：契约给了两个不同的 409。
			if existing, gerr := s.GetCode(ctx, code); gerr == nil && !equalBytes(existing.PublicKey, publicKey) {
				return Code{}, ErrCodeTaken
			}
			if _, gerr := s.GetCodeByPublicKey(ctx, publicKey); gerr == nil {
				return Code{}, ErrPubkeyTaken
			}
			return Code{}, ErrCodeTaken
		}
		return Code{}, fmt.Errorf("store: insert code: %w", err)
	}
	return c, nil
}

// GetCode 按码取记录。
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

// GetCodeByPublicKey 按公钥取记录（PUBKEY_TAKEN 判定用）。
func (s *Store) GetCodeByPublicKey(ctx context.Context, publicKey []byte) (Code, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+codeColumns+` FROM codes WHERE public_key = $1`, publicKey)
	c, err := scanCode(row)
	if err != nil {
		if isNoRows(err) {
			return Code{}, ErrNotFound
		}
		return Code{}, fmt.Errorf("store: get code by public key: %w", err)
	}
	return c, nil
}

// UpdateNickname 改昵称（需先过 NICKNAME_UPDATE 签名挑战）。
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
