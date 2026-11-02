package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrChunkOutOfRange 表示块序号超出包的块数。
var ErrChunkOutOfRange = errors.New("store: chunk index out of range")

// Package 是一个传输包的元数据（**没有文件名、没有 MIME**，这是设计要求）。
type Package struct {
	ID             string
	SenderCode     string
	RecipientCode  string
	State          string
	ChunkCount     int
	ChunkSize      int
	PlaintextSize  int64
	PreludeLen     int
	PreludeDigest  []byte
	ReceivedCount  int
	MaxDownloads   int
	DownloadsUsed  int
	DeleteOnAck    bool
	CreatedAt      time.Time
	ExpiresAt      time.Time
	CommittedAt    *time.Time
	TerminalAt     *time.Time
	TerminalReason *string
}

const packageColumns = `id, sender_code, recipient_code, state, chunk_count, chunk_size, plaintext_size,
	prelude_len, prelude_digest, received_count, max_downloads, downloads_used, delete_on_ack,
	created_at, expires_at, committed_at, terminal_at, terminal_reason`

func scanPackage(row interface{ Scan(...any) error }) (Package, error) {
	var p Package
	err := row.Scan(&p.ID, &p.SenderCode, &p.RecipientCode, &p.State, &p.ChunkCount, &p.ChunkSize,
		&p.PlaintextSize, &p.PreludeLen, &p.PreludeDigest, &p.ReceivedCount, &p.MaxDownloads,
		&p.DownloadsUsed, &p.DeleteOnAck, &p.CreatedAt, &p.ExpiresAt, &p.CommittedAt,
		&p.TerminalAt, &p.TerminalReason)
	return p, err
}

// CreatePackage 建包，初始状态 uploading。
func (s *Store) CreatePackage(ctx context.Context, p Package) (Package, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO packages (`+packageColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0,$10,0,$11,$12,$13,NULL,NULL,NULL)
		RETURNING `+packageColumns,
		p.ID, p.SenderCode, p.RecipientCode, p.State, p.ChunkCount, p.ChunkSize, p.PlaintextSize,
		p.PreludeLen, nil, p.MaxDownloads, p.DeleteOnAck, p.CreatedAt, p.ExpiresAt)
	out, err := scanPackage(row)
	if err != nil {
		return Package{}, fmt.Errorf("store: create package: %w", err)
	}
	return out, nil
}

// GetPackage 取包。
func (s *Store) GetPackage(ctx context.Context, id string) (Package, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+packageColumns+` FROM packages WHERE id = $1`, id)
	p, err := scanPackage(row)
	if err != nil {
		if isNoRows(err) {
			return Package{}, ErrNotFound
		}
		return Package{}, fmt.Errorf("store: get package: %w", err)
	}
	return p, nil
}

// SetPreludeDigest 记录 prelude 的 SM3 摘要。
// 已存在同摘要 → 幂等返回 duplicate=true；已存在不同摘要 → ErrPreludeConflict。
func (s *Store) SetPreludeDigest(ctx context.Context, id string, digest []byte) (duplicate bool, err error) {
	tag, err := s.pool.Exec(ctx, `UPDATE packages SET prelude_digest = $2
		WHERE id = $1 AND prelude_digest IS NULL AND state = 'uploading'`, id, digest)
	if err != nil {
		return false, fmt.Errorf("store: set prelude digest: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return false, nil
	}
	// 没有更新到：要么包不在/已锁定，要么已有摘要。
	var existing []byte
	var state string
	err = s.pool.QueryRow(ctx, `SELECT prelude_digest, state FROM packages WHERE id = $1`, id).
		Scan(&existing, &state)
	if err != nil {
		if isNoRows(err) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("store: read prelude digest: %w", err)
	}
	if state != "uploading" {
		return false, ErrPackageLocked
	}
	if bytes.Equal(existing, digest) {
		return true, nil
	}
	return false, ErrPreludeConflict
}

// AddChunkResult 是一次块写入的结果。
type AddChunkResult struct {
	Inserted      bool
	Duplicate     bool
	ReceivedCount int
}

// AddChunk 幂等写入一块：同序号同内容 → 不产生副本；同序号不同内容 → ErrChunkConflict。
func (s *Store) AddChunk(ctx context.Context, pkgID string, index, ctLen int, digest []byte, now time.Time) (AddChunkResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AddChunkResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var state string
	var chunkCount int
	if err := tx.QueryRow(ctx, `SELECT state, chunk_count FROM packages WHERE id = $1 FOR UPDATE`, pkgID).
		Scan(&state, &chunkCount); err != nil {
		if isNoRows(err) {
			return AddChunkResult{}, ErrNotFound
		}
		return AddChunkResult{}, err
	}
	if index < 0 || index >= chunkCount {
		return AddChunkResult{}, ErrChunkOutOfRange
	}
	if state != "uploading" {
		return AddChunkResult{}, ErrPackageLocked
	}

	tag, err := tx.Exec(ctx, `INSERT INTO package_chunks (package_id, chunk_index, ct_len, ct_digest, received_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (package_id, chunk_index) DO NOTHING`,
		pkgID, index, ctLen, digest, now)
	if err != nil {
		return AddChunkResult{}, fmt.Errorf("store: insert chunk: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var existingLen int
		var existingDigest []byte
		if err := tx.QueryRow(ctx, `SELECT ct_len, ct_digest FROM package_chunks
			WHERE package_id = $1 AND chunk_index = $2`, pkgID, index).
			Scan(&existingLen, &existingDigest); err != nil {
			return AddChunkResult{}, fmt.Errorf("store: read existing chunk: %w", err)
		}
		if existingLen != ctLen || !bytes.Equal(existingDigest, digest) {
			return AddChunkResult{}, ErrChunkConflict
		}
		var received int
		if err := tx.QueryRow(ctx, `SELECT received_count FROM packages WHERE id = $1`, pkgID).
			Scan(&received); err != nil {
			return AddChunkResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AddChunkResult{}, err
		}
		return AddChunkResult{Duplicate: true, ReceivedCount: received}, nil
	}

	var received int
	if err := tx.QueryRow(ctx, `UPDATE packages SET received_count = received_count + 1
		WHERE id = $1 RETURNING received_count`, pkgID).Scan(&received); err != nil {
		return AddChunkResult{}, fmt.Errorf("store: bump received_count: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AddChunkResult{}, err
	}
	return AddChunkResult{Inserted: true, ReceivedCount: received}, nil
}

// CommitPackage 完成标记：包锁定，之后块不可再改。
func (s *Store) CommitPackage(ctx context.Context, id string, now time.Time) (Package, error) {
	row := s.pool.QueryRow(ctx, `UPDATE packages
		SET state = 'ready', committed_at = $2
		WHERE id = $1 AND state = 'uploading'
		RETURNING `+packageColumns, id, now)
	p, err := scanPackage(row)
	if err != nil {
		if isNoRows(err) {
			return Package{}, ErrConflict
		}
		return Package{}, fmt.Errorf("store: commit package: %w", err)
	}
	return p, nil
}

// AckResult 是接收确认的结果。
type AckResult struct {
	Package Package
	// ShouldPurge 为 true 表示调用方应在事务外删除磁盘密文。
	ShouldPurge bool
}

// AckPackage 接收方确认：扣减下载次数；次数用尽即进入终结态。
func (s *Store) AckPackage(ctx context.Context, id string, countsAsDownload bool, now time.Time) (AckResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AckResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `SELECT `+packageColumns+` FROM packages WHERE id = $1 FOR UPDATE`, id)
	p, err := scanPackage(row)
	if err != nil {
		if isNoRows(err) {
			return AckResult{}, ErrNotFound
		}
		return AckResult{}, err
	}
	if p.State != "ready" {
		return AckResult{}, ErrConflict
	}

	shouldPurge := p.DeleteOnAck
	if countsAsDownload {
		p.DownloadsUsed++
		if p.DownloadsUsed >= p.MaxDownloads {
			p.State = "exhausted"
			p.TerminalAt = &now
			reason := "exhausted"
			p.TerminalReason = &reason
			shouldPurge = true
		}
		row = tx.QueryRow(ctx, `UPDATE packages
			SET downloads_used = $2, state = $3, terminal_at = $4, terminal_reason = $5
			WHERE id = $1 RETURNING `+packageColumns,
			id, p.DownloadsUsed, p.State, p.TerminalAt, p.TerminalReason)
		if p, err = scanPackage(row); err != nil {
			return AckResult{}, fmt.Errorf("store: ack package: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return AckResult{}, err
	}
	return AckResult{Package: p, ShouldPurge: shouldPurge}, nil
}

// RevokePackage 发送方撤回。
func (s *Store) RevokePackage(ctx context.Context, id, senderCode string, now time.Time) (Package, error) {
	reason := "revoked"
	row := s.pool.QueryRow(ctx, `UPDATE packages
		SET state = 'revoked', terminal_at = $3, terminal_reason = $4
		WHERE id = $1 AND sender_code = $2 AND state IN ('uploading', 'ready')
		RETURNING `+packageColumns, id, senderCode, now, reason)
	p, err := scanPackage(row)
	if err != nil {
		if isNoRows(err) {
			return Package{}, ErrConflict
		}
		return Package{}, fmt.Errorf("store: revoke package: %w", err)
	}
	return p, nil
}

// ListInbox 列出某码待收的包（只列可下载/上传中的，终结态不出现）。
func (s *Store) ListInbox(ctx context.Context, code string, now time.Time, limit int) ([]Package, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+packageColumns+` FROM packages
		WHERE recipient_code = $1 AND state IN ('uploading', 'ready') AND expires_at > $2
		ORDER BY created_at DESC LIMIT $3`, code, now, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list inbox: %w", err)
	}
	defer rows.Close()
	var out []Package
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ChunkMeta 是块的元信息（不含内容）。
type ChunkMeta struct {
	Index      int
	CTLen      int
	CTDigest   []byte
	ReceivedAt time.Time
}

// ListChunks 返回已收到的块索引与长度（续传用）。
func (s *Store) ListChunks(ctx context.Context, pkgID string) ([]ChunkMeta, error) {
	rows, err := s.pool.Query(ctx, `SELECT chunk_index, ct_len, ct_digest, received_at
		FROM package_chunks WHERE package_id = $1 ORDER BY chunk_index`, pkgID)
	if err != nil {
		return nil, fmt.Errorf("store: list chunks: %w", err)
	}
	defer rows.Close()
	var out []ChunkMeta
	for rows.Next() {
		var c ChunkMeta
		if err := rows.Scan(&c.Index, &c.CTLen, &c.CTDigest, &c.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetChunk 取单块元信息。
func (s *Store) GetChunk(ctx context.Context, pkgID string, index int) (ChunkMeta, error) {
	var c ChunkMeta
	err := s.pool.QueryRow(ctx, `SELECT chunk_index, ct_len, ct_digest, received_at
		FROM package_chunks WHERE package_id = $1 AND chunk_index = $2`, pkgID, index).
		Scan(&c.Index, &c.CTLen, &c.CTDigest, &c.ReceivedAt)
	if err != nil {
		if isNoRows(err) {
			return ChunkMeta{}, ErrNotFound
		}
		return ChunkMeta{}, fmt.Errorf("store: get chunk: %w", err)
	}
	return c, nil
}

// TerminalizeExpired 把 TTL 到期的包置为终结态（expired）。
func (s *Store) TerminalizeExpired(ctx context.Context, now time.Time) (int64, error) {
	reason := "expired"
	tag, err := s.pool.Exec(ctx, `UPDATE packages
		SET state = 'expired', terminal_at = $1, terminal_reason = $2
		WHERE state IN ('uploading', 'ready') AND expires_at <= $1`, now, reason)
	if err != nil {
		return 0, fmt.Errorf("store: terminalize expired: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListPurgeable 列出应从磁盘物理删除的包：已终结，或已过期。
func (s *Store) ListPurgeable(ctx context.Context, now time.Time, limit int) ([]Package, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+packageColumns+` FROM packages
		WHERE state IN ('expired', 'revoked', 'exhausted')
		   OR (expires_at <= $1 AND state IN ('uploading', 'ready'))
		ORDER BY created_at ASC LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list purgeable: %w", err)
	}
	defer rows.Close()
	var out []Package
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PurgePackage 物理删除：包行 + 块行（级联），并留一条无内容墓碑。
func (s *Store) PurgePackage(ctx context.Context, id string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `SELECT `+packageColumns+` FROM packages WHERE id = $1 FOR UPDATE`, id)
	p, err := scanPackage(row)
	if err != nil {
		if isNoRows(err) {
			return ErrNotFound
		}
		return err
	}
	terminalAt := now
	if p.TerminalAt != nil {
		terminalAt = *p.TerminalAt
	}
	state := p.State
	if state == "uploading" || state == "ready" {
		state = "expired"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO package_tombstones
		(id, state, sender_code, recipient_code, created_at, terminal_at, purged_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET purged_at = EXCLUDED.purged_at, state = EXCLUDED.state`,
		p.ID, state, p.SenderCode, p.RecipientCode, p.CreatedAt, terminalAt, now); err != nil {
		return fmt.Errorf("store: insert tombstone: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM packages WHERE id = $1`, id); err != nil {
		return fmt.Errorf("store: delete package: %w", err)
	}
	return tx.Commit(ctx)
}

// Tombstone 是终结包的墓碑（无内容，只用于区分终结原因）。
type Tombstone struct {
	ID            string
	State         string
	SenderCode    string
	RecipientCode string
	CreatedAt     time.Time
	TerminalAt    time.Time
	PurgedAt      *time.Time
}

// GetTombstone 取墓碑。
func (s *Store) GetTombstone(ctx context.Context, id string) (Tombstone, error) {
	var t Tombstone
	err := s.pool.QueryRow(ctx, `SELECT id, state, sender_code, recipient_code, created_at, terminal_at, purged_at
		FROM package_tombstones WHERE id = $1`, id).
		Scan(&t.ID, &t.State, &t.SenderCode, &t.RecipientCode, &t.CreatedAt, &t.TerminalAt, &t.PurgedAt)
	if err != nil {
		if isNoRows(err) {
			return Tombstone{}, ErrNotFound
		}
		return Tombstone{}, fmt.Errorf("store: get tombstone: %w", err)
	}
	return t, nil
}

// SenderUsage 返回某发送方当前未清理包的密文字节总量（配额用）。
func (s *Store) SenderUsage(ctx context.Context, senderCode string) (int64, error) {
	var prelude, chunks int64
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(prelude_len), 0) FROM packages
		WHERE sender_code = $1 AND state <> 'purged'`, senderCode).Scan(&prelude); err != nil {
		return 0, fmt.Errorf("store: sum prelude bytes: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(c.ct_len), 0)
		FROM package_chunks c JOIN packages p ON p.id = c.package_id
		WHERE p.sender_code = $1 AND p.state <> 'purged'`, senderCode).Scan(&chunks); err != nil {
		return 0, fmt.Errorf("store: sum chunk bytes: %w", err)
	}
	return prelude + chunks, nil
}

// DeleteOldTombstones 删除老墓碑（只保留终结原因一段时间供排障）。
func (s *Store) DeleteOldTombstones(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM package_tombstones WHERE terminal_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete tombstones: %w", err)
	}
	return tag.RowsAffected(), nil
}
