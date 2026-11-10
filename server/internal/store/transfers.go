package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

// 传输语义错误。
var (
	ErrCodeTaken        = errors.New("store: code taken")
	ErrPubkeyTaken      = errors.New("store: public key taken")
	ErrTransferNotReady = errors.New("store: transfer not ready")
	ErrPreludeMissing   = errors.New("store: prelude missing")
	ErrChunksMissing    = errors.New("store: chunks missing")
	ErrChunkOutOfRange  = errors.New("store: chunk index out of range")
	ErrChunkConflict    = errors.New("store: chunk conflict")
	ErrPreludeConflict  = errors.New("store: prelude conflict")
	ErrLeaseExpired     = errors.New("store: download lease expired")
	ErrAlreadyAcked     = errors.New("store: download already acked")
	ErrNotParty         = errors.New("store: credential is not a party of the transfer")
	ErrIdempotencyMiss  = errors.New("store: idempotency record not found")
)

// Transfer 是一条传输的元数据（**没有文件名、没有 MIME**）。
type Transfer struct {
	ID                   string
	SenderCode           string
	RecipientCode        string
	PlaintextSize        int64
	ChunkSize            int
	ChunkCount           int
	PreludeLen           int
	PreludeSM3           []byte
	PreludeReceived      bool
	ReceivedChunks       int
	TotalCiphertextBytes int64
	DownloadCount        int
	MaxDownloads         int
	State                string
	TerminalReason       *string
	TerminalAt           *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	ExpiresAt            time.Time
	UploadTokenSM3       []byte
	UploadTokenKID       string
	UploaderIP           string
}

const transferColumns = `transfer_id, sender_code, recipient_code, plaintext_size, chunk_size, chunk_count,
	prelude_len, prelude_sm3, prelude_received, received_chunks, total_ciphertext_bytes,
	download_count, max_downloads, state, terminal_reason, terminal_at,
	created_at, updated_at, expires_at, upload_token_sm3, upload_token_kid, uploader_ip`

func scanTransfer(row interface{ Scan(...any) error }) (Transfer, error) {
	var t Transfer
	var uploaderIP *string
	err := row.Scan(&t.ID, &t.SenderCode, &t.RecipientCode, &t.PlaintextSize, &t.ChunkSize,
		&t.ChunkCount, &t.PreludeLen, &t.PreludeSM3, &t.PreludeReceived, &t.ReceivedChunks,
		&t.TotalCiphertextBytes, &t.DownloadCount, &t.MaxDownloads, &t.State,
		&t.TerminalReason, &t.TerminalAt, &t.CreatedAt, &t.UpdatedAt, &t.ExpiresAt,
		&t.UploadTokenSM3, &t.UploadTokenKID, &uploaderIP)
	if err == nil && uploaderIP != nil {
		t.UploaderIP = *uploaderIP
	}
	return t, err
}

// CreateTransfer 建传输，初始状态 UPLOADING。
//
// 建包行与 `created` 计数**同一个事务**：分成两句写时，统计写失败会让接口 500
// 而传输行已经落库（客户端重试就多一条），两边口径也会永久漂移。
func (s *Store) CreateTransfer(ctx context.Context, t Transfer) (Transfer, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Transfer{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `INSERT INTO transfers (`+transferColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false,0,$9,0,$10,'UPLOADING',NULL,NULL,$11,$11,$12,$13,$14,$15)
		RETURNING `+transferColumns,
		t.ID, t.SenderCode, t.RecipientCode, t.PlaintextSize, t.ChunkSize, t.ChunkCount,
		t.PreludeLen, t.PreludeSM3, t.TotalCiphertextBytes, t.MaxDownloads,
		t.CreatedAt, t.ExpiresAt, t.UploadTokenSM3, t.UploadTokenKID, nullableString(t.UploaderIP))
	out, err := scanTransfer(row)
	if err != nil {
		return Transfer{}, fmt.Errorf("store: create transfer: %w", err)
	}
	if err := addCreatedStat(ctx, tx, t.CreatedAt); err != nil {
		return Transfer{}, fmt.Errorf("store: stats created: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Transfer{}, fmt.Errorf("store: commit create transfer: %w", err)
	}
	return out, nil
}

// GetTransfer 取传输。
func (s *Store) GetTransfer(ctx context.Context, id string) (Transfer, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+transferColumns+` FROM transfers WHERE transfer_id = $1`, id)
	t, err := scanTransfer(row)
	if err != nil {
		if isNoRows(err) {
			return Transfer{}, ErrNotFound
		}
		return Transfer{}, fmt.Errorf("store: get transfer: %w", err)
	}
	return t, nil
}

// MarkPreludeReceived 标记 prelude 已收。返回 false 表示此前已标记（→ 204）。
func (s *Store) MarkPreludeReceived(ctx context.Context, id string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE transfers SET prelude_received = true, updated_at = $2
		WHERE transfer_id = $1 AND prelude_received = false AND state = 'UPLOADING'`, id, now)
	if err != nil {
		return false, fmt.Errorf("store: mark prelude: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	t, err := s.GetTransfer(ctx, id)
	if err != nil {
		return false, err
	}
	if t.State != "UPLOADING" {
		return false, ErrTransferNotReady
	}
	return false, nil
}

// AddChunkResult 是一次块写入的结果。
type AddChunkResult struct {
	Inserted      bool
	Duplicate     bool
	ReceivedCount int
	ChunkCount    int
}

// AddChunk 幂等写入一块：同 index 同长度同 SM3 → 幂等；不同 → ErrChunkConflict。
func (s *Store) AddChunk(ctx context.Context, transferID string, index, length int, sm3 []byte, now time.Time) (AddChunkResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AddChunkResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var state string
	var chunkCount int
	if err := tx.QueryRow(ctx, `SELECT state, chunk_count FROM transfers WHERE transfer_id = $1 FOR UPDATE`, transferID).
		Scan(&state, &chunkCount); err != nil {
		if isNoRows(err) {
			return AddChunkResult{}, ErrNotFound
		}
		return AddChunkResult{}, err
	}
	if index < 0 || index >= chunkCount {
		return AddChunkResult{}, ErrChunkOutOfRange
	}
	if state != "UPLOADING" {
		return AddChunkResult{}, ErrTransferNotReady
	}

	tag, err := tx.Exec(ctx, `INSERT INTO transfer_chunks (transfer_id, chunk_index, length, ciphertext_sm3, stored_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (transfer_id, chunk_index) DO NOTHING`,
		transferID, index, length, sm3, now)
	if err != nil {
		return AddChunkResult{}, fmt.Errorf("store: insert chunk: %w", err)
	}

	if tag.RowsAffected() == 0 {
		var existingLen int
		var existingSM3 []byte
		if err := tx.QueryRow(ctx, `SELECT length, ciphertext_sm3 FROM transfer_chunks
			WHERE transfer_id = $1 AND chunk_index = $2`, transferID, index).
			Scan(&existingLen, &existingSM3); err != nil {
			return AddChunkResult{}, fmt.Errorf("store: read existing chunk: %w", err)
		}
		if existingLen != length || !bytes.Equal(existingSM3, sm3) {
			return AddChunkResult{}, ErrChunkConflict
		}
		var received int
		if err := tx.QueryRow(ctx, `SELECT received_chunks FROM transfers WHERE transfer_id = $1`, transferID).
			Scan(&received); err != nil {
			return AddChunkResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return AddChunkResult{}, err
		}
		return AddChunkResult{Duplicate: true, ReceivedCount: received, ChunkCount: chunkCount}, nil
	}

	var received int
	var total int64
	if err := tx.QueryRow(ctx, `UPDATE transfers
		SET received_chunks = received_chunks + 1,
		    total_ciphertext_bytes = total_ciphertext_bytes + $2,
		    updated_at = $3
		WHERE transfer_id = $1
		RETURNING received_chunks, total_ciphertext_bytes`,
		transferID, length, now).Scan(&received, &total); err != nil {
		return AddChunkResult{}, fmt.Errorf("store: bump received_chunks: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AddChunkResult{}, err
	}
	return AddChunkResult{Inserted: true, ReceivedCount: received, ChunkCount: chunkCount}, nil
}

// ChunkMeta 是块的元信息（不含内容）。
type ChunkMeta struct {
	Index    int
	Length   int
	SM3      []byte
	StoredAt time.Time
}

// GetChunk 取单块元信息。
func (s *Store) GetChunk(ctx context.Context, transferID string, index int) (ChunkMeta, error) {
	var c ChunkMeta
	err := s.pool.QueryRow(ctx, `SELECT chunk_index, length, ciphertext_sm3, stored_at
		FROM transfer_chunks WHERE transfer_id = $1 AND chunk_index = $2`, transferID, index).
		Scan(&c.Index, &c.Length, &c.SM3, &c.StoredAt)
	if err != nil {
		if isNoRows(err) {
			return ChunkMeta{}, ErrNotFound
		}
		return ChunkMeta{}, fmt.Errorf("store: get chunk: %w", err)
	}
	return c, nil
}

// ListChunks 返回已收到的块（按 index 升序）。
func (s *Store) ListChunks(ctx context.Context, transferID string) ([]ChunkMeta, error) {
	rows, err := s.pool.Query(ctx, `SELECT chunk_index, length, ciphertext_sm3, stored_at
		FROM transfer_chunks WHERE transfer_id = $1 ORDER BY chunk_index`, transferID)
	if err != nil {
		return nil, fmt.Errorf("store: list chunks: %w", err)
	}
	defer rows.Close()
	var out []ChunkMeta
	for rows.Next() {
		var c ChunkMeta
		if err := rows.Scan(&c.Index, &c.Length, &c.SM3, &c.StoredAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CompleteTransfer 把 UPLOADING 置为 READY；缺 prelude 或缺块返回对应语义错误。
func (s *Store) CompleteTransfer(ctx context.Context, id string, now time.Time) (Transfer, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Transfer{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var preludeReceived bool
	var received, chunkCount int
	var state string
	if err := tx.QueryRow(ctx, `SELECT state, prelude_received, received_chunks, chunk_count
		FROM transfers WHERE transfer_id = $1 FOR UPDATE`, id).
		Scan(&state, &preludeReceived, &received, &chunkCount); err != nil {
		if isNoRows(err) {
			return Transfer{}, ErrNotFound
		}
		return Transfer{}, err
	}
	if state == "READY" || state == "LEASED" {
		return Transfer{}, ErrAlreadyReady
	}
	if state != "UPLOADING" {
		return Transfer{}, ErrConflict
	}
	if !preludeReceived {
		return Transfer{}, ErrPreludeMissing
	}
	if received != chunkCount {
		return Transfer{}, ErrChunksMissing
	}
	row := tx.QueryRow(ctx, `UPDATE transfers SET state = 'READY', updated_at = $2
		WHERE transfer_id = $1 RETURNING `+transferColumns, id, now)
	t, err := scanTransfer(row)
	if err != nil {
		return Transfer{}, fmt.Errorf("store: complete transfer: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Transfer{}, err
	}
	return t, nil
}

// ErrAlreadyReady 表示 complete 重复调用（幂等 200）。
var ErrAlreadyReady = errors.New("store: transfer already ready")

// StartLease 开启或沿用下载租约（API.md §7.3）。
//
//   - READY → LEASED，创建新的 download_id；
//   - LEASED 且租约仍有效 → 沿用同一 download_id 并刷新到期时间；
//   - LEASED 但租约已过期 → 回收为 READY，再创建新租约。
func (s *Store) StartLease(ctx context.Context, id, newDownloadID string, now time.Time, ttl time.Duration) (Transfer, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Transfer{}, "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `SELECT `+transferColumns+` FROM transfers WHERE transfer_id = $1 FOR UPDATE`, id)
	t, err := scanTransfer(row)
	if err != nil {
		if isNoRows(err) {
			return Transfer{}, "", ErrNotFound
		}
		return Transfer{}, "", err
	}
	if t.State == "UPLOADING" {
		return Transfer{}, "", ErrTransferNotReady
	}
	if t.State == "READY" {
		if _, err := tx.Exec(ctx, `INSERT INTO transfer_downloads (download_id, transfer_id, created_at, lease_expires_at)
			VALUES ($1, $2, $3, $4)`, newDownloadID, id, now, now.Add(ttl)); err != nil {
			return Transfer{}, "", fmt.Errorf("store: insert download: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE transfers SET state = 'LEASED', updated_at = $2 WHERE transfer_id = $1`, id, now); err != nil {
			return Transfer{}, "", fmt.Errorf("store: set leased: %w", err)
		}
		t.State = "LEASED"
		t.UpdatedAt = now
		if err := tx.Commit(ctx); err != nil {
			return Transfer{}, "", err
		}
		return t, newDownloadID, nil
	}
	if t.State == "LEASED" {
		var downloadID string
		var leaseExpires time.Time
		err := tx.QueryRow(ctx, `SELECT download_id, lease_expires_at FROM transfer_downloads
			WHERE transfer_id = $1 AND acked_at IS NULL ORDER BY created_at DESC LIMIT 1`, id).
			Scan(&downloadID, &leaseExpires)
		if err == nil && leaseExpires.After(now) {
			if _, err := tx.Exec(ctx, `UPDATE transfer_downloads SET lease_expires_at = $2 WHERE download_id = $1`,
				downloadID, now.Add(ttl)); err != nil {
				return Transfer{}, "", fmt.Errorf("store: refresh lease: %w", err)
			}
			if err := tx.Commit(ctx); err != nil {
				return Transfer{}, "", err
			}
			return t, downloadID, nil
		}
		// 租约过期：回到 READY，再开新租约。
		if _, err := tx.Exec(ctx, `UPDATE transfers SET state = 'READY', updated_at = $2
			WHERE transfer_id = $1 AND state = 'LEASED'`, id, now); err != nil {
			return Transfer{}, "", fmt.Errorf("store: reclaim lease: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO transfer_downloads (download_id, transfer_id, created_at, lease_expires_at)
			VALUES ($1, $2, $3, $4)`, newDownloadID, id, now, now.Add(ttl)); err != nil {
			return Transfer{}, "", fmt.Errorf("store: insert download: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE transfers SET state = 'LEASED', updated_at = $2 WHERE transfer_id = $1`, id, now); err != nil {
			return Transfer{}, "", fmt.Errorf("store: set leased: %w", err)
		}
		t.State = "LEASED"
		if err := tx.Commit(ctx); err != nil {
			return Transfer{}, "", err
		}
		return t, newDownloadID, nil
	}
	return Transfer{}, "", ErrTerminal
}

// ErrTerminal 表示传输已进入终结态。
var ErrTerminal = errors.New("store: transfer is terminal")

// ReclaimExpiredLease 惰性回收过期租约（GET /transfers/{id} 与 status 时调用）。
func (s *Store) ReclaimExpiredLease(ctx context.Context, id string, now time.Time) (Transfer, error) {
	t, err := s.GetTransfer(ctx, id)
	if err != nil {
		return Transfer{}, err
	}
	if t.State != "LEASED" {
		return t, nil
	}
	var expires time.Time
	err = s.pool.QueryRow(ctx, `SELECT lease_expires_at FROM transfer_downloads
		WHERE transfer_id = $1 AND acked_at IS NULL ORDER BY created_at DESC LIMIT 1`, id).Scan(&expires)
	if err == nil && expires.After(now) {
		return t, nil
	}
	if _, err := s.pool.Exec(ctx, `UPDATE transfers SET state = 'READY', updated_at = $2
		WHERE transfer_id = $1 AND state = 'LEASED'`, id, now); err != nil {
		return Transfer{}, fmt.Errorf("store: reclaim lease: %w", err)
	}
	return s.GetTransfer(ctx, id)
}

// Download 是一条下载租约。
type Download struct {
	ID             string
	TransferID     string
	CreatedAt      time.Time
	LeaseExpiresAt time.Time
	AckedAt        *time.Time
}

// GetDownload 取租约。
func (s *Store) GetDownload(ctx context.Context, downloadID string) (Download, error) {
	var d Download
	err := s.pool.QueryRow(ctx, `SELECT download_id, transfer_id, created_at, lease_expires_at, acked_at
		FROM transfer_downloads WHERE download_id = $1`, downloadID).
		Scan(&d.ID, &d.TransferID, &d.CreatedAt, &d.LeaseExpiresAt, &d.AckedAt)
	if err != nil {
		if isNoRows(err) {
			return Download{}, ErrNotFound
		}
		return Download{}, fmt.Errorf("store: get download: %w", err)
	}
	return d, nil
}

// AckResult 是取件确认的结果。
type AckResult struct {
	Transfer     Transfer
	Counted      bool // 本次调用是否 +1
	AlreadyAcked bool // 同一 download_id 重复 ack（幂等）
	Consumed     bool // 本次后达到 max_downloads
}

// AckDownload 以 download_id 为幂等键做取件确认（API.md §7.5）。
func (s *Store) AckDownload(ctx context.Context, downloadID string, now time.Time) (AckResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AckResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var d Download
	if err := tx.QueryRow(ctx, `SELECT download_id, transfer_id, created_at, lease_expires_at, acked_at
		FROM transfer_downloads WHERE download_id = $1 FOR UPDATE`, downloadID).
		Scan(&d.ID, &d.TransferID, &d.CreatedAt, &d.LeaseExpiresAt, &d.AckedAt); err != nil {
		if isNoRows(err) {
			return AckResult{}, ErrNotFound
		}
		return AckResult{}, fmt.Errorf("store: lock download: %w", err)
	}

	row := tx.QueryRow(ctx, `SELECT `+transferColumns+` FROM transfers WHERE transfer_id = $1 FOR UPDATE`, d.TransferID)
	t, err := scanTransfer(row)
	if err != nil {
		if isNoRows(err) {
			return AckResult{}, ErrNotFound
		}
		return AckResult{}, err
	}

	if d.AckedAt != nil {
		if err := tx.Commit(ctx); err != nil {
			return AckResult{}, err
		}
		return AckResult{Transfer: t, AlreadyAcked: true, Consumed: t.State == "CONSUMED"}, nil
	}
	if t.State != "LEASED" {
		return AckResult{}, ErrConflict
	}
	if !d.LeaseExpiresAt.After(now) {
		return AckResult{}, ErrLeaseExpired
	}

	if _, err := tx.Exec(ctx, `UPDATE transfer_downloads SET acked_at = $2 WHERE download_id = $1`, downloadID, now); err != nil {
		return AckResult{}, fmt.Errorf("store: mark acked: %w", err)
	}

	count := t.DownloadCount + 1
	state := "READY"
	var reason *string
	var terminalAt *time.Time
	consumed := count >= t.MaxDownloads
	if consumed {
		state = "CONSUMED"
		r := "CONSUMED"
		reason = &r
		terminalAt = &now
	}
	row = tx.QueryRow(ctx, `UPDATE transfers
		SET download_count = $2, state = $3, terminal_reason = $4, terminal_at = $5, updated_at = $6
		WHERE transfer_id = $1 RETURNING `+transferColumns,
		t.ID, count, state, reason, terminalAt, now)
	out, err := scanTransfer(row)
	if err != nil {
		return AckResult{}, fmt.Errorf("store: ack transfer: %w", err)
	}
	if consumed {
		if err := addConsumedStat(ctx, tx, now, out.PlaintextSize); err != nil {
			return AckResult{}, fmt.Errorf("store: stats consumed: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return AckResult{}, err
	}
	return AckResult{Transfer: out, Counted: true, Consumed: consumed}, nil
}

// RevokeTransfer 发送方撤回（API.md §6.7）。对 REVOKED 幂等返回 200。
func (s *Store) RevokeTransfer(ctx context.Context, id, senderCode string, now time.Time) (Transfer, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Transfer{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `SELECT `+transferColumns+` FROM transfers WHERE transfer_id = $1 FOR UPDATE`, id)
	t, err := scanTransfer(row)
	if err != nil {
		if isNoRows(err) {
			return Transfer{}, ErrNotFound
		}
		return Transfer{}, err
	}
	if t.SenderCode != senderCode {
		return Transfer{}, ErrNotParty
	}
	if t.State == "REVOKED" {
		if err := tx.Commit(ctx); err != nil {
			return Transfer{}, err
		}
		return t, nil
	}
	if t.State == "EXPIRED" || t.State == "CONSUMED" {
		return Transfer{}, ErrConflict
	}
	reason := "REVOKED"
	row = tx.QueryRow(ctx, `UPDATE transfers
		SET state = 'REVOKED', terminal_reason = $2, terminal_at = $3, updated_at = $3
		WHERE transfer_id = $1 RETURNING `+transferColumns, id, reason, now)
	out, err := scanTransfer(row)
	if err != nil {
		return Transfer{}, fmt.Errorf("store: revoke: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Transfer{}, err
	}
	return out, nil
}

// TerminalizeExpired 把 TTL 到期的非终结传输置为 EXPIRED。
func (s *Store) TerminalizeExpired(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `UPDATE transfers
		SET state = 'EXPIRED', terminal_reason = 'EXPIRED', terminal_at = $1, updated_at = $1
		WHERE state IN ('UPLOADING', 'READY', 'LEASED') AND expires_at <= $1
		RETURNING transfer_id`, now)
	if err != nil {
		return nil, fmt.Errorf("store: terminalize expired: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListTerminal 列出已终结的传输（清理密文用）。
//
// 注意：这个函数**会反复返回同一批最老的行**（终结行永久保留，集合不会因为删除而缩小）。
// 兜底删密文必须用 ListUnpurgedTerminal 的水位语义，别再用它做"每次取 200 行"的批处理。
func (s *Store) ListTerminal(ctx context.Context, limit int) ([]Transfer, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+transferColumns+` FROM transfers
		WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED')
		ORDER BY terminal_at ASC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list terminal: %w", err)
	}
	defer rows.Close()
	var out []Transfer
	for rows.Next() {
		t, err := scanTransfer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UnpurgedTerminal 是一条「已终结但密文还没确认删除」的行。
type UnpurgedTerminal struct {
	ID         string
	TerminalAt time.Time
}

// ListUnpurgedTerminal 按水位（`ciphertext_purged_at IS NULL`）列出待删密文的终结行。
//
// 这是 P0 修复的核心：每删成功一批就把 `ciphertext_purged_at` 写上，这些行就**离开**了
// 候选集合，下一批自然推进到更晚终结的行。用「ORDER BY terminal_at LIMIT n」的老写法，
// 永久保留后每个 tick 都会拿回同一批最老的行，后面的行永远轮不到。
func (s *Store) ListUnpurgedTerminal(ctx context.Context, limit int) ([]UnpurgedTerminal, error) {
	rows, err := s.pool.Query(ctx, `SELECT transfer_id, COALESCE(terminal_at, updated_at) FROM transfers
		WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED') AND ciphertext_purged_at IS NULL
		ORDER BY COALESCE(terminal_at, updated_at) ASC, transfer_id ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list unpurged terminal: %w", err)
	}
	defer rows.Close()
	var out []UnpurgedTerminal
	for rows.Next() {
		var row UnpurgedTerminal
		if err := rows.Scan(&row.ID, &row.TerminalAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// MarkCiphertextPurged 记录这些行的密文已删除（幂等；已是非空的不重写）。
func (s *Store) MarkCiphertextPurged(ctx context.Context, ids []string, now time.Time) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `UPDATE transfers SET ciphertext_purged_at = $2
		WHERE transfer_id = ANY($1) AND ciphertext_purged_at IS NULL`, ids, now)
	if err != nil {
		return 0, fmt.Errorf("store: mark ciphertext purged: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountUnpurgedTerminal 返回还剩多少条终结行的密文没确认删除（日志/告警用真实数字）。
func (s *Store) CountUnpurgedTerminal(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM transfers
		WHERE state IN ('CONSUMED', 'REVOKED', 'EXPIRED') AND ciphertext_purged_at IS NULL`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count unpurged terminal: %w", err)
	}
	return n, nil
}

// CountActiveByCode 统计某发送码当前未终结的传输数（§11.4：上限 20）。
func (s *Store) CountActiveByCode(ctx context.Context, code string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM transfers
		WHERE sender_code = $1 AND state IN ('UPLOADING', 'READY', 'LEASED')`, code).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count active transfers: %w", err)
	}
	return n, nil
}

// StorageUsageByIP 统计某 IP 未取走（非 CONSUMED/REVOKED/EXPIRED）的密文总量（§11.4）。
func (s *Store) StorageUsageByIP(ctx context.Context, ip string) (int64, error) {
	var total int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(total_ciphertext_bytes + prelude_len), 0)
		FROM transfers WHERE uploader_ip = $1 AND state IN ('UPLOADING', 'READY', 'LEASED')`, ip).
		Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("store: storage usage: %w", err)
	}
	return total, nil
}

// InboxQuery 是收件列表查询参数。
type InboxQuery struct {
	Code   string
	States []string
	Limit  int
	// Cursor 是 base64url("<created_at_unix_nano>|<transfer_id>")，空表示第一页。
	BeforeCreatedAt time.Time
	BeforeID        string
	HasCursor       bool
}

// InboxRow 是收件列表的一行（带发送方昵称）。
type InboxRow struct {
	Transfer
	SenderNickname string
}

// ListInbox 按接收码列出传输（keyset 分页）。
func (s *Store) ListInbox(ctx context.Context, q InboxQuery) ([]InboxRow, error) {
	args := []any{q.Code, q.States}
	clause := `t.recipient_code = $1 AND t.state = ANY($2)`
	if q.HasCursor {
		args = append(args, q.BeforeCreatedAt, q.BeforeID)
		clause += ` AND (t.created_at, t.transfer_id) < ($3, $4)`
	}
	args = append(args, q.Limit)
	query := `SELECT ` + prefixedTransfers("t") + `, COALESCE(c.nickname, '')
		FROM transfers t LEFT JOIN codes c ON c.code = t.sender_code
		WHERE ` + clause + `
		ORDER BY t.created_at DESC, t.transfer_id DESC
		LIMIT $` + itoa(len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list inbox: %w", err)
	}
	defer rows.Close()
	var out []InboxRow
	for rows.Next() {
		var r InboxRow
		var uploaderIP *string
		err := rows.Scan(&r.ID, &r.SenderCode, &r.RecipientCode, &r.PlaintextSize, &r.ChunkSize,
			&r.ChunkCount, &r.PreludeLen, &r.PreludeSM3, &r.PreludeReceived, &r.ReceivedChunks,
			&r.TotalCiphertextBytes, &r.DownloadCount, &r.MaxDownloads, &r.State,
			&r.TerminalReason, &r.TerminalAt, &r.CreatedAt, &r.UpdatedAt, &r.ExpiresAt,
			&r.UploadTokenSM3, &r.UploadTokenKID, &uploaderIP, &r.SenderNickname)
		if err != nil {
			return nil, err
		}
		if uploaderIP != nil {
			r.UploaderIP = *uploaderIP
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// prefixedTransfers 给列名加表别名前缀。
func prefixedTransfers(alias string) string {
	return alias + `.transfer_id, ` + alias + `.sender_code, ` + alias + `.recipient_code, ` +
		alias + `.plaintext_size, ` + alias + `.chunk_size, ` + alias + `.chunk_count, ` +
		alias + `.prelude_len, ` + alias + `.prelude_sm3, ` + alias + `.prelude_received, ` +
		alias + `.received_chunks, ` + alias + `.total_ciphertext_bytes, ` +
		alias + `.download_count, ` + alias + `.max_downloads, ` + alias + `.state, ` +
		alias + `.terminal_reason, ` + alias + `.terminal_at, ` +
		alias + `.created_at, ` + alias + `.updated_at, ` + alias + `.expires_at, ` +
		alias + `.upload_token_sm3, ` + alias + `.upload_token_kid, ` + alias + `.uploader_ip`
}

// IdempotencyRecord 是 POST /transfers 的幂等记录。
type IdempotencyRecord struct {
	KeyHash            []byte
	SenderCode         string
	RequestFingerprint []byte
	TransferID         string
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

// GetIdempotency 取幂等记录。
func (s *Store) GetIdempotency(ctx context.Context, keyHash []byte, now time.Time) (IdempotencyRecord, error) {
	var r IdempotencyRecord
	err := s.pool.QueryRow(ctx, `SELECT key_hash, sender_code, request_fingerprint, transfer_id, created_at, expires_at
		FROM idempotency_keys WHERE key_hash = $1 AND expires_at > $2`, keyHash, now).
		Scan(&r.KeyHash, &r.SenderCode, &r.RequestFingerprint, &r.TransferID, &r.CreatedAt, &r.ExpiresAt)
	if err != nil {
		if isNoRows(err) {
			return IdempotencyRecord{}, ErrNotFound
		}
		return IdempotencyRecord{}, fmt.Errorf("store: get idempotency: %w", err)
	}
	return r, nil
}

// PutIdempotency 落幂等记录（同 key 已存在则忽略）。
func (s *Store) PutIdempotency(ctx context.Context, r IdempotencyRecord) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO idempotency_keys
		(key_hash, sender_code, request_fingerprint, transfer_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (key_hash) DO NOTHING`,
		r.KeyHash, r.SenderCode, r.RequestFingerprint, r.TransferID, r.CreatedAt, r.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: put idempotency: %w", err)
	}
	return nil
}

// DeleteExpiredIdempotency 清理过期幂等记录。
func (s *Store) DeleteExpiredIdempotency(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("store: delete idempotency: %w", err)
	}
	return tag.RowsAffected(), nil
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func equalBytes(a, b []byte) bool { return bytes.Equal(a, b) }

// GetActiveLease 取某传输当前未 ack 的租约（没有则 ErrNotFound）。
func (s *Store) GetActiveLease(ctx context.Context, transferID string) (Download, error) {
	var d Download
	err := s.pool.QueryRow(ctx, `SELECT download_id, transfer_id, created_at, lease_expires_at, acked_at
		FROM transfer_downloads WHERE transfer_id = $1 AND acked_at IS NULL
		ORDER BY created_at DESC LIMIT 1`, transferID).
		Scan(&d.ID, &d.TransferID, &d.CreatedAt, &d.LeaseExpiresAt, &d.AckedAt)
	if err != nil {
		if isNoRows(err) {
			return Download{}, ErrNotFound
		}
		return Download{}, fmt.Errorf("store: get active lease: %w", err)
	}
	return d, nil
}
