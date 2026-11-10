package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

var transferIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// handleCreateTransfer 是 POST /v1/transfers（API.md §6.1）。
func (a *API) handleCreateTransfer(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	var req spec.CreateTransferRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	recipient, err := gm.NormalizeCode(req.RecipientCode)
	if err != nil {
		fail(w, r, spec.ErrCodeFormatInvalid)
		return
	}
	preludeSM3, err := decodeB64(req.PreludeSM3)
	if err != nil || len(preludeSM3) != 32 {
		fail(w, r, spec.ErrBadRequest)
		return
	}

	// 先验签（签名覆盖全部尺寸字段），再做语义校验。
	senderCode, ok := a.verifySignature(w, r, spec.PurposeTransferCreate, "", nil,
		func(code string) ([]byte, error) {
			return auth.TransferCreateFields(code, recipient, req.PlaintextSize,
				req.ChunkSize, req.ChunkCount, req.PreludeLen, preludeSM3)
		})
	if !ok {
		return
	}

	if req.PlaintextSize > spec.MaxPlaintextSize {
		fail(w, r, spec.ErrSizeLimitExceeded)
		return
	}
	if req.ChunkSize < spec.MinChunkSize || req.ChunkSize > spec.MaxChunkSize {
		fail(w, r, spec.ErrChunkSizeInvalid)
		return
	}
	if req.ChunkCount > spec.MaxChunkCount {
		fail(w, r, spec.ErrSizeLimitExceeded)
		return
	}
	if req.ChunkCount != expectedChunkCount(req.PlaintextSize, req.ChunkSize) {
		fail(w, r, spec.ErrChunkCountMismatch)
		return
	}
	if req.PreludeLen < 1 || req.PreludeLen > spec.MaxPreludeLen {
		fail(w, r, spec.ErrSizeLimitExceeded)
		return
	}

	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	// 收件码必须存在。
	if _, err := a.store.GetCode(ctx, recipient); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrCodeNotFound)
			return
		}
		a.internalError(w, r, "get recipient code", err)
		return
	}

	ttl := spec.DefaultTTL
	if req.TTLSeconds != nil {
		ttl = clampUint32(*req.TTLSeconds, spec.MinTTLSeconds, spec.MaxTTLSeconds)
	}
	maxDownloads := spec.DefaultDownloads
	if req.MaxDownloads != nil {
		maxDownloads = clampUint32(*req.MaxDownloads, spec.MinDownloads, spec.MaxDownloads)
	}

	// 幂等（§6.2）：600 秒内同 key 折叠为同一 transfer。
	idemKey := r.Header.Get(spec.HeaderIdempotencyKey)
	var idemHash, fingerprint []byte
	if idemKey != "" {
		raw, err := decodeB64(idemKey)
		if err != nil || len(raw) < 16 || len(raw) > 32 {
			fail(w, r, spec.ErrBadRequest)
			return
		}
		sum := gm.SM3([]byte(idemKey + "|" + senderCode))
		idemHash = sum[:]
		fingerprint = createFingerprint(req, recipient, preludeSM3, ttl, maxDownloads)
		if rec, err := a.store.GetIdempotency(ctx, idemHash, now); err == nil {
			if !auth.EqualBytes(rec.RequestFingerprint, fingerprint) {
				fail(w, r, spec.ErrTransferStateConflict)
				return
			}
			existing, err := a.store.GetTransfer(ctx, rec.TransferID)
			if err != nil {
				a.internalError(w, r, "get idempotent transfer", err)
				return
			}
			cur, err := a.store.CurrentTokenEpoch(ctx)
			if err != nil {
				a.internalError(w, r, "current token kid", err)
				return
			}
			token, err := a.tokens.UploadToken(existing.ID, cur)
			if err != nil {
				a.internalError(w, r, "derive upload token", err)
				return
			}
			// 幂等重放要返回同一个 token；secret 轮换过就重建不出来，
			// 这时不能把不可用的 token 发出去，让客户端重建传输。
			if existing.UploadTokenKID != strconv.FormatInt(cur, 10) ||
				!a.tokens.Derives(token, existing.ID, cur, existing.UploadTokenSM3) {
				a.log.Warn("idempotency replay after token rotation", "transferId", existing.ID)
				fail(w, r, spec.ErrTransferStateConflict)
				return
			}
			writeJSON(w, http.StatusOK, createTransferResponse(existing, token))
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			a.internalError(w, r, "get idempotency", err)
			return
		}
	}

	if !a.allow(w, r, "create:code:"+senderCode, "code", spec.DefaultLimits.TransferCreatePerCode) {
		return
	}
	active, err := a.store.CountActiveByCode(ctx, senderCode)
	if err != nil {
		a.internalError(w, r, "count active", err)
		return
	}
	if active >= spec.DefaultLimits.MaxConcurrentTransfersPerCode {
		writeError(w, r, apiError{code: spec.ErrRateLimited, scope: "code", retryAfter: time.Minute})
		return
	}
	// 配额类错误用 507，不用 429（§11.4）。
	used, err := a.store.StorageUsageByIP(ctx, ip)
	if err != nil {
		a.internalError(w, r, "storage usage", err)
		return
	}
	estimate := int64(req.PreludeLen) + int64(req.PlaintextSize) + 16*int64(req.ChunkCount)
	if used+estimate > a.cfg.StorageQuotaBytes {
		fail(w, r, spec.ErrInsufficientStorage)
		return
	}

	transferID, err := auth.NewID()
	if err != nil {
		a.internalError(w, r, "transfer id", err)
		return
	}
	epoch, err := a.store.CurrentTokenEpoch(ctx)
	if err != nil {
		a.internalError(w, r, "current token kid", err)
		return
	}
	token, err := a.tokens.UploadToken(transferID, epoch)
	if err != nil {
		a.internalError(w, r, "upload token", err)
		return
	}

	created, err := a.store.CreateTransfer(ctx, store.Transfer{
		ID:             transferID,
		SenderCode:     senderCode,
		RecipientCode:  recipient,
		PlaintextSize:  int64(req.PlaintextSize),
		ChunkSize:      int(req.ChunkSize),
		ChunkCount:     int(req.ChunkCount),
		PreludeLen:     int(req.PreludeLen),
		PreludeSM3:     preludeSM3,
		MaxDownloads:   int(maxDownloads),
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Duration(ttl) * time.Second),
		UploadTokenSM3: auth.UploadTokenHash(token),
		UploadTokenKID: strconv.FormatInt(epoch, 10),
		UploaderIP:     ip,
	})
	if err != nil {
		a.internalError(w, r, "create transfer", err)
		return
	}

	if idemHash != nil {
		if err := a.store.PutIdempotency(ctx, store.IdempotencyRecord{
			KeyHash:            idemHash,
			SenderCode:         senderCode,
			RequestFingerprint: fingerprint,
			TransferID:         created.ID,
			CreatedAt:          now,
			ExpiresAt:          now.Add(spec.IdempotencyWindow),
		}); err != nil {
			a.log.Warn("put idempotency failed", "err", err.Error())
		}
	}

	// 收件人在线则推一条 TRANSFER_NOTICE（§9.3）；离线不发，客户端靠轮询 inbox。
	a.notifyTransfer(created)

	writeJSON(w, http.StatusCreated, createTransferResponse(created, token))
}

// notifyTransfer 给收件人推送 TRANSFER_NOTICE；不在线时静默跳过。
func (a *API) notifyTransfer(t store.Transfer) {
	if a.hub == nil || !a.hub.Online(t.RecipientCode) {
		return
	}
	a.hub.Deliver(t.RecipientCode, map[string]any{
		"type": "TRANSFER_NOTICE",
		"payload": map[string]any{
			"transfer_id":    t.ID,
			"sender_code":    t.SenderCode,
			"plaintext_size": t.PlaintextSize,
			"chunk_count":    t.ChunkCount,
			"expires_at":     t.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
	})
}

// expireIfNeeded 是 TTL 的**读写路径即时判定**：`expires_at` 一到就把这条置 EXPIRED 并物理删密文。
//
// 清道夫 30 秒才扫一次，若只靠它，到期后的这 30 秒里仍能取件、列表里还挂着「可下载」，
// 与「已过期，无法取回」的界面语义直接矛盾，所以到期判定必须落在每次读写上。
func (a *API) expireIfNeeded(w http.ResponseWriter, r *http.Request, id string) (store.Transfer, bool) {
	t, newly, err := a.store.TerminalizeExpiredID(r.Context(), id, a.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotFound)
			return store.Transfer{}, false
		}
		a.internalError(w, r, "terminalize expired", err)
		return store.Transfer{}, false
	}
	// 已终结的 EXPIRED 也要删一次密文：StartLease / AckDownload 在事务里终结时
	// newly=false，密文只能靠这里或兜底任务补删（契约要求三路径都"立刻删除"）。
	if newly || t.State == spec.StateExpired {
		a.purgeCiphertext(r, id)
	}
	return t, true
}

// handleGetTransfer 是 GET /v1/transfers/{id}（API.md §7.2）。
// transfer_id 是能力凭证：持有即可读元数据，不需要签名。
func (a *API) handleGetTransfer(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	id, ok := a.transferIDParam(w, r)
	if !ok {
		return
	}
	ip := a.clientIP(r)
	if !a.allow(w, r, "read:ip:"+ip, "ip", spec.DefaultLimits.TransferReadPerIP) {
		return
	}
	if !a.allow(w, r, "read:transfer:"+id, "transfer", spec.DefaultLimits.TransferReadPerTransfer) {
		return
	}

	t, ok := a.expireIfNeeded(w, r, id)
	if !ok {
		return
	}
	if spec.IsTerminalState(t.State) {
		// 到期即终结：返回 EXPIRED tombstone（expires_at / terminal_at 都是原始值）。
		writeJSON(w, http.StatusOK, a.transferResponse(r, t))
		return
	}
	t, err := a.store.ReclaimExpiredLease(r.Context(), id, a.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotFound)
			return
		}
		a.internalError(w, r, "get transfer", err)
		return
	}
	writeJSON(w, http.StatusOK, a.transferResponse(r, t))
}

// handleInbox 是 GET /v1/inbox（API.md §7.1）。
func (a *API) handleInbox(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r, "state", "limit", "cursor") {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	code, ok := a.verifySignature(w, r, spec.PurposeInboxList, "", nil,
		func(signedCode string) ([]byte, error) { return auth.InboxListFields(signedCode) })
	if !ok {
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		state = "ready"
	}
	var states []string
	switch state {
	case "ready":
		states = []string{spec.StateReady, spec.StateLeased}
	case "all":
		states = []string{spec.StateReady, spec.StateLeased, spec.StateUploading}
	default:
		fail(w, r, spec.ErrBadRequest)
		return
	}

	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 50 {
			fail(w, r, spec.ErrBadRequest)
			return
		}
		limit = n
	}

	q := store.InboxQuery{Code: code, States: states, Limit: limit + 1, Now: a.now()}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		at, id, err := decodeCursor(cursor)
		if err != nil {
			fail(w, r, spec.ErrBadRequest)
			return
		}
		q.BeforeCreatedAt, q.BeforeID, q.HasCursor = at, id, true
	}

	rows, err := a.store.ListInbox(r.Context(), q)
	if err != nil {
		a.internalError(w, r, "list inbox", err)
		return
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := encodeCursor(last.CreatedAt, last.ID)
		next = &c
	}
	items := make([]spec.InboxItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, spec.InboxItem{
			TransferID:     row.ID,
			SenderCode:     row.SenderCode,
			SenderNickname: row.SenderNickname,
			RecipientCode:  row.RecipientCode,
			PlaintextSize:  uint64(row.PlaintextSize),
			ChunkSize:      uint32(row.ChunkSize),
			ChunkCount:     uint32(row.ChunkCount),
			PreludeLen:     uint32(row.PreludeLen),
			CreatedAt:      spec.FormatTime(row.CreatedAt),
			ExpiresAt:      spec.FormatTime(row.ExpiresAt),
			State:          row.State,
		})
	}
	writeJSON(w, http.StatusOK, spec.InboxResponse{Items: items, NextCursor: next})
}

// handleStatus 是 GET /v1/transfers/{id}/status（API.md §6.5），用 upload_token。
func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	t, ok := a.requireUploadToken(w, r)
	if !ok {
		return
	}
	if !a.allow(w, r, "status:transfer:"+t.ID, "transfer", spec.DefaultLimits.ChunkPutPerTransfer) {
		return
	}
	// 终结态（CONSUMED / REVOKED / EXPIRED）在 requireUploadToken 里已按 §1.7.4 回 410，
	// 走到这里一定未终结——不要再加一个 409 分支，那会让"终结态 410 先于凭据"被悄悄顶掉。
	chunks, err := a.store.ListChunks(r.Context(), t.ID)
	if err != nil {
		a.internalError(w, r, "list chunks", err)
		return
	}
	indexes := make([]int, 0, len(chunks))
	var uploaded int64
	for _, c := range chunks {
		indexes = append(indexes, c.Index)
		uploaded += int64(c.Length)
	}
	if t.PreludeReceived {
		uploaded += int64(t.PreludeLen)
	}
	writeJSON(w, http.StatusOK, spec.StatusResponse{
		TransferID:      t.ID,
		State:           t.State,
		ChunkCount:      uint32(t.ChunkCount),
		ChunkSize:       uint32(t.ChunkSize),
		PreludeReceived: t.PreludeReceived,
		ReceivedChunks:  uint32(t.ReceivedChunks),
		Bitmap:          auth.B64.EncodeToString(buildBitmap(indexes, uint32(t.ChunkCount))),
		Missing:         missingRanges(indexes, uint32(t.ChunkCount)),
		UploadedBytes:   uploaded,
		ExpiresAt:       spec.FormatTime(t.ExpiresAt),
		UpdatedAt:       spec.FormatTime(t.UpdatedAt),
	})
}

// handleComplete 是 POST /v1/transfers/{id}/complete（API.md §6.6）。
func (a *API) handleComplete(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	t, ok := a.requireUploadToken(w, r)
	if !ok {
		return
	}
	updated, err := a.store.CompleteTransfer(r.Context(), t.ID, a.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlreadyReady):
			cur, gerr := a.store.GetTransfer(r.Context(), t.ID)
			if gerr != nil {
				a.internalError(w, r, "get transfer", gerr)
				return
			}
			writeJSON(w, http.StatusOK, spec.CompleteResponse{State: cur.State, ExpiresAt: spec.FormatTime(cur.ExpiresAt)})
		case errors.Is(err, store.ErrPreludeMissing):
			fail(w, r, spec.ErrPreludeMissing)
		case errors.Is(err, store.ErrChunksMissing):
			chunks, _ := a.store.ListChunks(r.Context(), t.ID)
			indexes := make([]int, 0, len(chunks))
			for _, c := range chunks {
				indexes = append(indexes, c.Index)
			}
			writeError(w, r, apiError{code: spec.ErrChunksMissing, missing: missingRanges(indexes, uint32(t.ChunkCount))})
		case errors.Is(err, store.ErrNotFound):
			fail(w, r, spec.ErrTransferNotFound)
		default:
			fail(w, r, spec.ErrTransferStateConflict)
		}
		return
	}
	writeJSON(w, http.StatusOK, spec.CompleteResponse{
		State:     updated.State,
		ExpiresAt: spec.FormatTime(updated.ExpiresAt),
	})
}

// handleAck 是 POST /v1/transfers/{id}/ack（API.md §7.5）。
//
// 计数口径（唯一）：只有 ack 成功才 +1；同一 download_id 重复 ack 只计一次。
func (a *API) handleAck(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	id, ok := a.transferIDParam(w, r)
	if !ok {
		return
	}
	code, ok := a.verifySignature(w, r, spec.PurposeTransferAck, "", nil,
		func(signedCode string) ([]byte, error) { return auth.TransferAckFields(signedCode, id) })
	if !ok {
		return
	}
	dl := downloadID(r)
	if dl == "" {
		fail(w, r, spec.ErrDownloadNotStarted)
		return
	}
	d, err := a.store.GetDownload(r.Context(), dl)
	if err != nil || d.TransferID != id {
		fail(w, r, spec.ErrDownloadNotStarted)
		return
	}
	t, err := a.store.GetTransfer(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotFound)
			return
		}
		a.internalError(w, r, "get transfer", err)
		return
	}
	// 裁决 G1：已认证但非当事人 → 403 NOT_TRANSFER_PARTY。
	if code != t.RecipientCode {
		fail(w, r, spec.ErrNotTransferParty)
		return
	}

	res, err := a.store.AckDownload(r.Context(), dl, a.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			fail(w, r, spec.ErrDownloadNotStarted)
		case errors.Is(err, store.ErrLeaseExpired):
			fail(w, r, spec.ErrDownloadNotStarted)
		case errors.Is(err, store.ErrExpired):
			// TTL 到点：ack 不计数，返回 410；错误名按**当时的真实状态**取，
			// 已 REVOKED/CONSUMED 的行不能报成 EXPIRED（与 loadReadableTransfer 口径一致）。
			fresh, ok := a.expireIfNeeded(w, r, id)
			if !ok {
				return
			}
			fail(w, r, spec.TerminalErrorCode(fresh.State))
		case errors.Is(err, store.ErrConflict):
			fail(w, r, spec.ErrTransferStateConflict)
		default:
			a.internalError(w, r, "ack", err)
		}
		return
	}
	if res.Consumed && res.Counted {
		a.purgeCiphertext(r, res.Transfer.ID)
	}

	resp := spec.AckResponse{State: res.Transfer.State, DownloadCount: uint32(res.Transfer.DownloadCount)}
	if res.Transfer.TerminalReason != nil {
		resp.TerminalReason = res.Transfer.TerminalReason
	}
	if res.Transfer.TerminalAt != nil {
		at := spec.FormatTime(*res.Transfer.TerminalAt)
		resp.TerminalAt = &at
	}
	if !res.Consumed {
		remaining := uint32(res.Transfer.MaxDownloads - res.Transfer.DownloadCount)
		resp.RemainingDownloads = &remaining
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRevoke 是 POST /v1/transfers/{id}/revoke（API.md §6.7）。
func (a *API) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	id, ok := a.transferIDParam(w, r)
	if !ok {
		return
	}
	code, ok := a.verifySignature(w, r, spec.PurposeTransferRevoke, "", nil,
		func(signedCode string) ([]byte, error) { return auth.TransferRevokeFields(signedCode, id) })
	if !ok {
		return
	}
	// 已到 TTL 的先判过期：否则会给出 REVOKED 200，而契约里 EXPIRED 撤回是 409（§6.7）。
	if _, ok := a.expireIfNeeded(w, r, id); !ok {
		return
	}
	t, err := a.store.RevokeTransfer(r.Context(), id, code, a.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			fail(w, r, spec.ErrTransferNotFound)
		case errors.Is(err, store.ErrNotParty):
			fail(w, r, spec.ErrNotTransferParty)
		case errors.Is(err, store.ErrConflict):
			fail(w, r, spec.ErrTransferStateConflict)
		default:
			a.internalError(w, r, "revoke", err)
		}
		return
	}
	a.purgeCiphertext(r, t.ID)
	at := a.now()
	if t.TerminalAt != nil {
		at = *t.TerminalAt
	}
	writeJSON(w, http.StatusOK, spec.RevokeResponse{
		State:          t.State,
		TerminalReason: spec.ReasonRevoked,
		TerminalAt:     spec.FormatTime(at),
	})
}

// ---------- helpers ----------

// requireUploadToken 校验 X-YS-Upload-Token 并返回传输。
func (a *API) requireUploadToken(w http.ResponseWriter, r *http.Request) (store.Transfer, bool) {
	id, ok := a.transferIDParam(w, r)
	if !ok {
		return store.Transfer{}, false
	}
	// 先取资源，**再**看凭据：契约 §1.7.4 把判定顺序写死为「终结态 410 → KID → 值 → 有效期 →
	// 409 状态冲突」，终结态连"没带凭据"也排在后面（否则客户端会按 401 去重签，白跑一轮）。
	t, err := a.store.GetTransfer(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotFound)
			return store.Transfer{}, false
		}
		a.internalError(w, r, "get transfer", err)
		return store.Transfer{}, false
	}
	// TTL 到点 → 410 TRANSFER_EXPIRED，且**先于**凭据判定：
	// 传输终结不可恢复，先回 401 AUTH_TOKEN_EXPIRED（可重签发）会把发送方引向重签，
	// 重签之后仍然是 410（API.md §1.7.4「两者语义不同、不得混用」）。
	if !t.ExpiresAt.After(a.now()) {
		fresh, ok := a.expireIfNeeded(w, r, id)
		if !ok {
			return store.Transfer{}, false
		}
		if spec.IsTerminalState(fresh.State) {
			fail(w, r, spec.TerminalErrorCode(fresh.State))
		} else {
			fail(w, r, spec.ErrTransferExpired)
		}
		return store.Transfer{}, false
	}
	// 已终结（CONSUMED / REVOKED）：一律按实际终态回 410，**不返回任何 401**——
	// 即使凭据缺失、被轮换、已超期或干脆是伪造的（§1.7.4 判定顺序第一条）。
	if spec.IsTerminalState(t.State) {
		fail(w, r, spec.TerminalErrorCode(t.State))
		return store.Transfer{}, false
	}
	token := uploadToken(r)
	if token == "" {
		fail(w, r, spec.ErrAuthMissing)
		return store.Transfer{}, false
	}
	// 资源未终结，才轮到凭据内部顺序：
	// ① EPOCH 不符 → AUTH_TOKEN_STALE（EPOCH 是唯一吊销开关，递增即生效、无需重启）
	epoch, err := a.store.CurrentTokenEpoch(r.Context())
	if err != nil {
		a.internalError(w, r, "current token epoch", err)
		return store.Transfer{}, false
	}
	if t.UploadTokenKID != strconv.FormatInt(epoch, 10) {
		writeError(w, r, apiError{code: spec.ErrAuthTokenStale})
		return store.Transfer{}, false
	}
	// ② 值不对（伪造/串传输）→ AUTH_TOKEN_INVALID。**不重算**：secret 只是派生盐。
	if !auth.ValidateHash(token, t.UploadTokenSM3) {
		writeError(w, r, apiError{code: spec.ErrAuthTokenInvalid})
		return store.Transfer{}, false
	}
	// ③ 上传凭据 6 小时过期 → AUTH_TOKEN_EXPIRED（传输终结仍走 410）
	if a.now().After(t.CreatedAt.Add(spec.UploadTokenTTL)) {
		writeError(w, r, apiError{code: spec.ErrAuthTokenExpired})
		return store.Transfer{}, false
	}
	return t, true
}

// transferIDParam 取并校验路径里的 transfer_id。
func (a *API) transferIDParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue(spec.ParamTransferID)
	if !transferIDRe.MatchString(id) {
		fail(w, r, spec.ErrTransferNotFound)
		return "", false
	}
	return id, true
}

// purgeCiphertext 物理删除密文（ack 达上限 / 撤回 / TTL 三条路径），并写下删除水位。
//
// 水位（`ciphertext_purged_at`）不是审计字段，而是兜底任务推进的依据：
// 请求路径删成功之后，这一行就离开「待删密文」集合，清理任务不会反复处理同一批行。
func (a *API) purgeCiphertext(r *http.Request, id string) {
	if err := a.blobs.Purge(id); err != nil {
		a.log.Error("purge ciphertext failed", "transferId", id, "err", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
	defer cancel()
	if _, err := a.store.MarkCiphertextPurged(ctx, []string{id}, a.now()); err != nil {
		// 删密文已成功；水位没写上只会让兜底多删一次（幂等），不阻断请求。
		a.log.Warn("mark ciphertext purged failed", "transferId", id, "err", err.Error())
	}
}

// transferResponse 组装 §7.2 的响应；终结态不返回 prelude_sm3 与租约。
func (a *API) transferResponse(r *http.Request, t store.Transfer) spec.TransferResponse {
	out := spec.TransferResponse{
		TransferID:           t.ID,
		SenderCode:           t.SenderCode,
		RecipientCode:        t.RecipientCode,
		PlaintextSize:        uint64(t.PlaintextSize),
		ChunkSize:            uint32(t.ChunkSize),
		ChunkCount:           uint32(t.ChunkCount),
		PreludeLen:           uint32(t.PreludeLen),
		TotalCiphertextBytes: t.TotalCiphertextBytes,
		DownloadCount:        uint32(t.DownloadCount),
		MaxDownloads:         uint32(t.MaxDownloads),
		CreatedAt:            spec.FormatTime(t.CreatedAt),
		ExpiresAt:            spec.FormatTime(t.ExpiresAt),
		State:                t.State,
	}
	if c, err := a.store.GetCode(r.Context(), t.SenderCode); err == nil {
		out.SenderNickname = c.Nickname
	}
	if t.TerminalReason != nil {
		out.TerminalReason = t.TerminalReason
	}
	if t.TerminalAt != nil {
		at := spec.FormatTime(*t.TerminalAt)
		out.TerminalAt = &at
	}
	if !spec.IsTerminalState(t.State) {
		sm3 := auth.B64.EncodeToString(t.PreludeSM3)
		out.PreludeSM3 = &sm3
		if t.State == spec.StateLeased {
			if d, err := a.store.GetActiveLease(r.Context(), t.ID); err == nil {
				at := spec.FormatTime(d.LeaseExpiresAt)
				out.LeaseExpiresAt = &at
			}
		}
	}
	return out
}

func createTransferResponse(t store.Transfer, token string) spec.CreateTransferResponse {
	return spec.CreateTransferResponse{
		TransferID:    t.ID,
		State:         t.State,
		UploadToken:   token,
		ChunkSize:     uint32(t.ChunkSize),
		ChunkCount:    uint32(t.ChunkCount),
		PreludeLen:    uint32(t.PreludeLen),
		DownloadCount: uint32(t.DownloadCount),
		MaxDownloads:  uint32(t.MaxDownloads),
		CreatedAt:     spec.FormatTime(t.CreatedAt),
		ExpiresAt:     spec.FormatTime(t.ExpiresAt),
	}
}

func clampUint32(v, min, max uint32) uint32 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// createFingerprint 是幂等请求体的指纹（同 key 不同体 → 409）。
func createFingerprint(req spec.CreateTransferRequest, recipient string, preludeSM3 []byte, ttl, maxDownloads uint32) []byte {
	raw := fmt.Sprintf("%s|%d|%d|%d|%d|%x|%d|%d",
		recipient, req.PlaintextSize, req.ChunkSize, req.ChunkCount,
		req.PreludeLen, preludeSM3, ttl, maxDownloads)
	sum := gm.SM3([]byte(raw))
	return sum[:]
}
