package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// handlePutPrelude 是 PUT /v1/transfers/{id}/prelude（API.md §6.3）。
//
// 服务端**不解析** prelude，只校验长度与 SM3。
func (a *API) handlePutPrelude(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	t, ok := a.requireUploadToken(w, r)
	if !ok {
		return
	}
	if !a.requireOctetStream(w, r) {
		return
	}
	if t.State != spec.StateUploading {
		fail(w, r, spec.ErrTransferStateConflict)
		return
	}
	if !a.allow(w, r, "chunkput:transfer:"+t.ID, "transfer", spec.DefaultLimits.ChunkPutPerTransfer) {
		return
	}

	declared := int64(t.PreludeLen)
	if !a.checkDeclaredLength(w, r, declared) {
		return
	}
	body, ok := a.readExact(w, r, declared)
	if !ok {
		return
	}
	sum := gm.SM3(body)
	if !auth.EqualBytes(sum[:], t.PreludeSM3) {
		fail(w, r, spec.ErrPreludeDigestMismatch)
		return
	}

	if _, err := a.blobs.PutPrelude(t.ID, body); err != nil {
		if errors.Is(err, blob.ErrConflict) {
			fail(w, r, spec.ErrPreludeConflict)
			return
		}
		a.internalError(w, r, "put prelude", err)
		return
	}
	fresh, err := a.store.MarkPreludeReceived(r.Context(), t.ID, a.now())
	if err != nil {
		if errors.Is(err, store.ErrTransferNotReady) {
			fail(w, r, spec.ErrTransferStateConflict)
			return
		}
		a.internalError(w, r, "mark prelude", err)
		return
	}
	if !fresh {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusCreated, spec.PreludePutResponse{
		PreludeLen: uint32(len(body)),
		PreludeSM3: auth.B64.EncodeToString(sum[:]),
	})
}

// handleGetPrelude 是 GET /v1/transfers/{id}/prelude（API.md §7.3），会开启下载租约。
func (a *API) handleGetPrelude(w http.ResponseWriter, r *http.Request) {
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

	t, ok := a.loadReadableTransfer(w, r, id)
	if !ok {
		return
	}
	downloadID, leaseExpiry, ok := a.startLease(w, r, t)
	if !ok {
		return
	}

	rc, size, err := a.blobs.OpenPrelude(t.ID)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotReady)
			return
		}
		a.internalError(w, r, "open prelude", err)
		return
	}
	defer rc.Close()

	h := w.Header()
	h.Set(spec.HeaderContentType, spec.ContentTypeBinary)
	h.Set(spec.HeaderDownloadID, downloadID)
	h.Set(spec.HeaderLeaseExpiresAt, spec.FormatTime(leaseExpiry))
	h.Set(spec.HeaderState, spec.StateLeased)
	h.Set("X-Content-Type-Options", "nosniff")
	if !a.serveRange(w, r, rc, size) {
		return
	}
}

// handlePutChunk 是 PUT /v1/transfers/{id}/chunks/{index}（API.md §6.4）。
func (a *API) handlePutChunk(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	t, ok := a.requireUploadToken(w, r)
	if !ok {
		return
	}
	if !a.requireOctetStream(w, r) {
		return
	}
	index, ok := a.indexParam(w, r, t)
	if !ok {
		return
	}
	if t.State != spec.StateUploading {
		fail(w, r, spec.ErrTransferStateConflict)
		return
	}
	if !a.allow(w, r, "chunkput:transfer:"+t.ID, "transfer", spec.DefaultLimits.ChunkPutPerTransfer) {
		return
	}

	expected := int64(expectedChunkLen(uint32(t.ChunkSize), uint64(t.PlaintextSize), uint32(t.ChunkCount), index))
	if !a.checkDeclaredLength(w, r, expected) {
		return
	}
	body, ok := a.readExact(w, r, expected)
	if !ok {
		return
	}
	sum := gm.SM3(body)

	res, err := a.blobs.PutChunk(t.ID, index, body)
	if err != nil {
		if errors.Is(err, blob.ErrConflict) {
			fail(w, r, spec.ErrChunkConflict)
			return
		}
		a.internalError(w, r, "put chunk", err)
		return
	}
	add, err := a.store.AddChunk(r.Context(), t.ID, int(index), len(body), res.Digest, a.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrChunkConflict):
			fail(w, r, spec.ErrChunkConflict)
		case errors.Is(err, store.ErrChunkOutOfRange):
			fail(w, r, spec.ErrChunkIndexOutOfRange)
		case errors.Is(err, store.ErrTransferNotReady):
			fail(w, r, spec.ErrTransferStateConflict)
		case errors.Is(err, store.ErrNotFound):
			fail(w, r, spec.ErrTransferNotFound)
		default:
			a.internalError(w, r, "add chunk", err)
		}
		return
	}
	_ = sum
	if add.Duplicate {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusCreated, spec.ChunkPutResponse{
		Index:          index,
		Length:         uint32(len(body)),
		ReceivedChunks: uint32(add.ReceivedCount),
		ChunkCount:     uint32(add.ChunkCount),
	})
}

// handleGetChunk 是 GET /v1/transfers/{id}/chunks/{index}（API.md §7.4）。
func (a *API) handleGetChunk(w http.ResponseWriter, r *http.Request) {
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
	t, ok := a.loadReadableTransfer(w, r, id)
	if !ok {
		return
	}
	if err := a.checkLease(w, r, t); err != nil {
		return
	}
	index, ok := a.indexParam(w, r, t)
	if !ok {
		return
	}
	meta, err := a.store.GetChunk(r.Context(), t.ID, int(index))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrChunkNotFound)
			return
		}
		a.internalError(w, r, "get chunk", err)
		return
	}
	rc, size, err := a.blobs.OpenChunk(t.ID, index)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			a.log.Error("chunk metadata exists but blob is missing", "transferId", t.ID, "index", index)
			fail(w, r, spec.ErrInternal)
			return
		}
		a.internalError(w, r, "open chunk", err)
		return
	}
	defer rc.Close()

	h := w.Header()
	h.Set(spec.HeaderContentType, spec.ContentTypeBinary)
	h.Set("X-Content-Type-Options", "nosniff")
	if len(meta.SM3) > 0 {
		h.Set("X-YS-Ciphertext-Sm3", auth.B64.EncodeToString(meta.SM3))
	}
	if !a.serveRange(w, r, rc, size) {
		return
	}
}

// handleHeadChunk 是 HEAD /v1/transfers/{id}/chunks/{index}（API.md §7.6）。
func (a *API) handleHeadChunk(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	id, ok := a.transferIDParam(w, r)
	if !ok {
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
	if spec.IsTerminalState(t.State) {
		fail(w, r, spec.TerminalErrorCode(t.State))
		return
	}
	index, ok := a.indexParam(w, r, t)
	if !ok {
		return
	}
	meta, err := a.store.GetChunk(r.Context(), t.ID, int(index))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrChunkNotFound)
			return
		}
		a.internalError(w, r, "get chunk", err)
		return
	}
	w.Header().Set(spec.HeaderContentLength, strconv.Itoa(meta.Length))
	w.Header().Set(spec.HeaderAcceptRanges, "bytes")
	w.WriteHeader(http.StatusOK)
}

// ---------- helpers ----------

// loadReadableTransfer 取传输并处理状态：终结 → 410，未就绪 → 409。
func (a *API) loadReadableTransfer(w http.ResponseWriter, r *http.Request, id string) (store.Transfer, bool) {
	t, err := a.store.ReclaimExpiredLease(r.Context(), id, a.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotFound)
			return store.Transfer{}, false
		}
		a.internalError(w, r, "get transfer", err)
		return store.Transfer{}, false
	}
	if spec.IsTerminalState(t.State) {
		fail(w, r, spec.TerminalErrorCode(t.State))
		return store.Transfer{}, false
	}
	if t.State == spec.StateUploading {
		fail(w, r, spec.ErrTransferNotReady)
		return store.Transfer{}, false
	}
	return t, true
}

// startLease 开启或沿用下载租约。
func (a *API) startLease(w http.ResponseWriter, r *http.Request, t store.Transfer) (string, time.Time, bool) {
	downloadID, err := auth.NewID()
	if err != nil {
		a.internalError(w, r, "download id", err)
		return "", time.Time{}, false
	}
	now := a.now()
	updated, dl, err := a.store.StartLease(r.Context(), t.ID, downloadID, now, spec.LeaseTTL)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrTransferNotReady):
			fail(w, r, spec.ErrTransferNotReady)
		case errors.Is(err, store.ErrTerminal):
			fail(w, r, spec.ErrTransferStateConflict)
		case errors.Is(err, store.ErrNotFound):
			fail(w, r, spec.ErrTransferNotFound)
		default:
			a.internalError(w, r, "start lease", err)
		}
		return "", time.Time{}, false
	}
	_ = updated
	lease, err := a.store.GetDownload(r.Context(), dl)
	if err != nil {
		a.internalError(w, r, "get lease", err)
		return "", time.Time{}, false
	}
	return dl, lease.LeaseExpiresAt, true
}

// checkLease 校验下载租约：缺失/过期 → 409 DOWNLOAD_NOT_STARTED。
func (a *API) checkLease(w http.ResponseWriter, r *http.Request, t store.Transfer) error {
	dl := downloadID(r)
	if dl == "" {
		fail(w, r, spec.ErrDownloadNotStarted)
		return errors.New("missing download id")
	}
	d, err := a.store.GetDownload(r.Context(), dl)
	if err != nil || d.TransferID != t.ID || d.AckedAt != nil || !d.LeaseExpiresAt.After(a.now()) || t.State != spec.StateLeased {
		fail(w, r, spec.ErrDownloadNotStarted)
		return errors.New("invalid lease")
	}
	return nil
}

// checkDeclaredLength 校验 Content-Length：超出 → 413，缺失或不等 → 400。
func (a *API) checkDeclaredLength(w http.ResponseWriter, r *http.Request, declared int64) bool {
	if r.ContentLength < 0 {
		fail(w, r, spec.ErrLengthMismatch)
		return false
	}
	if r.ContentLength > declared {
		fail(w, r, spec.ErrPayloadTooLarge)
		return false
	}
	if r.ContentLength != declared {
		fail(w, r, spec.ErrLengthMismatch)
		return false
	}
	return true
}

// readExact 读恰好 declared 字节；超读或短读分别映射 413 / 400。
func (a *API) readExact(w http.ResponseWriter, r *http.Request, declared int64) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, declared)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			fail(w, r, spec.ErrPayloadTooLarge)
			return nil, false
		}
		fail(w, r, spec.ErrBadRequest)
		return nil, false
	}
	if int64(len(data)) != declared {
		fail(w, r, spec.ErrLengthMismatch)
		return nil, false
	}
	return data, true
}

// indexParam 解析并校验块序号。
func (a *API) indexParam(w http.ResponseWriter, r *http.Request, t store.Transfer) (uint32, bool) {
	raw := r.PathValue(spec.ParamIndex)
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || uint32(v) >= uint32(t.ChunkCount) {
		fail(w, r, spec.ErrChunkIndexOutOfRange)
		return 0, false
	}
	return uint32(v), true
}

// serveRange 处理单区间 Range 并写响应（API.md §8.1）。
//
// 多区间 → 400 RANGE_UNSUPPORTED；越界 → 416（由 ServeContent 负责，带 Content-Range）。
func (a *API) serveRange(w http.ResponseWriter, r *http.Request, body io.ReadSeeker, size int64) bool {
	if rng := r.Header.Get(spec.HeaderRange); rng != "" {
		if strings.Contains(rng, ",") {
			fail(w, r, spec.ErrRangeUnsupported)
			return false
		}
	}
	http.ServeContent(w, r, "", time.Time{}, body)
	return true
}
