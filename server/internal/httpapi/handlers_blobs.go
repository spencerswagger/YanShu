package httpapi

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// handlePutPrelude 上传 prelude（HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC）。
//
// 服务端**不解析**这段字节，只按声明的长度校验并落盘、记 SM3。
func (a *API) handlePutPrelude(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	p, ok := a.loadPackage(w, r, r.PathValue(spec.ParamPackageID))
	if !ok {
		return
	}
	if sess.Code != p.SenderCode {
		writeError(w, r, spec.ErrForbidden, 0)
		return
	}
	if p.State != spec.PackageUploading {
		writeError(w, r, spec.ErrPackageLocked, 0)
		return
	}

	data, ok := a.readBlobBody(w, r, a.cfg.MaxPreludeBytes)
	if !ok {
		return
	}
	if uint32(len(data)) != uint32(p.PreludeLen) {
		writeError(w, r, spec.ErrPreludeLengthMismatch, 0)
		return
	}

	res, err := a.blobs.PutPrelude(p.ID, data)
	if err != nil {
		if errors.Is(err, blob.ErrConflict) {
			writeError(w, r, spec.ErrPreludeConflict, 0)
			return
		}
		a.internalError(w, r, "put prelude", err)
		return
	}

	duplicate, err := a.store.SetPreludeDigest(r.Context(), p.ID, res.Digest)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrPreludeConflict):
			writeError(w, r, spec.ErrPreludeConflict, 0)
		case errors.Is(err, store.ErrPackageLocked):
			writeError(w, r, spec.ErrPackageLocked, 0)
		case errors.Is(err, store.ErrNotFound):
			writeError(w, r, spec.ErrPackageNotFound, 0)
		default:
			a.internalError(w, r, "set prelude digest", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, spec.PreludePutResponse{
		PackageID:  p.ID,
		PreludeLen: uint32(len(data)),
		Duplicate:  duplicate || res.Duplicate,
	})
}

// handleGetPrelude 下载 prelude。
func (a *API) handleGetPrelude(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	p, ok := a.loadPackage(w, r, r.PathValue(spec.ParamPackageID))
	if !ok {
		return
	}
	if !canReadPackage(p, sess.Code) {
		writeError(w, r, spec.ErrForbidden, 0)
		return
	}
	// 接收方只能在包 locked（ready）之后下载；发送方上传途中可自检。
	if sess.Code == p.RecipientCode && p.State != spec.PackageReady {
		writeError(w, r, spec.ErrPackageIncomplete, 0)
		return
	}
	rc, size, err := a.blobs.OpenPrelude(p.ID)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			writeError(w, r, spec.ErrPackageIncomplete, 0)
			return
		}
		a.internalError(w, r, "open prelude", err)
		return
	}
	defer rc.Close()

	a.writeBlobHeaders(w, size, p.PreludeDigest)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// handlePutChunk 上传单块（切片 = CHUNK_CT ‖ TAG，不含 16 字节块头）。
func (a *API) handlePutChunk(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	p, ok := a.loadPackage(w, r, r.PathValue(spec.ParamPackageID))
	if !ok {
		return
	}
	if sess.Code != p.SenderCode {
		writeError(w, r, spec.ErrForbidden, 0)
		return
	}
	if p.State != spec.PackageUploading {
		writeError(w, r, spec.ErrPackageLocked, 0)
		return
	}

	index, ok := parseChunkIndex(w, r, p)
	if !ok {
		return
	}

	data, ok := a.readBlobBody(w, r, a.cfg.MaxChunkBytes)
	if !ok {
		return
	}
	expected := expectedChunkCTLen(uint32(p.ChunkSize), uint64(p.PlaintextSize), uint32(p.ChunkCount), index)
	if uint32(len(data)) != expected {
		writeError(w, r, spec.ErrChunkLengthMismatch, 0)
		return
	}

	res, err := a.blobs.PutChunk(p.ID, index, data)
	if err != nil {
		if errors.Is(err, blob.ErrConflict) {
			writeError(w, r, spec.ErrChunkConflict, 0)
			return
		}
		a.internalError(w, r, "put chunk", err)
		return
	}

	add, err := a.store.AddChunk(r.Context(), p.ID, int(index), len(data), res.Digest, a.now())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrChunkConflict):
			writeError(w, r, spec.ErrChunkConflict, 0)
		case errors.Is(err, store.ErrPackageLocked):
			writeError(w, r, spec.ErrPackageLocked, 0)
		case errors.Is(err, store.ErrChunkOutOfRange):
			writeError(w, r, spec.ErrChunkIndexOutOfRange, 0)
		case errors.Is(err, store.ErrNotFound):
			writeError(w, r, spec.ErrPackageNotFound, 0)
		default:
			a.internalError(w, r, "add chunk", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, spec.ChunkPutResponse{
		PackageID:      p.ID,
		Index:          index,
		CiphertextLen:  uint32(len(data)),
		ReceivedChunks: uint32(add.ReceivedCount),
		Duplicate:      add.Duplicate || res.Duplicate,
	})
}

// handleGetChunk 下载单块。
func (a *API) handleGetChunk(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	p, ok := a.loadPackage(w, r, r.PathValue(spec.ParamPackageID))
	if !ok {
		return
	}
	if !canReadPackage(p, sess.Code) {
		writeError(w, r, spec.ErrForbidden, 0)
		return
	}
	if sess.Code == p.RecipientCode && p.State != spec.PackageReady {
		writeError(w, r, spec.ErrPackageIncomplete, 0)
		return
	}
	index, ok := parseChunkIndex(w, r, p)
	if !ok {
		return
	}

	meta, err := a.store.GetChunk(r.Context(), p.ID, int(index))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, spec.ErrChunkNotFound, 0)
			return
		}
		a.internalError(w, r, "get chunk", err)
		return
	}
	rc, size, err := a.blobs.OpenChunk(p.ID, index)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			// 库里有、盘上没了：数据不一致，按 500 报警而不是假装 404。
			a.log.Error("chunk metadata exists but blob is missing", "packageId", p.ID, "index", index)
			writeError(w, r, spec.ErrInternal, 0)
			return
		}
		a.internalError(w, r, "open chunk", err)
		return
	}
	defer rc.Close()

	a.writeBlobHeaders(w, size, meta.CTDigest)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// writeBlobHeaders 写密文响应头（摘要用 hex，便于与端侧核对）。
func (a *API) writeBlobHeaders(w http.ResponseWriter, size int64, digest []byte) {
	h := w.Header()
	h.Set("Content-Type", spec.ContentTypeBinary)
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	h.Set("X-Content-Type-Options", "nosniff")
	if len(digest) > 0 {
		h.Set(spec.HeaderContentDigest, hex.EncodeToString(digest))
		h.Set(spec.HeaderContentDigestAlg, spec.DigestAlgSM3)
	}
}

// parseChunkIndex 解析并校验块序号。
func parseChunkIndex(w http.ResponseWriter, r *http.Request, p store.Package) (uint32, bool) {
	raw := r.PathValue(spec.ParamIndex)
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		writeError(w, r, spec.ErrChunkIndexOutOfRange, 0)
		return 0, false
	}
	index := uint32(v)
	if index >= uint32(p.ChunkCount) {
		writeError(w, r, spec.ErrChunkIndexOutOfRange, 0)
		return 0, false
	}
	return index, true
}
