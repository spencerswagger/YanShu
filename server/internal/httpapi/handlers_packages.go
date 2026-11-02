package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

const (
	maxInboxItems   = 200
	maxMissingItems = 4096
)

// handleCreatePackage 创建一次传输。
func (a *API) handleCreatePackage(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	var req spec.CreatePackageRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	if !a.allow(w, r, "pkgcreate:ip:"+ip, spec.DefaultLimits.PackageCreatePerIP) {
		return
	}
	if !a.allow(w, r, "pkgcreate:code:"+sess.Code, spec.DefaultLimits.PackageCreatePerCode) {
		return
	}

	recipient, err := a.normalizeCode(req.RecipientCode)
	if err != nil {
		writeError(w, r, spec.ErrInvalidCode, 0)
		return
	}
	row, err := a.store.GetCode(ctx, recipient)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, spec.ErrCodeNotFound, 0)
			return
		}
		a.internalError(w, r, "get recipient code", err)
		return
	}
	if !row.ExpiresAt.After(now) {
		writeError(w, r, spec.ErrCodeExpired, 0)
		return
	}

	if !validPackageShape(req) {
		writeError(w, r, spec.ErrInvalidRequest, 0)
		return
	}

	// 密文总量估算：prelude + (明文 + 每块 16 字节 tag)。
	estimated := int64(req.PreludeLen) + int64(req.PlaintextSize) + 16*int64(req.ChunkCount)
	if estimated > a.cfg.MaxPackageBytes {
		writeError(w, r, spec.ErrPayloadTooLarge, 0)
		return
	}
	used, err := a.store.SenderUsage(ctx, sess.Code)
	if err != nil {
		a.internalError(w, r, "sender usage", err)
		return
	}
	if used+estimated > a.cfg.StorageQuotaBytes {
		writeError(w, r, spec.ErrQuotaExceeded, 0)
		return
	}

	ttl := a.cfg.PackageTTL
	if req.TTLSeconds != nil {
		ttl = time.Duration(*req.TTLSeconds) * time.Second
		if ttl < time.Minute {
			ttl = time.Minute
		}
		if ttl > 7*24*time.Hour {
			ttl = 7 * 24 * time.Hour
		}
	}
	maxDownloads := 1
	if req.MaxDownloads != nil {
		maxDownloads = int(*req.MaxDownloads)
		if maxDownloads < 1 {
			maxDownloads = 1
		}
		if maxDownloads > 100 {
			maxDownloads = 100
		}
	}
	deleteOnAck := true
	if req.DeleteOnAck != nil {
		deleteOnAck = *req.DeleteOnAck
	}

	p, err := a.store.CreatePackage(ctx, store.Package{
		ID:            newID(16),
		SenderCode:    sess.Code,
		RecipientCode: recipient,
		State:         spec.PackageUploading,
		ChunkCount:    int(req.ChunkCount),
		ChunkSize:     int(req.ChunkSize),
		PlaintextSize: int64(req.PlaintextSize),
		PreludeLen:    int(req.PreludeLen),
		MaxDownloads:  maxDownloads,
		DeleteOnAck:   deleteOnAck,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	})
	if err != nil {
		a.internalError(w, r, "create package", err)
		return
	}

	_ = a.store.Audit(ctx, store.AuditEvent{
		At: now, Kind: store.AuditPackageOpen, Code: sess.Code, PackageID: p.ID,
		Bytes: estimated, Outcome: "created", IP: ip,
	})
	writeJSON(w, http.StatusCreated, packageInfo(p))
}

// handleGetPackage 取包元信息（发送方或接收方均可）。
func (a *API) handleGetPackage(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, packageInfo(p))
}

// handleInbox 列出该码待收的包。
func (a *API) handleInbox(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	list, err := a.store.ListInbox(r.Context(), sess.Code, a.now(), maxInboxItems)
	if err != nil {
		a.internalError(w, r, "list inbox", err)
		return
	}
	out := make([]spec.PackageInfo, 0, len(list))
	for _, p := range list {
		out = append(out, packageInfo(p))
	}
	writeJSON(w, http.StatusOK, spec.InboxResponse{Packages: out})
}

// handleCommit 完成标记：包锁定，之后块不可再改。
func (a *API) handleCommit(w http.ResponseWriter, r *http.Request) {
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
	if p.PreludeDigest == nil || p.ReceivedCount != p.ChunkCount {
		writeError(w, r, spec.ErrPackageIncomplete, 0)
		return
	}
	updated, err := a.store.CommitPackage(r.Context(), p.ID, a.now())
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, r, spec.ErrPackageLocked, 0)
			return
		}
		a.internalError(w, r, "commit package", err)
		return
	}
	writeJSON(w, http.StatusOK, packageInfo(updated))
}

// handleProgress 续传进度：已收块的位图 + 缺失块。
func (a *API) handleProgress(w http.ResponseWriter, r *http.Request) {
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

	chunks, err := a.store.ListChunks(r.Context(), p.ID)
	if err != nil {
		a.internalError(w, r, "list chunks", err)
		return
	}
	indexes := make([]uint32, 0, len(chunks))
	metas := make([]spec.ChunkMeta, 0, len(chunks))
	present := make(map[int]struct{}, len(chunks))
	for _, c := range chunks {
		indexes = append(indexes, uint32(c.Index))
		present[c.Index] = struct{}{}
		metas = append(metas, spec.ChunkMeta{
			Index:         uint32(c.Index),
			CiphertextLen: uint32(c.CTLen),
			ReceivedAt:    c.ReceivedAt,
		})
	}
	missing := make([]uint32, 0, 64)
	for i := 0; i < p.ChunkCount; i++ {
		if _, ok := present[i]; ok {
			continue
		}
		if len(missing) >= maxMissingItems {
			break
		}
		missing = append(missing, uint32(i))
	}
	missingTotal := p.ChunkCount - len(chunks)

	remaining := 0
	if p.MaxDownloads > p.DownloadsUsed {
		remaining = p.MaxDownloads - p.DownloadsUsed
	}

	writeJSON(w, http.StatusOK, spec.ProgressResponse{
		PackageID:          p.ID,
		State:              p.State,
		PreludeReceived:    p.PreludeDigest != nil,
		PreludeLen:         uint32(p.PreludeLen),
		ChunkCount:         uint32(p.ChunkCount),
		ReceivedChunks:     uint32(p.ReceivedCount),
		ReceivedBitmap:     bitmapB64(buildBitmap(indexesToInt(indexes), uint32(p.ChunkCount))),
		ReceivedIndexes:    indexes,
		MissingIndexes:     missing,
		MissingTruncated:   len(missing) < missingTotal,
		DownloadsRemaining: uint32(remaining),
		ExpiresAt:          p.ExpiresAt,
		Chunks:             metas,
	})
}

// handleAck 接收方确认：扣次数；按策略立即删密文。
func (a *API) handleAck(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	p, ok := a.loadPackage(w, r, r.PathValue(spec.ParamPackageID))
	if !ok {
		return
	}
	if sess.Code != p.RecipientCode {
		writeError(w, r, spec.ErrForbidden, 0)
		return
	}
	var req spec.AckRequest
	if r.ContentLength != 0 && !a.decodeJSON(w, r, &req) {
		return
	}
	if p.State != spec.PackageReady {
		writeError(w, r, spec.ErrPackageIncomplete, 0)
		return
	}
	counts := true
	if req.CountsAsDownload != nil {
		counts = *req.CountsAsDownload
	}
	res, err := a.store.AckPackage(r.Context(), p.ID, counts, a.now())
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, r, spec.ErrPackageConflict, 0)
			return
		}
		a.internalError(w, r, "ack package", err)
		return
	}
	if res.ShouldPurge {
		a.purgePackage(r.Context(), p.ID)
	}
	_ = a.store.Audit(r.Context(), store.AuditEvent{
		At: a.now(), Kind: store.AuditPackageAck, Code: sess.Code, PackageID: p.ID,
		Outcome: res.Package.State, IP: a.clientIP(r),
	})
	writeJSON(w, http.StatusOK, spec.StateResponse{
		PackageID: p.ID,
		State:     res.Package.State,
		UpdatedAt: a.now(),
	})
}

// handleRevoke 发送方撤回：立刻终结并真删密文。
func (a *API) handleRevoke(w http.ResponseWriter, r *http.Request) {
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
	updated, err := a.store.RevokePackage(r.Context(), p.ID, sess.Code, a.now())
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, r, spec.ErrPackageConflict, 0)
			return
		}
		a.internalError(w, r, "revoke package", err)
		return
	}
	a.purgePackage(r.Context(), p.ID)
	_ = a.store.Audit(r.Context(), store.AuditEvent{
		At: a.now(), Kind: store.AuditPackageRevoke, Code: sess.Code, PackageID: p.ID,
		Outcome: "revoked", IP: a.clientIP(r),
	})
	writeJSON(w, http.StatusOK, spec.StateResponse{
		PackageID: updated.ID,
		State:     spec.PackageRevoked,
		UpdatedAt: a.now(),
	})
}

// purgePackage 物理删除密文 + 元数据，留一条墓碑。
func (a *API) purgePackage(ctx context.Context, id string) {
	if err := a.blobs.Purge(id); err != nil {
		a.log.Error("purge blobs failed", "packageId", id, "err", err.Error())
	}
	if err := a.store.PurgePackage(ctx, id, a.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		a.log.Error("purge package row failed", "packageId", id, "err", err.Error())
	}
}

func indexesToInt(in []uint32) []int {
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

// packageInfo 把库记录转成对外元信息。
func packageInfo(p store.Package) spec.PackageInfo {
	return spec.PackageInfo{
		PackageID:      p.ID,
		SenderCode:     p.SenderCode,
		RecipientCode:  p.RecipientCode,
		State:          p.State,
		ChunkCount:     uint32(p.ChunkCount),
		ChunkSize:      uint32(p.ChunkSize),
		PlaintextSize:  uint64(p.PlaintextSize),
		PreludeLen:     uint32(p.PreludeLen),
		MaxDownloads:   uint32(p.MaxDownloads),
		DownloadsUsed:  uint32(p.DownloadsUsed),
		ReceivedChunks: uint32(p.ReceivedCount),
		CreatedAt:      p.CreatedAt,
		ExpiresAt:      p.ExpiresAt,
		CommittedAt:    p.CommittedAt,
		TerminalReason: derefStr(p.TerminalReason),
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// validPackageShape 校验尺寸类元数据的自洽性（不解析任何密文内容）。
func validPackageShape(req spec.CreatePackageRequest) bool {
	if req.ChunkSize < 16 || req.ChunkSize > spec.DefaultMaxChunkSize {
		return false
	}
	if req.ChunkCount < 1 || req.ChunkCount > spec.DefaultMaxChunkCount {
		return false
	}
	if req.PlaintextSize > 4<<30 {
		return false
	}
	if req.PreludeLen < 1 || req.PreludeLen > spec.MaxPreludeLen {
		return false
	}
	return expectedChunkCount(req.PlaintextSize, req.ChunkSize) == req.ChunkCount
}
