package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// handleRegisterCode 注册用户码。
//
// 流程：公钥 → 派生码 → 校验挑战签名 → 落库。
// 撞码（码已被别人的公钥占用）→ 409 code_taken，**服务端不改码**，
// 由客户端重新生成密钥对再来（这是基线里拍死的交互）。
func (a *API) handleRegisterCode(w http.ResponseWriter, r *http.Request) {
	var req spec.RegisterCodeRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	if a.checkLocked(w, r, "register:ip:"+ip) || a.checkLocked(w, r, "auth:fail:"+ip) {
		return
	}
	if !a.allow(w, r, "register:ip:"+ip, spec.DefaultLimits.CodeRegisterPerIP) {
		return
	}

	pubKey, err := decodePubKey(req.PubKey)
	if err != nil {
		writeError(w, r, spec.ErrPubKeyInvalid, 0)
		return
	}
	derived := gm.DeriveCode(pubKey)
	if req.Code != "" {
		c, err := a.normalizeCode(req.Code)
		if err != nil || c != derived {
			writeError(w, r, spec.ErrCodeMismatch, 0)
			return
		}
	}
	nickname, err := sanitizeNickname(req.Nickname)
	if err != nil {
		writeError(w, r, spec.ErrNicknameInvalid, 0)
		return
	}

	ch, ok := a.loadChallenge(w, r, req.ChallengeID, spec.PurposeRegister, derived, pubKey)
	if !ok {
		return
	}
	if !a.verifySignature(w, r, pubKey, ch.Message, req.Signature) {
		a.recordAuthFailure(ctx, ip, derived)
		return
	}
	used, err := a.store.UseChallenge(ctx, ch.ID, now)
	if err != nil {
		a.internalError(w, r, "use challenge", err)
		return
	}
	if !used {
		writeError(w, r, spec.ErrChallengeUsed, 0)
		return
	}

	code, err := a.store.InsertCode(ctx, derived, pubKey, nickname, now, now.Add(a.cfg.CodeTTL))
	if err != nil {
		if errors.Is(err, store.ErrCodeTaken) {
			existing, gerr := a.store.GetCode(ctx, derived)
			if gerr == nil && auth.EqualBytes(existing.PubKey, pubKey) {
				// 同一密钥对重复注册：幂等成功，不覆盖昵称（改昵称要走签名挑战）。
				_ = a.store.TouchCode(ctx, derived, now, now.Add(a.cfg.CodeTTL))
				writeJSON(w, http.StatusOK, codeInfo(existing, spec.CodeActive, now))
				return
			}
			writeError(w, r, spec.ErrCodeTaken, 0)
			return
		}
		a.internalError(w, r, "insert code", err)
		return
	}

	a.limiter.Succeed("register:ip:" + ip)
	_ = a.store.Audit(ctx, store.AuditEvent{
		At: now, Kind: store.AuditCodeRegister, Code: code.Code, Outcome: "ok", IP: ip,
	})
	writeJSON(w, http.StatusCreated, codeInfo(code, spec.CodeActive, now))
}

// handleGetCode 按 4 位码查公钥与昵称。
//
// 严格限速 + 失败锁定：4 位码只有 104 万组合，不限速就是可枚举。
// 「不存在」与「已过期」刻意区分（客户端据此决定是否换密钥对），
// 但除这两者之外不透露任何信息。
func (a *API) handleGetCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	code, err := a.normalizeCode(r.PathValue(spec.ParamCode))
	if err != nil {
		writeError(w, r, spec.ErrInvalidCode, 0)
		return
	}

	failKey := "lookup:fail:" + ip + ":" + code
	if a.checkLocked(w, r, failKey) {
		return
	}
	if !a.allow(w, r, "lookup:ip:"+ip, spec.DefaultLimits.CodeLookupPerIP) {
		return
	}
	if !a.allow(w, r, "lookup:code:"+code, spec.DefaultLimits.CodeLookupPerCode) {
		return
	}

	row, err := a.store.GetCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.recordLookupFailure(ctx, failKey, ip, code)
			writeError(w, r, spec.ErrCodeNotFound, 0)
			return
		}
		a.internalError(w, r, "get code", err)
		return
	}
	if !row.ExpiresAt.After(now) {
		_ = a.store.Audit(ctx, store.AuditEvent{
			At: now, Kind: store.AuditCodeLookup, Code: code, Outcome: "expired", IP: ip,
		})
		writeError(w, r, spec.ErrCodeExpired, 0)
		return
	}

	a.limiter.Succeed(failKey)
	_ = a.store.TouchCode(ctx, code, now, now.Add(a.cfg.CodeTTL))
	_ = a.store.Audit(ctx, store.AuditEvent{
		At: now, Kind: store.AuditCodeLookup, Code: code, Outcome: "ok", IP: ip,
	})
	writeJSON(w, http.StatusOK, codeInfo(row, spec.CodeActive, now))
}

// handleUpdateNickname 改昵称：必须带该码的会话 + 绑定新昵称的签名挑战。
func (a *API) handleUpdateNickname(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	code, err := a.normalizeCode(r.PathValue(spec.ParamCode))
	if err != nil {
		writeError(w, r, spec.ErrInvalidCode, 0)
		return
	}
	if _, ok := a.requireOwnSession(w, r, code); !ok {
		return
	}

	var req spec.UpdateNicknameRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	nickname, err := sanitizeNickname(req.Nickname)
	if err != nil {
		writeError(w, r, spec.ErrNicknameInvalid, 0)
		return
	}

	row, err := a.store.GetCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, spec.ErrCodeNotFound, 0)
			return
		}
		a.internalError(w, r, "get code", err)
		return
	}

	ch, ok := a.loadChallenge(w, r, req.ChallengeID, spec.PurposeNickname, code, row.PubKey)
	if !ok {
		return
	}
	// 挑战消息里绑了新昵称：换个昵称重放同一个签名会验不过。
	if challengeContext(ch.Message) != auth.B64.EncodeToString([]byte(nickname)) {
		writeError(w, r, spec.ErrChallengeInvalid, 0)
		return
	}
	if !a.verifySignature(w, r, row.PubKey, ch.Message, req.Signature) {
		a.recordAuthFailure(ctx, ip, code)
		return
	}
	used, err := a.store.UseChallenge(ctx, ch.ID, now)
	if err != nil {
		a.internalError(w, r, "use challenge", err)
		return
	}
	if !used {
		writeError(w, r, spec.ErrChallengeUsed, 0)
		return
	}
	if err := a.store.UpdateNickname(ctx, code, nickname, now); err != nil {
		a.internalError(w, r, "update nickname", err)
		return
	}
	row.Nickname = nickname
	row.UpdatedAt = now
	writeJSON(w, http.StatusOK, codeInfo(row, spec.CodeActive, now))
}

// loadChallenge 取挑战并做通用校验（用途/归属/未用/未过期/公钥一致）。
func (a *API) loadChallenge(w http.ResponseWriter, r *http.Request, id, purpose, code string, pubKey []byte) (store.Challenge, bool) {
	ch, err := a.store.GetChallenge(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, spec.ErrChallengeNotFound, 0)
			return store.Challenge{}, false
		}
		a.internalError(w, r, "get challenge", err)
		return store.Challenge{}, false
	}
	if ch.Purpose != purpose || ch.Code != code || !auth.EqualBytes(ch.PubKey, pubKey) {
		writeError(w, r, spec.ErrChallengeInvalid, 0)
		return store.Challenge{}, false
	}
	if ch.UsedAt != nil {
		writeError(w, r, spec.ErrChallengeUsed, 0)
		return store.Challenge{}, false
	}
	if !ch.ExpiresAt.After(a.now()) {
		writeError(w, r, spec.ErrChallengeExpired, 0)
		return store.Challenge{}, false
	}
	return ch, true
}

// challengeContext 取出挑战消息里 `context=` 行的值。
func challengeContext(msg []byte) string {
	const prefix = "context="
	for _, line := range strings.Split(string(msg), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// recordLookupFailure 记一次查询失败并做锁定（按 IP+码 组合，避免误锁别人的码）。
func (a *API) recordLookupFailure(ctx context.Context, failKey, ip, code string) {
	threshold := spec.DefaultLimits.FailureThreshold
	lockFor := time.Duration(spec.DefaultLimits.FailureLockSeconds) * time.Second
	a.limiter.Fail(failKey, threshold, lockFor)
	_ = a.store.Audit(ctx, store.AuditEvent{
		At: a.now(), Kind: store.AuditCodeLookup, Code: code, Outcome: "not_found", IP: ip,
	})
}

// codeInfo 把库里的记录转成对外结构。
func codeInfo(c store.Code, status string, now time.Time) spec.CodeInfo {
	_ = now
	return spec.CodeInfo{
		Code:         c.Code,
		PubKey:       auth.B64.EncodeToString(c.PubKey),
		Nickname:     c.Nickname,
		Status:       status,
		RegisteredAt: c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		ExpiresAt:    c.ExpiresAt,
	}
}
