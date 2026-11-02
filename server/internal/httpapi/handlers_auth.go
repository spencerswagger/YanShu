package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// handleChallenge 下发一次性 nonce 与「待签名消息」。
func (a *API) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req spec.ChallengeRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	var code string
	var pubKey []byte
	var contextBytes []byte

	switch req.Purpose {
	case spec.PurposeRegister:
		if !a.allow(w, r, "challenge:register:ip:"+ip, spec.DefaultLimits.CodeRegisterPerIP) {
			return
		}
		pub, err := decodePubKey(req.PubKey)
		if err != nil {
			writeError(w, r, spec.ErrPubKeyInvalid, 0)
			return
		}
		pubKey = pub
		// 码由公钥派生，客户端不能自选码（撞码时只能换密钥对）。
		code = gm.DeriveCode(pub)

	case spec.PurposeSession, spec.PurposeNickname:
		if !a.allow(w, r, "challenge:session:ip:"+ip, spec.DefaultLimits.SessionPerIP) {
			return
		}
		c, err := a.normalizeCode(req.Code)
		if err != nil {
			writeError(w, r, spec.ErrInvalidCode, 0)
			return
		}
		row, err := a.store.GetCode(ctx, c)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, r, spec.ErrCodeNotFound, 0)
				return
			}
			a.internalError(w, r, "get code", err)
			return
		}
		if !row.ExpiresAt.After(now) {
			writeError(w, r, spec.ErrCodeExpired, 0)
			return
		}
		code, pubKey = row.Code, row.PubKey
		if req.Purpose == spec.PurposeNickname {
			nn, err := sanitizeNickname(req.Nickname)
			if err != nil {
				writeError(w, r, spec.ErrNicknameInvalid, 0)
				return
			}
			contextBytes = []byte(nn)
		}

	default:
		writeError(w, r, spec.ErrInvalidRequest, 0)
		return
	}

	nonce, err := auth.NewNonce()
	if err != nil {
		a.internalError(w, r, "nonce", err)
		return
	}
	expiresAt := now.Add(a.cfg.ChallengeTTL).Truncate(time.Second)
	message := auth.BuildChallengeMessage(auth.ChallengeInput{
		Purpose:   req.Purpose,
		Code:      code,
		PubKey:    pubKey,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
		Context:   contextBytes,
	})

	challengeID := newID(16)
	if err := a.store.InsertChallenge(ctx, store.Challenge{
		ID:        challengeID,
		Purpose:   req.Purpose,
		Code:      code,
		PubKey:    pubKey,
		Message:   message,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}); err != nil {
		a.internalError(w, r, "insert challenge", err)
		return
	}

	writeJSON(w, http.StatusCreated, spec.ChallengeResponse{
		ChallengeID:     challengeID,
		Purpose:         req.Purpose,
		Nonce:           auth.B64.EncodeToString(nonce),
		Message:         auth.B64.EncodeToString(message),
		MessageEncoding: spec.MessageEncodingB64URL,
		ExpiresAt:       expiresAt,
	})
}

// handleSession 用签名换会话令牌。
func (a *API) handleSession(w http.ResponseWriter, r *http.Request) {
	var req spec.SessionRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	now := a.now()
	ip := a.clientIP(r)

	if a.checkLocked(w, r, "auth:fail:"+ip) {
		return
	}
	if !a.allow(w, r, "session:ip:"+ip, spec.DefaultLimits.SessionPerIP) {
		return
	}

	ch, err := a.store.GetChallenge(ctx, req.ChallengeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, spec.ErrChallengeNotFound, 0)
			return
		}
		a.internalError(w, r, "get challenge", err)
		return
	}
	if ch.Purpose != spec.PurposeSession {
		writeError(w, r, spec.ErrChallengeInvalid, 0)
		return
	}
	if ch.UsedAt != nil {
		writeError(w, r, spec.ErrChallengeUsed, 0)
		return
	}
	if !ch.ExpiresAt.After(now) {
		writeError(w, r, spec.ErrChallengeExpired, 0)
		return
	}
	if req.Code != "" {
		c, err := a.normalizeCode(req.Code)
		if err != nil || c != ch.Code {
			writeError(w, r, spec.ErrChallengeInvalid, 0)
			return
		}
	}
	if !a.verifySignature(w, r, ch.PubKey, ch.Message, req.Signature) {
		a.recordAuthFailure(ctx, ip, ch.Code)
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

	row, err := a.store.GetCode(ctx, ch.Code)
	if err != nil || !row.ExpiresAt.After(now) {
		writeError(w, r, spec.ErrCodeExpired, 0)
		return
	}

	token, hash, err := auth.NewToken()
	if err != nil {
		a.internalError(w, r, "token", err)
		return
	}
	expiresAt := now.Add(a.cfg.SessionTTL)
	if err := a.store.InsertSession(ctx, hash, ch.Code, now, expiresAt); err != nil {
		a.internalError(w, r, "insert session", err)
		return
	}
	a.limiter.Succeed("auth:code:" + ch.Code)

	writeJSON(w, http.StatusCreated, spec.SessionResponse{
		SessionToken: token,
		Code:         ch.Code,
		ExpiresAt:    expiresAt,
	})
}

// verifySignature 统一处理签名校验的三种结果。
func (a *API) verifySignature(w http.ResponseWriter, r *http.Request, pubKey, message []byte, sigB64 string) bool {
	sig, err := decodeB64(sigB64)
	if err != nil {
		writeError(w, r, spec.ErrSignatureInvalid, 0)
		return false
	}
	err = a.verifier.Verify(pubKey, message, sig)
	if err == nil {
		return true
	}
	if errors.Is(err, auth.ErrUnavailable) {
		// 骨架期的诚实回答：不是签名错，是服务端还没接 SM2。
		writeError(w, r, spec.ErrVerifierUnavailable, 0)
		return false
	}
	writeError(w, r, spec.ErrSignatureInvalid, 0)
	return false
}

// recordAuthFailure 记一次鉴权失败并做失败锁定。
func (a *API) recordAuthFailure(ctx context.Context, ip, code string) {
	threshold := spec.DefaultLimits.FailureThreshold
	lockFor := time.Duration(spec.DefaultLimits.FailureLockSeconds) * time.Second
	if _, _ = a.limiter.Fail("auth:fail:"+ip, threshold, lockFor); ip != "" {
		// 记审计但不阻断（失败本身已经返回 401）。
		_ = a.store.Audit(ctx, store.AuditEvent{
			At: a.now(), Kind: store.AuditAuthFailure, Code: code, Outcome: "failure", IP: ip,
		})
	}
}

// normalizeCode 归一化用户码；严格模式下只接受已归一化形式。
func (a *API) normalizeCode(raw string) (string, error) {
	if a.cfg.StrictCode {
		if !gm.IsNormalizedCode(raw) {
			return "", gm.ErrInvalidCode
		}
		return raw, nil
	}
	return gm.NormalizeCode(raw)
}

// newID 生成 n 字节随机 ID 的十六进制串。
func newID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 随机源不可用属于致命错误；返回固定串会被 DB 唯一约束挡住，不会静默复用。
		zeros := strings.Repeat("0", 2*n)
		return zeros
	}
	return hex.EncodeToString(b)
}

// internalError 记详细日志、对外只给通用错误码（不泄露内部细节）。
func (a *API) internalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	a.log.Error("internal error", "op", op, "requestId", requestIDFrom(r), "err", err.Error())
	writeError(w, r, spec.ErrInternal, 0)
}

// allow 是一次限速检查；超限时直接写 429 并返回 false。
func (a *API) allow(w http.ResponseWriter, r *http.Request, key string, l spec.Limit) bool {
	d := a.limiter.Take(key, l)
	if d.Allowed {
		return true
	}
	_ = a.store.Audit(r.Context(), store.AuditEvent{
		At: a.now(), Kind: store.AuditRateLimited, Outcome: "rate_limited", IP: a.clientIP(r),
	})
	writeError(w, r, spec.ErrRateLimited, d.RetryAfter)
	return false
}

// checkLocked 检查失败锁定；锁定中写 423 并返回 true。
func (a *API) checkLocked(w http.ResponseWriter, r *http.Request, key string) bool {
	locked, retry := a.limiter.Locked(key)
	if !locked {
		return false
	}
	writeError(w, r, spec.ErrLockedOut, retry)
	return true
}
