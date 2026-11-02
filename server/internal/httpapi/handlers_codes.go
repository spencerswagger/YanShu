package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// handleRegisterCode 是 POST /v1/codes（API.md §4.3）。
//
// 签名输入字段串 = CODE(4) ‖ PUBKEY(65)；码由公钥派生，服务端自行重算并比对。
// 撞码 → 409 CODE_TAKEN，服务端不改码（客户端换密钥对重试）。
func (a *API) handleRegisterCode(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	var req spec.RegisterCodeRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	code, err := gm.NormalizeCode(req.Code)
	if err != nil {
		fail(w, r, spec.ErrCodeFormatInvalid)
		return
	}
	pubKey, err := decodePublicKey(req.PublicKey)
	if err != nil {
		fail(w, r, spec.ErrBadRequest)
		return
	}
	nickname, err := sanitizeNickname(req.Nickname)
	if err != nil {
		fail(w, r, spec.ErrNicknameInvalid)
		return
	}
	// 码必须等于 SM3(公钥) 的派生结果；否则就是「码与公钥不匹配」。
	if gm.DeriveCode(pubKey) != code {
		fail(w, r, spec.ErrAuthCodeMismatch)
		return
	}

	if _, ok := a.verifySignature(w, r, spec.PurposeRegister, code, pubKey,
		func(signedCode string) ([]byte, error) { return auth.RegisterFields(signedCode, pubKey) }); !ok {
		return
	}

	now := a.now()
	row, err := a.store.InsertCode(r.Context(), code, pubKey, nickname, now)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCodeTaken), errors.Is(err, store.ErrPubkeyTaken):
			// 同一密钥对重复注册：幂等成功，不覆盖昵称（改昵称要走签名挑战）。
			if existing, gerr := a.store.GetCode(r.Context(), code); gerr == nil && auth.EqualBytes(existing.PublicKey, pubKey) {
				writeJSON(w, http.StatusOK, spec.CodeResponse{
					Code:         existing.Code,
					PublicKey:    auth.B64.EncodeToString(existing.PublicKey),
					Nickname:     existing.Nickname,
					RegisteredAt: spec.FormatTime(existing.RegisteredAt),
				})
				return
			}
			if errors.Is(err, store.ErrPubkeyTaken) {
				fail(w, r, spec.ErrPubkeyTaken)
				return
			}
			fail(w, r, spec.ErrCodeTaken)
		default:
			a.internalError(w, r, "insert code", err)
		}
		return
	}

	writeJSON(w, http.StatusCreated, spec.CodeResponse{
		Code:         row.Code,
		PublicKey:    auth.B64.EncodeToString(row.PublicKey),
		Nickname:     row.Nickname,
		RegisteredAt: spec.FormatTime(row.RegisteredAt),
	})
}

// handleLookupCode 是 GET /v1/codes/{code}（API.md §4.4）。
//
// 只返回 4 个字段；未知码与"已注销"统一 404，不区分原因。
// 失败锁定：同一 IP 对同一码连续 5 次未命中 → 423 CODE_LOCKED，锁定 1 分钟起逐次翻倍。
func (a *API) handleLookupCode(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	code, err := gm.NormalizeCode(r.PathValue(spec.ParamCode))
	if err != nil {
		fail(w, r, spec.ErrCodeFormatInvalid)
		return
	}
	ip := a.clientIP(r)
	if !a.allow(w, r, "lookup:ip:"+ip, "ip", spec.DefaultLimits.CodeLookupPerIP) {
		return
	}

	lockKey := "lookup:" + ip + ":" + code
	if locked, retry := a.locks.Locked(lockKey); locked {
		writeError(w, r, apiError{code: spec.ErrCodeLocked, scope: "ip", retryAfter: retry})
		return
	}

	row, err := a.store.GetCode(r.Context(), code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// 记录失败并按阈值锁定。
			if locked, retry := a.locks.Hit(lockKey,
				spec.DefaultLimits.CodeLockThreshold,
				time.Duration(spec.DefaultLimits.CodeLockBaseSeconds)*time.Second,
				time.Duration(spec.DefaultLimits.CodeLockMaxSeconds)*time.Second); locked {
				writeError(w, r, apiError{code: spec.ErrCodeLocked, scope: "ip", retryAfter: retry})
				return
			}
			fail(w, r, spec.ErrCodeNotFound)
			return
		}
		a.internalError(w, r, "get code", err)
		return
	}

	a.locks.Reset(lockKey)
	writeJSON(w, http.StatusOK, spec.CodeLookupResponse{
		Code:         row.Code,
		PublicKey:    auth.B64.EncodeToString(row.PublicKey),
		Nickname:     row.Nickname,
		RegisteredAt: spec.FormatTime(row.RegisteredAt),
	})
}

// handleUpdateNickname 是 PATCH /v1/codes/{code}（API.md §4.5）。
func (a *API) handleUpdateNickname(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	code, err := gm.NormalizeCode(r.PathValue(spec.ParamCode))
	if err != nil {
		fail(w, r, spec.ErrCodeFormatInvalid)
		return
	}
	var req spec.UpdateNicknameRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	nickname, err := sanitizeNickname(req.Nickname)
	if err != nil {
		fail(w, r, spec.ErrNicknameInvalid)
		return
	}
	if !a.allow(w, r, "nickname:code:"+code, "code", spec.DefaultLimits.NicknameUpdatePerCode) {
		return
	}

	if _, ok := a.verifySignature(w, r, spec.PurposeNicknameUpdate, code, nil,
		func(signedCode string) ([]byte, error) {
			return auth.NicknameUpdateFields(signedCode, nickname)
		}); !ok {
		return
	}

	now := a.now()
	if err := a.store.UpdateNickname(r.Context(), code, nickname, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrCodeNotFound)
			return
		}
		a.internalError(w, r, "update nickname", err)
		return
	}
	writeJSON(w, http.StatusOK, spec.UpdateNicknameResponse{
		Code:      code,
		Nickname:  nickname,
		UpdatedAt: spec.FormatTime(now),
	})
}
