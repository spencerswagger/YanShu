package httpapi

import (
	"errors"
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// requireAuthHeaders 先做「三个 X-YS-* 头是否齐」的检查，保证缺头时返回
// AUTH_MISSING 而不是先被请求体解析抢答（API.md §1.4）。
func (a *API) requireAuthHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get(spec.HeaderCode) == "" ||
		r.Header.Get(spec.HeaderChallengeID) == "" ||
		r.Header.Get(spec.HeaderSignature) == "" {
		fail(w, r, spec.ErrAuthMissing)
		return false
	}
	return true
}

// verifySignature 是全部写操作的统一门（API.md §1.2 / §1.3）。
//
// 步骤：
//  1. 取 X-YS-Code / X-YS-Challenge-Id / X-YS-Signature，缺任一 → AUTH_MISSING；
//  2. 归一化码，非法 → CODE_FORMAT_INVALID；
//  3. 请求里另有码（body/path）时必须与头里的码逐字一致 → 否则 AUTH_CODE_MISMATCH；
//  4. **先作废挑战**（成功失败都作废，防爆破），过期/已用/用途不符 → AUTH_CHALLENGE_INVALID；
//  5. 按 purpose 拼 SIG_INPUT（`YSAUTH1` ‖ PURPOSE ‖ NONCE ‖ 字段串），验签；
//  6. 失败 → AUTH_SIGNATURE_INVALID；验签实现不可用 → 503 SERVICE_UNAVAILABLE。
//
// 返回签名者的 code。
func (a *API) verifySignature(
	w http.ResponseWriter,
	r *http.Request,
	purpose string,
	requestCode string,
	pubKey []byte,
	buildFields func(code string) ([]byte, error),
) (string, bool) {
	codeHdr := r.Header.Get(spec.HeaderCode)
	challengeID := r.Header.Get(spec.HeaderChallengeID)
	signature := r.Header.Get(spec.HeaderSignature)
	if codeHdr == "" || challengeID == "" || signature == "" {
		fail(w, r, spec.ErrAuthMissing)
		return "", false
	}

	code, err := gm.NormalizeCode(codeHdr)
	if err != nil {
		fail(w, r, spec.ErrCodeFormatInvalid)
		return "", false
	}
	if requestCode != "" && requestCode != code {
		fail(w, r, spec.ErrAuthCodeMismatch)
		return "", false
	}

	ch, err := a.store.ConsumeChallenge(r.Context(), challengeID, a.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrAuthChallengeInvalid)
			return "", false
		}
		a.internalError(w, r, "consume challenge", err)
		return "", false
	}
	if ch.Purpose != purpose {
		fail(w, r, spec.ErrAuthChallengeInvalid)
		return "", false
	}

	if pubKey == nil {
		row, err := a.store.GetCode(r.Context(), code)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				fail(w, r, spec.ErrCodeNotFound)
				return "", false
			}
			a.internalError(w, r, "get code", err)
			return "", false
		}
		pubKey = row.PublicKey
	}

	fields, err := buildFields(code)
	if err != nil {
		// 字段不合法属于请求问题，不是签名问题。
		fail(w, r, spec.ErrBadRequest)
		return "", false
	}
	sigInput := auth.BuildSignInput(spec.PurposeCode(purpose), ch.Nonce, fields)

	sig, err := auth.B64.DecodeString(signature)
	if err != nil {
		a.noteAuthFailure(w, r, code)
		return "", false
	}
	if err := a.verifier.Verify(pubKey, sigInput, sig); err != nil {
		if errors.Is(err, auth.ErrUnavailable) {
			fail(w, r, spec.ErrServiceUnavailable)
			return "", false
		}
		a.noteAuthFailure(w, r, code)
		return "", false
	}
	return code, true
}

// noteAuthFailure 记一次签名失败；同一码 10 次/小时 → 429（scope=code）。
func (a *API) noteAuthFailure(w http.ResponseWriter, r *http.Request, code string) {
	d := a.limiter.Take("authfail:"+code, spec.DefaultLimits.AuthFailurePerCode)
	if !d.Allowed {
		writeError(w, r, apiError{code: spec.ErrRateLimited, scope: "code", retryAfter: d.RetryAfter})
		return
	}
	fail(w, r, spec.ErrAuthSignatureInvalid)
}
