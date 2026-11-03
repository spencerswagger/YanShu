package httpapi

import (
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// handleChallenge 下发一次性挑战（API.md §4.2）。
//
// 挑战**只绑 purpose**，不绑码：码由客户端签进 SIG_INPUT，服务端验签后比对
// X-YS-Code（§1.2 的唯一口径）。
func (a *API) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	var req spec.ChallengeRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	if spec.PurposeCode(req.Purpose) == 0 {
		fail(w, r, spec.ErrBadRequest)
		return
	}
	if !a.allow(w, r, "challenge:ip:"+a.clientIP(r), "ip", spec.DefaultLimits.ChallengePerIP) {
		return
	}

	nonce, err := auth.NewNonce()
	if err != nil {
		a.internalError(w, r, "nonce", err)
		return
	}
	id, err := auth.NewID()
	if err != nil {
		a.internalError(w, r, "challenge id", err)
		return
	}
	expiresAt := a.now().Add(spec.ChallengeTTL)
	if err := a.store.InsertChallenge(r.Context(), id, req.Purpose, nonce, expiresAt); err != nil {
		a.internalError(w, r, "insert challenge", err)
		return
	}

	writeJSON(w, http.StatusOK, spec.ChallengeResponse{
		ChallengeID: id,
		Nonce:       auth.B64.EncodeToString(nonce),
		Purpose:     req.Purpose,
		ExpiresAt:   spec.FormatTime(expiresAt),
	})
}
