package httpapi

import (
	"errors"
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// requireSession 从 Authorization: Bearer 取会话。
//
// 鉴权边界（写清楚，别靠读代码猜）：
//   - 没有令牌 → 401 unauthorized；
//   - 令牌过期 / 码过期 → 401 session_expired（不让客户端区分"令牌错"与"过期"）；
//   - 令牌只存 SHA-256，日志里永不出现原文。
func (a *API) requireSession(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, r, spec.ErrUnauthorized, 0)
		return store.Session{}, false
	}
	sess, err := a.store.GetSession(r.Context(), auth.HashToken(token), a.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, spec.ErrSessionExpired, 0)
			return store.Session{}, false
		}
		a.internalError(w, r, "get session", err)
		return store.Session{}, false
	}
	return sess, true
}

// requireOwnSession 要求会话属于 path 里的码。
func (a *API) requireOwnSession(w http.ResponseWriter, r *http.Request, code string) (store.Session, bool) {
	sess, ok := a.requireSession(w, r)
	if !ok {
		return store.Session{}, false
	}
	if sess.Code != code {
		writeError(w, r, spec.ErrForbidden, 0)
		return store.Session{}, false
	}
	return sess, true
}

// canReadPackage 判定某码能否读取包内容。
//
// 允许：发送方（续传/自检）、接收方（下载）。
// 拒绝：其他任何码 —— 4 位码只是索引，不是访问凭据；真正的保密性来自端侧加密。
func canReadPackage(p store.Package, code string) bool {
	return code == p.SenderCode || code == p.RecipientCode
}

// packageStateError 把终结态映射成对外错误码。
func packageStateError(state string) spec.ErrorCode {
	switch state {
	case spec.PackageExpired:
		return spec.ErrPackageExpired
	case spec.PackageRevoked:
		return spec.ErrPackageRevoked
	case spec.PackageExhausted:
		return spec.ErrPackageExhausted
	case spec.PackagePurged:
		return spec.ErrPackagePurged
	}
	return spec.ErrPackageNotFound
}

// loadPackage 取包；不存在时看墓碑，保证「已过期/已撤回/已领取/已删除」可区分。
func (a *API) loadPackage(w http.ResponseWriter, r *http.Request, id string) (store.Package, bool) {
	p, err := a.store.GetPackage(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			tomb, terr := a.store.GetTombstone(r.Context(), id)
			if terr == nil {
				writeError(w, r, packageStateError(tomb.State), 0)
				return store.Package{}, false
			}
			writeError(w, r, spec.ErrPackageNotFound, 0)
			return store.Package{}, false
		}
		a.internalError(w, r, "get package", err)
		return store.Package{}, false
	}
	if spec.IsTerminalPackageState(p.State) {
		writeError(w, r, packageStateError(p.State), 0)
		return store.Package{}, false
	}
	return p, true
}
