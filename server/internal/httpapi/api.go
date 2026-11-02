// Package httpapi 是 HTTP 接口层。
//
// 分层约定：
//   - 所有对外名字（路径/字段/错误码）来自 internal/spec，这里不写字面量；
//   - 这里只做协议与鉴权边界，持久化在 internal/store，密文在 internal/blob；
//   - 服务端**从不解析** prelude 与块的内容，只当不透明字节存取。
package httpapi

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/config"
	"github.com/spencerswagger/YanShu/server/internal/ratelimit"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// API 是接口层依赖的集合。
type API struct {
	cfg      config.Config
	store    *store.Store
	blobs    blob.Store
	verifier auth.Verifier
	limiter  ratelimit.Limiter
	log      *slog.Logger
	now      func() time.Time
}

// New 组装 API。
func New(cfg config.Config, st *store.Store, blobs blob.Store, v auth.Verifier, l ratelimit.Limiter, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{
		cfg:      cfg,
		store:    st,
		blobs:    blobs,
		verifier: v,
		limiter:  l,
		log:      log,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Handler 返回挂好中间件的路由。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// 健康检查与信令桩。
	mux.HandleFunc("GET "+spec.PathHealthz, a.handleHealthz)
	mux.HandleFunc("GET "+spec.PathWS, a.handleWS)

	// 挑战与会话。
	mux.HandleFunc("POST "+spec.PathChallenges, a.handleChallenge)
	mux.HandleFunc("POST "+spec.PathSessions, a.handleSession)

	// 用户码。
	mux.HandleFunc("POST "+spec.PathCodes, a.handleRegisterCode)
	mux.HandleFunc("GET "+spec.PathCode, a.handleGetCode)
	mux.HandleFunc("PATCH "+spec.PathCode, a.handleUpdateNickname)

	// 收件箱与包。
	mux.HandleFunc("GET "+spec.PathInbox, a.handleInbox)
	mux.HandleFunc("POST "+spec.PathPackages, a.handleCreatePackage)
	mux.HandleFunc("GET "+spec.PathPackage, a.handleGetPackage)
	mux.HandleFunc("PUT "+spec.PathPrelude, a.handlePutPrelude)
	mux.HandleFunc("GET "+spec.PathPrelude, a.handleGetPrelude)
	mux.HandleFunc("PUT "+spec.PathChunk, a.handlePutChunk)
	mux.HandleFunc("GET "+spec.PathChunk, a.handleGetChunk)
	mux.HandleFunc("POST "+spec.PathCommit, a.handleCommit)
	mux.HandleFunc("GET "+spec.PathProgress, a.handleProgress)
	mux.HandleFunc("POST "+spec.PathAck, a.handleAck)
	mux.HandleFunc("POST "+spec.PathRevoke, a.handleRevoke)

	return a.withMiddleware(mux)
}

// clientIP 取客户端 IP；只有显式信任反代时才看 X-Forwarded-For。
func (a *API) clientIP(r *http.Request) string {
	if a.cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return trimSpace(xff[:i])
				}
			}
			return trimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
