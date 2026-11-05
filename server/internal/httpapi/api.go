// Package httpapi 是 HTTP 接口层，逐字对齐 docs/API.md v1（commit 376c5b5）。
//
// 分层约定：
//   - 对外名字（路径/字段/头/错误码）全部来自 internal/spec，这里不写字面量；
//   - 持久化在 internal/store，密文在 internal/blob；
//   - 服务端**从不解析** prelude 与块内容，只算长度与 SM3。
package httpapi

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/config"
	"github.com/spencerswagger/YanShu/server/internal/ratelimit"
	"github.com/spencerswagger/YanShu/server/internal/signal"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// API 是接口层依赖的集合。
type API struct {
	cfg      config.Config
	store    *store.Store
	blobs    blob.Store
	verifier auth.Verifier
	tokens   *auth.TokenIssuer
	limiter  ratelimit.Limiter
	locks    ratelimit.Lockout
	log      *slog.Logger
	now      func() time.Time
	hub      *signal.Hub

	// /v1/stats 的进程内缓存（60s）。
	statsMu    sync.Mutex
	statsCache spec.StatsResponse
	statsAt    time.Time
	// statsTTL 默认 60s；测试可置 0 关掉缓存。
	statsTTL time.Duration
}

// New 组装 API。
func New(cfg config.Config, st *store.Store, blobs blob.Store, v auth.Verifier, tokens *auth.TokenIssuer, l ratelimit.Limiter, locks ratelimit.Lockout, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{
		cfg:      cfg,
		store:    st,
		blobs:    blobs,
		verifier: v,
		tokens:   tokens,
		limiter:  l,
		locks:    locks,
		log:      log,
		now:      func() time.Time { return time.Now().UTC() },
		hub:      signal.New(),
		statsTTL: 60 * time.Second,
	}
}

// Handler 返回挂好中间件的路由（API.md §3）。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+spec.PathHealthz, a.handleHealthz)
	mux.HandleFunc("GET "+spec.PathConfig, a.handleConfig)

	mux.HandleFunc("POST "+spec.PathChallenges, a.handleChallenge)

	mux.HandleFunc("POST "+spec.PathCodes, a.handleRegisterCode)
	mux.HandleFunc("GET "+spec.PathCode, a.handleLookupCode)
	mux.HandleFunc("PATCH "+spec.PathCode, a.handleUpdateNickname)

	mux.HandleFunc("POST "+spec.PathTransfers, a.handleCreateTransfer)
	mux.HandleFunc("GET "+spec.PathTransfer, a.handleGetTransfer)
	mux.HandleFunc("GET "+spec.PathInbox, a.handleInbox)
	mux.HandleFunc("PUT "+spec.PathPrelude, a.handlePutPrelude)
	mux.HandleFunc("GET "+spec.PathPrelude, a.handleGetPrelude)
	mux.HandleFunc("PUT "+spec.PathChunk, a.handlePutChunk)
	mux.HandleFunc("GET "+spec.PathChunk, a.handleGetChunk)
	mux.HandleFunc("HEAD "+spec.PathChunk, a.handleHeadChunk)
	mux.HandleFunc("GET "+spec.PathStatus, a.handleStatus)
	mux.HandleFunc("POST "+spec.PathComplete, a.handleComplete)
	mux.HandleFunc("POST "+spec.PathAck, a.handleAck)
	mux.HandleFunc("POST "+spec.PathRevoke, a.handleRevoke)

	mux.HandleFunc("GET "+spec.PathWS, a.handleWS)
	mux.HandleFunc("POST "+spec.PathTransferReport, a.handleAbuseReport)
	mux.HandleFunc("GET "+spec.PathStats, a.handleStats)

	return a.withMiddleware(mux)
}

// clientIP 取客户端 IP；只有显式信任反代时才看 X-Forwarded-For。
func (a *API) clientIP(r *http.Request) string {
	if a.cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			host := xff
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					host = xff[:i]
					break
				}
			}
			return trimSpace(host)
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
