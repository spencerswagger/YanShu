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

// routes 是路由表**唯一声明处**（API.md §3）：既用于注册 handler，也用于兜底判定（ADR-0003）。
// 漏写一行 → 该路由被兜底成 404，`TestRoutesAreAllRegistered` 会点名。
func (a *API) routes() []routeEntry {
	return []routeEntry{
		{http.MethodGet, spec.PathHealthz, a.handleHealthz},
		{http.MethodGet, spec.PathConfig, a.handleConfig},
		{http.MethodPost, spec.PathChallenges, a.handleChallenge},

		{http.MethodPost, spec.PathCodes, a.handleRegisterCode},
		{http.MethodGet, spec.PathCode, a.handleLookupCode},
		{http.MethodPatch, spec.PathCode, a.handleUpdateNickname},

		{http.MethodPost, spec.PathTransfers, a.handleCreateTransfer},
		{http.MethodPut, spec.PathPrelude, a.handlePutPrelude},
		{http.MethodGet, spec.PathPrelude, a.handleGetPrelude},
		{http.MethodPut, spec.PathChunk, a.handlePutChunk},
		{http.MethodGet, spec.PathChunk, a.handleGetChunk},
		{http.MethodHead, spec.PathChunk, a.handleHeadChunk},
		{http.MethodGet, spec.PathStatus, a.handleStatus},
		{http.MethodPost, spec.PathComplete, a.handleComplete},
		{http.MethodPost, spec.PathAck, a.handleAck},
		{http.MethodPost, spec.PathRevoke, a.handleRevoke},
		{http.MethodGet, spec.PathInbox, a.handleInbox},
		{http.MethodGet, spec.PathTransfer, a.handleGetTransfer},
		{http.MethodPost, spec.PathTransferReport, a.handleAbuseReport},

		{http.MethodGet, spec.PathWS, a.handleWS},
		{http.MethodGet, spec.PathStats, a.handleStats},
	}
}

// Handler 返回挂好中间件的路由。
func (a *API) Handler() http.Handler {
	routes := a.routes()
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.HandleFunc(rt.key(), rt.handler)
	}

	return a.withMiddleware(guardUnrouted(mux, routes))
}

// guardUnrouted 把 ServeMux 自己抢答的 404/405 换成契约错误信封（ADR-0003）。
//
// 判据用 `ServeMux.Handler`：模板为空意味着"没有任何注册的模式同时匹配方法+路径"，
// 也就是 mux 正要自己回 404/405。命中真实 handler 时模板非空，原样透传，不干预。
func guardUnrouted(mux *http.ServeMux, routes []routeEntry) http.Handler {
	fallback := newUnrouted(routes).handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern == "" {
			fallback(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
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
