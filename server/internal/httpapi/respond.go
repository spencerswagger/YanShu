package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

type ctxKey int

const ctxRequestID ctxKey = iota

// maxJSONBody 是 JSON 端点的请求体上限（远大于任何合法 JSON 报文）。
const maxJSONBody = 64 << 10

// apiError 描述一次失败响应。
type apiError struct {
	code       spec.ErrorCode
	scope      string
	retryAfter time.Duration
	missing    []spec.MissingRange
}

// writeError 写统一错误信封（API.md §0.2）。
func writeError(w http.ResponseWriter, r *http.Request, e apiError) {
	body := spec.ErrorResponse{Error: spec.ErrorBody{
		Code:      string(e.code),
		Message:   e.code.Message(),
		Scope:     e.scope,
		RequestID: requestIDFrom(r),
	}}
	if e.retryAfter > 0 {
		secs := int(e.retryAfter.Seconds() + 0.5)
		if secs < 1 {
			secs = 1
		}
		body.Error.RetryAfter = &secs
		w.Header().Set(spec.HeaderRetryAfter, strconv.Itoa(secs))
		w.Header().Set(spec.HeaderRateLimitReset, strconv.Itoa(secs))
	}
	if len(e.missing) > 0 {
		body.Missing = e.missing
	}
	writeJSON(w, e.code.Status(), body)
}

// fail 是 writeError 的简写。
func fail(w http.ResponseWriter, r *http.Request, code spec.ErrorCode) {
	writeError(w, r, apiError{code: code})
}

// writeJSON 写 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(spec.HeaderContentType, spec.ContentTypeJSON)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set(spec.HeaderAcceptRanges, "none")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func requestIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b[:])
}

// decodeJSON 解码请求体。
//
// API.md §0.1：未知字段 MUST 拒绝（FIELD_NOT_ALLOWED）—— 这是「服务端不落明文」
// 的可测试边界：客户端若试图塞 filename 之类的字段，必须报错而不是忽略。
func (a *API) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			fail(w, r, spec.ErrPayloadTooLarge)
		case strings.Contains(err.Error(), "unknown field"):
			fail(w, r, spec.ErrFieldNotAllowed)
		default:
			fail(w, r, spec.ErrBadRequest)
		}
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		fail(w, r, spec.ErrBadRequest)
		return false
	}
	return true
}

// requireOctetStream 强制二进制端点只接受 application/octet-stream（API.md §2.3）。
func (a *API) requireOctetStream(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get(spec.HeaderContentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(strings.ToLower(ct)) != spec.ContentTypeBinary {
		fail(w, r, spec.ErrContentTypeUnsupported)
		return false
	}
	return true
}

// validateQuery 拒绝白名单之外的查询参数（API.md §0.1）。
func (a *API) validateQuery(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	ok := make(map[string]struct{}, len(allowed))
	for _, k := range allowed {
		ok[k] = struct{}{}
	}
	for k := range r.URL.Query() {
		if _, exists := ok[k]; !exists {
			fail(w, r, spec.ErrBadRequest)
			return false
		}
	}
	return true
}

// allow 是一次限速检查；超限写 429（带 scope 与 Retry-After）。
func (a *API) allow(w http.ResponseWriter, r *http.Request, key, scope string, l spec.Limit) bool {
	d := a.limiter.Take(key, l)
	if d.Allowed {
		w.Header().Set(spec.HeaderRateLimitLimit, strconv.Itoa(d.Limit))
		w.Header().Set(spec.HeaderRateLimitRemaining, strconv.Itoa(d.Remaining))
		return true
	}
	writeError(w, r, apiError{code: spec.ErrRateLimited, scope: scope, retryAfter: d.RetryAfter})
	return false
}

// audit 记一条审计（白名单字段）。失败只记日志，不影响响应。
func (a *API) audit(r *http.Request, status int, bytes int64) {
	path := r.Pattern
	if path == "" {
		path = "unmatched"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
	defer cancel()
	if err := a.store.Audit(ctx, storeAuditEvent(r, a.clientIP(r), path, status, bytes, requestIDFrom(r), a.now())); err != nil {
		a.log.Warn("audit failed", "err", err.Error())
	}
}

// internalError 记详细日志、对外只给通用错误码。
func (a *API) internalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	a.log.Error("internal error", "op", op, "requestId", requestIDFrom(r), "err", err.Error())
	fail(w, r, spec.ErrInternal)
}
