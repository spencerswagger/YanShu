package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

type ctxKey int

const ctxRequestID ctxKey = iota

const maxJSONBody = 64 << 10

// withMiddleware 串起：panic 兜底 → request id → 访问日志。
func (a *API) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get(spec.HeaderRequestID)
		if reqID == "" || len(reqID) > 64 {
			reqID = newRequestID()
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxRequestID, reqID))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rec.Header().Set(spec.HeaderRequestID, reqID)

		defer func() {
			if v := recover(); v != nil {
				a.log.Error("panic recovered", "requestId", reqID, "panic", v, "stack", string(debug.Stack()))
				writeError(rec, r, spec.ErrInternal, 0)
			}
			// 只记路由模板与状态，不记路径参数、请求体、令牌。
			pattern := r.Pattern
			if pattern == "" {
				pattern = "unmatched"
			}
			a.log.Info("http",
				"requestId", reqID,
				"method", r.Method,
				"route", pattern,
				"status", rec.status,
				"bytes", rec.bytes,
				"durationMs", time.Since(start).Milliseconds(),
			)
		}()

		next.ServeHTTP(rec, r)
	})
}

// statusRecorder 记录状态码与响应字节数。
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unknown"
	}
	return hex.EncodeToString(b[:])
}

func requestIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// writeJSON 写 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", spec.ContentTypeJSON)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// 头已发出，无法再改状态码，只能放弃。
		return
	}
}

// writeError 写统一错误体。retryAfter>0 时补 Retry-After 头。
func writeError(w http.ResponseWriter, r *http.Request, code spec.ErrorCode, retryAfter time.Duration) {
	body := spec.ErrorResponse{Error: spec.ErrorBody{
		Code:      string(code),
		Message:   code.Message(),
		RequestID: requestIDFrom(r),
	}}
	if retryAfter > 0 {
		secs := int(retryAfter.Seconds() + 0.5)
		if secs < 1 {
			secs = 1
		}
		body.Error.RetryAfterMs = retryAfter.Milliseconds()
		w.Header().Set(spec.HeaderRetryAfter, itoa(secs))
	}
	writeJSON(w, code.Status(), body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// decodeJSON 解码请求体；未知字段直接报错（契约漂移要当场发现）。
func (a *API) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, r, spec.ErrPayloadTooLarge, 0)
			return false
		}
		writeError(w, r, spec.ErrInvalidRequest, 0)
		return false
	}
	// 只允许一个 JSON 值，防"多段拼接"绕过。
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, r, spec.ErrInvalidRequest, 0)
		return false
	}
	return true
}

// readBlobBody 读取不透明二进制请求体，超过 limit 直接 413。
func (a *API) readBlobBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if limit <= 0 {
		writeError(w, r, spec.ErrInternal, 0)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, r, spec.ErrPayloadTooLarge, 0)
			return nil, false
		}
		writeError(w, r, spec.ErrInvalidRequest, 0)
		return nil, false
	}
	return data, true
}

// bearerToken 从 Authorization 头取 Bearer 令牌。
func bearerToken(r *http.Request) string {
	v := r.Header.Get(spec.HeaderAuthorization)
	const prefix = "bearer "
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}
