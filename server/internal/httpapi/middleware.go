package httpapi

import (
	"context"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

// withMiddleware 串起：panic 兜底 → 请求 ID → 访问日志 → 审计。
func (a *API) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get(spec.HeaderRequestID)
		if !validRequestID(reqID) {
			reqID = newRequestID()
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxRequestID, reqID))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rec.Header().Set(spec.HeaderRequestID, reqID)

		defer func() {
			if v := recover(); v != nil {
				a.log.Error("panic recovered", "requestId", reqID, "panic", v, "stack", string(debug.Stack()))
				fail(rec, r, spec.ErrInternal)
			}
			pattern := r.Pattern
			if pattern == "" {
				pattern = "unmatched"
			}
			// 日志只记路由模板：不记路径参数（transfer_id 是能力凭证）、不记查询串、不记请求体。
			a.log.Info("http",
				"requestId", reqID,
				"method", r.Method,
				"route", pattern,
				"status", rec.status,
				"bytes", rec.bytes,
				"durationMs", time.Since(start).Milliseconds(),
			)
			a.audit(r, rec.status, rec.bytes)
		}()

		next.ServeHTTP(rec, r)
	})
}

// validRequestID 只接受 ≤64 字符的可打印 ASCII（API.md §0.1）。
func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

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

// storeAuditEvent 组装审计记录；path 用路由模板，不落真实路径参数。
func storeAuditEvent(r *http.Request, ip, path string, status int, bytes int64, reqID string, now time.Time) store.AuditEvent {
	return store.AuditEvent{
		TS:        now,
		Method:    r.Method,
		Path:      path,
		Status:    status,
		Bytes:     bytes,
		IP:        ip,
		RequestID: reqID,
	}
}
