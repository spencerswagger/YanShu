package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEvent 是审计记录：只允许 API.md §2.1 的审计白名单字段
// （ip / method / path / status / bytes / ts / request_id）。
//
// 注意：Path 由 handler 传**路由模板**（如 `/v1/transfers/{transferId}`），
// 不传真实路径 —— 真实路径里的 transfer_id 是能力凭证，落库等于把凭证写进日志。
type AuditEvent struct {
	TS        time.Time
	Method    string
	Path      string
	Status    int
	Bytes     int64
	IP        string
	RequestID string
}

// Audit 落一条审计。失败不阻断业务，由调用方决定是否记日志。
func (s *Store) Audit(ctx context.Context, ev AuditEvent) error {
	var ip *string
	if ev.IP != "" {
		ip = &ev.IP
	}
	var reqID *string
	if ev.RequestID != "" {
		reqID = &ev.RequestID
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_events (ts, method, path, status, bytes, ip, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ev.TS, ev.Method, ev.Path, ev.Status, ev.Bytes, ip, reqID)
	if err != nil {
		return fmt.Errorf("store: audit: %w", err)
	}
	return nil
}
