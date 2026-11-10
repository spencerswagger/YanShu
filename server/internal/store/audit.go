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

// DeleteOldAudit 批量删除早于 before 的审计行（audit_events 必须有保留期：
// 没有保留期的审计表迟早变成第二张大表，且带 IP，见 ADR-0002 §2.4）。
func (s *Store) DeleteOldAudit(ctx context.Context, before time.Time, batch int) (int64, error) {
	var total int64
	for {
		tag, err := s.pool.Exec(ctx, `
			DELETE FROM audit_events WHERE id IN (
				SELECT id FROM audit_events WHERE ts < $1 ORDER BY ts LIMIT $2
			)`, before, batch)
		if err != nil {
			return total, fmt.Errorf("store: delete old audit: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			return total, nil
		}
	}
}
