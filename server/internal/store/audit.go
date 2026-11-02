package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEvent 是审计记录：只记 IP / 时间 / 大小 / 次数，不记业务内容。
type AuditEvent struct {
	At        time.Time
	Kind      string
	Code      string
	PackageID string
	Bytes     int64
	Outcome   string
	IP        string
}

// 审计事件种类。
const (
	AuditCodeRegister  = "code.register"
	AuditCodeLookup    = "code.lookup"
	AuditPackageOpen   = "package.open"
	AuditPackageAck    = "package.ack"
	AuditPackageRevoke = "package.revoke"
	AuditPackagePurge  = "package.purge"
	AuditAuthFailure   = "auth.failure"
	AuditRateLimited   = "rate.limited"
)

// Audit 落一条审计。失败不阻断业务，只由调用方记录日志。
func (s *Store) Audit(ctx context.Context, ev AuditEvent) error {
	var ip *string
	if ev.IP != "" {
		ip = &ev.IP
	}
	var code *string
	if ev.Code != "" {
		code = &ev.Code
	}
	var pkg *string
	if ev.PackageID != "" {
		pkg = &ev.PackageID
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_events (at, kind, code, package_id, bytes, outcome, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ev.At, ev.Kind, code, pkg, ev.Bytes, ev.Outcome, ip)
	if err != nil {
		return fmt.Errorf("store: audit: %w", err)
	}
	return nil
}
