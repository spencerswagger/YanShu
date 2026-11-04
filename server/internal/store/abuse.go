package store

import (
	"context"
	"fmt"
	"time"
)

// AbuseReport 是一条举报记录（API.md §11.5）。只含元数据，不含被举报内容。
type AbuseReport struct {
	ReportID     string
	ReporterCode string
	TransferID   string
	Reason       string
	Note         string
	ReporterIP   string
	CreatedAt    time.Time
}

// InsertAbuseReport 写入一条举报；同一 (reporter_code, transfer_id) 重复写入不会新增记录。
// 返回被存储的那条记录（重复时返回已有记录）以及是否本次新建。
func (s *Store) InsertAbuseReport(ctx context.Context, r AbuseReport) (AbuseReport, bool, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO abuse_reports (report_id, reporter_code, transfer_id, reason, note, reporter_ip, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (reporter_code, transfer_id) DO NOTHING`,
		r.ReportID, r.ReporterCode, r.TransferID, r.Reason, r.Note, nullableString(r.ReporterIP), r.CreatedAt)
	if err != nil {
		return AbuseReport{}, false, fmt.Errorf("store: insert abuse report: %w", err)
	}

	var out AbuseReport
	var ip *string
	err = s.pool.QueryRow(ctx, `
		SELECT report_id, reporter_code, transfer_id, reason, note, reporter_ip, created_at
		FROM abuse_reports WHERE reporter_code = $1 AND transfer_id = $2`,
		r.ReporterCode, r.TransferID).
		Scan(&out.ReportID, &out.ReporterCode, &out.TransferID, &out.Reason, &out.Note, &ip, &out.CreatedAt)
	if err != nil {
		return AbuseReport{}, false, fmt.Errorf("store: read abuse report: %w", err)
	}
	if ip != nil {
		out.ReporterIP = *ip
	}
	return out, tag.RowsAffected() == 1, nil
}

// CountDistinctReports 返回某传输被多少个不同码举报过。
func (s *Store) CountDistinctReports(ctx context.Context, transferID string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(DISTINCT reporter_code) FROM abuse_reports WHERE transfer_id = $1`,
		transferID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count abuse reports: %w", err)
	}
	return n, nil
}
