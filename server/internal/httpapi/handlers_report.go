package httpapi

// POST /v1/transfers/{id}/report（API.md §11.5）
//
// 只记录：写一条举报、维护 distinct_reports、记审计。**不改传输状态、不删密文、不通知上传者**。
// 下架走运维的撤回路径，v1 不提供管理端点。

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

var abuseReasons = map[string]bool{"ABUSE": true, "CSAM": true, "MALWARE": true, "OTHER": true}

func (a *API) handleAbuseReport(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	if !a.requireAuthHeaders(w, r) {
		return
	}
	id, ok := a.transferIDParam(w, r)
	if !ok {
		return
	}

	// 签名覆盖 REPORTER_CODE 与 TRANSFER_ID（purpose 0x09），并与 X-YS-Code 逐字节比对。
	code, ok := a.verifySignature(w, r, spec.PurposeAbuseReport, "", nil,
		func(signedCode string) ([]byte, error) { return auth.AbuseReportFields(signedCode, id) })
	if !ok {
		return
	}

	// 限速：按码 5 次/小时、按 IP 20 次/小时（429 + Retry-After，scope 不泄露对象存在性）。
	if !a.allow(w, r, "report:code:"+code, "code", spec.DefaultLimits.AbuseReportPerCode) {
		return
	}
	if !a.allow(w, r, "report:ip:"+a.clientIP(r), "ip", spec.DefaultLimits.AbuseReportPerIP) {
		return
	}

	var req spec.AbuseReportRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	if !abuseReasons[req.Reason] {
		fail(w, r, spec.ErrBadRequest)
		return
	}
	// 契约未给 note 超长的专属码，按字段级校验统一回 BAD_REQUEST（不自创错误码）。
	if len(req.Note) > 200 {
		fail(w, r, spec.ErrBadRequest)
		return
	}
	for i := 0; i < len(req.Note); i++ {
		if req.Note[i] < 0x20 && req.Note[i] != '\t' && req.Note[i] != '\n' {
			fail(w, r, spec.ErrBadRequest)
			return
		}
	}

	t, err := a.store.GetTransfer(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, r, spec.ErrTransferNotFound)
			return
		}
		a.internalError(w, r, "report: get transfer", err)
		return
	}
	// 已终结的传输按 §5.2 回 410；举报不改状态。
	switch t.State {
	case spec.StateRevoked:
		fail(w, r, spec.ErrTransferRevoked)
		return
	case spec.StateExpired:
		fail(w, r, spec.ErrTransferExpired)
		return
	case spec.StateConsumed:
		fail(w, r, spec.ErrTransferConsumed)
		return
	}

	reportID := abuseReportID(code, id)
	if _, _, err := a.store.InsertAbuseReport(r.Context(), store.AbuseReport{
		ReportID:     reportID,
		ReporterCode: code,
		TransferID:   id,
		Reason:       req.Reason,
		Note:         req.Note,
		ReporterIP:   a.clientIP(r),
		CreatedAt:    a.now(),
	}); err != nil {
		a.internalError(w, r, "report: insert", err)
		return
	}

	n, err := a.store.CountDistinctReports(r.Context(), id)
	if err != nil {
		a.internalError(w, r, "report: count", err)
		return
	}

	writeJSON(w, http.StatusAccepted, spec.AbuseReportResponse{
		ReportID:        reportID,
		State:           "RECORDED",
		DistinctReports: n,
	})
}

// abuseReportID 由 (reporter_code, transfer_id) 派生，保证幂等时返回同一个 report_id。
func abuseReportID(reporterCode, transferID string) string {
	sum := sha256.Sum256([]byte("yanshu/abuse-report/v1" + reporterCode + transferID))
	return "r_" + hex.EncodeToString(sum[:4])
}

var _ = strings.TrimSpace
