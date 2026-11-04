package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

func reportPath(id string) string { return spec.Prefix + "/transfers/" + id + "/report" }

// reportHeaders 构造举报用途（0x09）的鉴权头；字段串由服务端按 header 码 + transfer_id 重建。
func (e *env) reportHeaders(code string, transferID string) map[string]string {
	e.t.Helper()
	return e.authHeaders(spec.PurposeAbuseReport, code)
}

// 正常举报 202；重复举报幂等（同一 report_id、distinct 不变）；举报后传输与密文不变。
func TestAbuseReportRecordsOnly(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	other, _ := e.register("other")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	// 举报前先传完（prelude + 3 块 + complete），后面用它证明"举报不动密文"。
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		t.Fatalf("prelude: %d %s", resp.status, resp.body)
	}
	for i, c := range f.Chunks {
		if resp := e.putChunk(tr.UploadToken, tr, i, c); resp.status != http.StatusCreated {
			t.Fatalf("chunk %d: %d %s", i, resp.status, resp.body)
		}
	}
	if resp := e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken,
	}); resp.status != http.StatusOK {
		t.Fatalf("complete: %d %s", resp.status, resp.body)
	}

	body := spec.AbuseReportRequest{Reason: "ABUSE", Note: "冒充登录页"}

	r1 := e.do(http.MethodPost, reportPath(tr.TransferID), body, e.reportHeaders(other, tr.TransferID))
	if r1.status != http.StatusAccepted {
		t.Fatalf("report: %d %s", r1.status, r1.body)
	}
	var first spec.AbuseReportResponse
	if err := json.Unmarshal(r1.body, &first); err != nil {
		t.Fatal(err)
	}
	if first.State != "RECORDED" || first.DistinctReports != 1 || !strings.HasPrefix(first.ReportID, "r_") {
		t.Fatalf("unexpected response: %+v", first)
	}

	// 幂等：同一码重复举报 → 同一 report_id，distinct 不变。
	r2 := e.do(http.MethodPost, reportPath(tr.TransferID), body, e.reportHeaders(other, tr.TransferID))
	if r2.status != http.StatusAccepted {
		t.Fatalf("repeat: %d %s", r2.status, r2.body)
	}
	var second spec.AbuseReportResponse
	if err := json.Unmarshal(r2.body, &second); err != nil {
		t.Fatal(err)
	}
	if second.ReportID != first.ReportID || second.DistinctReports != 1 {
		t.Fatalf("idempotency broken: %+v vs %+v", first, second)
	}

	// 另一个码举报 → distinct 变 2。
	r3 := e.do(http.MethodPost, reportPath(tr.TransferID), body, e.reportHeaders(sender, tr.TransferID))
	var third spec.AbuseReportResponse
	if err := json.Unmarshal(r3.body, &third); err != nil {
		t.Fatal(err)
	}
	if third.DistinctReports != 2 {
		t.Fatalf("distinct = %d, want 2", third.DistinctReports)
	}

	// 关键：举报后传输状态与密文都不变——先看状态（仍是 READY），再取 prelude 比字节。
	if resp := e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken,
	}); resp.status != http.StatusOK || !strings.Contains(string(resp.body), "READY") {
		t.Fatalf("state changed after report: %d %s", resp.status, resp.body)
	}
	got := e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken,
	})
	if got.status != http.StatusOK {
		t.Fatalf("prelude after report: %d %s", got.status, got.body)
	}
	if string(got.body) != string(f.Prelude) {
		t.Fatalf("prelude bytes changed after report: got %d bytes, want %d", len(got.body), len(f.Prelude))
	}
}

// 非法 reason / 超长 note / 控制字符 → BAD_REQUEST。
func TestAbuseReportValidation(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	reporter, _ := e.register("reporter")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	post := func(b spec.AbuseReportRequest) apiResp {
		return e.do(http.MethodPost, reportPath(tr.TransferID), b, e.reportHeaders(reporter, tr.TransferID))
	}
	if r := post(spec.AbuseReportRequest{Reason: "SPAM"}); r.status != http.StatusBadRequest {
		t.Fatalf("bad reason: %d %s", r.status, r.body)
	}
	if r := post(spec.AbuseReportRequest{Reason: "ABUSE", Note: strings.Repeat("a", 201)}); r.status != http.StatusBadRequest {
		t.Fatalf("long note: %d %s", r.status, r.body)
	}
	if r := post(spec.AbuseReportRequest{Reason: "ABUSE", Note: "bad\x01note"}); r.status != http.StatusBadRequest {
		t.Fatalf("control char: %d %s", r.status, r.body)
	}
}

// 未知传输 → 404；缺鉴权头 → AUTH_MISSING；坏挑战 → AUTH_CHALLENGE_INVALID。
func TestAbuseReportAuthAndNotFound(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	reporter, _ := e.register("reporter")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	// 不存在的传输
	missing := strings.Repeat("a", 32)
	r := e.do(http.MethodPost, reportPath(missing), spec.AbuseReportRequest{Reason: "ABUSE"},
		e.reportHeaders(reporter, missing))
	e.wantError(r, spec.ErrTransferNotFound)

	// 缺鉴权头 → AUTH_MISSING
	r2 := e.do(http.MethodPost, reportPath(tr.TransferID), spec.AbuseReportRequest{Reason: "ABUSE"}, nil)
	e.wantError(r2, spec.ErrAuthMissing)

	// 挑战不存在 → AUTH_CHALLENGE_INVALID
	bad := e.reportHeaders(reporter, tr.TransferID)
	bad[spec.HeaderChallengeID] = "ch_does_not_exist"
	r3 := e.do(http.MethodPost, reportPath(tr.TransferID), spec.AbuseReportRequest{Reason: "ABUSE"}, bad)
	e.wantError(r3, spec.ErrAuthChallengeInvalid)
}

// 限速：按码 5 次/小时后 429，且带 Retry-After。
func TestAbuseReportRateLimit(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	reporter, _ := e.register("reporter")
	f := newFixture()

	for i := 0; i < 5; i++ {
		tr := e.createTransfer(sender, recipient, f, nil)
		r := e.do(http.MethodPost, reportPath(tr.TransferID), spec.AbuseReportRequest{Reason: "ABUSE"},
			e.reportHeaders(reporter, tr.TransferID))
		if r.status != http.StatusAccepted {
			t.Fatalf("report %d: %d %s", i, r.status, r.body)
		}
	}
	tr := e.createTransfer(sender, recipient, f, nil)
	r := e.do(http.MethodPost, reportPath(tr.TransferID), spec.AbuseReportRequest{Reason: "ABUSE"},
		e.reportHeaders(reporter, tr.TransferID))
	if r.status != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d %s", r.status, r.body)
	}
	var er spec.ErrorResponse
	if err := json.Unmarshal(r.body, &er); err != nil {
		t.Fatal(err)
	}
	if er.Error.RetryAfter == nil || *er.Error.RetryAfter <= 0 {
		t.Fatalf("429 must carry retry_after: %s", r.body)
	}
}
