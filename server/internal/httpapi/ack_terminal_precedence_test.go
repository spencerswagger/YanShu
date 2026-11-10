package httpapi

// `POST /v1/transfers/{id}/ack` 的 §1.7.4 判定顺序门禁（第五个入口）。
//
// 为什么单独一条：#56 给四条上传路径补了「终结态 410 先于凭据」，但 `handleAck` 里当时
// 先判 `download_id`（缺/不匹配 → 409 DOWNLOAD_NOT_STARTED）再取传输，于是
// "终态 + 无凭据/伪凭据" 回 409 —— 与两条契约条款直接冲突：
//   - §1.7.4「判定顺序写死（四类）」：终结态（410）先于凭据，409 状态冲突排最后；
//   - §5.2「到期后的 `POST /ack` → `410 TRANSFER_EXPIRED` 且**不计数**」（逐字）。
// 而 `terminal_410_precedence_test.go` 只用 ack 去**造** CONSUMED 态，从没断言 ack 自己的 410，
// 所以这条空转一直没人发现。

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// downloadCount 直接读库，用来断言"不计数"这半条（响应体里的 download_count 也可能被改）。
func (e *env) downloadCount(id string) uint32 {
	e.t.Helper()
	t, err := e.st.GetTransfer(context.Background(), id)
	if err != nil {
		e.t.Fatalf("get transfer: %v", err)
	}
	return uint32(t.DownloadCount)
}

// TestAckTerminalStatePrecedesLease 是 §1.7.4/§5.2 在 ack 上的门禁本体。
func TestAckTerminalStatePrecedesLease(t *testing.T) {
	bogusLease := "0123456789abcdef0123456789abcdef"

	cases := []struct {
		state    string
		code     spec.ErrorCode
		prepare  func(e *env, sender, recipient string, tr spec.CreateTransferResponse) // 造出该终态
		wantDown uint32                                                                 // 失败 ack 之后 download_count 必须还是这个数
	}{
		{
			state: "REVOKED", code: spec.ErrTransferRevoked,
			prepare: func(e *env, sender, _ string, tr spec.CreateTransferResponse) {
				resp := e.do(http.MethodPost, spec.RevokePath(tr.TransferID), nil,
					e.authHeaders(spec.PurposeTransferRevoke, sender))
				if resp.status != http.StatusOK {
					e.t.Fatalf("revoke: %d %s", resp.status, resp.body)
				}
			},
			wantDown: 0,
		},
		{
			state: "EXPIRED", code: spec.ErrTransferExpired,
			prepare: func(e *env, _, _ string, _ spec.CreateTransferResponse) {
				// TTL 判定是"每次请求的服务器时间"，把时钟推过 expires_at 即可。
				e.advance(25 * time.Hour)
			},
			wantDown: 0,
		},
		{
			state: "CONSUMED", code: spec.ErrTransferConsumed,
			prepare: func(e *env, _, recipient string, tr spec.CreateTransferResponse) {
				dl := e.openLease(tr.TransferID)
				resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, e.ackHeaders(recipient, dl))
				if resp.status != http.StatusOK {
					e.t.Fatalf("ack(造 CONSUMED): %d %s", resp.status, resp.body)
				}
			},
			wantDown: 1,
		},
	}

	creds := []struct {
		name   string
		header map[string]string
	}{
		{"无 download_id", nil},
		{"伪造 download_id", map[string]string{spec.HeaderDownloadID: bogusLease}},
	}

	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			for _, cred := range creds {
				t.Run(cred.name, func(t *testing.T) {
					e := newEnv(t, "")
					sender, _ := e.register("发送方")
					recipient, _ := e.register("接收方")
					f := newFixture()
					tr := e.readyTransfer(sender, recipient, f)
					tc.prepare(e, sender, recipient, tr)

					headers := e.authHeaders(spec.PurposeTransferAck, recipient)
					for k, v := range cred.header {
						headers[k] = v
					}
					resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, headers)

					if resp.status != http.StatusGone {
						t.Fatalf("§1.7.4 被违反：ack 在 %s 终态（%s）应回 410，实测 %d %s",
							tc.state, cred.name, resp.status, resp.body)
					}
					if er := decodeErrorCode(t, resp); er != tc.code {
						t.Fatalf("§1.7.4 被违反：ack 在 %s 终态应回 %s，实测 %q", tc.state, tc.code, er)
					}
					// §5.2 的另一半：失败 ack **不计数**。
					if got := e.downloadCount(tr.TransferID); got != tc.wantDown {
						t.Fatalf("§5.2 被违反：%s 终态的失败 ack 不得计数，download_count = %d, want %d",
							tc.state, got, tc.wantDown)
					}
				})
			}
		})
	}
}

// TestAckConsumedReplayStaysIdempotent 锁住 §1.7.4 唯一的那条例外：
// §7.5「同一 `download_id` 的重复 ack 只计一次**并返回 200**」——它不是错误路径，
// 所以不能被"终结态一律 410"吞掉；反之**换一个 download_id**（哪怕格式合法）就是错误路径 → 410。
func TestAckConsumedReplayStaysIdempotent(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("发送方")
	recipient, _ := e.register("接收方")
	f := newFixture()
	tr := e.readyTransfer(sender, recipient, f) // max_downloads 默认 1 → 一次 ack 即 CONSUMED

	dl := e.openLease(tr.TransferID)
	if resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil,
		e.ackHeaders(recipient, dl)); resp.status != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.status, resp.body)
	}
	if got := e.downloadCount(tr.TransferID); got != 1 {
		t.Fatalf("首次 ack 应计数一次，download_count = %d", got)
	}

	// 同一 download_id 重复 ack：200 幂等，不再计数（§7.5）。
	resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, e.ackHeaders(recipient, dl))
	if resp.status != http.StatusOK {
		t.Fatalf("同租约重复 ack 应 200（§7.5 幂等），实测 %d %s", resp.status, resp.body)
	}
	var ack spec.AckResponse
	if err := json.Unmarshal(resp.body, &ack); err != nil {
		t.Fatalf("解 ack 体: %v", err)
	}
	if ack.State != spec.StateConsumed || ack.DownloadCount != 1 {
		t.Fatalf("重复 ack 不得再计数：%+v", ack)
	}

	// 换一个格式合法但不属于该传输的 download_id：这是错误路径 → 410 TRANSFER_CONSUMED。
	resp = e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil,
		e.ackHeaders(recipient, "0123456789abcdef0123456789abcdef"))
	e.wantError(resp, spec.ErrTransferConsumed)
	if got := e.downloadCount(tr.TransferID); got != 1 {
		t.Fatalf("被拒的 ack 不得计数，download_count = %d, want 1", got)
	}
}

// TestAckNonTerminalStillChecksLease 是上一条的**阴性对照**：
// 未终结时照旧按凭据分支（缺 → 409 DOWNLOAD_NOT_STARTED、有效 → 200 并计数），
// 否则"一律 410"会把真正该走 409 的场景吞掉，门禁就变成永远绿。
func TestAckNonTerminalStillChecksLease(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("发送方")
	recipient, _ := e.register("接收方")
	f := newFixture()
	tr := e.readyTransfer(sender, recipient, f) // READY，未终结

	resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil,
		e.authHeaders(spec.PurposeTransferAck, recipient))
	e.wantError(resp, spec.ErrDownloadNotStarted)
	if got := e.downloadCount(tr.TransferID); got != 0 {
		t.Fatalf("未终结但缺租约的 ack 不得计数，download_count = %d", got)
	}

	// 有效租约要能正常 ack 并 +1（证明上面那条不是因为路径坏了）。
	dl := e.openLease(tr.TransferID)
	if resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil,
		e.ackHeaders(recipient, dl)); resp.status != http.StatusOK {
		t.Fatalf("ack(有效租约): %d %s", resp.status, resp.body)
	}
	if got := e.downloadCount(tr.TransferID); got != 1 {
		t.Fatalf("成功 ack 应计数一次，download_count = %d, want 1", got)
	}
}

// decodeErrorCode 取错误体里的 code（无体外壳时返回空串）。
func decodeErrorCode(t *testing.T, resp apiResp) spec.ErrorCode {
	t.Helper()
	var er spec.ErrorResponse
	if err := json.Unmarshal(resp.body, &er); err != nil {
		t.Fatalf("解错误体: %v (%s)", err, resp.body)
	}
	return spec.ErrorCode(er.Error.Code)
}
