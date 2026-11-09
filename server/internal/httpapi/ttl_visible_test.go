package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// pushExpiresAt 把一条传输的 expires_at 直接改到过去。
// 契约把 ttl_seconds 夹在 [3600, 86400]，接口上造不出"已到期"，只能在库里把时钟推过去。
func (e *env) pushExpiresAt(id string, at time.Time) {
	e.t.Helper()
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE transfers SET expires_at = $2 WHERE transfer_id = $1`, id, at); err != nil {
		e.t.Fatalf("push expires_at: %v", err)
	}
}

// readyTransfer 走完整上传流程，返回处于 READY 的传输。
func (e *env) readyTransfer(sender, recipient string, f fixture) spec.CreateTransferResponse {
	e.t.Helper()
	tr := e.createTransfer(sender, recipient, f, nil)
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		e.t.Fatalf("put prelude: %d %s", resp.status, resp.body)
	}
	for i := range f.Chunks {
		if resp := e.putChunk(tr.UploadToken, tr, i, f.Chunks[i]); resp.status != http.StatusCreated {
			e.t.Fatalf("put chunk %d: %d %s", i, resp.status, resp.body)
		}
	}
	if resp := e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil,
		map[string]string{spec.HeaderUploadToken: tr.UploadToken}); resp.status != http.StatusOK {
		e.t.Fatalf("complete: %d %s", resp.status, resp.body)
	}
	return tr
}

// TestConfigServerTime 覆盖 TTL 可见化的时钟基准：客户端拿 server_time 算偏差，
// 不能依赖设备本地时钟，也不能依赖中间层是否保留 Date 头。
func TestConfigServerTime(t *testing.T) {
	e := newEnv(t, "")
	resp := e.do(http.MethodGet, spec.PathConfig, nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("config: %d", resp.status)
	}
	var raw map[string]any
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	s, ok := raw["server_time"].(string)
	if !ok || s == "" {
		t.Fatalf("config.server_time missing: %s", resp.body)
	}
	got, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("server_time not RFC3339: %q", s)
	}
	if d := got.Sub(e.now); d < -time.Second || d > time.Second {
		t.Fatalf("server_time %s is not the server clock (%s)", s, e.now)
	}
}

// TestStatusExposesExpiresAt 覆盖发送方在传输过程中的 TTL 可见性（API.md §6.5）。
func TestStatusExposesExpiresAt(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, map[string]any{"ttl_seconds": 3600})

	resp := e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil,
		map[string]string{spec.HeaderUploadToken: tr.UploadToken})
	if resp.status != http.StatusOK {
		t.Fatalf("status: %d %s", resp.status, resp.body)
	}
	var st spec.StatusResponse
	e.decode(resp, &st)
	if st.ExpiresAt != tr.ExpiresAt {
		t.Fatalf("status.expires_at = %q, create.expires_at = %q", st.ExpiresAt, tr.ExpiresAt)
	}
	want := e.now.Add(time.Hour)
	if got, err := time.Parse(time.RFC3339, st.ExpiresAt); err != nil || !got.Equal(want) {
		t.Fatalf("expires_at = %q, want %s (%v)", st.ExpiresAt, want, err)
	}
}

// TestTTLExpiredOnRead 是这一块的核心：expires_at 一过，**下一次读写就终结**，
// 不等清道夫的 tick；终态一致（GET 返回 EXPIRED tombstone、内容端点 410、上传 410、撤回 409），
// 且密文已物理删除。
func TestTTLExpiredOnRead(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.readyTransfer(sender, recipient, f)

	// 先确认可下载（租约正常）。
	if resp := e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil); resp.status != http.StatusOK {
		t.Fatalf("prelude before expiry: %d %s", resp.status, resp.body)
	}

	// TTL 到点：库里把 expires_at 推回 1 秒前（不清道夫，ACK 也不跑）。
	pinned := e.now.Add(-time.Second)
	e.pushExpiresAt(tr.TransferID, pinned)

	// ① 元数据：200 + EXPIRED tombstone，expires_at 仍是原始值，不再给 prelude_sm3。
	resp := e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("get transfer after expiry: %d %s", resp.status, resp.body)
	}
	var meta spec.TransferResponse
	e.decode(resp, &meta)
	if meta.State != spec.StateExpired {
		t.Fatalf("state after expiry = %s, want EXPIRED", meta.State)
	}
	if meta.TerminalReason == nil || *meta.TerminalReason != spec.ReasonExpired {
		t.Fatalf("terminal_reason = %v", meta.TerminalReason)
	}
	if meta.TerminalAt == nil || *meta.TerminalAt != spec.FormatTime(e.now) {
		t.Fatalf("terminal_at = %v, want %s", meta.TerminalAt, spec.FormatTime(e.now))
	}
	if meta.PreludeSM3 != nil {
		t.Fatal("expired tombstone must not carry prelude_sm3")
	}
	if meta.ExpiresAt != spec.FormatTime(pinned) {
		t.Fatalf("tombstone expires_at = %q, want %q（原始到期时刻，不能被 terminal_at 改写）",
			meta.ExpiresAt, spec.FormatTime(pinned))
	}

	// ② 密文已删：prelude 与块都 410 TRANSFER_EXPIRED。
	e.wantError(e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil), spec.ErrTransferExpired)
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil,
		map[string]string{spec.HeaderDownloadID: "00112233445566778899aabbccddeeff"}), spec.ErrTransferExpired)

	// ③ 上传侧：status / complete / 再传块都 410（不是 401 AUTH_TOKEN_EXPIRED）。
	up := map[string]string{spec.HeaderUploadToken: tr.UploadToken}
	e.wantError(e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, up), spec.ErrTransferExpired)
	e.wantError(e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil, up), spec.ErrTransferExpired)
	e.wantError(e.putChunk(tr.UploadToken, tr, 0, f.Chunks[0]), spec.ErrTransferExpired)

	// ④ 撤回：EXPIRED 撤回是 409（契约 §6.7），不能返 REVOKED 200。
	revokeHeaders := e.authHeaders(spec.PurposeTransferRevoke, sender)
	e.wantError(e.do(http.MethodPost, spec.RevokePath(tr.TransferID), nil, revokeHeaders), spec.ErrTransferStateConflict)

	// ⑤ 幂等：再读一次仍是 EXPIRED，且 terminal_at 不被刷新。
	before := *meta.TerminalAt
	e.advance(5 * time.Minute)
	resp = e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil)
	e.decode(resp, &meta)
	if meta.State != spec.StateExpired || meta.TerminalAt == nil || *meta.TerminalAt != before {
		t.Fatalf("expiry not idempotent: state=%s terminal_at=%v", meta.State, meta.TerminalAt)
	}
}

// TestTTLInboxHidesExpired 覆盖列表口径：expires_at 已过的条目不出现在收件列表里
// （API.md §7.1「永不返回 EXPIRED」——库里没被清道夫扫到的行也不能漏出来）。
func TestTTLInboxHidesExpired(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	alive := e.readyTransfer(sender, recipient, f)
	dead := e.readyTransfer(sender, recipient, f)
	e.pushExpiresAt(dead.TransferID, e.now.Add(-time.Second))

	headers := e.authHeaders(spec.PurposeInboxList, recipient)
	resp := e.do(http.MethodGet, spec.PathInbox, nil, headers)
	if resp.status != http.StatusOK {
		t.Fatalf("inbox: %d %s", resp.status, resp.body)
	}
	var inbox spec.InboxResponse
	e.decode(resp, &inbox)
	if len(inbox.Items) != 1 || inbox.Items[0].TransferID != alive.TransferID {
		t.Fatalf("inbox must hide expired rows, got %+v", inbox.Items)
	}
}

// TestAckAfterExpiryNotCounted 覆盖「次数耗尽与过期的一致性」：
// 租约还在有效期内、但传输已到 TTL → ack 必须 410 且不扣次数（不能算"已取走"）。
func TestAckAfterExpiryNotCounted(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.readyTransfer(sender, recipient, f)

	resp := e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("prelude: %d %s", resp.status, resp.body)
	}
	dl := resp.header.Get(spec.HeaderDownloadID)
	if dl == "" {
		t.Fatal("missing download id")
	}

	// 传输先到期（租约 30 分钟仍在有效期内）。
	e.pushExpiresAt(tr.TransferID, e.now.Add(-time.Second))
	e.advance(2 * time.Second)

	ackHeaders := e.authHeaders(spec.PurposeTransferAck, recipient)
	ackHeaders[spec.HeaderDownloadID] = dl
	e.wantError(e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, ackHeaders), spec.ErrTransferExpired)

	// 未计数：download_count 仍为 0，状态 EXPIRED（不是 CONSUMED）。
	resp = e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil)
	var meta spec.TransferResponse
	e.decode(resp, &meta)
	if meta.State != spec.StateExpired || meta.DownloadCount != 0 {
		t.Fatalf("state=%s download_count=%d, want EXPIRED/0", meta.State, meta.DownloadCount)
	}
}
