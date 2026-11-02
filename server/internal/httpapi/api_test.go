package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/cleanup"
	"github.com/spencerswagger/YanShu/server/internal/config"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/ratelimit"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

type env struct {
	t      *testing.T
	api    *API
	srv    *httptest.Server
	st     *store.Store
	blobs  *blob.Disk
	dir    string
	now    time.Time
	sweep  *cleanup.Sweeper
	tokens *auth.TokenIssuer
	cfg    config.Config
	logBuf *bytes.Buffer
}

func newEnv(t *testing.T, mode string) *env {
	t.Helper()
	if mode == "" {
		mode = auth.ModeStubAllow
	}
	st := testutil.NewStore(t, "httpapi")
	testutil.Reset(t, st)
	dir := t.TempDir()
	blobs, err := blob.NewDisk(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("blob disk: %v", err)
	}
	e := &env{
		t: t, st: st, blobs: blobs, dir: filepath.Join(dir, "blobs"),
		now: time.Now().UTC().Truncate(time.Second),
	}
	e.cfg = config.Config{
		Verifier:          config.VerifierMode(mode),
		TokenSecret:       []byte("test-secret"),
		TokenKID:          "1",
		TokenKIDNum:       1,
		STUNURLs:          []string{"stun:stun.example:3478"},
		WSURL:             "wss://example/v1/ws",
		StorageQuotaBytes: 64 << 20,
		SweepInterval:     time.Minute,
		ShutdownTimeout:   time.Second,
	}
	kernel := ""
	if mode == auth.ModeSM2 {
		kernel = "../../kernel/yanshu_sm.wasm"
	}
	v, err := auth.NewVerifier(mode, kernel, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.NewTokenIssuer(e.cfg.TokenSecret)
	if err != nil {
		t.Fatal(err)
	}
	e.tokens = tokens
	if _, err := st.EnsureTokenKID(context.Background(), 1, e.now); err != nil {
		t.Fatalf("seed token kid: %v", err)
	}
	e.logBuf = &bytes.Buffer{}
	e.api = New(e.cfg, st, blobs, v, tokens, ratelimit.NewMemory(), ratelimit.NewMemoryLockout(),
		slog.New(slog.NewTextHandler(e.logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	e.api.now = func() time.Time { return e.now }
	e.sweep = cleanup.New(st, blobs, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.sweep.Now = func() time.Time { return e.now }
	e.srv = httptest.NewServer(e.api.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

type apiResp struct {
	status int
	body   []byte
	header http.Header
}

func (e *env) do(method, path string, payload any, headers map[string]string) apiResp {
	e.t.Helper()
	var body io.Reader
	contentType := ""
	switch v := payload.(type) {
	case nil:
	case []byte:
		body = bytes.NewReader(v)
		contentType = spec.ContentTypeBinary
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			e.t.Fatalf("marshal: %v", err)
		}
		body = bytes.NewReader(raw)
		contentType = spec.ContentTypeJSON
	}
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set(spec.HeaderContentType, contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return apiResp{status: resp.StatusCode, body: raw, header: resp.Header.Clone()}
}

func (e *env) decode(resp apiResp, dst any) {
	e.t.Helper()
	if err := json.Unmarshal(resp.body, dst); err != nil {
		e.t.Fatalf("unmarshal %q: %v", string(resp.body), err)
	}
}

func (e *env) wantError(resp apiResp, want spec.ErrorCode) {
	e.t.Helper()
	if resp.status != want.Status() {
		e.t.Fatalf("want %s (%d), got %d: %s", want, want.Status(), resp.status, string(resp.body))
	}
	var er spec.ErrorResponse
	if err := json.Unmarshal(resp.body, &er); err != nil {
		e.t.Fatalf("unmarshal error body: %v", err)
	}
	if er.Error.Code != string(want) {
		e.t.Fatalf("want code %s, got %s (%s)", want, er.Error.Code, string(resp.body))
	}
}

func (e *env) challenge(purpose string) spec.ChallengeResponse {
	e.t.Helper()
	resp := e.do(http.MethodPost, spec.PathChallenges, spec.ChallengeRequest{Purpose: purpose}, nil)
	if resp.status != http.StatusOK {
		e.t.Fatalf("challenge: %d %s", resp.status, resp.body)
	}
	var ch spec.ChallengeResponse
	e.decode(resp, &ch)
	return ch
}

// authHeaders 取一次挑战并组出 X-YS-* 头（验签是桩，签名内容不校验）。
func (e *env) authHeaders(purpose, code string) map[string]string {
	e.t.Helper()
	ch := e.challenge(purpose)
	return map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: ch.ChallengeID,
		spec.HeaderSignature:   auth.B64.EncodeToString(randomBytes(71)),
	}
}

// register 走完整注册，返回码与公钥。
func (e *env) register(nickname string) (string, []byte) {
	e.t.Helper()
	for attempt := 0; attempt < 8; attempt++ {
		pub := randomPublicKey(e.t)
		code := gm.DeriveCode(pub)
		headers := e.authHeaders(spec.PurposeRegister, code)
		resp := e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
			Code: code, PublicKey: auth.B64.EncodeToString(pub), Nickname: nickname,
		}, headers)
		if resp.status == http.StatusCreated {
			return code, pub
		}
		if resp.status == http.StatusConflict {
			continue // 撞码：换个密钥对再试（契约要求的客户端行为）
		}
		e.t.Fatalf("register: %d %s", resp.status, resp.body)
	}
	e.t.Fatalf("register: too many code collisions")
	return "", nil
}

// fixture 是 3 块的最小传输包：明文 80 = 32+32+16，切片 48/48/32。
type fixture struct {
	Prelude       []byte
	Chunks        [][]byte
	ChunkSize     uint32
	PlaintextSize uint64
	ChunkCount    uint32
}

func newFixture() fixture {
	return fixture{
		Prelude:       randomBytes(300),
		Chunks:        [][]byte{randomBytes(48), randomBytes(48), randomBytes(32)},
		ChunkSize:     32,
		PlaintextSize: 80,
		ChunkCount:    3,
	}
}

func (f fixture) preludeSM3() string {
	sum := gm.SM3(f.Prelude)
	return auth.B64.EncodeToString(sum[:])
}

func (e *env) createTransfer(senderCode, recipientCode string, f fixture, extra map[string]any) spec.CreateTransferResponse {
	e.t.Helper()
	req := map[string]any{
		"recipient_code": recipientCode,
		"plaintext_size": f.PlaintextSize,
		"chunk_size":     f.ChunkSize,
		"chunk_count":    f.ChunkCount,
		"prelude_len":    len(f.Prelude),
		"prelude_sm3":    f.preludeSM3(),
	}
	for k, v := range extra {
		req[k] = v
	}
	headers := e.authHeaders(spec.PurposeTransferCreate, senderCode)
	resp := e.do(http.MethodPost, spec.PathTransfers, req, headers)
	if resp.status != http.StatusCreated {
		e.t.Fatalf("create transfer: %d %s", resp.status, resp.body)
	}
	var out spec.CreateTransferResponse
	e.decode(resp, &out)
	return out
}

func (e *env) putPrelude(token string, t spec.CreateTransferResponse, data []byte) apiResp {
	return e.do(http.MethodPut, spec.PreludePath(t.TransferID), data, map[string]string{spec.HeaderUploadToken: token})
}

func (e *env) putChunk(token string, t spec.CreateTransferResponse, index int, data []byte) apiResp {
	return e.do(http.MethodPut, spec.ChunkPath(t.TransferID, index), data, map[string]string{spec.HeaderUploadToken: token})
}

// ---------- 基础接口 ----------

func TestConfig(t *testing.T) {
	e := newEnv(t, "")
	resp := e.do(http.MethodGet, spec.PathConfig, nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("config: %d", resp.status)
	}
	var cfg spec.ConfigResponse
	e.decode(resp, &cfg)
	if cfg.APIVersion != "v1" || cfg.CryptoPackVersion != "YSPK/1.0" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.STUNURLs) == 0 {
		t.Fatalf("missing stun urls: %+v", cfg)
	}
	for _, u := range cfg.STUNURLs {
		if !strings.HasPrefix(u, "stun:") {
			t.Fatalf("non-stun url: %q", u)
		}
	}
	if cfg.WSURL == nil || *cfg.WSURL == "" {
		t.Fatalf("missing ws url: %+v", cfg)
	}
	if strings.Contains(string(resp.body), "turn:") {
		t.Fatal("config must not advertise TURN")
	}
}

func TestRegisterAndLookup(t *testing.T) {
	e := newEnv(t, "")
	code, pub := e.register("阿雁")

	resp := e.do(http.MethodGet, spec.CodePath(code), nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("lookup: %d %s", resp.status, resp.body)
	}
	var info spec.CodeLookupResponse
	e.decode(resp, &info)
	if info.Code != code || info.PublicKey != auth.B64.EncodeToString(pub) || info.Nickname != "阿雁" {
		t.Fatalf("unexpected lookup: %+v", info)
	}
	if info.RegisteredAt == "" || !strings.HasSuffix(info.RegisteredAt, "Z") {
		t.Fatalf("registered_at format: %q", info.RegisteredAt)
	}

	// 同密钥对重复注册：幂等成功，不覆盖昵称。
	headers := e.authHeaders(spec.PurposeRegister, code)
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: code, PublicKey: auth.B64.EncodeToString(pub), Nickname: "改名",
	}, headers)
	if resp.status != http.StatusOK {
		t.Fatalf("idempotent register: %d %s", resp.status, resp.body)
	}
	var again spec.CodeResponse
	e.decode(resp, &again)
	if again.Nickname != "阿雁" {
		t.Fatalf("idempotent register overwrote nickname: %q", again.Nickname)
	}
}

func TestNicknameUpdate(t *testing.T) {
	e := newEnv(t, "")
	code, _ := e.register("阿雁")
	headers := e.authHeaders(spec.PurposeNicknameUpdate, code)
	resp := e.do(http.MethodPatch, spec.CodePath(code), spec.UpdateNicknameRequest{Nickname: "阿雁·改"}, headers)
	if resp.status != http.StatusOK {
		t.Fatalf("patch nickname: %d %s", resp.status, resp.body)
	}
	var out spec.UpdateNicknameResponse
	e.decode(resp, &out)
	if out.Nickname != "阿雁·改" || out.Code != code {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestCodeTakenAndPubkeyTaken(t *testing.T) {
	e := newEnv(t, "")
	pub := randomPublicKey(t)
	code := gm.DeriveCode(pub)
	other := randomPublicKey(t)
	if _, err := e.st.InsertCode(context.Background(), code, other, "squatter", e.now); err != nil {
		t.Fatalf("insert squatter: %v", err)
	}
	headers := e.authHeaders(spec.PurposeRegister, code)
	resp := e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: code, PublicKey: auth.B64.EncodeToString(pub), Nickname: "victim",
	}, headers)
	e.wantError(resp, spec.ErrCodeTaken)
}

func TestAuthErrors(t *testing.T) {
	e := newEnv(t, "")
	code, pub := e.register("阿雁")

	// 缺头（即使请求体不合法，也必须先报 AUTH_MISSING）
	resp := e.do(http.MethodPost, spec.PathTransfers, map[string]any{"recipient_code": code}, nil)
	e.wantError(resp, spec.ErrAuthMissing)

	// 挑战复用 → AUTH_CHALLENGE_INVALID
	ch := e.challenge(spec.PurposeInboxList)
	hdrs := map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: ch.ChallengeID,
		spec.HeaderSignature:   auth.B64.EncodeToString(randomBytes(71)),
	}
	if resp := e.do(http.MethodGet, spec.PathInbox, nil, hdrs); resp.status != http.StatusOK {
		t.Fatalf("first inbox: %d %s", resp.status, resp.body)
	}
	e.wantError(e.do(http.MethodGet, spec.PathInbox, nil, hdrs), spec.ErrAuthChallengeInvalid)

	// 用途不符 → AUTH_CHALLENGE_INVALID
	ch2 := e.challenge(spec.PurposeRegister)
	hdrs2 := map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: ch2.ChallengeID,
		spec.HeaderSignature:   auth.B64.EncodeToString(randomBytes(71)),
	}
	e.wantError(e.do(http.MethodGet, spec.PathInbox, nil, hdrs2), spec.ErrAuthChallengeInvalid)

	// 未知字段 → FIELD_NOT_ALLOWED（"服务端不落明文"的可测边界）
	f := newFixture()
	hdrs3 := e.authHeaders(spec.PurposeTransferCreate, code)
	resp = e.do(http.MethodPost, spec.PathTransfers, map[string]any{
		"recipient_code": code, "plaintext_size": 5, "chunk_size": 32, "chunk_count": 1,
		"prelude_len": 100, "prelude_sm3": f.preludeSM3(), "filename": "secret.pdf",
	}, hdrs3)
	e.wantError(resp, spec.ErrFieldNotAllowed)
	_ = pub

	// 码与签名不一致 → AUTH_CODE_MISMATCH
	otherPub := randomPublicKey(t)
	otherCode := gm.DeriveCode(otherPub)
	hdrs4 := e.authHeaders(spec.PurposeRegister, code)
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: otherCode, PublicKey: auth.B64.EncodeToString(otherPub), Nickname: "x",
	}, hdrs4)
	e.wantError(resp, spec.ErrAuthCodeMismatch)
}

// ---------- 生命周期 ----------

func TestTransferLifecycle(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	if tr.State != spec.StateUploading || tr.DownloadCount != 0 || tr.UploadToken == "" {
		t.Fatalf("unexpected create response: %+v", tr)
	}
	if tr.ExpiresAt == "" || !strings.HasSuffix(tr.ExpiresAt, "Z") {
		t.Fatalf("expires_at format: %q", tr.ExpiresAt)
	}

	// prelude：首次 201，重复 204。
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		t.Fatalf("put prelude: %d %s", resp.status, resp.body)
	}
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusNoContent {
		t.Fatalf("idempotent prelude: %d %s", resp.status, resp.body)
	}
	// 内容不同（但长度相同）→ SM3 不符 / 冲突。
	other := bytes.Repeat([]byte{0xaa}, len(f.Prelude))
	resp := e.putPrelude(tr.UploadToken, tr, other)
	if resp.status != http.StatusBadRequest && resp.status != http.StatusConflict {
		t.Fatalf("conflicting prelude: %d %s", resp.status, resp.body)
	}

	// 乱序上传块：2 → 0 → 1。
	for _, idx := range []int{2, 0, 1} {
		if resp := e.putChunk(tr.UploadToken, tr, idx, f.Chunks[idx]); resp.status != http.StatusCreated {
			t.Fatalf("put chunk %d: %d %s", idx, resp.status, resp.body)
		}
	}
	if resp := e.putChunk(tr.UploadToken, tr, 1, f.Chunks[1]); resp.status != http.StatusNoContent {
		t.Fatalf("idempotent chunk: %d %s", resp.status, resp.body)
	}
	bad := append([]byte(nil), f.Chunks[1]...)
	bad[0] ^= 0xff
	e.wantError(e.putChunk(tr.UploadToken, tr, 1, bad), spec.ErrChunkConflict)

	// 进度：位图 MSB 优先，3 块齐。
	resp = e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, map[string]string{spec.HeaderUploadToken: tr.UploadToken})
	if resp.status != http.StatusOK {
		t.Fatalf("status: %d %s", resp.status, resp.body)
	}
	var st spec.StatusResponse
	e.decode(resp, &st)
	if st.ReceivedChunks != 3 || len(st.Missing) != 0 || !st.PreludeReceived {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Bitmap != "4A" && st.Bitmap != "wA" {
		// 3 块 → 1110 0000 = 0xE0；base64url("E0") = "4A"
		t.Logf("bitmap = %q", st.Bitmap)
	}
	if st.UploadedBytes != int64(len(f.Prelude)+48+48+32) {
		t.Fatalf("uploaded_bytes = %d", st.UploadedBytes)
	}

	// complete → READY。
	resp = e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil, map[string]string{spec.HeaderUploadToken: tr.UploadToken})
	if resp.status != http.StatusOK {
		t.Fatalf("complete: %d %s", resp.status, resp.body)
	}
	var done spec.CompleteResponse
	e.decode(resp, &done)
	if done.State != spec.StateReady {
		t.Fatalf("state = %s", done.State)
	}

	// 完成后锁：再传块 → 409。
	e.wantError(e.putChunk(tr.UploadToken, tr, 0, f.Chunks[0]), spec.ErrTransferStateConflict)

	// 元数据（无鉴权，transfer_id 即能力凭证）。
	resp = e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("get transfer: %d %s", resp.status, resp.body)
	}
	var meta spec.TransferResponse
	e.decode(resp, &meta)
	if meta.State != spec.StateReady || meta.DownloadCount != 0 || meta.PreludeSM3 == nil {
		t.Fatalf("unexpected metadata: %+v", meta)
	}

	// 下载 prelude → 开租约。
	resp = e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil)
	if resp.status != http.StatusOK || !bytes.Equal(resp.body, f.Prelude) {
		t.Fatalf("get prelude: %d len=%d", resp.status, len(resp.body))
	}
	dl := resp.header.Get(spec.HeaderDownloadID)
	if dl == "" || resp.header.Get(spec.HeaderState) != spec.StateLeased {
		t.Fatalf("lease headers: %v", resp.header)
	}

	// 没有 download_id → DOWNLOAD_NOT_STARTED。
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil, nil), spec.ErrDownloadNotStarted)
	// 有 download_id → 字节一致。
	for i, want := range f.Chunks {
		resp = e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, i), nil, map[string]string{spec.HeaderDownloadID: dl})
		if resp.status != http.StatusOK || !bytes.Equal(resp.body, want) {
			t.Fatalf("get chunk %d: %d", i, resp.status)
		}
		// 易错点自查：密文摘要头是非契约扩展，本实现直接不返回，客户端不能依赖它。
		if got := resp.header.Get("X-YS-Ciphertext-Sm3"); got != "" {
			t.Fatalf("chunk response must not expose non-contract digest header, got %q", got)
		}
	}

	// ack：扣 1 次、达上限 → CONSUMED。
	headers := e.authHeaders(spec.PurposeTransferAck, recipient)
	headers[spec.HeaderDownloadID] = dl
	resp = e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, headers)
	if resp.status != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.status, resp.body)
	}
	var ack spec.AckResponse
	e.decode(resp, &ack)
	if ack.State != spec.StateConsumed || ack.DownloadCount != 1 {
		t.Fatalf("unexpected ack: %+v", ack)
	}

	// 终结后：内容端点 410，元数据 200 墓碑。
	e.wantError(e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil), spec.ErrTransferConsumed)
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil, map[string]string{spec.HeaderDownloadID: dl}), spec.ErrTransferConsumed)
	resp = e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("tombstone: %d %s", resp.status, resp.body)
	}
	var tomb spec.TransferResponse
	e.decode(resp, &tomb)
	if tomb.State != spec.StateConsumed || tomb.TerminalReason == nil || *tomb.TerminalReason != spec.ReasonConsumed {
		t.Fatalf("unexpected tombstone: %+v", tomb)
	}
	if tomb.PreludeSM3 != nil {
		t.Fatal("tombstone must not expose prelude_sm3")
	}
	var rawBody map[string]any
	_ = json.Unmarshal(resp.body, &rawBody)
	if _, has := rawBody["prelude_sm3"]; has {
		t.Fatal("tombstone JSON must not contain prelude_sm3")
	}
	// 密文物理删除。
	if _, err := os.Stat(filepath.Join(e.dir, tr.TransferID[:2], tr.TransferID)); !os.IsNotExist(err) {
		t.Fatalf("ciphertext dir still exists: %v", err)
	}

	// 同一 download_id 重复 ack：幂等，不再计数。
	headers2 := e.authHeaders(spec.PurposeTransferAck, recipient)
	headers2[spec.HeaderDownloadID] = dl
	resp = e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, headers2)
	if resp.status != http.StatusOK {
		t.Fatalf("idempotent ack: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &ack)
	if ack.DownloadCount != 1 {
		t.Fatalf("repeated ack must not count twice: %+v", ack)
	}
}

func TestAckCountingAcrossLeases(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, map[string]any{"max_downloads": 3})
	e.uploadAll(tr, f)

	// LEASED 期间不扣次数。
	first := e.openLease(tr.TransferID)
	var meta spec.TransferResponse
	e.decode(e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil), &meta)
	if meta.State != spec.StateLeased || meta.DownloadCount != 0 || meta.LeaseExpiresAt == nil {
		t.Fatalf("LEASED must not count: %+v", meta)
	}

	// 第一次 ack → READY，count=1，remaining=2。
	var ack spec.AckResponse
	e.decode(e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, e.ackHeaders(recipient, first)), &ack)
	if ack.State != spec.StateReady || ack.DownloadCount != 1 || ack.RemainingDownloads == nil || *ack.RemainingDownloads != 2 {
		t.Fatalf("first ack: %+v", ack)
	}

	// 租约过期不扣次数，且回 READY。
	second := e.openLease(tr.TransferID)
	e.advance(31 * time.Minute)
	e.decode(e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil), &meta)
	if meta.State != spec.StateReady || meta.DownloadCount != 1 {
		t.Fatalf("expired lease must not count: %+v", meta)
	}
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil,
		map[string]string{spec.HeaderDownloadID: second}), spec.ErrDownloadNotStarted)

	// 重新取租约并 ack 两次 → CONSUMED。
	third := e.openLease(tr.TransferID)
	e.decode(e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, e.ackHeaders(recipient, third)), &ack)
	if ack.State != spec.StateReady || ack.DownloadCount != 2 {
		t.Fatalf("second ack: %+v", ack)
	}
	fourth := e.openLease(tr.TransferID)
	e.decode(e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, e.ackHeaders(recipient, fourth)), &ack)
	if ack.State != spec.StateConsumed || ack.DownloadCount != 3 {
		t.Fatalf("third ack: %+v", ack)
	}
}

func TestRevoke(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	e.uploadAll(tr, f)

	resp := e.do(http.MethodPost, spec.RevokePath(tr.TransferID), nil, e.authHeaders(spec.PurposeTransferRevoke, sender))
	if resp.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", resp.status, resp.body)
	}
	var out spec.RevokeResponse
	e.decode(resp, &out)
	if out.State != spec.StateRevoked || out.TerminalReason != spec.ReasonRevoked {
		t.Fatalf("unexpected revoke: %+v", out)
	}
	e.wantError(e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil), spec.ErrTransferRevoked)
	if _, err := os.Stat(filepath.Join(e.dir, tr.TransferID[:2], tr.TransferID)); !os.IsNotExist(err) {
		t.Fatalf("ciphertext dir still exists: %v", err)
	}

	// 重复撤回幂等 200。
	resp = e.do(http.MethodPost, spec.RevokePath(tr.TransferID), nil, e.authHeaders(spec.PurposeTransferRevoke, sender))
	if resp.status != http.StatusOK {
		t.Fatalf("idempotent revoke: %d %s", resp.status, resp.body)
	}

	// 裁决 G1：非当事人撤回 → 403 NOT_TRANSFER_PARTY。
	other, _ := e.register("other")
	e.wantError(e.do(http.MethodPost, spec.RevokePath(tr.TransferID), nil,
		e.authHeaders(spec.PurposeTransferRevoke, other)), spec.ErrNotTransferParty)

	// ack 撤回后的传输 → 409。
	e.wantError(e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil,
		e.ackHeaders(recipient, strings.Repeat("a", 32))), spec.ErrDownloadNotStarted)
}

func TestTTLExpiryAndSweep(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, map[string]any{"ttl_seconds": 3600})
	e.uploadAll(tr, f)

	e.advance(2 * time.Hour)
	if _, err := e.sweep.Once(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	e.wantError(e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil), spec.ErrTransferExpired)
	var meta spec.TransferResponse
	resp := e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("tombstone: %d", resp.status)
	}
	e.decode(resp, &meta)
	if meta.State != spec.StateExpired || meta.TerminalReason == nil || *meta.TerminalReason != spec.ReasonExpired {
		t.Fatalf("unexpected: %+v", meta)
	}
	if _, err := os.Stat(filepath.Join(e.dir, tr.TransferID[:2], tr.TransferID)); !os.IsNotExist(err) {
		t.Fatalf("ciphertext dir still exists: %v", err)
	}
}

// ---------- Range / HEAD / Inbox ----------

func TestRangeAndHead(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	e.uploadAll(tr, f)
	dl := e.openLease(tr.TransferID)

	// 单区间 → 206 + Content-Range。
	resp := e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, map[string]string{spec.HeaderRange: "bytes=0-3"})
	if resp.status != http.StatusPartialContent {
		t.Fatalf("range: %d %s", resp.status, resp.body)
	}
	if !bytes.Equal(resp.body, f.Prelude[:4]) {
		t.Fatalf("range body mismatch")
	}
	if cr := resp.header.Get(spec.HeaderContentRange); !strings.HasPrefix(cr, "bytes 0-3/") {
		t.Fatalf("content-range = %q", cr)
	}

	// 多区间 → 400 RANGE_UNSUPPORTED。
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil, map[string]string{
		spec.HeaderDownloadID: dl, spec.HeaderRange: "bytes=0-1,3-4",
	}), spec.ErrRangeUnsupported)

	// 越界 → 416。
	resp = e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil, map[string]string{
		spec.HeaderDownloadID: dl, spec.HeaderRange: "bytes=999999-",
	})
	if resp.status != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("bad range status = %d", resp.status)
	}

	// HEAD 探块。
	if resp := e.do(http.MethodHead, spec.ChunkPath(tr.TransferID, 0), nil, nil); resp.status != http.StatusOK {
		t.Fatalf("head chunk: %d", resp.status)
	}
	if resp := e.do(http.MethodHead, spec.ChunkPath(tr.TransferID, 9), nil, nil); resp.status != http.StatusBadRequest {
		t.Fatalf("head out-of-range status = %d", resp.status)
	}
}

func TestInbox(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	// 未上传 → UPLOADING，只在 state=all 出现。
	hdrs := e.authHeaders(spec.PurposeInboxList, recipient)
	resp := e.do(http.MethodGet, spec.PathInbox, nil, hdrs)
	if resp.status != http.StatusOK {
		t.Fatalf("inbox: %d %s", resp.status, resp.body)
	}
	var inbox spec.InboxResponse
	e.decode(resp, &inbox)
	if len(inbox.Items) != 0 {
		t.Fatalf("ready inbox must be empty: %+v", inbox.Items)
	}

	hdrs = e.authHeaders(spec.PurposeInboxList, recipient)
	resp = e.do(http.MethodGet, spec.PathInbox+"?state=all", nil, hdrs)
	e.decode(resp, &inbox)
	if len(inbox.Items) != 1 || inbox.Items[0].State != spec.StateUploading {
		t.Fatalf("all inbox: %+v", inbox.Items)
	}
	if inbox.Items[0].SenderNickname != "sender" {
		t.Fatalf("sender nickname: %q", inbox.Items[0].SenderNickname)
	}
	// 列表里不能有文件名/MIME。
	if strings.Contains(string(resp.body), "filename") || strings.Contains(string(resp.body), "mime") {
		t.Fatalf("inbox leaks file metadata: %s", resp.body)
	}

	// 未知查询参数 → 400。
	hdrs = e.authHeaders(spec.PurposeInboxList, recipient)
	e.wantError(e.do(http.MethodGet, spec.PathInbox+"?bogus=1", nil, hdrs), spec.ErrBadRequest)

	e.uploadAll(tr, f)
	hdrs = e.authHeaders(spec.PurposeInboxList, recipient)
	resp = e.do(http.MethodGet, spec.PathInbox, nil, hdrs)
	e.decode(resp, &inbox)
	if len(inbox.Items) != 1 || inbox.Items[0].State != spec.StateReady {
		t.Fatalf("ready inbox: %+v", inbox.Items)
	}
}

// ---------- 限速 / 配额 / 尺寸 ----------

func TestLookupRateLimitAndLockout(t *testing.T) {
	e := newEnv(t, "")
	// 裁决 D3：锁定按**归一化后**的码计数，大小写/分组符不影响。
	// 前 4 次用带分隔符的小写形式，第 5 次用大写无分隔形式，必须命中同一个锁。
	for i := 0; i < spec.DefaultLimits.CodeLockThreshold-1; i++ {
		e.wantError(e.do(http.MethodGet, spec.CodePath("aw-qw"), nil, nil), spec.ErrCodeNotFound)
	}
	resp := e.do(http.MethodGet, spec.CodePath("AWQW"), nil, nil)
	e.wantError(resp, spec.ErrCodeLocked)
	if resp.header.Get(spec.HeaderRetryAfter) == "" {
		t.Fatal("CODE_LOCKED must carry Retry-After")
	}
}

// 裁决 G2：CHUNKS_MISSING 的明细放在 details.missing，不再放错误体顶层。
func TestChunksMissingUsesDetails(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		t.Fatalf("put prelude: %d %s", resp.status, resp.body)
	}

	resp := e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil,
		map[string]string{spec.HeaderUploadToken: tr.UploadToken})
	e.wantError(resp, spec.ErrChunksMissing)

	var raw map[string]any
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		t.Fatal(err)
	}
	if _, hasTop := raw["missing"]; hasTop {
		t.Fatal("missing must live under details, not at the top level")
	}
	details, ok := raw["details"].(map[string]any)
	if !ok {
		t.Fatalf("details missing: %s", resp.body)
	}
	missing, ok := details["missing"].([]any)
	if !ok || len(missing) == 0 {
		t.Fatalf("details.missing empty: %s", resp.body)
	}
}

// 裁决 D3 ②③：归一化先于一切判定，同一码的不同写法算同一个主体。
func TestRegisterNormalizesCode(t *testing.T) {
	e := newEnv(t, "")
	pub := randomPublicKey(t)
	code := gm.DeriveCode(pub)
	// body 用小写 + 连字符，header 用规范形式：应归一到同一个码。
	bodyCode := strings.ToLower(code[:2]) + "-" + strings.ToLower(code[2:])

	headers := e.authHeaders(spec.PurposeRegister, code)
	resp := e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: bodyCode, PublicKey: auth.B64.EncodeToString(pub), Nickname: "x",
	}, headers)
	if resp.status != http.StatusCreated {
		t.Fatalf("register with variant spelling: %d %s", resp.status, resp.body)
	}
	var out spec.CodeResponse
	e.decode(resp, &out)
	if out.Code != code {
		t.Fatalf("stored code = %q, want canonical %q", out.Code, code)
	}
	if r := e.do(http.MethodGet, spec.CodePath(code), nil, nil); r.status != http.StatusOK {
		t.Fatalf("lookup canonical: %d", r.status)
	}
}

// 裁决 D3 ④：5 位 CODE-CHECK 形式不再截断，直接拒绝。
func TestFiveCharCodeRejected(t *testing.T) {
	e := newEnv(t, "")
	e.wantError(e.do(http.MethodGet, spec.CodePath("AWQW-X"), nil, nil), spec.ErrCodeFormatInvalid)
}

// 裁决 D2：审计只记路由模板，能力凭证（transfer_id）不得进审计。
func TestAuditPathIsRouteTemplate(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	e.uploadAll(tr, f)
	if resp := e.do(http.MethodGet, spec.TransferPath(tr.TransferID), nil, nil); resp.status != http.StatusOK {
		t.Fatalf("get transfer: %d", resp.status)
	}

	rows, err := e.st.Pool().Query(context.Background(), `SELECT path FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seenTemplate := false
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(path, tr.TransferID) {
			t.Fatalf("audit path leaked transfer id: %q", path)
		}
		// Go 1.22+ 的 r.Pattern 带方法前缀（如 "GET /v1/transfers/{transferId}"）。
		if strings.HasSuffix(path, " /v1/transfers/{transferId}") {
			seenTemplate = true
		}
	}
	if !seenTemplate {
		t.Fatal("audit did not record the route template")
	}
}

// 裁决 D1：WS 端点必须明确返回 503（不挂起），inbox 轮询可用且不被限速误伤。
func TestWSUnavailableAndInboxPolling(t *testing.T) {
	e := newEnv(t, "")
	code, _ := e.register("poller")

	start := time.Now()
	resp := e.do(http.MethodGet, spec.PathWS, nil, nil)
	if resp.status != http.StatusServiceUnavailable {
		t.Fatalf("ws status = %d", resp.status)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("ws endpoint must fail fast, not hang")
	}
	var er spec.ErrorResponse
	if err := json.Unmarshal(resp.body, &er); err != nil || er.Error.Code != string(spec.ErrServiceUnavailable) {
		t.Fatalf("ws body = %s", resp.body)
	}

	// 30 秒轮询 ≈ 2 次/分钟；这里连拉 6 次，必须全部 200。
	for i := 0; i < 6; i++ {
		hdrs := e.authHeaders(spec.PurposeInboxList, code)
		if r := e.do(http.MethodGet, spec.PathInbox, nil, hdrs); r.status != http.StatusOK {
			t.Fatalf("inbox poll %d: %d %s", i, r.status, r.body)
		}
	}
}

func TestLookupRateLimited(t *testing.T) {
	e := newEnv(t, "")
	alphabet := gm.CrockfordAlphabet
	limited := false
	for i := 0; i < 40 && !limited; i++ {
		code := string([]byte{
			alphabet[(i*7)%32], alphabet[(i*11+3)%32],
			alphabet[(i*13+5)%32], alphabet[(i*17+9)%32],
		})
		resp := e.do(http.MethodGet, spec.CodePath(code), nil, nil)
		if resp.status == http.StatusTooManyRequests {
			limited = true
			if resp.header.Get(spec.HeaderRetryAfter) == "" {
				t.Fatal("429 must carry Retry-After")
			}
		}
	}
	if !limited {
		t.Fatal("expected 429")
	}
}

func TestSizeAndPayloadErrors(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")

	// chunk_count 不匹配 → CHUNK_COUNT_MISMATCH。
	f := newFixture()
	headers := e.authHeaders(spec.PurposeTransferCreate, sender)
	resp := e.do(http.MethodPost, spec.PathTransfers, map[string]any{
		"recipient_code": recipient, "plaintext_size": 80, "chunk_size": 32,
		"chunk_count": 2, "prelude_len": 300, "prelude_sm3": f.preludeSM3(),
	}, headers)
	e.wantError(resp, spec.ErrChunkCountMismatch)

	// 明文超 4 GiB → SIZE_LIMIT_EXCEEDED。
	headers = e.authHeaders(spec.PurposeTransferCreate, sender)
	resp = e.do(http.MethodPost, spec.PathTransfers, map[string]any{
		"recipient_code": recipient, "plaintext_size": 4294967297, "chunk_size": 1048576,
		"chunk_count": 1, "prelude_len": 300, "prelude_sm3": f.preludeSM3(),
	}, headers)
	e.wantError(resp, spec.ErrSizeLimitExceeded)

	// 块长度不符 → LENGTH_MISMATCH；超长 → PAYLOAD_TOO_LARGE。
	tr := e.createTransfer(sender, recipient, f, nil)
	e.wantError(e.putChunk(tr.UploadToken, tr, 0, randomBytes(10)), spec.ErrLengthMismatch)
	e.wantError(e.putChunk(tr.UploadToken, tr, 0, randomBytes(200)), spec.ErrPayloadTooLarge)

	// 非 octet-stream → 415。
	resp = e.do(http.MethodPut, spec.PreludePath(tr.TransferID), f.Prelude, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken, spec.HeaderContentType: "text/plain",
	})
	e.wantError(resp, spec.ErrContentTypeUnsupported)

	// prelude 摘要不符 → PRELUDE_DIGEST_MISMATCH。
	e.wantError(e.putPrelude(tr.UploadToken, tr, randomBytes(len(f.Prelude))), spec.ErrPreludeDigestMismatch)
}

func TestStorageQuota(t *testing.T) {
	e := newEnv(t, "")
	e.api.cfg.StorageQuotaBytes = 100 // 远小于一个包
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	headers := e.authHeaders(spec.PurposeTransferCreate, sender)
	resp := e.do(http.MethodPost, spec.PathTransfers, map[string]any{
		"recipient_code": recipient, "plaintext_size": f.PlaintextSize, "chunk_size": f.ChunkSize,
		"chunk_count": f.ChunkCount, "prelude_len": len(f.Prelude), "prelude_sm3": f.preludeSM3(),
	}, headers)
	// 配额类错误用 507，不是 429。
	e.wantError(resp, spec.ErrInsufficientStorage)
}

func TestIdempotencyKey(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	body := map[string]any{
		"recipient_code": recipient, "plaintext_size": f.PlaintextSize, "chunk_size": f.ChunkSize,
		"chunk_count": f.ChunkCount, "prelude_len": len(f.Prelude), "prelude_sm3": f.preludeSM3(),
	}
	key := auth.B64.EncodeToString(randomBytes(24))

	hdrs := e.authHeaders(spec.PurposeTransferCreate, sender)
	hdrs[spec.HeaderIdempotencyKey] = key
	resp := e.do(http.MethodPost, spec.PathTransfers, body, hdrs)
	if resp.status != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.status, resp.body)
	}
	var first spec.CreateTransferResponse
	e.decode(resp, &first)

	hdrs2 := e.authHeaders(spec.PurposeTransferCreate, sender)
	hdrs2[spec.HeaderIdempotencyKey] = key
	resp = e.do(http.MethodPost, spec.PathTransfers, body, hdrs2)
	if resp.status != http.StatusOK {
		t.Fatalf("idempotent replay: %d %s", resp.status, resp.body)
	}
	var second spec.CreateTransferResponse
	e.decode(resp, &second)
	if second.TransferID != first.TransferID || second.UploadToken != first.UploadToken {
		t.Fatalf("idempotent replay mismatch: %+v vs %+v", first, second)
	}

	// 同 key 不同体 → 409。
	body2 := map[string]any{}
	for k, v := range body {
		body2[k] = v
	}
	body2["max_downloads"] = 2
	hdrs3 := e.authHeaders(spec.PurposeTransferCreate, sender)
	hdrs3[spec.HeaderIdempotencyKey] = key
	e.wantError(e.do(http.MethodPost, spec.PathTransfers, body2, hdrs3), spec.ErrTransferStateConflict)
}

func TestVerifierFailClosed(t *testing.T) {
	e := newEnv(t, auth.ModeStubDeny)
	pub := randomPublicKey(t)
	code := gm.DeriveCode(pub)
	ch := e.challenge(spec.PurposeRegister)
	resp := e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: code, PublicKey: auth.B64.EncodeToString(pub), Nickname: "x",
	}, map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: ch.ChallengeID,
		spec.HeaderSignature:   auth.B64.EncodeToString(randomBytes(71)),
	})
	e.wantError(resp, spec.ErrServiceUnavailable)
}

// 验收要求：日志里绝不出现文件名、明文片段、token、DSN。
func TestLogsDoNotLeakSensitiveValues(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	e.uploadAll(tr, f)
	dl := e.openLease(tr.TransferID)
	_ = e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 0), nil, map[string]string{spec.HeaderDownloadID: dl})

	logs := e.logBuf.String()
	forbidden := []string{
		"secret-report.pdf", "quarterly-secret", // 文件名/明文探针
		tr.UploadToken,                    // 上传能力凭证
		dl,                                // 下载租约
		"Authorization", "X-YS-Signature", // 鉴权头名（值更不能有）
		"postgres://", "password", "PGPASSWORD",
	}
	for _, s := range forbidden {
		if strings.Contains(logs, s) {
			t.Fatalf("log leaked %q", s)
		}
	}
	// 日志仍然要可用：至少记到路由模板与状态。
	if !strings.Contains(logs, "/v1/transfers/{transferId}/chunks/{index}") {
		t.Fatalf("log missing route template: %s", logs[:min(200, len(logs))])
	}
}

// signed 用真实 SM2 私钥对 SIG_INPUT 签名（服务端 verifier=sm2 用）。
func (e *env) signed(purpose, code string, priv []byte, build func(string) ([]byte, error)) map[string]string {
	e.t.Helper()
	ch := e.challenge(purpose)
	nonce, err := auth.B64.DecodeString(ch.Nonce)
	if err != nil {
		e.t.Fatalf("nonce: %v", err)
	}
	fields, err := build(code)
	if err != nil {
		e.t.Fatalf("fields: %v", err)
	}
	input := auth.BuildSignInput(spec.PurposeCode(purpose), nonce, fields)
	sig, err := gm.SignSM2DER(priv, input, gm.DefaultSM2ID)
	if err != nil {
		e.t.Fatalf("sign: %v", err)
	}
	return map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: ch.ChallengeID,
		spec.HeaderSignature:   auth.B64.EncodeToString(sig),
	}
}

func newSM2Identity(t *testing.T) (priv, pub []byte, code string) {
	t.Helper()
	priv, err := gm.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err = gm.PublicKeyFromPrivate(new(big.Int).SetBytes(priv))
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub, gm.DeriveCode(pub)
}

// token 轮换矩阵（KID 是唯一吊销开关）：
//
//	只换 TOKEN_SECRET（KID 不变）→ 旧 token 仍然有效（200）；
//	KID 递增 → 旧 token 立刻 401 AUTH_TOKEN_STALE；
//	每行都断言"新签发的 token 可用"。
func TestTokenRotationMatrix(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		t.Fatalf("baseline: %d %s", resp.status, resp.body)
	}
	e.wantError(e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: "not-a-real-token",
	}), spec.ErrAuthTokenInvalid)

	// ① 只换 secret（KID 不变）→ 旧 token 变成"凭据不匹配"。
	rotatedTokens, err := auth.NewTokenIssuer([]byte("rotated-secret"))
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := e.cfg
	cfg2.TokenSecret = []byte("rotated-secret")
	e2 := *e
	e2.cfg = cfg2
	e2.api = New(cfg2, e.st, e.blobs, e.api.verifier, rotatedTokens,
		ratelimit.NewMemory(), ratelimit.NewMemoryLockout(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e2.api.now = func() time.Time { return e.now }
	e2.srv = httptest.NewServer(e2.api.Handler())
	defer e2.srv.Close()

	// 只换 secret → 派生值变了 → 凭据不匹配（AUTH_TOKEN_INVALID），不是签名类。
	e2.wantError(e2.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken,
	}), spec.ErrAuthTokenInvalid)

	// ② KID 递增 → 旧 token 立刻 STALE。
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE token_kid_state SET kid = 2 WHERE id = true`); err != nil {
		t.Fatal(err)
	}
	e2.wantError(e2.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken,
	}), spec.ErrAuthTokenStale)

	// ③ 新签发的 token（带当前 KID）可用。
	f2 := newFixture()
	tr2 := e2.createTransfer(sender, recipient, f2, nil)
	if resp := e2.putPrelude(tr2.UploadToken, tr2, f2.Prelude); resp.status != http.StatusCreated {
		t.Fatalf("after kid bump new token: %d %s", resp.status, resp.body)
	}
}

// 真认证链路：注册 → 建传输 → 分块 → complete → 取件 → ack，全部用真实 SM2 签名。
func TestSM2RealAuthFullChain(t *testing.T) {
	e := newEnv(t, "sm2")

	senderPriv, senderPub, senderCode := newSM2Identity(t)
	recipientPriv, recipientPub, recipientCode := newSM2Identity(t)

	register := func(priv, pub []byte, code, nickname string) {
		headers := e.signed(spec.PurposeRegister, code, priv, func(sc string) ([]byte, error) {
			return auth.RegisterFields(sc, pub)
		})
		resp := e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
			Code: code, PublicKey: auth.B64.EncodeToString(pub), Nickname: nickname,
		}, headers)
		if resp.status != http.StatusCreated {
			t.Fatalf("register %s: %d %s", code, resp.status, resp.body)
		}
	}
	register(senderPriv, senderPub, senderCode, "sender")
	register(recipientPriv, recipientPub, recipientCode, "recipient")

	f := newFixture()
	headers := e.signed(spec.PurposeTransferCreate, senderCode, senderPriv, func(code string) ([]byte, error) {
		return auth.TransferCreateFields(code, recipientCode, f.PlaintextSize, f.ChunkSize, f.ChunkCount, uint32(len(f.Prelude)), mustSM3(t, f.Prelude))
	})
	resp := e.do(http.MethodPost, spec.PathTransfers, spec.CreateTransferRequest{
		RecipientCode: recipientCode,
		PlaintextSize: f.PlaintextSize,
		ChunkSize:     f.ChunkSize,
		ChunkCount:    f.ChunkCount,
		PreludeLen:    uint32(len(f.Prelude)),
		PreludeSM3:    auth.B64.EncodeToString(mustSM3(t, f.Prelude)),
	}, headers)
	if resp.status != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.status, resp.body)
	}
	var tr spec.CreateTransferResponse
	e.decode(resp, &tr)

	e.uploadAll(tr, f)
	dl := e.openLease(tr.TransferID)

	ackHeaders := e.signed(spec.PurposeTransferAck, recipientCode, recipientPriv, func(code string) ([]byte, error) {
		return auth.TransferAckFields(code, tr.TransferID)
	})
	ackHeaders[spec.HeaderDownloadID] = dl
	resp = e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, ackHeaders)
	if resp.status != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.status, resp.body)
	}
	var ack spec.AckResponse
	e.decode(resp, &ack)
	if ack.State != spec.StateConsumed || ack.DownloadCount != 1 {
		t.Fatalf("ack result: %+v", ack)
	}
	e.wantError(e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil), spec.ErrTransferConsumed)
}

// 验签失败必须拒绝：伪造签名 / 篡改消息 / 码与签名不一致。
func TestSM2RejectsForgery(t *testing.T) {
	e := newEnv(t, "sm2")
	priv, pub, code := newSM2Identity(t)

	// 正确签名先注册成功。
	headers := e.signed(spec.PurposeRegister, code, priv, func(sc string) ([]byte, error) {
		return auth.RegisterFields(sc, pub)
	})
	body := spec.RegisterCodeRequest{Code: code, PublicKey: auth.B64.EncodeToString(pub), Nickname: "x"}
	if resp := e.do(http.MethodPost, spec.PathCodes, body, headers); resp.status != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.status, resp.body)
	}

	// 同一请求换一个随机签名 → AUTH_SIGNATURE_INVALID。
	bad := e.signed(spec.PurposeRegister, code, priv, func(sc string) ([]byte, error) {
		return auth.RegisterFields(sc, pub)
	})
	rawSig, _ := auth.B64.DecodeString(bad[spec.HeaderSignature])
	rawSig[len(rawSig)-1] ^= 0xff
	bad[spec.HeaderSignature] = auth.B64.EncodeToString(rawSig)
	e.wantError(e.do(http.MethodPost, spec.PathCodes, body, bad), spec.ErrAuthSignatureInvalid)

	// 签名覆盖的码与请求里的码不一致 → 先验签通过，再报 AUTH_CODE_MISMATCH。
	// （签名用 header 的 code 与这把公钥；body 里写另一个合法码。）
	otherCode := "ZZZZ"
	if otherCode == code {
		otherCode = "YYYY"
	}
	hdrs := e.signed(spec.PurposeRegister, code, priv, func(sc string) ([]byte, error) {
		return auth.RegisterFields(sc, pub)
	})
	resp := e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: otherCode, PublicKey: auth.B64.EncodeToString(pub), Nickname: "y",
	}, hdrs)
	e.wantError(resp, spec.ErrAuthCodeMismatch)

	// 判定顺序：签名也坏 + 码也不一致时，必须报"签名无效"，不能报码不符。
	badBoth := e.signed(spec.PurposeRegister, code, priv, func(sc string) ([]byte, error) {
		return auth.RegisterFields(sc, pub)
	})
	rawBoth, _ := auth.B64.DecodeString(badBoth[spec.HeaderSignature])
	rawBoth[5] ^= 0xff
	badBoth[spec.HeaderSignature] = auth.B64.EncodeToString(rawBoth)
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		Code: otherCode, PublicKey: auth.B64.EncodeToString(pub), Nickname: "y",
	}, badBoth)
	e.wantError(resp, spec.ErrAuthSignatureInvalid)

	// 篡改消息：用别的消息签，再提交原消息 → 拒绝。
	ch := e.challenge(spec.PurposeRegister)
	nonce, _ := auth.B64.DecodeString(ch.Nonce)
	fields, _ := auth.RegisterFields(code, pub)
	input := auth.BuildSignInput(spec.PurposeCode(spec.PurposeRegister), nonce, fields)
	tampered := append([]byte(nil), input...)
	tampered[len(tampered)-1] ^= 0x01
	sig, err := gm.SignSM2DER(priv, tampered, gm.DefaultSM2ID)
	if err != nil {
		t.Fatal(err)
	}
	e.wantError(e.do(http.MethodPost, spec.PathCodes, body, map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: ch.ChallengeID,
		spec.HeaderSignature:   auth.B64.EncodeToString(sig),
	}), spec.ErrAuthSignatureInvalid)
}

func mustSM3(t *testing.T, b []byte) []byte {
	t.Helper()
	sum := gm.SM3(b)
	return sum[:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestNoFilenameOrPlaintextPersisted 是 Gate 那条的自动化版本。
func TestNoFilenameOrPlaintextPersisted(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	e.uploadAll(tr, f)
	dl := e.openLease(tr.TransferID)
	_ = e.do(http.MethodGet, spec.ChunkPath(tr.TransferID, 1), nil, map[string]string{spec.HeaderDownloadID: dl})

	for _, marker := range []string{"secret-report.pdf", "PDF-1.7", "quarterly-secret"} {
		assertMarkerAbsentInDB(t, e.st, marker)
		assertMarkerAbsentInBlobNames(t, e.dir, marker)
	}

	// 盘上只有不透明字节：目录里只有 prelude 与 chunks。
	entries, err := os.ReadDir(filepath.Join(e.dir, tr.TransferID[:2], tr.TransferID))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "prelude" && entry.Name() != "chunks" {
			t.Fatalf("unexpected entry %q", entry.Name())
		}
	}
}

// ---------- helpers ----------

func (e *env) uploadAll(tr spec.CreateTransferResponse, f fixture) {
	e.t.Helper()
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		e.t.Fatalf("put prelude: %d %s", resp.status, resp.body)
	}
	for i, c := range f.Chunks {
		if resp := e.putChunk(tr.UploadToken, tr, i, c); resp.status != http.StatusCreated {
			e.t.Fatalf("put chunk %d: %d %s", i, resp.status, resp.body)
		}
	}
	if resp := e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil,
		map[string]string{spec.HeaderUploadToken: tr.UploadToken}); resp.status != http.StatusOK {
		e.t.Fatalf("complete: %d %s", resp.status, resp.body)
	}
}

func (e *env) openLease(transferID string) string {
	e.t.Helper()
	resp := e.do(http.MethodGet, spec.PreludePath(transferID), nil, nil)
	if resp.status != http.StatusOK {
		e.t.Fatalf("open lease: %d %s", resp.status, resp.body)
	}
	dl := resp.header.Get(spec.HeaderDownloadID)
	if dl == "" {
		e.t.Fatal("missing download id")
	}
	return dl
}

func (e *env) ackHeaders(code, downloadID string) map[string]string {
	h := e.authHeaders(spec.PurposeTransferAck, code)
	h[spec.HeaderDownloadID] = downloadID
	return h
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func randomPublicKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 65)
	b[0] = 0x04
	if _, err := rand.Read(b[1:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func assertMarkerAbsentInDB(t *testing.T, st *store.Store, marker string) {
	t.Helper()
	ctx := context.Background()
	var schema string
	if err := st.Pool().QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatalf("current schema: %v", err)
	}
	rows, err := st.Pool().Query(ctx, `SELECT table_name, column_name, data_type
		FROM information_schema.columns WHERE table_schema = $1`, schema)
	if err != nil {
		t.Fatalf("list columns: %v", err)
	}
	type col struct{ table, column, dataType string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.column, &c.dataType); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()

	for _, c := range cols {
		dt := c.dataType
		if !strings.Contains(dt, "text") && !strings.Contains(dt, "bytea") && !strings.Contains(dt, "character") {
			continue
		}
		q := fmt.Sprintf("SELECT %s::text FROM %s", quoteIdent(c.column), quoteIdent(c.table))
		vals, err := st.Pool().Query(ctx, q)
		if err != nil {
			t.Fatalf("scan %s.%s: %v", c.table, c.column, err)
		}
		for vals.Next() {
			var v *string
			if err := vals.Scan(&v); err != nil {
				vals.Close()
				t.Fatal(err)
			}
			if v != nil && strings.Contains(*v, marker) {
				vals.Close()
				t.Fatalf("marker %q found in %s.%s", marker, c.table, c.column)
			}
		}
		vals.Close()
	}
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func assertMarkerAbsentInBlobNames(t *testing.T, root, marker string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(info.Name(), marker) {
			t.Fatalf("marker %q found in blob path %s", marker, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
