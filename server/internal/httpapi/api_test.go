package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	client *http.Client
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
	e := &env{t: t, st: st, blobs: blobs, dir: filepath.Join(dir, "blobs"), now: time.Now().UTC().Truncate(time.Second)}
	cfg := config.Config{
		Verifier:          config.VerifierMode(mode),
		CodeTTL:           time.Hour,
		PackageTTL:        time.Hour,
		SessionTTL:        time.Hour,
		ChallengeTTL:      5 * time.Minute,
		MaxPackageBytes:   64 << 20,
		MaxPreludeBytes:   1 << 20,
		MaxChunkBytes:     (1 << 20) + 16,
		StorageQuotaBytes: 1 << 30,
		SweepInterval:     time.Minute,
		ShutdownTimeout:   time.Second,
	}
	v, err := auth.NewVerifier(mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.api = New(cfg, st, blobs, v, ratelimit.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.api.now = func() time.Time { return e.now }
	e.sweep = cleanup.New(st, blobs, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.sweep.Now = func() time.Time { return e.now }
	e.srv = httptest.NewServer(e.api.Handler())
	t.Cleanup(e.srv.Close)
	e.client = e.srv.Client()
	return e
}

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

type apiResp struct {
	status int
	body   []byte
	header http.Header
}

func (e *env) do(method, path string, payload any, token string) apiResp {
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
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set(spec.HeaderAuthorization, "Bearer "+token)
	}
	resp, err := e.client.Do(req)
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
	if resp.status == want.Status() {
		var er spec.ErrorResponse
		if err := json.Unmarshal(resp.body, &er); err == nil && er.Error.Code == string(want) {
			return
		}
	}
	e.t.Fatalf("want error %s (%d), got %d: %s", want, want.Status(), resp.status, string(resp.body))
}

// register 走完整注册 + 会话流程，返回码、会话令牌、公钥。
func (e *env) register(nickname string) (string, string, []byte) {
	e.t.Helper()
	pub := randomPubKey(e.t)

	var ch spec.ChallengeResponse
	resp := e.do(http.MethodPost, spec.PathChallenges, spec.ChallengeRequest{
		Purpose: spec.PurposeRegister, PubKey: auth.B64.EncodeToString(pub),
	}, "")
	if resp.status != http.StatusCreated {
		e.t.Fatalf("register challenge: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &ch)

	var info spec.CodeInfo
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		PubKey:      auth.B64.EncodeToString(pub),
		Nickname:    nickname,
		ChallengeID: ch.ChallengeID,
		Signature:   fakeSig(),
		Code:        gm.DeriveCode(pub),
	}, "")
	if resp.status != http.StatusCreated {
		e.t.Fatalf("register: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &info)

	token := e.session(info.Code)
	return info.Code, token, pub
}

func (e *env) session(code string) string {
	e.t.Helper()
	var ch spec.ChallengeResponse
	resp := e.do(http.MethodPost, spec.PathChallenges, spec.ChallengeRequest{
		Purpose: spec.PurposeSession, Code: code,
	}, "")
	if resp.status != http.StatusCreated {
		e.t.Fatalf("session challenge: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &ch)
	var sess spec.SessionResponse
	resp = e.do(http.MethodPost, spec.PathSessions, spec.SessionRequest{
		ChallengeID: ch.ChallengeID, Code: code, Signature: fakeSig(),
	}, "")
	if resp.status != http.StatusCreated {
		e.t.Fatalf("session: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &sess)
	return sess.SessionToken
}

// pkgFixture 是最小可用的传输包参数：3 块（32, 32, 16 明文 + 16 tag）。
type pkgFixture struct {
	Prelude []byte
	Chunks  [][]byte
	Info    spec.PackageInfo
}

func (e *env) createPackage(senderToken, recipientCode string) pkgFixture {
	e.t.Helper()
	const chunkSize = 32
	const plaintext = 80
	f := pkgFixture{
		Prelude: randomBytes(300),
		Chunks:  [][]byte{randomBytes(48), randomBytes(48), randomBytes(32)},
	}
	resp := e.do(http.MethodPost, spec.PathPackages, spec.CreatePackageRequest{
		RecipientCode: recipientCode,
		ChunkCount:    3,
		ChunkSize:     chunkSize,
		PlaintextSize: plaintext,
		PreludeLen:    uint32(len(f.Prelude)),
	}, senderToken)
	if resp.status != http.StatusCreated {
		e.t.Fatalf("create package: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &f.Info)
	return f
}

func (e *env) putPrelude(token, pkgID string, data []byte) apiResp {
	return e.do(http.MethodPut, spec.PreludePath(pkgID), data, token)
}

func (e *env) putChunk(token, pkgID string, index int, data []byte) apiResp {
	return e.do(http.MethodPut, spec.ChunkPath(pkgID, index), data, token)
}

func TestRegisterLookupAndSession(t *testing.T) {
	e := newEnv(t, "")
	code, token, pub := e.register("alice")
	if len(code) != 4 {
		t.Fatalf("code = %q", code)
	}
	if token == "" {
		t.Fatal("empty session token")
	}

	var info spec.CodeInfo
	resp := e.do(http.MethodGet, spec.CodePath(code), nil, "")
	if resp.status != http.StatusOK {
		t.Fatalf("lookup: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &info)
	if info.PubKey != auth.B64.EncodeToString(pub) || info.Nickname != "alice" || info.Status != spec.CodeActive {
		t.Fatalf("unexpected code info: %+v", info)
	}

	// 同密钥对重复注册是幂等的（刷新 last_seen，不覆盖昵称）。
	var ch spec.ChallengeResponse
	resp = e.do(http.MethodPost, spec.PathChallenges, spec.ChallengeRequest{
		Purpose: spec.PurposeRegister, PubKey: auth.B64.EncodeToString(pub),
	}, "")
	e.decode(resp, &ch)
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		PubKey: auth.B64.EncodeToString(pub), Nickname: "alice2",
		ChallengeID: ch.ChallengeID, Signature: fakeSig(),
	}, "")
	if resp.status != http.StatusOK {
		t.Fatalf("idempotent register: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &info)
	if info.Nickname != "alice" {
		t.Fatalf("idempotent register overwrote nickname: %q", info.Nickname)
	}
}

func TestCodeTakenByAnotherKey(t *testing.T) {
	e := newEnv(t, "")
	pub := randomPubKey(t)
	code := gm.DeriveCode(pub)

	// 先让别人的公钥占住这个码（模拟撞码）。
	other := randomPubKey(t)
	if _, err := e.st.InsertCode(context.Background(), code, other, "squatter", e.now, e.now.Add(time.Hour)); err != nil {
		t.Fatalf("insert squatter: %v", err)
	}

	var ch spec.ChallengeResponse
	resp := e.do(http.MethodPost, spec.PathChallenges, spec.ChallengeRequest{
		Purpose: spec.PurposeRegister, PubKey: auth.B64.EncodeToString(pub),
	}, "")
	e.decode(resp, &ch)
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		PubKey: auth.B64.EncodeToString(pub), Nickname: "victim",
		ChallengeID: ch.ChallengeID, Signature: fakeSig(),
	}, "")
	e.wantError(resp, spec.ErrCodeTaken)
}

func TestCodeNotFoundVsExpired(t *testing.T) {
	e := newEnv(t, "")
	code, _, _ := e.register("bob")

	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE codes SET expires_at = $2 WHERE code = $1`, code, e.now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.wantError(e.do(http.MethodGet, spec.CodePath(code), nil, ""), spec.ErrCodeExpired)

	missing := "ZZZZ"
	if missing == code {
		missing = "YYYY"
	}
	e.wantError(e.do(http.MethodGet, spec.CodePath(missing), nil, ""), spec.ErrCodeNotFound)
}

func TestPackageLifecycle(t *testing.T) {
	e := newEnv(t, "")
	senderCode, senderToken, _ := e.register("sender")
	recipientCode, recipientToken, _ := e.register("recipient")
	_ = senderCode

	f := e.createPackage(senderToken, recipientCode)

	if resp := e.putPrelude(senderToken, f.Info.PackageID, f.Prelude); resp.status != http.StatusOK {
		t.Fatalf("put prelude: %d %s", resp.status, resp.body)
	}
	// 乱序上传：2 → 0 → 1
	for _, idx := range []int{2, 0, 1} {
		if resp := e.putChunk(senderToken, f.Info.PackageID, idx, f.Chunks[idx]); resp.status != http.StatusOK {
			t.Fatalf("put chunk %d: %d %s", idx, resp.status, resp.body)
		}
	}

	// 同序号同内容 → 幂等，不产生副本、不改已收计数。
	var cp spec.ChunkPutResponse
	resp := e.putChunk(senderToken, f.Info.PackageID, 1, f.Chunks[1])
	if resp.status != http.StatusOK {
		t.Fatalf("idempotent chunk: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &cp)
	if !cp.Duplicate || cp.ReceivedChunks != 3 {
		t.Fatalf("idempotent chunk result: %+v", cp)
	}

	// 同序号不同内容 → 冲突，且不破坏已收块。
	bad := append([]byte(nil), f.Chunks[1]...)
	bad[0] ^= 0xff
	e.wantError(e.putChunk(senderToken, f.Info.PackageID, 1, bad), spec.ErrChunkConflict)

	// 续传进度：已收 3 块、缺 0 块。
	var prog spec.ProgressResponse
	resp = e.do(http.MethodGet, spec.ProgressPath(f.Info.PackageID), nil, senderToken)
	if resp.status != http.StatusOK {
		t.Fatalf("progress: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &prog)
	if prog.ReceivedChunks != 3 || len(prog.MissingIndexes) != 0 || !prog.PreludeReceived {
		t.Fatalf("progress: %+v", prog)
	}
	if prog.ReceivedBitmap == "" {
		t.Fatal("empty received bitmap")
	}

	// 完成标记 → ready。
	var info spec.PackageInfo
	resp = e.do(http.MethodPost, spec.CommitPath(f.Info.PackageID), nil, senderToken)
	if resp.status != http.StatusOK {
		t.Fatalf("commit: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &info)
	if info.State != spec.PackageReady {
		t.Fatalf("state after commit: %s", info.State)
	}

	// 锁定：commit 后再传块必须失败。
	e.wantError(e.putChunk(senderToken, f.Info.PackageID, 0, f.Chunks[0]), spec.ErrPackageLocked)
	e.wantError(e.putPrelude(senderToken, f.Info.PackageID, f.Prelude), spec.ErrPackageLocked)

	// 下载：prelude + 每块字节必须与上传完全一致。
	resp = e.do(http.MethodGet, spec.PreludePath(f.Info.PackageID), nil, recipientToken)
	if resp.status != http.StatusOK || !bytes.Equal(resp.body, f.Prelude) {
		t.Fatalf("get prelude: %d len=%d", resp.status, len(resp.body))
	}
	if resp.header.Get(spec.HeaderContentDigestAlg) != spec.DigestAlgSM3 || resp.header.Get(spec.HeaderContentDigest) == "" {
		t.Fatalf("missing digest headers: %v", resp.header)
	}
	for i, want := range f.Chunks {
		resp = e.do(http.MethodGet, spec.ChunkPath(f.Info.PackageID, i), nil, recipientToken)
		if resp.status != http.StatusOK || !bytes.Equal(resp.body, want) {
			t.Fatalf("get chunk %d: %d", i, resp.status)
		}
	}

	// 接收确认：默认 1 次额度 + 收到即删。
	var st spec.StateResponse
	resp = e.do(http.MethodPost, spec.AckPath(f.Info.PackageID), nil, recipientToken)
	if resp.status != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.status, resp.body)
	}
	e.decode(resp, &st)
	if st.State != spec.PackageExhausted {
		t.Fatalf("state after ack: %s", st.State)
	}

	// 终结后块必须不可下载。
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(f.Info.PackageID, 0), nil, recipientToken), spec.ErrPackageExhausted)
	e.wantError(e.do(http.MethodGet, spec.PreludePath(f.Info.PackageID), nil, recipientToken), spec.ErrPackageExhausted)

	// 磁盘上必须已经没有这个包的目录。
	if _, err := os.Stat(filepath.Join(e.dir, f.Info.PackageID[:2], f.Info.PackageID)); !os.IsNotExist(err) {
		t.Fatalf("package dir still exists after ack: %v", err)
	}
}

func TestAuthBoundary(t *testing.T) {
	e := newEnv(t, "")
	_, senderToken, _ := e.register("sender")
	recipientCode, recipientToken, _ := e.register("recipient")
	_, strangerToken, _ := e.register("stranger")

	f := e.createPackage(senderToken, recipientCode)

	// 无令牌：一律 401。
	e.wantError(e.do(http.MethodGet, spec.ProgressPath(f.Info.PackageID), nil, ""), spec.ErrUnauthorized)
	e.wantError(e.putChunk("", f.Info.PackageID, 0, f.Chunks[0]), spec.ErrUnauthorized)

	// 陌生码既不能读也不能写。
	e.wantError(e.do(http.MethodGet, spec.ProgressPath(f.Info.PackageID), nil, strangerToken), spec.ErrForbidden)
	e.wantError(e.putChunk(strangerToken, f.Info.PackageID, 0, f.Chunks[0]), spec.ErrForbidden)

	// 接收方不能上传（只有发送方能写）。
	e.wantError(e.putChunk(recipientToken, f.Info.PackageID, 0, f.Chunks[0]), spec.ErrForbidden)
	e.wantError(e.putPrelude(recipientToken, f.Info.PackageID, f.Prelude), spec.ErrForbidden)

	// 发送方不能替接收方确认。
	_ = e.putPrelude(senderToken, f.Info.PackageID, f.Prelude)
	for i, c := range f.Chunks {
		_ = e.putChunk(senderToken, f.Info.PackageID, i, c)
	}
	_ = e.do(http.MethodPost, spec.CommitPath(f.Info.PackageID), nil, senderToken)
	e.wantError(e.do(http.MethodPost, spec.AckPath(f.Info.PackageID), nil, senderToken), spec.ErrForbidden)

	// 未 commit 之前接收方不能下载。
	f2 := e.createPackage(senderToken, recipientCode)
	_ = e.putPrelude(senderToken, f2.Info.PackageID, f2.Prelude)
	e.wantError(e.do(http.MethodGet, spec.PreludePath(f2.Info.PackageID), nil, recipientToken), spec.ErrPackageIncomplete)
}

func TestRevoke(t *testing.T) {
	e := newEnv(t, "")
	_, senderToken, _ := e.register("sender")
	recipientCode, recipientToken, _ := e.register("recipient")

	f := e.createPackage(senderToken, recipientCode)
	_ = e.putPrelude(senderToken, f.Info.PackageID, f.Prelude)
	for i, c := range f.Chunks {
		_ = e.putChunk(senderToken, f.Info.PackageID, i, c)
	}
	_ = e.do(http.MethodPost, spec.CommitPath(f.Info.PackageID), nil, senderToken)

	resp := e.do(http.MethodPost, spec.RevokePath(f.Info.PackageID), nil, senderToken)
	if resp.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", resp.status, resp.body)
	}
	e.wantError(e.do(http.MethodGet, spec.ChunkPath(f.Info.PackageID, 0), nil, recipientToken), spec.ErrPackageRevoked)
	if _, err := os.Stat(filepath.Join(e.dir, f.Info.PackageID[:2], f.Info.PackageID)); !os.IsNotExist(err) {
		t.Fatalf("package dir still exists after revoke: %v", err)
	}
}

func TestTTLExpiryAndSweep(t *testing.T) {
	e := newEnv(t, "")
	_, senderToken, _ := e.register("sender")
	recipientCode, recipientToken, _ := e.register("recipient")

	ttl := uint32(60)
	resp := e.do(http.MethodPost, spec.PathPackages, spec.CreatePackageRequest{
		RecipientCode: recipientCode, ChunkCount: 1, ChunkSize: 32,
		PlaintextSize: 10, PreludeLen: 100, TTLSeconds: &ttl,
	}, senderToken)
	var info spec.PackageInfo
	e.decode(resp, &info)
	_ = e.putPrelude(senderToken, info.PackageID, randomBytes(100))

	e.advance(2 * time.Minute)
	if _, err := e.sweep.Once(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	e.wantError(e.do(http.MethodGet, spec.PreludePath(info.PackageID), nil, recipientToken), spec.ErrPackageExpired)
	if _, err := os.Stat(filepath.Join(e.dir, info.PackageID[:2], info.PackageID)); !os.IsNotExist(err) {
		t.Fatalf("package dir still exists after TTL: %v", err)
	}
}

func TestLookupRateLimited(t *testing.T) {
	e := newEnv(t, "")
	limited := false
	alphabet := gm.CrockfordAlphabet
	// 25 个各不相同的合法码：突发上限内会开始 429。
	for i := 0; i < 25 && !limited; i++ {
		code := string([]byte{
			alphabet[(i*7)%32], alphabet[(i*11+3)%32],
			alphabet[(i*13+5)%32], alphabet[(i*17+9)%32],
		})
		resp := e.do(http.MethodGet, spec.CodePath(code), nil, "")
		switch resp.status {
		case http.StatusTooManyRequests:
			limited = true
		case http.StatusNotFound:
		default:
			t.Fatalf("unexpected status %d", resp.status)
		}
	}
	if !limited {
		t.Fatal("expected lookup rate limit to trigger")
	}
}

func TestLookupFailureLockout(t *testing.T) {
	e := newEnv(t, "")
	code := "AWQW"
	if _, err := e.st.GetCode(context.Background(), code); err == nil {
		t.Fatal("unexpected code present")
	}
	for i := 0; i < spec.DefaultLimits.FailureThreshold; i++ {
		e.wantError(e.do(http.MethodGet, spec.CodePath(code), nil, ""), spec.ErrCodeNotFound)
	}
	e.wantError(e.do(http.MethodGet, spec.CodePath(code), nil, ""), spec.ErrLockedOut)
}

func TestVerifierFailClosed(t *testing.T) {
	e := newEnv(t, auth.ModeStubDeny)
	pub := randomPubKey(t)
	var ch spec.ChallengeResponse
	resp := e.do(http.MethodPost, spec.PathChallenges, spec.ChallengeRequest{
		Purpose: spec.PurposeRegister, PubKey: auth.B64.EncodeToString(pub),
	}, "")
	e.decode(resp, &ch)
	resp = e.do(http.MethodPost, spec.PathCodes, spec.RegisterCodeRequest{
		PubKey: auth.B64.EncodeToString(pub), Nickname: "x",
		ChallengeID: ch.ChallengeID, Signature: fakeSig(),
	}, "")
	e.wantError(resp, spec.ErrVerifierUnavailable)
}

// TestNoFilenameOrPlaintextPersisted 是 Gate 那一条的自动化版本：
// 服务端从不上行文件名与明文，库与盘都不该出现它们。
func TestNoFilenameOrPlaintextPersisted(t *testing.T) {
	e := newEnv(t, "")
	_, senderToken, _ := e.register("sender")
	recipientCode, recipientToken, _ := e.register("recipient")

	f := e.createPackage(senderToken, recipientCode)
	_ = e.putPrelude(senderToken, f.Info.PackageID, f.Prelude)
	for i, c := range f.Chunks {
		_ = e.putChunk(senderToken, f.Info.PackageID, i, c)
	}
	_ = e.do(http.MethodPost, spec.CommitPath(f.Info.PackageID), nil, senderToken)
	_ = e.do(http.MethodGet, spec.ChunkPath(f.Info.PackageID, 1), nil, recipientToken)

	// 这些标记只存在于客户端，永远不该上行；用它们做探针。
	for _, marker := range []string{"secret-report.pdf", "PDF-1.7", "quarterly-secret"} {
		assertMarkerAbsentInDB(t, e.st, marker)
		assertMarkerAbsentInBlobNames(t, e.dir, marker)
	}

	// 盘上只有不透明字节：文件名只能是固定名字或块序号。
	entries, err := os.ReadDir(filepath.Join(e.dir, f.Info.PackageID[:2], f.Info.PackageID))
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "prelude" || name == "chunks" {
			continue
		}
		t.Fatalf("unexpected file in package dir: %q", name)
	}
}

// ---------- helpers ----------

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) % 251)
	}
	return b
}

func randomPubKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 65)
	b[0] = 0x04
	if _, err := rand.Read(b[1:]); err != nil {
		t.Fatal(err)
	}
	return b
}

func fakeSig() string { return auth.B64.EncodeToString(randomBytes(71)) }

// assertMarkerAbsentInDB 扫当前 schema 里所有 text/bytea 列。
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
		if !strings.Contains(c.dataType, "text") && !strings.Contains(c.dataType, "bytea") && !strings.Contains(c.dataType, "character") {
			continue
		}
		q := fmt.Sprintf("SELECT %s::text FROM %s",
			quoteIdent(c.column), quoteIdent(c.table))
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
				t.Fatalf("marker %q found in DB column %s.%s", marker, c.table, c.column)
			}
		}
		vals.Close()
	}
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

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
		t.Fatalf("walk blob dir: %v", err)
	}
}
