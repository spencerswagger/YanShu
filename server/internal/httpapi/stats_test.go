package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// /v1/stats：形状固定、匿名可读、响应头排除缓存；created 与 consumed 随业务动作累加。
func TestStatsEndpoint(t *testing.T) {
	e := newEnv(t, "")
	e.api.statsTTL = 0 // 关缓存，逐次读源站

	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")

	get := func() (spec.StatsResponse, http.Header) {
		resp := e.do(http.MethodGet, spec.PathStats, nil, nil)
		if resp.status != http.StatusOK {
			t.Fatalf("stats: %d %s", resp.status, resp.body)
		}
		var st spec.StatsResponse
		if err := json.Unmarshal(resp.body, &st); err != nil {
			t.Fatal(err)
		}
		return st, resp.header
	}

	base, hdr := get()
	if hdr.Get("Cache-Control") != "no-store" || hdr.Get("CDN-Cache-Control") != "no-store" ||
		hdr.Get("Surrogate-Control") != "no-store" {
		t.Fatalf("cache headers must all be no-store: %v", hdr)
	}
	if base.Today.Created != 0 || base.Total.Created != 0 {
		t.Fatalf("fresh env should start at 0: %+v", base)
	}

	// 建包 → created +1。
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)
	afterCreate, _ := get()
	if afterCreate.Today.Created != 1 || afterCreate.Total.Created != 1 {
		t.Fatalf("created not counted: %+v", afterCreate)
	}
	if afterCreate.Today.Consumed != 0 {
		t.Fatalf("consumed should stay 0: %+v", afterCreate)
	}

	// 走完整链路到 ack → consumed +1、bytes = plaintext_size。
	if resp := e.putPrelude(tr.UploadToken, tr, f.Prelude); resp.status != http.StatusCreated {
		t.Fatalf("prelude: %d", resp.status)
	}
	for i, c := range f.Chunks {
		if resp := e.putChunk(tr.UploadToken, tr, i, c); resp.status != http.StatusCreated {
			t.Fatalf("chunk %d: %d", i, resp.status)
		}
	}
	if resp := e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: tr.UploadToken,
	}); resp.status != http.StatusOK {
		t.Fatalf("complete: %d", resp.status)
	}
	leaseResp := e.do(http.MethodGet, spec.PreludePath(tr.TransferID), nil, nil)
	dl := leaseResp.header.Get(spec.HeaderDownloadID)
	ackHdrs := e.authHeaders(spec.PurposeTransferAck, recipient)
	ackHdrs[spec.HeaderDownloadID] = dl
	if resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, ackHdrs); resp.status != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.status, resp.body)
	}

	afterAck, _ := get()
	if afterAck.Today.Consumed != 1 || afterAck.Total.Consumed != 1 {
		t.Fatalf("consumed not counted: %+v", afterAck)
	}
	if afterAck.Today.ConsumedBytes != int64(f.PlaintextSize) {
		t.Fatalf("consumed_bytes = %d, want %d", afterAck.Today.ConsumedBytes, f.PlaintextSize)
	}
	if afterAck.GeneratedAt == "" {
		t.Fatal("generated_at missing")
	}
}

// 缓存生效验证：60s 内两次 generated_at 相同（不重新打库）。
func TestStatsCache(t *testing.T) {
	e := newEnv(t, "")
	r1 := e.do(http.MethodGet, spec.PathStats, nil, nil)
	r2 := e.do(http.MethodGet, spec.PathStats, nil, nil)
	var a, b spec.StatsResponse
	if err := json.Unmarshal(r1.body, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(r2.body, &b); err != nil {
		t.Fatal(err)
	}
	if a.GeneratedAt != b.GeneratedAt {
		t.Fatalf("cache not effective: %s vs %s", a.GeneratedAt, b.GeneratedAt)
	}
}

// 基准：1000 次 /v1/stats（60s 缓存生效时；用 Go 客户端复用连接，排除进程启动开销）。
func BenchmarkStatsEndpoint(b *testing.B) {
	e := newEnv(&testing.T{}, "") // 仅为拿到 httptest server 与 store
	client := e.srv.Client()
	url := e.srv.URL + spec.PathStats
	e.api.statsTTL = 60 * time.Second // 缓存生效
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}
