package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/config"
)

// 服务端取 X-Forwarded-For 的**第一跳（最左）**；只有显式信任反代时才看这个头。
func TestClientIPUsesFirstHop(t *testing.T) {
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1, 10.0.0.2")

	trusted := &API{cfg: config.Config{TrustProxyHeaders: true}}
	if got := trusted.clientIP(r); got != "203.0.113.9" {
		t.Fatalf("trust proxy: got %q, want leftmost 203.0.113.9", got)
	}

	untrusted := &API{cfg: config.Config{TrustProxyHeaders: false}}
	if got := untrusted.clientIP(r); got != "10.1.2.3" {
		t.Fatalf("no trust: got %q, want remote addr 10.1.2.3", got)
	}
}
