package ratelimit

import (
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

func TestTokenBucket(t *testing.T) {
	m := NewMemory()
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	limit := spec.Limit{WindowSeconds: 60, Max: 60, Burst: 3}

	for i := 0; i < 3; i++ {
		if d := m.Take("k", limit); !d.Allowed {
			t.Fatalf("request %d denied", i)
		}
	}
	d := m.Take("k", limit)
	if d.Allowed {
		t.Fatal("4th request allowed beyond burst")
	}
	if d.RetryAfter <= 0 {
		t.Fatalf("retryAfter = %v", d.RetryAfter)
	}

	// 过一秒应该补 1 个令牌（60/min = 1/s）。
	now = now.Add(time.Second)
	if d := m.Take("k", limit); !d.Allowed {
		t.Fatal("token not refilled after 1s")
	}
}

func TestFailureLock(t *testing.T) {
	m := NewMemory()
	now := time.Unix(2000, 0)
	m.now = func() time.Time { return now }

	for i := 0; i < 4; i++ {
		if locked, _ := m.Fail("code:AWQW", 5, time.Minute); locked {
			t.Fatalf("locked too early at %d", i+1)
		}
	}
	locked, retry := m.Fail("code:AWQW", 5, time.Minute)
	if !locked || retry != time.Minute {
		t.Fatalf("5th failure: locked=%v retry=%v", locked, retry)
	}
	if l, _ := m.Locked("code:AWQW"); !l {
		t.Fatal("Locked() = false during lock")
	}

	now = now.Add(2 * time.Minute)
	if l, _ := m.Locked("code:AWQW"); l {
		t.Fatal("still locked after expiry")
	}

	m.Fail("code:AWQW", 5, time.Minute)
	m.Succeed("code:AWQW")
	if l, _ := m.Locked("code:AWQW"); l {
		t.Fatal("Succeed did not clear failure state")
	}
}

func TestIndependentKeys(t *testing.T) {
	m := NewMemory()
	limit := spec.Limit{WindowSeconds: 60, Max: 60, Burst: 1}
	if d := m.Take("a", limit); !d.Allowed {
		t.Fatal("a denied")
	}
	if d := m.Take("b", limit); !d.Allowed {
		t.Fatal("b denied; keys are not independent")
	}
}
