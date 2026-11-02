package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/store"
	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

// kid 只增不减：相等幂等、更大更新、更小拒绝。
func TestEnsureTokenKIDMonotonic(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()
	now := time.Now().UTC()

	stored, err := st.EnsureTokenKID(ctx, 1, now)
	if err != nil || stored != 1 {
		t.Fatalf("first: stored=%d err=%v", stored, err)
	}
	// 相等：幂等。
	if stored, err = st.EnsureTokenKID(ctx, 1, now); err != nil || stored != 1 {
		t.Fatalf("equal: stored=%d err=%v", stored, err)
	}
	// 更大：更新。
	if stored, err = st.EnsureTokenKID(ctx, 5, now); err != nil || stored != 5 {
		t.Fatalf("increase: stored=%d err=%v", stored, err)
	}
	// 更小：拒绝，并回传已记录的最大值。
	stored, err = st.EnsureTokenKID(ctx, 4, now)
	if !errors.Is(err, store.ErrTokenKIDLower) {
		t.Fatalf("decrease: err=%v, want ErrTokenKIDLower", err)
	}
	if stored != 5 {
		t.Fatalf("decrease: stored=%d, want 5", stored)
	}
}
