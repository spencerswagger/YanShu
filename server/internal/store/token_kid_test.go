package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/store"
	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

// EPOCH 只增不减：相等幂等、更大更新、更小拒绝。
func TestEnsureTokenEpochMonotonic(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()
	now := time.Now().UTC()

	stored, err := st.EnsureTokenEpoch(ctx, 1, now)
	if err != nil || stored != 1 {
		t.Fatalf("first: stored=%d err=%v", stored, err)
	}
	if stored, err = st.EnsureTokenEpoch(ctx, 1, now); err != nil || stored != 1 {
		t.Fatalf("equal: stored=%d err=%v", stored, err)
	}
	if stored, err = st.EnsureTokenEpoch(ctx, 5, now); err != nil || stored != 5 {
		t.Fatalf("increase: stored=%d err=%v", stored, err)
	}
	stored, err = st.EnsureTokenEpoch(ctx, 4, now)
	if !errors.Is(err, store.ErrTokenEpochLower) || stored != 5 {
		t.Fatalf("decrease: stored=%d err=%v", stored, err)
	}
	if cur, err := st.CurrentTokenEpoch(ctx); err != nil || cur != 5 {
		t.Fatalf("current: %d %v", cur, err)
	}
}
