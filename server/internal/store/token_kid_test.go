package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/store"
	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

// KID 只增不减：递增可写、**相等幂等（重复启动不报错）**、调小拒绝。
func TestEnsureTokenEpoch(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()
	now := time.Now().UTC()

	if stored, err := st.EnsureTokenEpoch(ctx, 1, now); err != nil || stored != 1 {
		t.Fatalf("first: stored=%d err=%v", stored, err)
	}
	// 等于：允许（重启幂等）。
	if stored, err := st.EnsureTokenEpoch(ctx, 1, now); err != nil || stored != 1 {
		t.Fatalf("equal: stored=%d err=%v", stored, err)
	}
	// 递增：更新。
	if stored, err := st.EnsureTokenEpoch(ctx, 3, now); err != nil || stored != 3 {
		t.Fatalf("increase: stored=%d err=%v", stored, err)
	}
	// 调小：拒绝，并回传当前值。
	stored, err := st.EnsureTokenEpoch(ctx, 2, now)
	if !errors.Is(err, store.ErrTokenEpochLower) || stored != 3 {
		t.Fatalf("decrease: stored=%d err=%v", stored, err)
	}
}
