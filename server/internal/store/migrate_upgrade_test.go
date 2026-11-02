package store_test

import (
	"context"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/testutil"
)

// 升级路径：模拟"已经应用过 0001、但没有 upload_token_kid 列的旧库"，
// 再跑一次迁移，断言列被 ALTER 补上、schema_migrations 有 0002 记账、连跑两次幂等。
//
// 这是 739293a 那个 P0 的回归测试：只测"全新建库"发现不了缺 ALTER。
func TestMigrateUpgradeFromOldSchema(t *testing.T) {
	st := testutil.NewStore(t, "store")
	ctx := context.Background()

	// 退回到"没有该列、也没记 0002"的旧库形态。
	if _, err := st.Pool().Exec(ctx, `ALTER TABLE transfers DROP COLUMN IF EXISTS upload_token_kid`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if _, err := st.Pool().Exec(ctx, `DELETE FROM schema_migrations WHERE version LIKE '0002%'`); err != nil {
		t.Fatalf("forget 0002: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate upgrade: %v", err)
	}

	var nullable string
	err := st.Pool().QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_name = 'transfers' AND column_name = 'upload_token_kid'`).Scan(&nullable)
	if err != nil {
		t.Fatalf("column missing after upgrade: %v", err)
	}
	if nullable != "NO" {
		t.Fatalf("column must be NOT NULL after upgrade, got is_nullable=%s", nullable)
	}

	var version string
	if err := st.Pool().QueryRow(ctx,
		`SELECT version FROM schema_migrations WHERE version LIKE '0002%'`).Scan(&version); err != nil {
		t.Fatalf("schema_migrations missing 0002: %v", err)
	}

	// 连跑两次：幂等。
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}
