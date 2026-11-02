package config

import (
	"strings"
	"testing"
)

func TestValidateForServeRequiresTokenSecret(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", "")
	t.Setenv("YANSHU_TOKEN_EPOCH", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.ValidateForServe(); err == nil {
		t.Fatal("empty TOKEN_SECRET must be rejected when serving")
	} else if !strings.Contains(err.Error(), "YANSHU_TOKEN_SECRET") {
		t.Fatalf("error should name the variable: %v", err)
	}

	// 太短也算缺失。
	t.Setenv("YANSHU_TOKEN_SECRET", "short")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.ValidateForServe(); err == nil {
		t.Fatal("short TOKEN_SECRET must be rejected")
	}

	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.ValidateForServe(); err != nil {
		t.Fatalf("valid secret rejected: %v", err)
	}
}

func TestVerifierDefaultsToFailClosed(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_VERIFIER", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Verifier != VerifierStubDeny {
		t.Fatalf("default verifier = %q, want %q", cfg.Verifier, VerifierStubDeny)
	}
}

// sm2 模式没有内核时必须启动失败（fail closed，不降级）。
func TestSM2RequiresKernelWhenServing(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	t.Setenv("YANSHU_TOKEN_EPOCH", "1")
	t.Setenv("YANSHU_VERIFIER", "sm2")
	t.Setenv("YANSHU_KERNEL_WASM", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	err = cfg.ValidateForServe()
	if err == nil {
		t.Fatal("sm2 without kernel must fail validation")
	}
	if !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("error should mention the kernel: %v", err)
	}
}

// EPOCH 缺省为 1（bootstrap）；非法值必须拒绝。
func TestTokenEpochDefaultsToOne(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	t.Setenv("YANSHU_TOKEN_EPOCH", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TokenEpoch != 1 {
		t.Fatalf("default epoch = %d, want 1", cfg.TokenEpoch)
	}
	if err := cfg.ValidateForServe(); err != nil {
		t.Fatalf("default epoch rejected: %v", err)
	}
}

// kid 必须是正整数（单调递增的前提）。
func TestTokenKIDMustBePositiveInteger(t *testing.T) {
	for _, bad := range []string{"k1", "0", "-3", "1.5", "abc"} {
		t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
		t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
		t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
		t.Setenv("YANSHU_TOKEN_EPOCH", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("kid %q accepted, want rejection", bad)
		}
	}
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	t.Setenv("YANSHU_TOKEN_EPOCH", "42")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid kid rejected: %v", err)
	}
	if cfg.TokenEpoch != 42 {
		t.Fatalf("TokenEpoch = %d", cfg.TokenEpoch)
	}
}

func TestDatabaseURLIsRequired(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	if _, err := Load(); err == nil {
		t.Fatal("missing YANSHU_DATABASE_URL must fail")
	}
}
