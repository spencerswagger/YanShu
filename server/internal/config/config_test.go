package config

import (
	"strings"
	"testing"
)

func TestValidateForServeRequiresTokenSecret(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", "")
	t.Setenv("YANSHU_TOKEN_KID", "1")

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
	t.Setenv("YANSHU_TOKEN_KID", "1")
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

// 没有密钥版本时必须拒绝启动（fail closed）：否则无法判断"旧 token"。
func TestTokenKIDRequired(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	t.Setenv("YANSHU_TOKEN_KID", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	err = cfg.ValidateForServe()
	if err == nil {
		t.Fatal("missing TOKEN_KID must fail validation")
	}
	if !strings.Contains(err.Error(), "YANSHU_TOKEN_KID") {
		t.Fatalf("error should name the variable: %v", err)
	}
}

// kid 必须是正整数（单调递增的前提）。
func TestTokenKIDMustBePositiveInteger(t *testing.T) {
	for _, bad := range []string{"k1", "0", "-3", "1.5", "abc"} {
		t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
		t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
		t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
		t.Setenv("YANSHU_TOKEN_KID", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("kid %q accepted, want rejection", bad)
		}
	}
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	t.Setenv("YANSHU_TOKEN_KID", "42")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid kid rejected: %v", err)
	}
	if cfg.TokenKIDNum != 42 {
		t.Fatalf("TokenKIDNum = %d", cfg.TokenKIDNum)
	}
}

func TestDatabaseURLIsRequired(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	if _, err := Load(); err == nil {
		t.Fatal("missing YANSHU_DATABASE_URL must fail")
	}
}
