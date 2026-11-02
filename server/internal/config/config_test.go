package config

import (
	"strings"
	"testing"
)

func TestValidateForServeRequiresTokenSecret(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_EPOCH", "1")
	t.Setenv("YANSHU_TOKEN_SECRET", "")

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

// 缺 KID 必须拒绝启动（fail closed）。
func TestTokenEpochDefaultsToOne(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
	t.Setenv("YANSHU_TOKEN_EPOCH", "")
	t.Setenv("YANSHU_TOKEN_KID", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TokenEpochNum != 1 {
		t.Fatalf("default epoch = %d, want 1", cfg.TokenEpochNum)
	}
	if err := cfg.ValidateForServe(); err != nil {
		t.Fatalf("default epoch rejected: %v", err)
	}
}

// stub-allow 只允许在 local|test + loopback 下启动。
func TestStubAllowRequiresLocalEnvAndLoopback(t *testing.T) {
	base := func() {
		t.Setenv("YANSHU_DATABASE_URL", "postgres://x@127.0.0.1:5432/x?sslmode=disable")
		t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
		t.Setenv("YANSHU_TOKEN_SECRET", strings.Repeat("k", MinTokenSecretLen))
		t.Setenv("YANSHU_TOKEN_EPOCH", "1")
		t.Setenv("YANSHU_VERIFIER", "stub-allow")
	}
	cases := []struct {
		name    string
		env     string
		addr    string
		wantErr bool
	}{
		{"local+loopback", "local", "127.0.0.1:18080", false},
		{"test+loopback", "test", "localhost:18080", false},
		{"non-local env", "prod", "127.0.0.1:18080", true},
		{"empty env", "", "127.0.0.1:18080", true},
		{"all interfaces", "local", ":18080", true},
		{"public addr", "local", "0.0.0.0:18080", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base()
			t.Setenv("YANSHU_ENV", c.env)
			t.Setenv("YANSHU_ADDR", c.addr)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			err = cfg.ValidateForServe()
			if (err != nil) != c.wantErr {
				t.Fatalf("wantErr=%v got %v", c.wantErr, err)
			}
		})
	}
}

func TestDatabaseURLIsRequired(t *testing.T) {
	t.Setenv("YANSHU_DATABASE_URL", "")
	t.Setenv("YANSHU_BLOB_DIR", t.TempDir())
	if _, err := Load(); err == nil {
		t.Fatal("missing YANSHU_DATABASE_URL must fail")
	}
}
