// Package config 读取环境变量配置。
//
// 约定：所有配置项都以 YANSHU_ 前缀；密钥/凭据**不进仓库**，只从环境取。
// 配置错误一律 fail fast（启动即退出），避免带着半套参数上线。
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// VerifierMode 选择 SM2 验签实现。
type VerifierMode string

const (
	// VerifierSM2 使用真实 SM2 验签实现（待接入）。
	VerifierSM2 VerifierMode = "sm2"
	// VerifierStubDeny 是默认值：一律拒绝，fail closed。
	VerifierStubDeny VerifierMode = "stub-deny"
	// VerifierStubAllow 只给本地联调与测试用，启动日志会告警。
	VerifierStubAllow VerifierMode = "stub-allow"
)

// Config 是服务端运行参数。
type Config struct {
	Addr        string
	DatabaseURL string
	BlobDir     string
	Verifier    VerifierMode
	// StrictCode 为 true 时只接受已归一化的 4 位码（CRYPTO-PACK §3.4 字面要求）。
	StrictCode bool
	// TrustProxyHeaders 为 true 时从 X-Forwarded-For 取客户端 IP。
	TrustProxyHeaders bool

	CodeTTL      time.Duration
	PackageTTL   time.Duration
	SessionTTL   time.Duration
	ChallengeTTL time.Duration

	MaxPackageBytes   int64 // 单包密文上限
	MaxPreludeBytes   int64
	MaxChunkBytes     int64
	StorageQuotaBytes int64 // 单 IP 未清理包的密文总量上限
	SweepInterval     time.Duration
	ShutdownTimeout   time.Duration
}

// Load 从环境变量构造配置。
func Load() (Config, error) {
	c := Config{
		Addr:              env("YANSHU_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("YANSHU_DATABASE_URL"),
		BlobDir:           env("YANSHU_BLOB_DIR", "./data/blobs"),
		Verifier:          VerifierMode(env("YANSHU_VERIFIER", string(VerifierStubDeny))),
		StrictCode:        envBool("YANSHU_CODE_STRICT", false),
		TrustProxyHeaders: envBool("YANSHU_TRUST_PROXY", false),
		CodeTTL:           envDuration("YANSHU_CODE_TTL", spec.DefaultCodeTTL),
		PackageTTL:        envDuration("YANSHU_PACKAGE_TTL", spec.DefaultPackageTTL),
		SessionTTL:        envDuration("YANSHU_SESSION_TTL", spec.DefaultSessionTTL),
		ChallengeTTL:      envDuration("YANSHU_CHALLENGE_TTL", spec.DefaultChallengeTTL),
		SweepInterval:     envDuration("YANSHU_SWEEP_INTERVAL", 30*time.Second),
		ShutdownTimeout:   envDuration("YANSHU_SHUTDOWN_TIMEOUT", 10*time.Second),
		MaxPackageBytes:   envInt64("YANSHU_MAX_PACKAGE_BYTES", 4<<30),
		MaxPreludeBytes:   envInt64("YANSHU_MAX_PRELUDE_BYTES", int64(spec.MaxPreludeLen)),
		MaxChunkBytes:     envInt64("YANSHU_MAX_CHUNK_BYTES", int64(spec.DefaultMaxChunkSize)+16),
		StorageQuotaBytes: envInt64("YANSHU_STORAGE_QUOTA_BYTES", 8<<30),
	}

	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: YANSHU_DATABASE_URL is required")
	}
	switch c.Verifier {
	case VerifierSM2, VerifierStubDeny, VerifierStubAllow:
	default:
		return Config{}, fmt.Errorf("config: unknown YANSHU_VERIFIER %q (want sm2|stub-deny|stub-allow)", c.Verifier)
	}
	if c.BlobDir == "" {
		return Config{}, fmt.Errorf("config: YANSHU_BLOB_DIR is required")
	}
	if c.MaxChunkBytes < 16 {
		return Config{}, fmt.Errorf("config: YANSHU_MAX_CHUNK_BYTES too small")
	}
	if c.SweepInterval <= 0 {
		return Config{}, fmt.Errorf("config: YANSHU_SWEEP_INTERVAL must be positive")
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
