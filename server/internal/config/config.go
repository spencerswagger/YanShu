// Package config 读取环境变量配置。
//
// 约定：配置项都以 YANSHU_ 前缀；密钥/凭据不进仓库，只从环境取。
// 配置错误一律 fail fast。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// VerifierMode 选择 SM2 验签实现。
type VerifierMode string

const (
	// VerifierSM2 使用真实 SM2 验签实现（待接入）。
	VerifierSM2 VerifierMode = "sm2"
	// VerifierStubDeny 是默认值：一律拒绝，fail closed。
	VerifierStubDeny VerifierMode = "stub-deny"
	// VerifierStubAllow 只给本地联调与测试用。
	VerifierStubAllow VerifierMode = "stub-allow"
)

// Config 是服务端运行参数。
type Config struct {
	Addr        string
	DatabaseURL string
	BlobDir     string
	Verifier    VerifierMode
	// TrustProxyHeaders 为 true 时从 X-Forwarded-For 取客户端 IP。
	TrustProxyHeaders bool

	// TokenSecret 是 upload_token 的 HMAC 密钥；为空则进程内随机（重启后旧 token 失效）。
	TokenSecret []byte

	// 对外配置（GET /v1/config）。
	STUNURLs []string
	WSURL    string

	// StorageQuotaBytes 是单 IP 未取走密文总量上限（API.md §11.4，默认 8 GiB）。
	StorageQuotaBytes int64

	// LogFile 非空时把日志同时追加写入该文件（常驻实例用；stdout 仍然保留）。
	LogFile string

	SweepInterval   time.Duration
	ShutdownTimeout time.Duration
}

// Load 从环境变量构造配置。
func Load() (Config, error) {
	c := Config{
		Addr:              env("YANSHU_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("YANSHU_DATABASE_URL"),
		BlobDir:           env("YANSHU_BLOB_DIR", "./data/blobs"),
		Verifier:          VerifierMode(env("YANSHU_VERIFIER", string(VerifierStubDeny))),
		TrustProxyHeaders: envBool("YANSHU_TRUST_PROXY", false),
		STUNURLs:          envList("YANSHU_STUN_URLS", []string{"stun:stun.l.google.com:19302"}),
		WSURL:             env("YANSHU_WS_URL", ""),
		StorageQuotaBytes: envInt64("YANSHU_STORAGE_QUOTA_BYTES", 8<<30),
		LogFile:           os.Getenv("YANSHU_LOG_FILE"),
		SweepInterval:     envDuration("YANSHU_SWEEP_INTERVAL", 30*time.Second),
		ShutdownTimeout:   envDuration("YANSHU_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	if secret := os.Getenv("YANSHU_TOKEN_SECRET"); secret != "" {
		c.TokenSecret = []byte(secret)
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

func envList(key string, def []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
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
