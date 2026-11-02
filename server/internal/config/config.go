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

	// LogFile 非空时把日志同时追加写入该文件（单文件，不滚动）。
	LogFile string
	// LogDir 非空时按 UTC 日期滚动写 <dir>/yanshu-server-YYYY-MM-DD.log（stdout 仍保留）。
	// 与 LogFile 同时设置时以 LogFile 为准。
	LogDir string
	// LogRetentionDays 是滚动日志的保留天数（默认 7）。
	LogRetentionDays int

	SweepInterval   time.Duration
	ShutdownTimeout time.Duration
}

// MinTokenSecretLen 是 upload_token HMAC 密钥的最小长度（字节）。
const MinTokenSecretLen = 16

// ValidateForServe 校验「真正对外服务」所需的配置。
//
// 刻意与 Load 分开：`-migrate-only` 只需要数据库，不需要 token 密钥；
// 但只要开始监听端口，就必须有稳定的 TOKEN_SECRET —— 缺失时**报错退出**，
// 不允许静默用空值/进程内随机值跑起来（那会让 upload_token 在重启后全部失效，
// 而且部署方根本察觉不到）。
func (c Config) ValidateForServe() error {
	if len(c.TokenSecret) < MinTokenSecretLen {
		return fmt.Errorf("config: YANSHU_TOKEN_SECRET is required when serving (>=%d bytes); "+
			"read it from an env var or a 0600 file, never hardcode it", MinTokenSecretLen)
	}
	return nil
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
		LogDir:            os.Getenv("YANSHU_LOG_DIR"),
		LogRetentionDays:  int(envInt64("YANSHU_LOG_RETENTION_DAYS", 7)),
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
