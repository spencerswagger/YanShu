// Package config 读取环境变量配置。
//
// 约定：配置项都以 YANSHU_ 前缀；密钥/凭据不进仓库，只从环境取。
// 配置错误一律 fail fast。
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	// Env 是部署环境标识（local/test/…）；stub-allow 只在 local|test 下允许。
	Env      string
	Verifier VerifierMode
	// TrustProxyHeaders 为 true 时从 X-Forwarded-For 取客户端 IP。
	TrustProxyHeaders bool

	// TokenSecret 是 upload_token 的 HMAC 密钥（只作派生盐）。
	TokenSecret []byte
	// TokenEpoch 是 token 的密钥版本（严格单调递增；唯一吊销开关）。
	TokenEpoch    string
	TokenEpochNum int64

	// 对外配置（GET /v1/config）。
	STUNURLs []string
	WSURL    string

	// StorageQuotaBytes 是单 IP 未取走密文总量上限（API.md §11.4，默认 8 GiB）。
	StorageQuotaBytes int64

	// KernelWASM 是 sm2 验签用的端侧内核路径（YANSHU_KERNEL_WASM）；
	// 留空时自动探测 ./kernel/yanshu_sm.wasm 与可执行文件同级的 kernel/。
	KernelWASM string
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
// ResolveKernelWASM 解析内核路径：显式 env 优先，其次当前目录与可执行文件同级的 kernel/。
func (c Config) ResolveKernelWASM() string {
	if c.KernelWASM != "" {
		return c.KernelWASM
	}
	candidates := []string{"kernel/yanshu_sm.wasm"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "kernel", "yanshu_sm.wasm"))
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func (c Config) ValidateForServe() error {
	if c.Verifier == VerifierSM2 && c.ResolveKernelWASM() == "" {
		return fmt.Errorf("config: YANSHU_VERIFIER=sm2 requires the wasm kernel; " +
			"set YANSHU_KERNEL_WASM=/path/to/yanshu_sm.wasm (repo ships it at server/kernel/yanshu_sm.wasm)")
	}
	if c.Verifier == VerifierStubAllow {
		if c.Env != "local" && c.Env != "test" {
			return fmt.Errorf("config: YANSHU_VERIFIER=stub-allow requires YANSHU_ENV=local|test (got %q)", c.Env)
		}
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil || !isLoopbackHost(host) {
			return fmt.Errorf("config: YANSHU_VERIFIER=stub-allow requires a loopback listen address (got %q)", c.Addr)
		}
	}
	if c.TokenEpochNum <= 0 {
		// fail closed：没有 KID 就无法判断"旧凭据"，宁可拒绝启动。
		return fmt.Errorf("config: YANSHU_TOKEN_EPOCH is required when serving (positive decimal integer)")
	}
	if len(c.TokenSecret) < MinTokenSecretLen {
		return fmt.Errorf("config: YANSHU_TOKEN_SECRET is required when serving (>=%d bytes); "+
			"read it from an env var or a 0600 file, never hardcode it", MinTokenSecretLen)
	}
	return nil
}

// isLoopbackHost 判断监听地址是否只绑本机（空 host 表示所有网卡，不算 loopback）。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Load 从环境变量构造配置。
func Load() (Config, error) {
	c := Config{
		Addr:              env("YANSHU_ADDR", ":8080"),
		Env:               os.Getenv("YANSHU_ENV"),
		DatabaseURL:       os.Getenv("YANSHU_DATABASE_URL"),
		BlobDir:           env("YANSHU_BLOB_DIR", "./data/blobs"),
		Verifier:          VerifierMode(env("YANSHU_VERIFIER", string(VerifierStubDeny))),
		TrustProxyHeaders: envBool("YANSHU_TRUST_PROXY", false),
		STUNURLs:          envList("YANSHU_STUN_URLS", []string{"stun:stun.l.google.com:19302"}),
		WSURL:             env("YANSHU_WS_URL", ""),
		StorageQuotaBytes: envInt64("YANSHU_STORAGE_QUOTA_BYTES", 8<<30),
		KernelWASM:        os.Getenv("YANSHU_KERNEL_WASM"),
		LogFile:           os.Getenv("YANSHU_LOG_FILE"),
		LogDir:            os.Getenv("YANSHU_LOG_DIR"),
		LogRetentionDays:  int(envInt64("YANSHU_LOG_RETENTION_DAYS", 7)),
		SweepInterval:     envDuration("YANSHU_SWEEP_INTERVAL", 30*time.Second),
		ShutdownTimeout:   envDuration("YANSHU_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	if secret := os.Getenv("YANSHU_TOKEN_SECRET"); secret != "" {
		c.TokenSecret = []byte(secret)
	}
	kidRaw := os.Getenv("YANSHU_TOKEN_EPOCH")
	if kidRaw == "" {
		kidRaw = os.Getenv("YANSHU_TOKEN_KID") // 兼容旧变量名
	}
	if kidRaw == "" {
		kidRaw = "1" // 未配置默认 epoch=1（契约 §1.7）
	}
	if kidRaw != "" {
		n, err := strconv.ParseInt(kidRaw, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("config: YANSHU_TOKEN_EPOCH must be a positive decimal integer (got %q)", kidRaw)
		}
		c.TokenEpoch = strconv.FormatInt(n, 10)
		c.TokenEpochNum = n
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
	if len(c.STUNURLs) == 0 {
		return Config{}, fmt.Errorf("config: at least one STUN URL is required (YANSHU_STUN_URLS)")
	}
	for _, u := range c.STUNURLs {
		if strings.HasPrefix(strings.ToLower(u), "turn:") || strings.HasPrefix(strings.ToLower(u), "turns:") {
			return Config{}, fmt.Errorf("config: TURN is not supported; remove %q from YANSHU_STUN_URLS", u)
		}
		if !strings.HasPrefix(strings.ToLower(u), "stun:") {
			return Config{}, fmt.Errorf("config: only stun: URLs are allowed, got %q", u)
		}
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
