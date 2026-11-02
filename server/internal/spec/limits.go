package spec

// 限速与锁定的默认阈值（骨架期占位值）。
//
// DRAFT(API.md): 全部阈值、窗口长度、锁定时长待对齐；这里是「能让接口跑起来
// 且明显偏保守」的一组值，不是最终产品参数。对齐时只改本文件。

// Limit 描述一个「窗口 + 配额」。
type Limit struct {
	// Window 是计数窗口长度（秒）。
	WindowSeconds int `json:"windowSeconds"`
	// Max 是窗口内允许的请求数。
	Max int `json:"max"`
	// Burst 是允许的瞬时突发（令牌桶容量），0 表示等于 Max。
	Burst int `json:"burst"`
}

// DefaultLimits 按用途给出限速档位。
var DefaultLimits = struct {
	// 按 IP。
	CodeLookupPerIP          Limit // 按码查询公钥：严格限速（防枚举 4 位码）
	CodeRegisterPerIP        Limit
	SessionPerIP             Limit
	PackageCreatePerIP       Limit
	UploadBytesPerIPPerMin   int64 // 上传字节/分钟/IP
	DownloadBytesPerIPPerMin int64
	// 按码。
	CodeLookupPerCode    Limit
	PackageCreatePerCode Limit
	// 失败锁定。
	FailureThreshold   int // 连续失败次数
	FailureLockSeconds int // 锁定时长
}{
	CodeLookupPerIP:          Limit{WindowSeconds: 60, Max: 60, Burst: 20},
	CodeRegisterPerIP:        Limit{WindowSeconds: 60, Max: 10, Burst: 5},
	SessionPerIP:             Limit{WindowSeconds: 60, Max: 30, Burst: 10},
	PackageCreatePerIP:       Limit{WindowSeconds: 60, Max: 20, Burst: 5},
	UploadBytesPerIPPerMin:   512 << 20, // 512 MiB/min
	DownloadBytesPerIPPerMin: 1 << 30,   // 1 GiB/min
	CodeLookupPerCode:        Limit{WindowSeconds: 60, Max: 30, Burst: 10},
	PackageCreatePerCode:     Limit{WindowSeconds: 3600, Max: 100, Burst: 20},
	FailureThreshold:         5,
	FailureLockSeconds:       900,
}
