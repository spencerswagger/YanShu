package spec

// 限速与反滥用默认额度，逐条对齐 docs/API.md §11.1 / §11.3 / §11.4。
// 服务端可配，但契约给出的是默认值。

// Limit 描述一个「时间窗 + 配额」。
type Limit struct {
	WindowSeconds int `json:"window_seconds"`
	Max           int `json:"max"`
	Burst         int `json:"burst"`
}

// DefaultLimits 是契约默认额度。
var DefaultLimits = struct {
	CodeLookupPerIP   Limit
	ChallengePerIP    Limit
	TransferReadPerIP Limit
	// TransferReadBytesPerIP 是内容端点（GET /chunks/{i}、HEAD /chunks/{i}）的**单 IP 按字节**额度，
	// 单位 MiB/时间窗。按字节而不是按请求数，理由：1 GiB = 1024 块，若按请求数给
	// 120 次/分钟，单传输的读吞吐会被硬顶在 2 MiB/s（实测把 1 GiB 下载拖成 >7.5 分钟并
	// 持续 429，把客户端 5s 退避打满）。按字节则 1 GiB 单传输只需 1 分钟量级，
	// 而滥用面仍然是"带宽"本身，量级不放大。
	TransferReadBytesPerIP  Limit
	TransferCreatePerCode   Limit
	NicknameUpdatePerCode   Limit
	ChunkPutPerTransfer     Limit
	TransferReadPerTransfer Limit
	WSConnPerIP             Limit
	// 举报（API.md §11.5）：按码 5 次/小时、按 IP 20 次/小时。
	AbuseReportPerCode Limit
	AbuseReportPerIP   Limit

	// 失败锁定：同一 IP 对同一码连续 CODE_NOT_FOUND 5 次 → 423 CODE_LOCKED。
	CodeLockThreshold int
	// 锁定时长从 1 分钟起，逐次翻倍，上限 60 分钟。
	CodeLockBaseSeconds int
	CodeLockMaxSeconds  int

	// 签名失败：同一码 10 次/小时 → 429（scope=code）。
	AuthFailurePerCode Limit

	// 单码并发未终结传输上限。
	MaxConcurrentTransfersPerCode int
}{
	CodeLookupPerIP:   Limit{WindowSeconds: 60, Max: 30, Burst: 30},
	ChallengePerIP:    Limit{WindowSeconds: 60, Max: 20, Burst: 20},
	TransferReadPerIP: Limit{WindowSeconds: 60, Max: 120, Burst: 120},
	// 内容端点按字节：4096 MiB/分钟（约 68 MiB/s，**高于**单传输的 60 MiB/s），
	// 突发 512 MiB —— 单传输永远先撞 per-transfer 而不是 per-IP 这一档；
	// per-IP 这一档只在"同一 IP 同时拉多个传输"时才有意义（总出带宽硬顶）。
	TransferReadBytesPerIP:  Limit{WindowSeconds: 60, Max: 4096, Burst: 512},
	TransferCreatePerCode:   Limit{WindowSeconds: 3600, Max: 10, Burst: 10},
	NicknameUpdatePerCode:   Limit{WindowSeconds: 3600, Max: 5, Burst: 5},
	ChunkPutPerTransfer:     Limit{WindowSeconds: 60, Max: 600, Burst: 600},
	TransferReadPerTransfer: Limit{WindowSeconds: 60, Max: 3600, Burst: 1200},
	WSConnPerIP:             Limit{WindowSeconds: 60, Max: 10, Burst: 10},

	AbuseReportPerCode: Limit{WindowSeconds: 3600, Max: 5, Burst: 5},
	AbuseReportPerIP:   Limit{WindowSeconds: 3600, Max: 20, Burst: 20},

	CodeLockThreshold:   5,
	CodeLockBaseSeconds: 60,
	CodeLockMaxSeconds:  3600,

	AuthFailurePerCode: Limit{WindowSeconds: 3600, Max: 10, Burst: 10},

	MaxConcurrentTransfersPerCode: 20,
}
