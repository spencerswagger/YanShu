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
	CodeLookupPerIP         Limit
	ChallengePerIP          Limit
	TransferReadPerIP       Limit
	TransferCreatePerCode   Limit
	NicknameUpdatePerCode   Limit
	ChunkPutPerTransfer     Limit
	TransferReadPerTransfer Limit
	WSConnPerIP             Limit

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
	CodeLookupPerIP:         Limit{WindowSeconds: 60, Max: 30, Burst: 30},
	ChallengePerIP:          Limit{WindowSeconds: 60, Max: 20, Burst: 20},
	TransferReadPerIP:       Limit{WindowSeconds: 60, Max: 120, Burst: 120},
	TransferCreatePerCode:   Limit{WindowSeconds: 3600, Max: 10, Burst: 10},
	NicknameUpdatePerCode:   Limit{WindowSeconds: 3600, Max: 5, Burst: 5},
	ChunkPutPerTransfer:     Limit{WindowSeconds: 60, Max: 600, Burst: 600},
	TransferReadPerTransfer: Limit{WindowSeconds: 60, Max: 600, Burst: 600},
	WSConnPerIP:             Limit{WindowSeconds: 60, Max: 10, Burst: 10},

	CodeLockThreshold:   5,
	CodeLockBaseSeconds: 60,
	CodeLockMaxSeconds:  3600,

	AuthFailurePerCode: Limit{WindowSeconds: 3600, Max: 10, Burst: 10},

	MaxConcurrentTransfersPerCode: 20,
}
