// Package spec 是雁书服务端「对外契约」的唯一权威来源。
//
// 契约版本：docs/API.md v1（commit 376c5b5，分支 feat/contracts-v1）。
// 规则：
//   - 所有对外路径、JSON 字段、HTTP 头、错误码、状态、PURPOSE、限值都必须定义在本包；
//     业务代码里不允许出现字面量路径或字段名。
//   - 契约变更时只改本包，handlers 引用常量。
package spec

import "time"

const (
	// APIVersion 是对外 API 版本（/v1）。
	APIVersion = "v1"

	// Prefix 是全部业务接口的公共前缀（API.md §0.1）。
	Prefix = "/v1"

	// CryptoPackVersion 是加密包版本串（CRYPTO-PACK §2.1）。
	CryptoPackVersion = "YSPK/1.0"
)

// HTTP 路由模板（API.md §3）。
const (
	PathConfig     = Prefix + "/config"
	PathChallenges = Prefix + "/challenges"
	PathCodes      = Prefix + "/codes"
	PathCode       = Prefix + "/codes/{code}"
	PathTransfers  = Prefix + "/transfers"
	PathTransfer   = Prefix + "/transfers/{transferId}"
	PathPrelude    = Prefix + "/transfers/{transferId}/prelude"
	PathChunk      = Prefix + "/transfers/{transferId}/chunks/{index}"
	PathStatus     = Prefix + "/transfers/{transferId}/status"
	PathComplete   = Prefix + "/transfers/{transferId}/complete"
	PathAck        = Prefix + "/transfers/{transferId}/ack"
	PathRevoke     = Prefix + "/transfers/{transferId}/revoke"
	PathInbox      = Prefix + "/inbox"
	PathWS         = Prefix + "/ws"

	// PathHealthz 是运维探活，不在 API 契约内。
	PathHealthz = "/healthz"
)

// 路径参数名。
const (
	ParamCode       = "code"
	ParamTransferID = "transferId"
	ParamIndex      = "index"
)

// HTTP 头（API.md §1.4 / §6 / §7 / §8 / §11.2）。
const (
	HeaderCode           = "X-YS-Code"
	HeaderChallengeID    = "X-YS-Challenge-Id"
	HeaderSignature      = "X-YS-Signature"
	HeaderUploadToken    = "X-YS-Upload-Token"
	HeaderDownloadID     = "X-YS-Download-Id"
	HeaderLeaseExpiresAt = "X-YS-Lease-Expires-At"
	HeaderState          = "X-YS-State"
	HeaderRequestID      = "X-YS-Request-Id"
	HeaderIdempotencyKey = "Idempotency-Key"

	HeaderRateLimitLimit     = "X-YS-RateLimit-Limit"
	HeaderRateLimitRemaining = "X-YS-RateLimit-Remaining"
	HeaderRateLimitReset     = "X-YS-RateLimit-Reset"
	HeaderRetryAfter         = "Retry-After"

	HeaderContentType   = "Content-Type"
	HeaderAcceptRanges  = "Accept-Ranges"
	HeaderContentRange  = "Content-Range"
	HeaderContentLength = "Content-Length"
	HeaderRange         = "Range"
)

// 媒体类型（API.md §0.1 / §2.3）。
const (
	ContentTypeJSON   = "application/json; charset=utf-8"
	ContentTypeBinary = "application/octet-stream"
)

// PURPOSE 名称与字节码（API.md §1.3）。
const (
	PurposeRegister       = "REGISTER"
	PurposeNicknameUpdate = "NICKNAME_UPDATE"
	PurposeTransferCreate = "TRANSFER_CREATE"
	PurposeTransferRevoke = "TRANSFER_REVOKE"
	PurposeInboxList      = "INBOX_LIST"
	PurposeWSHello        = "WS_HELLO"
	PurposeTransferAck    = "TRANSFER_ACK"
)

// PURPOSE 的 1 字节编码（SIG_INPUT 第二个字段）。
const (
	PurposeCodeRegister       byte = 0x01
	PurposeCodeNicknameUpdate byte = 0x02
	PurposeCodeTransferCreate byte = 0x03
	PurposeCodeTransferRevoke byte = 0x04
	PurposeCodeInboxList      byte = 0x05
	PurposeCodeWSHello        byte = 0x06
	PurposeCodeTransferAck    byte = 0x07
)

// PurposeCode 把 PURPOSE 名称映射到字节码；未知返回 0。
func PurposeCode(purpose string) byte {
	switch purpose {
	case PurposeRegister:
		return PurposeCodeRegister
	case PurposeNicknameUpdate:
		return PurposeCodeNicknameUpdate
	case PurposeTransferCreate:
		return PurposeCodeTransferCreate
	case PurposeTransferRevoke:
		return PurposeCodeTransferRevoke
	case PurposeInboxList:
		return PurposeCodeInboxList
	case PurposeWSHello:
		return PurposeCodeWSHello
	case PurposeTransferAck:
		return PurposeCodeTransferAck
	}
	return 0
}

// AllPurposes 是全部合法 PURPOSE（/v1/challenges 校验用）。
func AllPurposes() []string {
	return []string{
		PurposeRegister, PurposeNicknameUpdate, PurposeTransferCreate,
		PurposeTransferRevoke, PurposeInboxList, PurposeWSHello, PurposeTransferAck,
	}
}

// 传输状态（API.md §5.1）。
const (
	StateUploading = "UPLOADING"
	StateReady     = "READY"
	StateLeased    = "LEASED"
	StateConsumed  = "CONSUMED"
	StateRevoked   = "REVOKED"
	StateExpired   = "EXPIRED"
)

// 终结原因（API.md §5.2 / §5.3）。
const (
	ReasonRevoked  = "REVOKED"
	ReasonExpired  = "EXPIRED"
	ReasonConsumed = "CONSUMED"
)

// IsTerminalState 判断是否终结态（终结后内容端点一律 410）。
func IsTerminalState(state string) bool {
	switch state {
	case StateConsumed, StateRevoked, StateExpired:
		return true
	}
	return false
}

// TerminalErrorCode 把终结态映射成内容端点错误码（API.md §5.2）。
func TerminalErrorCode(state string) ErrorCode {
	switch state {
	case StateRevoked:
		return ErrTransferRevoked
	case StateExpired:
		return ErrTransferExpired
	case StateConsumed:
		return ErrTransferConsumed
	}
	return ErrTransferNotFound
}

// 尺寸与时间常量（API.md §6.1 / §5.1 / §1.2）。
const (
	MaxPlaintextSize uint64 = 4294967296 // 4 GiB
	MinChunkSize     uint32 = 16
	MaxChunkSize     uint32 = 1048576
	MaxChunkCount    uint32 = 1048576
	MaxPreludeLen    uint32 = 4194304 // 4 MiB
	DefaultChunkSize uint32 = 1048576

	MinTTLSeconds uint32 = 3600
	MaxTTLSeconds uint32 = 86400
	DefaultTTL    uint32 = 86400

	MinDownloads     uint32 = 1
	MaxDownloads     uint32 = 3
	DefaultDownloads uint32 = 1

	// LeaseTTL 是下载租约时长（API.md §5.1：默认 30 分钟）。
	LeaseTTL = 30 * time.Minute
	// ChallengeTTL 是挑战有效期（API.md §1.2：120 秒）。
	ChallengeTTL = 120 * time.Second
	// ChallengeRetention 是挑战记录保留时长（API.md §1.2：10 分钟后失效）。
	ChallengeRetention = 10 * time.Minute
	// TombstoneTTL 是终结元数据保留时长（API.md §5.2：7 天）。
	TombstoneTTL = 7 * 24 * time.Hour
	// UploadTokenTTL 是 upload_token 的有效期（API §1.7：6 小时）。
	UploadTokenTTL = 6 * time.Hour
	// IdempotencyWindow 是 POST /transfers 的幂等窗口（API.md §6.2：600 秒）。
	IdempotencyWindow = 600 * time.Second
)

// FormatTime 输出契约要求的时间格式：RFC 3339 UTC、秒级、Z 结尾（API.md §0.1）。
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

// 路径构造器（测试与客户端 SDK 用）。
func CodePath(code string) string           { return Prefix + "/codes/" + code }
func TransferPath(id string) string         { return Prefix + "/transfers/" + id }
func PreludePath(id string) string          { return TransferPath(id) + "/prelude" }
func ChunkPath(id string, index int) string { return TransferPath(id) + "/chunks/" + itoa(index) }
func StatusPath(id string) string           { return TransferPath(id) + "/status" }
func CompletePath(id string) string         { return TransferPath(id) + "/complete" }
func AckPath(id string) string              { return TransferPath(id) + "/ack" }
func RevokePath(id string) string           { return TransferPath(id) + "/revoke" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
