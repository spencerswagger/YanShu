package spec

import "time"

// 本文件是全部 HTTP 请求/响应体（JSON）的字段名唯一来源。
// 字段名一律 camelCase；二进制一律 base64url（无填充，RFC 4648 §5），
// 与 docs/CRYPTO-PACK.md §3.2 的外部表示保持一致。
// DRAFT(API.md): 全部字段名待对齐；对齐时只改这里。

// ErrorResponse 是全部非 2xx 响应的统一外壳。
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody 是错误详情。Code 取值见 spec/errors.go。
type ErrorBody struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	RetryAfterMs int64  `json:"retryAfterMs,omitempty"`
	RequestID    string `json:"requestId,omitempty"`
}

// ---------- 挑战与会话 ----------

// ChallengeRequest 申请一个一次性 nonce。
type ChallengeRequest struct {
	// Purpose 取 PurposeRegister / PurposeNickname / PurposeSession。
	Purpose string `json:"purpose"`
	// Code 4 位用户码。PurposeSession/Nickname 必填。
	Code string `json:"code,omitempty"`
	// PubKey 未压缩 SM2 公钥（65 字节）的 base64url。PurposeRegister 必填。
	PubKey string `json:"pubKey,omitempty"`
	// Nickname 仅 PurposeNickname 使用，参与签名消息构造。
	Nickname string `json:"nickname,omitempty"`
}

// ChallengeResponse 下发 nonce 与「待签名消息」。
// Message 是服务端拼好的规范字节串（base64url），客户端直接对它签名，
// 避免两端各自拼串导致验签失败。
type ChallengeResponse struct {
	ChallengeID     string    `json:"challengeId"`
	Purpose         string    `json:"purpose"`
	Nonce           string    `json:"nonce"`
	Message         string    `json:"message"`
	MessageEncoding string    `json:"messageEncoding"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// MessageEncodingB64URL 是 ChallengeResponse.MessageEncoding 的固定值。
const MessageEncodingB64URL = "base64url"

// SessionRequest 用签名换会话令牌。
type SessionRequest struct {
	ChallengeID string `json:"challengeId"`
	Code        string `json:"code"`
	Signature   string `json:"signature"`
}

// SessionResponse 返回不透明会话令牌（Bearer）。
// 令牌只在本响应里出现一次，服务端只存它的 SHA-256。
type SessionResponse struct {
	SessionToken string    `json:"sessionToken"`
	Code         string    `json:"code"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// ---------- 用户码 ----------

// RegisterCodeRequest 注册用户码。服务端不存任何私钥相关物。
type RegisterCodeRequest struct {
	// PubKey 未压缩 SM2 公钥（65 字节）base64url。
	PubKey string `json:"pubKey"`
	// Nickname 展示名（≤64 字节 UTF-8，去控制字符）。
	Nickname string `json:"nickname"`
	// ChallengeID / Signature 是对 PurposeRegister 挑战消息的应答。
	ChallengeID string `json:"challengeId"`
	Signature   string `json:"signature"`
	// Code 客户端本地派生的码，仅作一致性校验（服务端会自行从公钥派生）。
	// DRAFT(API.md): 该字段是否需要存在待对齐。
	Code string `json:"code,omitempty"`
}

// CodeInfo 是码查询/注册的返回体。
type CodeInfo struct {
	Code         string    `json:"code"`
	PubKey       string    `json:"pubKey"`
	Nickname     string    `json:"nickname"`
	Status       string    `json:"status"`
	RegisteredAt time.Time `json:"registeredAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// UpdateNicknameRequest 改昵称走签名挑战（无账号体系）。
type UpdateNicknameRequest struct {
	Nickname    string `json:"nickname"`
	ChallengeID string `json:"challengeId"`
	Signature   string `json:"signature"`
}

// ---------- 包 ----------

// CreatePackageRequest 创建一次传输。
// 服务端只收「尺寸类元数据 + 码」，文件名/MIME 都在端侧加密清单里，从不上行。
type CreatePackageRequest struct {
	RecipientCode string `json:"recipientCode"`
	ChunkCount    uint32 `json:"chunkCount"`
	ChunkSize     uint32 `json:"chunkSize"`
	PlaintextSize uint64 `json:"plaintextSize"`
	PreludeLen    uint32 `json:"preludeLen"`
	// MaxDownloads 缺省由服务端策略给定；0 视为不合法。
	MaxDownloads *uint32 `json:"maxDownloads,omitempty"`
	// TTLSeconds 缺省由服务端策略给定；超过上限会被夹到上限。
	TTLSeconds *uint32 `json:"ttlSeconds,omitempty"`
	// DeleteOnAck 接收方确认后立刻删密文（默认 true）。
	DeleteOnAck *bool `json:"deleteOnAck,omitempty"`
}

// PackageInfo 是包的对外元信息。
// 注意：这里**没有**文件名字段，也没有 MIME —— 这是设计要求，不是漏了。
type PackageInfo struct {
	PackageID      string     `json:"packageId"`
	SenderCode     string     `json:"senderCode"`
	RecipientCode  string     `json:"recipientCode"`
	State          string     `json:"state"`
	ChunkCount     uint32     `json:"chunkCount"`
	ChunkSize      uint32     `json:"chunkSize"`
	PlaintextSize  uint64     `json:"plaintextSize"`
	PreludeLen     uint32     `json:"preludeLen"`
	MaxDownloads   uint32     `json:"maxDownloads"`
	DownloadsUsed  uint32     `json:"downloadsUsed"`
	ReceivedChunks uint32     `json:"receivedChunks"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	CommittedAt    *time.Time `json:"committedAt,omitempty"`
	TerminalReason string     `json:"terminalReason,omitempty"`
}

// InboxResponse 是收件列表。
type InboxResponse struct {
	Packages []PackageInfo `json:"packages"`
}

// PreludePutResponse 是 prelude 上传结果。
type PreludePutResponse struct {
	PackageID  string `json:"packageId"`
	PreludeLen uint32 `json:"preludeLen"`
	Duplicate  bool   `json:"duplicate"`
}

// ChunkPutResponse 是块上传结果。Duplicate=true 表示同序号同内容的幂等重传。
type ChunkPutResponse struct {
	PackageID      string `json:"packageId"`
	Index          uint32 `json:"index"`
	CiphertextLen  uint32 `json:"ciphertextLen"`
	ReceivedChunks uint32 `json:"receivedChunks"`
	Duplicate      bool   `json:"duplicate"`
}

// ChunkMeta 是单块的元信息（不含内容）。
type ChunkMeta struct {
	Index         uint32    `json:"index"`
	CiphertextLen uint32    `json:"ciphertextLen"`
	ReceivedAt    time.Time `json:"receivedAt"`
}

// ProgressResponse 是续传进度：已收块的位图 + 缺失块列表。
type ProgressResponse struct {
	PackageID          string      `json:"packageId"`
	State              string      `json:"state"`
	PreludeReceived    bool        `json:"preludeReceived"`
	PreludeLen         uint32      `json:"preludeLen"`
	ChunkCount         uint32      `json:"chunkCount"`
	ReceivedChunks     uint32      `json:"receivedChunks"`
	ReceivedBitmap     string      `json:"receivedBitmap"`
	ReceivedIndexes    []uint32    `json:"receivedIndexes,omitempty"`
	MissingIndexes     []uint32    `json:"missingIndexes,omitempty"`
	MissingTruncated   bool        `json:"missingTruncated,omitempty"`
	DownloadsRemaining uint32      `json:"downloadsRemaining"`
	ExpiresAt          time.Time   `json:"expiresAt"`
	Chunks             []ChunkMeta `json:"chunks,omitempty"`
}

// AckRequest 是接收方确认。CountsAsDownload 缺省 true。
type AckRequest struct {
	CountsAsDownload *bool `json:"countsAsDownload,omitempty"`
}

// StateResponse 用于撤回/确认这类只改状态的操作。
type StateResponse struct {
	PackageID string    `json:"packageId"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// HealthResponse 是 /healthz 返回。
type HealthResponse struct {
	Status     string `json:"status"`
	APIVersion string `json:"apiVersion"`
	Contract   string `json:"contract"`
}
