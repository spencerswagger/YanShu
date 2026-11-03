package spec

// 本文件是全部 HTTP 请求/响应体（JSON）的字段名唯一来源，逐字对齐 docs/API.md。
// 字段命名 snake_case、大小写敏感；二进制一律 base64url 无填充。
// 所有时间字段用 string，值由 FormatTime 生成（RFC 3339 UTC 秒级 Z）。

// ErrorResponse 是全部非 2xx 响应的统一外壳（API.md §0.2）。
//
// Details 承载错误附加信息（裁决 G2）；v1 只允许 `missing`。
type ErrorResponse struct {
	Error   ErrorBody     `json:"error"`
	Details *ErrorDetails `json:"details,omitempty"`
}

// ErrorDetails 是错误附加信息（裁决 G2：v1 只允许 `missing` 一个键）。
type ErrorDetails struct {
	Missing []MissingRange `json:"missing,omitempty"`
}

// ErrorBody 是错误详情。
type ErrorBody struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Scope      string `json:"scope,omitempty"`
	RetryAfter *int   `json:"retry_after,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

// ---------- /v1/config ----------

// ConfigResponse 是客户端启动配置（API.md §4.1）。
type ConfigResponse struct {
	APIVersion        string       `json:"api_version"`
	CryptoPackVersion string       `json:"crypto_pack_version"`
	ChunkSize         uint32       `json:"chunk_size"`
	MaxPlaintextSize  uint64       `json:"max_plaintext_size"`
	MaxTTLSeconds     uint32       `json:"max_ttl_seconds"`
	STUNURLs          []string     `json:"stun_urls"`
	WSURL             *string      `json:"ws_url"`
	Limits            ConfigLimits `json:"limits"`
	// TokenEpoch 是当前只读的密钥版本（递增即吊销全部旧 upload_token）。
	TokenEpoch int64 `json:"token_epoch"`
	// 以下为运行时自检信息（只读，便于部署核对）。
	Verifier      string `json:"verifier"`
	Env           string `json:"env"`
	KernelSHA256  string `json:"kernel_sha256,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
	KernelExports int    `json:"kernel_exports,omitempty"`
}

// ConfigLimits 是 /v1/config 里暴露的限速额度（API.md §4.1）。
type ConfigLimits struct {
	CodeLookupPerMin      int `json:"code_lookup_per_min"`
	ChallengePerMin       int `json:"challenge_per_min"`
	TransferCreatePerHour int `json:"transfer_create_per_hour"`
	ChunkPutPerMin        int `json:"chunk_put_per_min"`
}

// ---------- /v1/challenges ----------

// ChallengeRequest 只有 purpose（API.md §4.2：没有 code 字段）。
type ChallengeRequest struct {
	Purpose string `json:"purpose"`
}

// ChallengeResponse 下发挑战。
type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Purpose     string `json:"purpose"`
	ExpiresAt   string `json:"expires_at"`
}

// ---------- 码 ----------

// RegisterCodeRequest 注册码（API.md §4.3）。
type RegisterCodeRequest struct {
	Code      string `json:"code"`
	PublicKey string `json:"public_key"`
	Nickname  string `json:"nickname"`
}

// CodeResponse 是注册响应（API.md §4.3）。
type CodeResponse struct {
	Code         string `json:"code"`
	PublicKey    string `json:"public_key"`
	Nickname     string `json:"nickname"`
	RegisteredAt string `json:"registered_at"`
}

// CodeLookupResponse 是查码响应，只有 4 个字段（API.md §4.4）。
type CodeLookupResponse struct {
	Code         string `json:"code"`
	PublicKey    string `json:"public_key"`
	Nickname     string `json:"nickname"`
	RegisteredAt string `json:"registered_at"`
}

// UpdateNicknameRequest 改昵称（API.md §4.5）。
type UpdateNicknameRequest struct {
	Nickname string `json:"nickname"`
}

// UpdateNicknameResponse 是改昵称响应（API.md §4.5）。
type UpdateNicknameResponse struct {
	Code      string `json:"code"`
	Nickname  string `json:"nickname"`
	UpdatedAt string `json:"updated_at"`
}

// ---------- 传输 ----------

// CreateTransferRequest 创建传输（API.md §6.1）。
type CreateTransferRequest struct {
	RecipientCode string  `json:"recipient_code"`
	PlaintextSize uint64  `json:"plaintext_size"`
	ChunkSize     uint32  `json:"chunk_size"`
	ChunkCount    uint32  `json:"chunk_count"`
	PreludeLen    uint32  `json:"prelude_len"`
	PreludeSM3    string  `json:"prelude_sm3"`
	TTLSeconds    *uint32 `json:"ttl_seconds,omitempty"`
	MaxDownloads  *uint32 `json:"max_downloads,omitempty"`
}

// CreateTransferResponse 是创建响应（API.md §6.1）。
type CreateTransferResponse struct {
	TransferID    string `json:"transfer_id"`
	State         string `json:"state"`
	UploadToken   string `json:"upload_token"`
	ChunkSize     uint32 `json:"chunk_size"`
	ChunkCount    uint32 `json:"chunk_count"`
	PreludeLen    uint32 `json:"prelude_len"`
	DownloadCount uint32 `json:"download_count"`
	MaxDownloads  uint32 `json:"max_downloads"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
}

// PreludePutResponse 是 prelude 首次上传响应（API.md §6.3）。
type PreludePutResponse struct {
	PreludeLen uint32 `json:"prelude_len"`
	PreludeSM3 string `json:"prelude_sm3"`
}

// ChunkPutResponse 是块上传响应（API.md §6.4）。
type ChunkPutResponse struct {
	Index          uint32 `json:"index"`
	Length         uint32 `json:"length"`
	ReceivedChunks uint32 `json:"received_chunks"`
	ChunkCount     uint32 `json:"chunk_count"`
}

// MissingRange 是连续缺失区间（API.md §6.5）。
type MissingRange struct {
	Start uint32 `json:"start"`
	Count uint32 `json:"count"`
}

// StatusResponse 是断点续传进度（API.md §6.5）。
type StatusResponse struct {
	TransferID      string         `json:"transfer_id"`
	State           string         `json:"state"`
	ChunkCount      uint32         `json:"chunk_count"`
	ChunkSize       uint32         `json:"chunk_size"`
	PreludeReceived bool           `json:"prelude_received"`
	ReceivedChunks  uint32         `json:"received_chunks"`
	Bitmap          string         `json:"bitmap"`
	Missing         []MissingRange `json:"missing"`
	UploadedBytes   int64          `json:"uploaded_bytes"`
	UpdatedAt       string         `json:"updated_at"`
}

// CompleteResponse 是完成标记响应（API.md §6.6）。
type CompleteResponse struct {
	State     string `json:"state"`
	ExpiresAt string `json:"expires_at"`
}

// InboxItem 是收件列表项（API.md §7.1）。注意：没有文件名/MIME。
type InboxItem struct {
	TransferID     string `json:"transfer_id"`
	SenderCode     string `json:"sender_code"`
	SenderNickname string `json:"sender_nickname"`
	RecipientCode  string `json:"recipient_code"`
	PlaintextSize  uint64 `json:"plaintext_size"`
	ChunkSize      uint32 `json:"chunk_size"`
	ChunkCount     uint32 `json:"chunk_count"`
	PreludeLen     uint32 `json:"prelude_len"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	State          string `json:"state"`
}

// InboxResponse 是收件列表（API.md §7.1）。
type InboxResponse struct {
	Items      []InboxItem `json:"items"`
	NextCursor *string     `json:"next_cursor"`
}

// TransferResponse 是传输元数据（API.md §7.2）。
type TransferResponse struct {
	TransferID           string  `json:"transfer_id"`
	SenderCode           string  `json:"sender_code"`
	SenderNickname       string  `json:"sender_nickname,omitempty"`
	RecipientCode        string  `json:"recipient_code"`
	PlaintextSize        uint64  `json:"plaintext_size"`
	ChunkSize            uint32  `json:"chunk_size"`
	ChunkCount           uint32  `json:"chunk_count"`
	PreludeLen           uint32  `json:"prelude_len"`
	PreludeSM3           *string `json:"prelude_sm3,omitempty"`
	TotalCiphertextBytes int64   `json:"total_ciphertext_bytes,omitempty"`
	DownloadCount        uint32  `json:"download_count"`
	MaxDownloads         uint32  `json:"max_downloads"`
	CreatedAt            string  `json:"created_at"`
	ExpiresAt            string  `json:"expires_at"`
	State                string  `json:"state"`
	LeaseExpiresAt       *string `json:"lease_expires_at,omitempty"`
	TerminalReason       *string `json:"terminal_reason,omitempty"`
	TerminalAt           *string `json:"terminal_at,omitempty"`
}

// AckResponse 是取件确认响应（API.md §7.5）。
type AckResponse struct {
	State              string  `json:"state"`
	TerminalReason     *string `json:"terminal_reason,omitempty"`
	TerminalAt         *string `json:"terminal_at,omitempty"`
	DownloadCount      uint32  `json:"download_count"`
	RemainingDownloads *uint32 `json:"remaining_downloads,omitempty"`
}

// RevokeResponse 是撤回响应（API.md §6.7）。
type RevokeResponse struct {
	State          string `json:"state"`
	TerminalReason string `json:"terminal_reason"`
	TerminalAt     string `json:"terminal_at"`
}

// HealthResponse 是 /healthz（运维，不在契约内）。
type HealthResponse struct {
	Status     string `json:"status"`
	APIVersion string `json:"api_version"`
	Contract   string `json:"contract"`
}
