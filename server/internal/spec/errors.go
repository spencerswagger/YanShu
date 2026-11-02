package spec

import "net/http"

// ErrorCode 是服务端**唯一**的对外错误码类型，取值逐字对齐 docs/API.md §10。
//
// 与端侧错误码（CRYPTO_*）刻意不共用命名空间：两套码一个走 HTTP、一个只在浏览器内部。
type ErrorCode string

const (
	// 400
	ErrBadRequest            ErrorCode = "BAD_REQUEST"
	ErrFieldNotAllowed       ErrorCode = "FIELD_NOT_ALLOWED"
	ErrCodeFormatInvalid     ErrorCode = "CODE_FORMAT_INVALID"
	ErrNicknameInvalid       ErrorCode = "NICKNAME_INVALID"
	ErrChunkSizeInvalid      ErrorCode = "CHUNK_SIZE_INVALID"
	ErrChunkCountMismatch    ErrorCode = "CHUNK_COUNT_MISMATCH"
	ErrChunkIndexOutOfRange  ErrorCode = "CHUNK_INDEX_OUT_OF_RANGE"
	ErrLengthMismatch        ErrorCode = "LENGTH_MISMATCH"
	ErrPreludeDigestMismatch ErrorCode = "PRELUDE_DIGEST_MISMATCH"
	ErrRangeUnsupported      ErrorCode = "RANGE_UNSUPPORTED"
	ErrSizeLimitExceeded     ErrorCode = "SIZE_LIMIT_EXCEEDED"

	// 401
	ErrAuthMissing          ErrorCode = "AUTH_MISSING"
	ErrAuthSignatureInvalid ErrorCode = "AUTH_SIGNATURE_INVALID"
	ErrAuthChallengeInvalid ErrorCode = "AUTH_CHALLENGE_INVALID"
	ErrAuthCodeMismatch     ErrorCode = "AUTH_CODE_MISMATCH"
	// ErrAuthTokenStale：upload_token 因 KID 轮换而失效（旧 token）。
	ErrAuthTokenStale ErrorCode = "AUTH_TOKEN_STALE"
	// ErrSIGInputTooLong：SIG_INPUT 超过防御性上限（512 字节），仅作 DoS 门。
	ErrSIGInputTooLong ErrorCode = "SIG_INPUT_TOO_LONG"
	// ErrAuthTokenInvalid：token 值不对（伪造/不属于该传输），与"签名不被接受"分开。
	ErrAuthTokenInvalid ErrorCode = "AUTH_TOKEN_INVALID"

	// 403
	ErrSignalPeerMismatch ErrorCode = "SIGNAL_PEER_MISMATCH"
	// ErrNotTransferParty：已认证但不是该传输的当事人（裁决 G1）。
	ErrNotTransferParty ErrorCode = "NOT_TRANSFER_PARTY"

	// 404
	ErrCodeNotFound     ErrorCode = "CODE_NOT_FOUND"
	ErrTransferNotFound ErrorCode = "TRANSFER_NOT_FOUND"
	ErrChunkNotFound    ErrorCode = "CHUNK_NOT_FOUND"

	// 409
	ErrCodeTaken             ErrorCode = "CODE_TAKEN"
	ErrPubkeyTaken           ErrorCode = "PUBKEY_TAKEN"
	ErrPreludeConflict       ErrorCode = "PRELUDE_CONFLICT"
	ErrChunkConflict         ErrorCode = "CHUNK_CONFLICT"
	ErrChunksMissing         ErrorCode = "CHUNKS_MISSING"
	ErrPreludeMissing        ErrorCode = "PRELUDE_MISSING"
	ErrTransferNotReady      ErrorCode = "TRANSFER_NOT_READY"
	ErrDownloadNotStarted    ErrorCode = "DOWNLOAD_NOT_STARTED"
	ErrTransferStateConflict ErrorCode = "TRANSFER_STATE_CONFLICT"

	// 410
	ErrTransferRevoked  ErrorCode = "TRANSFER_REVOKED"
	ErrTransferExpired  ErrorCode = "TRANSFER_EXPIRED"
	ErrTransferConsumed ErrorCode = "TRANSFER_CONSUMED"

	// 413 / 415 / 416 / 423 / 429
	ErrPayloadTooLarge        ErrorCode = "PAYLOAD_TOO_LARGE"
	ErrContentTypeUnsupported ErrorCode = "CONTENT_TYPE_UNSUPPORTED"
	ErrRangeNotSatisfiable    ErrorCode = "RANGE_NOT_SATISFIABLE"
	ErrCodeLocked             ErrorCode = "CODE_LOCKED"
	ErrRateLimited            ErrorCode = "RATE_LIMITED"

	// 5xx
	ErrInternal            ErrorCode = "INTERNAL"
	ErrServiceUnavailable  ErrorCode = "SERVICE_UNAVAILABLE"
	ErrInsufficientStorage ErrorCode = "INSUFFICIENT_STORAGE"

	// WS 专属（API.md §10.4）
	ErrSignalTooLarge ErrorCode = "SIGNAL_TOO_LARGE"
)

var errStatus = map[ErrorCode]int{
	ErrBadRequest:            http.StatusBadRequest,
	ErrFieldNotAllowed:       http.StatusBadRequest,
	ErrCodeFormatInvalid:     http.StatusBadRequest,
	ErrNicknameInvalid:       http.StatusBadRequest,
	ErrChunkSizeInvalid:      http.StatusBadRequest,
	ErrChunkCountMismatch:    http.StatusBadRequest,
	ErrChunkIndexOutOfRange:  http.StatusBadRequest,
	ErrLengthMismatch:        http.StatusBadRequest,
	ErrPreludeDigestMismatch: http.StatusBadRequest,
	ErrRangeUnsupported:      http.StatusBadRequest,
	ErrSizeLimitExceeded:     http.StatusBadRequest,

	ErrAuthMissing:          http.StatusUnauthorized,
	ErrAuthSignatureInvalid: http.StatusUnauthorized,
	ErrAuthChallengeInvalid: http.StatusUnauthorized,
	ErrAuthCodeMismatch:     http.StatusUnauthorized,
	ErrAuthTokenStale:       http.StatusUnauthorized,
	ErrAuthTokenInvalid:     http.StatusUnauthorized,
	ErrSIGInputTooLong:      http.StatusBadRequest,

	ErrSignalPeerMismatch: http.StatusForbidden,
	ErrNotTransferParty:   http.StatusForbidden,

	ErrCodeNotFound:     http.StatusNotFound,
	ErrTransferNotFound: http.StatusNotFound,
	ErrChunkNotFound:    http.StatusNotFound,

	ErrCodeTaken:             http.StatusConflict,
	ErrPubkeyTaken:           http.StatusConflict,
	ErrPreludeConflict:       http.StatusConflict,
	ErrChunkConflict:         http.StatusConflict,
	ErrChunksMissing:         http.StatusConflict,
	ErrPreludeMissing:        http.StatusConflict,
	ErrTransferNotReady:      http.StatusConflict,
	ErrDownloadNotStarted:    http.StatusConflict,
	ErrTransferStateConflict: http.StatusConflict,

	ErrTransferRevoked:  http.StatusGone,
	ErrTransferExpired:  http.StatusGone,
	ErrTransferConsumed: http.StatusGone,

	ErrPayloadTooLarge:        http.StatusRequestEntityTooLarge,
	ErrContentTypeUnsupported: http.StatusUnsupportedMediaType,
	ErrRangeNotSatisfiable:    http.StatusRequestedRangeNotSatisfiable,
	ErrCodeLocked:             http.StatusLocked,
	ErrRateLimited:            http.StatusTooManyRequests,

	ErrInternal:            http.StatusInternalServerError,
	ErrServiceUnavailable:  http.StatusServiceUnavailable,
	ErrInsufficientStorage: http.StatusInsufficientStorage,
	ErrSignalTooLarge:      http.StatusBadRequest,
}

var errMessage = map[ErrorCode]string{
	ErrBadRequest:            "request format or parameter is invalid",
	ErrFieldNotAllowed:       "field is not allowed by the contract",
	ErrCodeFormatInvalid:     "code must be 4 Crockford Base32 characters",
	ErrNicknameInvalid:       "nickname is invalid",
	ErrChunkSizeInvalid:      "chunk_size is out of range",
	ErrChunkCountMismatch:    "chunk_count does not match plaintext_size and chunk_size",
	ErrChunkIndexOutOfRange:  "chunk index is out of range",
	ErrLengthMismatch:        "content length does not match the declared value",
	ErrPreludeDigestMismatch: "SM3(body) does not match prelude_sm3",
	ErrRangeUnsupported:      "only a single byte range is supported",
	ErrSizeLimitExceeded:     "declared size exceeds the allowed limit",

	ErrAuthMissing:          "authentication headers are missing",
	ErrAuthSignatureInvalid: "signature verification failed",
	ErrAuthChallengeInvalid: "challenge is expired, used or purpose mismatch",
	ErrAuthCodeMismatch:     "X-YS-Code does not match the signed code",
	ErrAuthTokenStale:       "upload token was revoked by a key version rotation; create a new transfer",
	ErrAuthTokenInvalid:     "upload token is invalid for this transfer",
	ErrSIGInputTooLong:      "SIG_INPUT exceeds the defensive limit (512 bytes)",

	ErrSignalPeerMismatch: "signal peers do not match the transfer",
	ErrNotTransferParty:   "authenticated credential is not a party of this transfer",

	ErrCodeNotFound:     "code is not registered",
	ErrTransferNotFound: "transfer not found",
	ErrChunkNotFound:    "chunk not found",

	ErrCodeTaken:             "code is already bound to another public key",
	ErrPubkeyTaken:           "public key is already registered under another code",
	ErrPreludeConflict:       "prelude already stored with different bytes",
	ErrChunkConflict:         "chunk already stored with different bytes",
	ErrChunksMissing:         "some chunks are missing",
	ErrPreludeMissing:        "prelude is missing",
	ErrTransferNotReady:      "transfer is not ready for download",
	ErrDownloadNotStarted:    "valid download_id is required",
	ErrTransferStateConflict: "operation is not allowed in the current state",

	ErrTransferRevoked:  "transfer was revoked",
	ErrTransferExpired:  "transfer has expired",
	ErrTransferConsumed: "transfer has been consumed",

	ErrPayloadTooLarge:        "request body exceeds the accepted limit",
	ErrContentTypeUnsupported: "only application/octet-stream is accepted",
	ErrRangeNotSatisfiable:    "requested range is not satisfiable",
	ErrCodeLocked:             "too many failed lookups, code is locked",
	ErrRateLimited:            "too many requests",

	ErrInternal:            "internal error",
	ErrServiceUnavailable:  "service unavailable",
	ErrInsufficientStorage: "insufficient storage quota",
	ErrSignalTooLarge:      "signal frame exceeds 64 KiB",
}

// Status 返回错误码的 HTTP 状态码；未知码按 500 处理（fail closed）。
func (c ErrorCode) Status() int {
	if s, ok := errStatus[c]; ok {
		return s
	}
	return http.StatusInternalServerError
}

// Message 返回错误码的默认文案。
func (c ErrorCode) Message() string {
	if m, ok := errMessage[c]; ok {
		return m
	}
	return errMessage[ErrInternal]
}

// AllErrorCodes 返回全部错误码，供契约自检与文档使用。
func AllErrorCodes() []ErrorCode {
	out := make([]ErrorCode, 0, len(errStatus))
	for c := range errStatus {
		out = append(out, c)
	}
	return out
}
