package spec

import "net/http"

// ErrorCode 是服务端**唯一**的对外错误码类型。
// 与端侧错误码（CRYPTO_*，见 docs/CRYPTO-PACK.md §13）刻意不共用命名空间：
// 两套码一个走 HTTP、一个只在浏览器内部，混用会让排障分不清是谁报的错。
type ErrorCode string

const (
	// 请求层面。
	ErrInvalidRequest  ErrorCode = "invalid_request"
	ErrPayloadTooLarge ErrorCode = "payload_too_large"
	ErrNotImplemented  ErrorCode = "not_implemented"
	ErrInternal        ErrorCode = "internal_error"

	// 用户码。
	ErrInvalidCode     ErrorCode = "invalid_code"
	ErrCodeNotFound    ErrorCode = "code_not_found"
	ErrCodeExpired     ErrorCode = "code_expired"
	ErrCodeTaken       ErrorCode = "code_taken"
	ErrCodeMismatch    ErrorCode = "code_mismatch"
	ErrNicknameInvalid ErrorCode = "nickname_invalid"
	ErrPubKeyInvalid   ErrorCode = "pubkey_invalid"

	// 挑战/会话/签名。
	ErrChallengeNotFound   ErrorCode = "challenge_not_found"
	ErrChallengeExpired    ErrorCode = "challenge_expired"
	ErrChallengeUsed       ErrorCode = "challenge_used"
	ErrChallengeInvalid    ErrorCode = "challenge_invalid"
	ErrSignatureInvalid    ErrorCode = "signature_invalid"
	ErrUnauthorized        ErrorCode = "unauthorized"
	ErrSessionExpired      ErrorCode = "session_expired"
	ErrVerifierUnavailable ErrorCode = "verifier_unavailable"

	// 鉴权边界。
	ErrForbidden ErrorCode = "forbidden"

	// 包。
	ErrPackageNotFound   ErrorCode = "package_not_found"
	ErrPackageExpired    ErrorCode = "package_expired"
	ErrPackageRevoked    ErrorCode = "package_revoked"
	ErrPackageExhausted  ErrorCode = "package_exhausted"
	ErrPackagePurged     ErrorCode = "package_purged"
	ErrPackageLocked     ErrorCode = "package_locked"
	ErrPackageIncomplete ErrorCode = "package_incomplete"
	ErrPackageConflict   ErrorCode = "package_conflict"

	// 块与 prelude。
	ErrChunkConflict         ErrorCode = "chunk_conflict"
	ErrChunkNotFound         ErrorCode = "chunk_not_found"
	ErrChunkIndexOutOfRange  ErrorCode = "chunk_index_out_of_range"
	ErrChunkLengthMismatch   ErrorCode = "chunk_length_mismatch"
	ErrPreludeConflict       ErrorCode = "prelude_conflict"
	ErrPreludeLengthMismatch ErrorCode = "prelude_length_mismatch"

	// 反滥用。
	ErrQuotaExceeded ErrorCode = "quota_exceeded"
	ErrRateLimited   ErrorCode = "rate_limited"
	ErrLockedOut     ErrorCode = "locked_out"
)

// errStatus 是错误码 → HTTP 状态码的唯一映射表。
// DRAFT(API.md): 状态码取值待对齐（尤其 410 vs 404 的取舍）。
var errStatus = map[ErrorCode]int{
	ErrInvalidRequest:  http.StatusBadRequest,
	ErrPayloadTooLarge: http.StatusRequestEntityTooLarge,
	ErrNotImplemented:  http.StatusNotImplemented,
	ErrInternal:        http.StatusInternalServerError,

	ErrInvalidCode:     http.StatusBadRequest,
	ErrCodeNotFound:    http.StatusNotFound,
	ErrCodeExpired:     http.StatusGone,
	ErrCodeTaken:       http.StatusConflict,
	ErrCodeMismatch:    http.StatusBadRequest,
	ErrNicknameInvalid: http.StatusBadRequest,
	ErrPubKeyInvalid:   http.StatusBadRequest,

	ErrChallengeNotFound:   http.StatusNotFound,
	ErrChallengeExpired:    http.StatusGone,
	ErrChallengeUsed:       http.StatusConflict,
	ErrChallengeInvalid:    http.StatusBadRequest,
	ErrSignatureInvalid:    http.StatusUnauthorized,
	ErrUnauthorized:        http.StatusUnauthorized,
	ErrSessionExpired:      http.StatusUnauthorized,
	ErrVerifierUnavailable: http.StatusServiceUnavailable,

	ErrForbidden: http.StatusForbidden,

	ErrPackageNotFound:   http.StatusNotFound,
	ErrPackageExpired:    http.StatusGone,
	ErrPackageRevoked:    http.StatusGone,
	ErrPackageExhausted:  http.StatusGone,
	ErrPackagePurged:     http.StatusGone,
	ErrPackageLocked:     http.StatusConflict,
	ErrPackageIncomplete: http.StatusConflict,
	ErrPackageConflict:   http.StatusConflict,

	ErrChunkConflict:         http.StatusConflict,
	ErrChunkNotFound:         http.StatusNotFound,
	ErrChunkIndexOutOfRange:  http.StatusBadRequest,
	ErrChunkLengthMismatch:   http.StatusBadRequest,
	ErrPreludeConflict:       http.StatusConflict,
	ErrPreludeLengthMismatch: http.StatusBadRequest,

	ErrQuotaExceeded: http.StatusTooManyRequests,
	ErrRateLimited:   http.StatusTooManyRequests,
	ErrLockedOut:     http.StatusLocked,
}

// errMessage 是给客户端看的默认文案（不泄露任何内部细节）。
var errMessage = map[ErrorCode]string{
	ErrInvalidRequest:  "request body or parameters are invalid",
	ErrPayloadTooLarge: "request body exceeds the configured limit",
	ErrNotImplemented:  "endpoint is reserved and not implemented yet",
	ErrInternal:        "internal error",

	ErrInvalidCode:     "code must be 4 Crockford Base32 characters",
	ErrCodeNotFound:    "code is not registered",
	ErrCodeExpired:     "code registration has expired; generate a new key pair",
	ErrCodeTaken:       "code is already bound to another public key; generate a new key pair",
	ErrCodeMismatch:    "code does not match the one derived from the public key",
	ErrNicknameInvalid: "nickname is invalid",
	ErrPubKeyInvalid:   "public key is invalid",

	ErrChallengeNotFound:   "challenge not found",
	ErrChallengeExpired:    "challenge has expired",
	ErrChallengeUsed:       "challenge has already been used",
	ErrChallengeInvalid:    "challenge does not match this request",
	ErrSignatureInvalid:    "signature verification failed",
	ErrUnauthorized:        "authentication required",
	ErrSessionExpired:      "session has expired",
	ErrVerifierUnavailable: "signature verifier is not available on this server",

	ErrForbidden: "not allowed for this credential",

	ErrPackageNotFound:   "package not found",
	ErrPackageExpired:    "package has expired",
	ErrPackageRevoked:    "package was revoked by the sender",
	ErrPackageExhausted:  "package download quota is exhausted",
	ErrPackagePurged:     "package payload has been deleted",
	ErrPackageLocked:     "package is locked after completion",
	ErrPackageIncomplete: "package is missing prelude or chunks",
	ErrPackageConflict:   "package state conflict",

	ErrChunkConflict:         "chunk index already holds different bytes",
	ErrChunkNotFound:         "chunk is not present in this package",
	ErrChunkIndexOutOfRange:  "chunk index is out of range",
	ErrChunkLengthMismatch:   "chunk length does not match the package manifest",
	ErrPreludeConflict:       "prelude already uploaded with different bytes",
	ErrPreludeLengthMismatch: "prelude length does not match the declared length",

	ErrQuotaExceeded: "storage quota exceeded",
	ErrRateLimited:   "too many requests, retry later",
	ErrLockedOut:     "too many failures, temporarily locked",
}

// Status 返回错误码对应的 HTTP 状态码；未知码按 500 处理（fail closed，不猜）。
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

// AllErrorCodes 返回全部已定义错误码，供契约自检测试与文档生成使用。
func AllErrorCodes() []ErrorCode {
	codes := make([]ErrorCode, 0, len(errStatus))
	for c := range errStatus {
		codes = append(codes, c)
	}
	return codes
}
