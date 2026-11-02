package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/spencerswagger/YanShu/server/internal/gm"
)

// B64 是 base64url（无填充），契约统一编码（API.md §0.1）。
var B64 = base64.RawURLEncoding

// NewNonce 生成 32 字节挑战 nonce。
func NewNonce() ([]byte, error) {
	var b [NonceLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("auth: nonce: %w", err)
	}
	return b[:], nil
}

// NewID 生成 32 位小写 hex 的 ID（challenge_id / transfer_id / download_id）。
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: id: %w", err)
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out), nil
}

// UploadTokenHash 返回 SM3(upload_token)，这是服务端唯一允许存的形态（API.md §1.5）。
func UploadTokenHash(token string) []byte {
	sum := gm.SM3([]byte(token))
	return sum[:]
}

// TokenIssuer 负责签发与校验 upload_token。
//
// 为什么用 HMAC 派生而不是纯随机：POST /transfers 的 Idempotency-Key 重放
// 必须返回**同一个** upload_token（API.md §6.2），而服务端只允许存 token 的
// SM3（§1.5）。派生式签发让两条约束同时成立：库里只有哈希，重放时能重算。
type TokenIssuer struct {
	secret []byte
}

// NewTokenIssuer 用服务端密钥构造签发器。secret 为空时随机生成（进程重启后旧
// token 失效，仅适合本地开发）。
func NewTokenIssuer(secret []byte) (*TokenIssuer, error) {
	if len(secret) == 0 {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("auth: token secret: %w", err)
		}
		secret = b[:]
	}
	return &TokenIssuer{secret: append([]byte(nil), secret...)}, nil
}

// uploadTokenInfo 是派生前缀（API §1.7，token v2 带 EPOCH）：
//
//	upload_token = base64url(HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v2" ‖ u64be(EPOCH) ‖ transfer_id))
//
// EPOCH 进了派生串，但**校验不靠重算**：库里存 SM3(token)，另存签发时的 EPOCH；
// 校验 = 「token 的 SM3 == 库里哈希」且「行内 EPOCH == 当前 EPOCH」。
// 因此：只换 TOKEN_SECRET 不影响既有 token（哈希没变）；只有 EPOCH 递增才会吊销。
const uploadTokenInfo = "yanshu/upload-token/v2"

// UploadToken 为某个 transfer_id + 当前 EPOCH 派生 upload_token。
func (t *TokenIssuer) UploadToken(transferID string, epoch int64) (string, error) {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(uploadTokenInfo))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(epoch))
	mac.Write(e[:])
	mac.Write([]byte(transferID))
	return B64.EncodeToString(mac.Sum(nil)), nil
}

// ValidateHash 只比对 token 的 SM3 与库里存的哈希。
//
// **不重算**：EPOCH 才是吊销开关（见 UploadToken 的注释与 API §1.7）。
// 行内 EPOCH 与当前 EPOCH 的比较由调用方完成。
func ValidateHash(token string, storedHash []byte) bool {
	if token == "" || len(storedHash) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(UploadTokenHash(token), storedHash) == 1
}

// EqualBytes 是常数时间比较。
func EqualBytes(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
