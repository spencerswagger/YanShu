package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

// uploadTokenInfo 是派生前缀（契约 §1.7，token v2 带 KID）：
//
//	upload_token = base64url(HMAC-SHA256(TOKEN_SECRET,
//	                 "yanshu/upload-token/v1" ‖ TRANSFER_ID ‖ u32be(KID)))
//
// KID **参与派生**（与契约 §1.7 一致），所以递增 KID 后为同一 transfer_id 重新签发的 token
// 与旧 token **逐字节不同** —— 旧凭据不可能"换个行就复活"。
// 校验同时用两条：行内 KID == 当前 KID（版本闸）+ 当前密钥/KID 下重算 == 库内哈希（值闸）。
const uploadTokenInfo = "yanshu/upload-token/v1"

// UploadToken 为某个 transfer_id + 当前 KID 派生 upload_token。
func (t *TokenIssuer) UploadToken(transferID string, kid int64) (string, error) {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(uploadTokenInfo))
	mac.Write([]byte(transferID))
	var k [4]byte
	k[0] = byte(uint32(kid) >> 24)
	k[1] = byte(uint32(kid) >> 16)
	k[2] = byte(uint32(kid) >> 8)
	k[3] = byte(uint32(kid))
	mac.Write(k[:])
	return B64.EncodeToString(mac.Sum(nil)), nil
}

// Derives 判断 token 是否等于该传输在当前密钥 + 指定 KID 下的派生值，
// 且与库内哈希一致。密钥轮换后派生值变化 → 返回 false（凭据不匹配）。
func (t *TokenIssuer) Derives(token, transferID string, kid int64, storedHash []byte) bool {
	expected, err := t.UploadToken(transferID, kid)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(UploadTokenHash(token), UploadTokenHash(expected)) == 1 &&
		subtle.ConstantTimeCompare(UploadTokenHash(expected), storedHash) == 1
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
