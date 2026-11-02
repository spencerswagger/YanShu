// Package auth 负责「身份即密钥对」的无账号鉴权：
// 一次性 nonce 挑战、签名验签接口、会话令牌。
//
// 注意：私钥永远不下发、不上行、不备份；这里只碰公钥与签名。
package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"
)

// 挑战消息的域分隔串。改动即等于改契约，必须与 API.md/端侧同步。
const challengeMagic = "YANSHU-CHALLENGE/1"

// ChallengeInput 是构造待签名消息所需的全部输入。
type ChallengeInput struct {
	Purpose   string
	Code      string
	PubKey    []byte
	Nonce     []byte
	ExpiresAt time.Time
	// Context 是用途相关的附加绑定：改昵称时放新昵称的 UTF-8 字节；
	// 注册/会话为空。绑进签名可以防「换个昵称重放同一签名」。
	Context []byte
}

// BuildChallengeMessage 生成规范化的待签名字节串。
//
// 格式（UTF-8，行分隔，行尾无空格，除末行外每行以 \n 结尾）：
//
//	YANSHU-CHALLENGE/1
//	purpose=<register|nickname|session>
//	code=<CODE>
//	pubkey=<base64url(pubkey)>
//	nonce=<base64url(nonce)>
//	expiresAt=<RFC3339Nano UTC>
//	context=<base64url(context) 或空>
//
// 客户端必须对**返回的 message 原文**签名（服务端已算好，不做二次拼装）。
func BuildChallengeMessage(in ChallengeInput) []byte {
	var buf bytes.Buffer
	buf.WriteString(challengeMagic)
	buf.WriteByte('\n')
	buf.WriteString("purpose=" + in.Purpose)
	buf.WriteByte('\n')
	buf.WriteString("code=" + in.Code)
	buf.WriteByte('\n')
	buf.WriteString("pubkey=" + B64.EncodeToString(in.PubKey))
	buf.WriteByte('\n')
	buf.WriteString("nonce=" + B64.EncodeToString(in.Nonce))
	buf.WriteByte('\n')
	buf.WriteString("expiresAt=" + in.ExpiresAt.UTC().Format(time.RFC3339Nano))
	buf.WriteByte('\n')
	buf.WriteString("context=" + B64.EncodeToString(in.Context))
	return buf.Bytes()
}

// B64 是 base64url（无填充），与 CRYPTO-PACK §3.2 一致。
var B64 = base64.RawURLEncoding

// NewNonce 生成 32 字节随机 nonce。
func NewNonce() ([]byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("auth: nonce: %w", err)
	}
	return b[:], nil
}

// NewToken 生成 32 字节随机会话令牌，返回原文（只回给客户端一次）与 SHA-256（入库）。
func NewToken() (token string, hash []byte, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, fmt.Errorf("auth: token: %w", err)
	}
	token = B64.EncodeToString(b[:])
	return token, HashToken(token), nil
}

// HashToken 计算令牌的 SHA-256。
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// EqualBytes 是常数时间比较（公钥/摘要比对用）。
func EqualBytes(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
