package auth

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/spencerswagger/YanShu/server/internal/gm"
)

// 验签错误。对外只暴露"签名不合法"或"验签不可用"，不区分内部原因（不给 oracle）。
var (
	// ErrSignature 表示签名验证失败。
	ErrSignature = errors.New("auth: signature invalid")
	// ErrUnavailable 表示服务端当前没有可用的验签实现。
	ErrUnavailable = errors.New("auth: verifier unavailable")
)

// Verifier 是 SM2 验签接口。
//
// 约定（与 docs/CRYPTO-PACK.md §10 对齐）：
//   - pubKey 是未压缩点 65 字节（0x04 ‖ X32 ‖ Y32）；
//   - message 是服务端给出的挑战消息原文（见 BuildChallengeMessage）；
//   - signature 是 ASN.1 DER 的 SEQUENCE{r,s}（§10.4），算法为 SM2-SM3、默认 ZA。
//
// 实现方要自己完成 SM3(ZA ‖ message) 与曲线点校验；本接口不传 ZA 参数，
// 因为 v1 只允许默认 ZA（ID = "1234567812345678"）。
type Verifier interface {
	Verify(pubKey, message, signature []byte) error
}

// 验签模式。
const (
	ModeSM2       = "sm2"
	ModeStubDeny  = "stub-deny"
	ModeStubAllow = "stub-allow"
)

// NewVerifier 按模式构造验签器。
//
// 默认 stub-deny（一律拒绝）是刻意的 fail-closed：SM2 实现还没接进来之前，
// 宁可全拒绝也不要"看起来能跑但谁都能过"。
func NewVerifier(mode string, log *slog.Logger) (Verifier, error) {
	switch mode {
	case ModeSM2:
		return sm2Verifier{}, nil
	case ModeStubDeny, "":
		return denyVerifier{}, nil
	case ModeStubAllow:
		if log != nil {
			log.Warn("SM2 verifier is a stub that ACCEPTS any well-formed signature; never use in production")
		}
		return allowVerifier{}, nil
	default:
		return nil, fmt.Errorf("auth: unknown verifier mode %q", mode)
	}
}

// denyVerifier 一律拒绝（fail closed）。
type denyVerifier struct{}

func (denyVerifier) Verify(_, _, _ []byte) error { return ErrUnavailable }

// allowVerifier 只做形状检查，供本地联调与测试。
type allowVerifier struct{}

func (allowVerifier) Verify(pubKey, message, signature []byte) error {
	if len(pubKey) != 65 || pubKey[0] != 0x04 {
		return ErrSignature
	}
	if len(message) == 0 || len(signature) == 0 {
		return ErrSignature
	}
	return nil
}

// sm2Verifier 是真实 SM2 验签（服务端自研实现，见 internal/gm/sm2.go）。
//
// 口径与 docs/CRYPTO-PACK.md §10 一致：
//   - 曲线 sm2p256v1，用户标识默认 "1234567812345678"（ENTL = 0x0080）；
//   - 待验摘要 e = SM3(ZA ‖ message)，message 就是 SIG_INPUT 原文；
//   - 签名值严格 DER SEQUENCE{r,s}（70..72 字节），拒绝非规范编码；
//   - 失败一律返回 ErrSignature，不区分"格式错"与"验签不过"（不给 oracle）。
type sm2Verifier struct{}

func (sm2Verifier) Verify(pubKey, message, signature []byte) error {
	if len(pubKey) != 65 || pubKey[0] != 0x04 {
		return ErrSignature
	}
	if len(message) == 0 || len(signature) == 0 {
		return ErrSignature
	}
	if !gm.VerifySM2DER(pubKey, message, signature) {
		return ErrSignature
	}
	return nil
}
