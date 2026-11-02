package auth

import (
	"errors"
	"fmt"
	"log/slog"
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
//   - message 是 SIG_INPUT 原文（YSAUTH1 ‖ PURPOSE ‖ NONCE ‖ 字段串）；
//   - signature 是 ASN.1 DER 的 SEQUENCE{r,s}（§10.4），算法为 SM2-SM3、默认 ZA。
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
// 默认 stub-deny（一律拒绝）是刻意的 fail-closed：内核没加载成功时，
// 宁可全拒绝也不要"看起来能跑但谁都能过"。
//
// sm2 走路线 B：wazero + 端侧内核的 `ys_sm2_verify_der`（kernelPath 必填，
// 缺失或加载失败时启动即报错，不降级）。
func NewVerifier(mode, kernelPath string, log *slog.Logger) (Verifier, error) {
	switch mode {
	case ModeSM2:
		v, err := NewWASMVerifier(kernelPath)
		if err != nil {
			return nil, err
		}
		if log != nil {
			if ver, err := v.Version(); err == nil {
				log.Info("sm2 verifier loaded", "kernel", kernelPath, "version", fmt.Sprintf("0x%08x", ver))
			} else {
				log.Warn("sm2 verifier loaded but ys_version failed", "err", err.Error())
			}
		}
		return v, nil
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
