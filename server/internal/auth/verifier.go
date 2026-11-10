package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// 验签错误。对外只暴露"签名不合法"或"验签不可用"，不区分内部原因（不给 oracle）。
var (
	// ErrSignature 表示签名验证失败。
	ErrSignature = errors.New("auth: signature invalid")
	// ErrUnavailable 表示服务端当前没有可用的验签实现。
	ErrUnavailable = errors.New("auth: verifier unavailable")
	// ErrSIGInputTooLong 表示 SIG_INPUT 超过 512 字节的防御性上限（DoS 门）。
	ErrSIGInputTooLong = errors.New("auth: sig input too long")
	// ErrBadInput 表示验签入参本身不合法（空消息、空签名、公钥长度不对）。
	// 与"签名不被接受"区分：这是 400 BAD_REQUEST，不是 401。
	ErrBadInput = errors.New("auth: invalid verifier input")
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

// frozenKernel 是白名单的一条：字节数与用途都写在这里，供展示与自检使用。
type frozenKernel struct {
	SHA256 string
	Bytes  int
	Role   string // "当前" / "回滚" / "灰度"
}

// frozenKernelOrder 是白名单的**有序**视图：首条必须是当前内核。
//
// 为什么不能用 map 当唯一来源：map 迭代顺序随机，`FrozenKernelSHA256List()` 早先是
// "range 到第一个就 return"，于是同一份输入两次跑会打印不同的"期望 sha"（实测 2/3 概率
// 给出回滚版或灰度版），既把人往错方向指、也没法 grep。顺序在此显式钉住。
var frozenKernelOrder = []frozenKernel{
	// 当前流式内核（140,762 B，43+memory=44 导出）：修掉 ys_alloc/ys_free 的长度依赖导致的
	// 堆损坏（≥80 MiB 的 prelude 触发 unreachable）；字节兼容 YSPK/1.0。
	{
		SHA256: "daa949261c3d84c5fb02612e284a240e5d539b11dcb3ff82db13266a365431de",
		Bytes:  140762,
		Role:   "当前",
	},
	// 上一版流式内核（140,742 B，同 44 导出）：保留作**回滚目标**——若新内核在目标环境暴露问题，
	// 把镜像里的 wasm 换回这份即可启动；确认无需回滚后由单独 PR 移除。
	{
		SHA256: "8766048ffdd16b9de8c4f3fea49590ec0802418dea9ad0fdca68f0e05bb625f8",
		Bytes:  140742,
		Role:   "回滚",
	},
	// 初版内核（127,313 B，34+memory=35 导出）：保留用于**灰度期**（仍在跑旧镜像的实例）；
	// 全部环境切换并确认无需回滚后，与上一条一并移除。
	{
		SHA256: "c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f",
		Bytes:  127313,
		Role:   "灰度",
	},
}

// FrozenKernelSHA256 是允许加载的内核白名单（冻结产物）。由 frozenKernelOrder 派生，
// 新增内核时必须显式登记，避免"同源不同字节"的产物被静默采用。
var FrozenKernelSHA256 = func() map[string]bool {
	m := make(map[string]bool, len(frozenKernelOrder))
	for _, k := range frozenKernelOrder {
		m[k.SHA256] = true
	}
	return m
}()

// CurrentFrozenKernelSHA256 返回"当前内核"的 sha256（即 frozenKernelOrder 首条）。
//
// 约定：白名单首条 = 当前应该用的那一版；另两条只是"允许加载"（回滚 / 灰度）。
// 仓库里的 `server/kernel/yanshu_sm.wasm` 必须等于它（有测试钉住）。
func CurrentFrozenKernelSHA256() string {
	return frozenKernelOrder[0].SHA256
}

// FrozenKernelSHA256List 返回白名单的确定性展示串，顺序固定、首条为当前内核，例如
// `daa94926…(当前)、8766048f…(回滚)、c1b87d0a…(灰度)`。
// 用于错误文案（"not in the frozen allowlist (expected …)"），同一输入两次跑必然一致。
func FrozenKernelSHA256List() string {
	parts := make([]string, 0, len(frozenKernelOrder))
	for _, k := range frozenKernelOrder {
		short := k.SHA256
		if len(short) > 8 {
			short = short[:8] + "…"
		}
		parts = append(parts, short+"("+k.Role+")")
	}
	return strings.Join(parts, "、")
}

// KernelInfo 由验签器实现，供 /v1/config 与启动自检使用。
type KernelInfo struct {
	SHA256  string
	Version uint32
	Exports int
}

// MaxSIGInputLen 是 SIG_INPUT 的**防御性上限**（DoS 门），不是业务校验：
// 七种 PURPOSE 的合法输入最长 109 字节（7+1+32+69），越界到 512 才按 SIG_INPUT_TOO_LONG 拒。
// 109 以内的字段问题必须由**字段级**校验报（NICKNAME_INVALID / CODE_FORMAT_INVALID …），
// 不允许用字节上限代替字段校验。
const MaxSIGInputLen = 512

// MaxLegitSIGInputLen 是最长合法 SIG_INPUT（REGISTER：7+1+32+4+65）。
const MaxLegitSIGInputLen = 109

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
		return ErrBadInput
	}
	if len(message) > MaxSIGInputLen {
		return ErrSIGInputTooLong
	}
	if len(message) == 0 || len(signature) == 0 {
		return ErrBadInput
	}
	return nil
}
