package gm

import (
	"errors"
	"strings"
)

// 用户码相关常量，口径与 docs/CRYPTO-PACK.md §3.4 一致。
const (
	// CrockfordAlphabet 是 32 个符号，剔除易混的 I L O U。
	CrockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// crockfordCheckAlphabet 是第 5 位校验字符的字母表（37 个符号）。
	crockfordCheckAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"

	// CodeLen 是用户码长度。
	CodeLen = 4
)

// ErrInvalidCode 表示码不合法（长度、字符集、非法 U 等）。
var ErrInvalidCode = errors.New("gm: invalid user code")

// DeriveCode 由未压缩 SM2 公钥（65 字节）派生 4 位用户码。
//
// 公式（CRYPTO-PACK §3.4）：D = SM3(PUB)，取 D 的前 20 bit（大端 bit 序），
// 按 5 bit 一组（MSB 在前）映射 Crockford 字母表。
func DeriveCode(pub []byte) string {
	d := SM3(pub)
	// D[0] bit7..bit0 → 高 8 位；D[1] → 次 8 位；D[2] 高 4 位 → 低 4 位。
	v := uint32(d[0])<<12 | uint32(d[1])<<4 | uint32(d[2])>>4
	return encode20(v)
}

// CheckChar 返回码的校验字符（仅本地纠错用，服务端不校验）。
func CheckChar(pub []byte) byte {
	d := SM3(pub)
	v := uint32(d[0])<<12 | uint32(d[1])<<4 | uint32(d[2])>>4
	return crockfordCheckAlphabet[v%uint32(len(crockfordCheckAlphabet))]
}

// encode20 把 20 bit 无符号整数编码成 4 个 Crockford 字符（MSB 在前）。
func encode20(v uint32) string {
	var b [CodeLen]byte
	for i := 0; i < CodeLen; i++ {
		idx := (v >> uint(15-5*i)) & 0x1f
		b[i] = CrockfordAlphabet[idx]
	}
	return string(b[:])
}

// NormalizeCode 按 Crockford 规范归一化用户输入：
//
//   - 转大写；
//   - 去掉分组符 `-` 与所有空白；
//   - 易混字符纠正：O→0、I→1、L→1；
//   - 长度必须为 4；
//   - 每个字符必须在字母表内（`U` 一律拒绝）。
//
// 契约裁决（docs/contract-rulings.md D3）：允许容错归一化，但 ① 幂等；② 先于一切
// 判定执行；③ 限速与锁定按归一化后的码计数；④ **禁止 5 位截断、禁止猜测性纠错**。
// 因此这里只保留 CRYPTO-PACK §3.4 明列的三步纠正，不做任何长度猜测。
func NormalizeCode(raw string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return "", ErrInvalidCode
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			continue
		case 'O':
			b.WriteByte('0')
		case 'I', 'L':
			b.WriteByte('1')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) != CodeLen {
		return "", ErrInvalidCode
	}
	for i := 0; i < len(out); i++ {
		if !strings.ContainsRune(CrockfordAlphabet, rune(out[i])) {
			return "", ErrInvalidCode
		}
	}
	return out, nil
}

// IsNormalizedCode 判断输入是否已经是规范形式（严格模式用）。
func IsNormalizedCode(s string) bool {
	if len(s) != CodeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(CrockfordAlphabet, rune(s[i])) {
			return false
		}
	}
	return true
}
