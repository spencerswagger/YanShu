// SM2 验签（GB/T 32918），服务端自研实现。
//
// 为什么自研而不是引第三方库：项目约束是「完全自研」，而服务端只需要**验签**这一件事
// （公钥固定、消息是 SIG_INPUT、签名是 DER）。实现范围因此很小：曲线点运算 + ZA + e =
// SM3(ZA‖M) + 验签方程。
//
// 正确性靠**另一套自研实现**（端侧 Rust，已与 GmSSL 逐字节交叉验证 84 项）的向量来钉：
// `testdata/sm2_vectors.json` 里的 ZA 与「固定 k 签名」都能逐字节复现（见 sm2_test.go）。
//
// 口径（与 docs/CRYPTO-PACK.md §10 一致）：
//   - 曲线 sm2p256v1；用户标识默认 "1234567812345678"（ENTL = 0x0080）；
//   - 待签摘要 e = SM3(ZA ‖ M)，M 是 SIG_INPUT 原文；
//   - 签名值 DER SEQUENCE{r,s}（70..72 字节），严格解析、拒绝非规范编码。
package gm

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// DefaultSM2ID 是国标默认用户标识。
const DefaultSM2ID = "1234567812345678"

// SM2 验签错误。
var (
	ErrSM2Point     = errors.New("gm: invalid sm2 public key")
	ErrSM2Signature = errors.New("gm: invalid sm2 signature")
)

// 曲线参数（GB/T 32918.5，推荐曲线）。
var (
	sm2P  = mustHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
	sm2A  = mustHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
	sm2B  = mustHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
	sm2N  = mustHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
	sm2Gx = mustHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
	sm2Gy = mustHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
)

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("gm: bad sm2 constant")
	}
	return v
}

// sm2Point 是仿射点；inf 表示无穷远点。
type sm2Point struct {
	x, y *big.Int
	inf  bool
}

var sm2G = &sm2Point{x: sm2Gx, y: sm2Gy}

func modP(v *big.Int) *big.Int { return v.Mod(v, sm2P) }

func pointAdd(p, q *sm2Point) *sm2Point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	var lambda *big.Int
	if p.x.Cmp(q.x) == 0 {
		sumY := new(big.Int).Add(p.y, q.y)
		if modP(sumY).Sign() == 0 {
			return &sm2Point{inf: true}
		}
		// lambda = (3x² + a) / (2y)
		num := new(big.Int).Mul(p.x, p.x)
		num.Mul(num, big.NewInt(3))
		num.Add(num, sm2A)
		den := new(big.Int).Lsh(p.y, 1)
		den.ModInverse(modP(den), sm2P)
		if den == nil {
			return &sm2Point{inf: true}
		}
		lambda = modP(new(big.Int).Mul(num, den))
	} else {
		num := new(big.Int).Sub(q.y, p.y)
		den := new(big.Int).Sub(q.x, p.x)
		den.ModInverse(modP(den), sm2P)
		if den == nil {
			return &sm2Point{inf: true}
		}
		lambda = modP(new(big.Int).Mul(num, den))
	}
	x := new(big.Int).Mul(lambda, lambda)
	x.Sub(x, p.x)
	x.Sub(x, q.x)
	x = modP(x)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, lambda)
	y.Sub(y, p.y)
	y = modP(y)
	return &sm2Point{x: x, y: y}
}

func pointMul(k *big.Int, p *sm2Point) *sm2Point {
	result := &sm2Point{inf: true}
	addend := p
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = pointAdd(result, addend)
		}
		addend = pointAdd(addend, addend)
	}
	return result
}

func pointOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(sm2P) >= 0 || y.Cmp(sm2P) >= 0 {
		return false
	}
	// y² == x³ + a·x + b (mod p)
	left := modP(new(big.Int).Mul(y, y))
	right := new(big.Int).Mul(x, x)
	right.Mul(right, x)
	ax := new(big.Int).Mul(sm2A, x)
	right.Add(right, ax)
	right.Add(right, sm2B)
	right = modP(right)
	return left.Cmp(right) == 0
}

// ParseSM2PublicKey 接受 65 字节（0x04‖X‖Y）或 64 字节（X‖Y），返回曲线点。
func ParseSM2PublicKey(raw []byte) (*sm2Point, error) {
	body := raw
	switch len(raw) {
	case 65:
		if raw[0] != 0x04 {
			return nil, fmt.Errorf("%w: compressed point is not accepted", ErrSM2Point)
		}
		body = raw[1:]
	case 64:
	default:
		return nil, fmt.Errorf("%w: length %d", ErrSM2Point, len(raw))
	}
	x := new(big.Int).SetBytes(body[:32])
	y := new(big.Int).SetBytes(body[32:])
	if !pointOnCurve(x, y) {
		return nil, fmt.Errorf("%w: point not on curve", ErrSM2Point)
	}
	return &sm2Point{x: x, y: y}, nil
}

func fixed32(v *big.Int) []byte {
	out := make([]byte, 32)
	b := v.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)。
func sm2ZA(pub *sm2Point, id string) []byte {
	if id == "" {
		id = DefaultSM2ID
	}
	idBytes := []byte(id)
	buf := make([]byte, 0, 2+len(idBytes)+32*6)
	var entl [2]byte
	binary.BigEndian.PutUint16(entl[:], uint16(len(idBytes)*8))
	buf = append(buf, entl[:]...)
	buf = append(buf, idBytes...)
	buf = append(buf, fixed32(sm2A)...)
	buf = append(buf, fixed32(sm2B)...)
	buf = append(buf, fixed32(sm2Gx)...)
	buf = append(buf, fixed32(sm2Gy)...)
	buf = append(buf, fixed32(pub.x)...)
	buf = append(buf, fixed32(pub.y)...)
	sum := SM3(buf)
	return sum[:]
}

// sm2Digest = SM3(ZA ‖ msg)。
func sm2Digest(pub *sm2Point, msg []byte, id string) *big.Int {
	za := sm2ZA(pub, id)
	buf := make([]byte, 0, len(za)+len(msg))
	buf = append(buf, za...)
	buf = append(buf, msg...)
	sum := SM3(buf)
	return new(big.Int).SetBytes(sum[:])
}

// VerifySM2 校验裸签名（R‖S，64 字节）。msg 是原文字节，函数内部算 ZA 与摘要。
func VerifySM2(pubRaw, msg, sig []byte) bool {
	return verifySM2WithID(pubRaw, msg, sig, DefaultSM2ID)
}

func verifySM2WithID(pubRaw, msg, sig []byte, id string) bool {
	if len(sig) != 64 {
		return false
	}
	pub, err := ParseSM2PublicKey(pubRaw)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return verifyRS(pub, msg, r, s, id)
}

func verifyRS(pub *sm2Point, msg []byte, r, s *big.Int, id string) bool {
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(sm2N, one)
	if r.Sign() <= 0 || r.Cmp(nMinus1) > 0 || s.Sign() <= 0 || s.Cmp(nMinus1) > 0 {
		return false
	}
	e := sm2Digest(pub, msg, id)
	t := new(big.Int).Add(r, s)
	t.Mod(t, sm2N)
	if t.Sign() == 0 {
		return false
	}
	sG := pointMul(s, sm2G)
	tP := pointMul(t, pub)
	sum := pointAdd(sG, tP)
	if sum.inf {
		return false
	}
	x1 := modP(new(big.Int).Set(sum.x))
	rc := new(big.Int).Add(e, x1)
	rc.Mod(rc, sm2N)
	return rc.Cmp(r) == 0
}

// VerifySM2DER 校验 DER 编码（SEQUENCE{r,s}）的签名。
func VerifySM2DER(pubRaw, msg, der []byte) bool {
	r, s, err := parseSM2DER(der)
	if err != nil {
		return false
	}
	pub, err := ParseSM2PublicKey(pubRaw)
	if err != nil {
		return false
	}
	return verifyRS(pub, msg, r, s, DefaultSM2ID)
}

// parseSM2DER 严格解析 SEQUENCE{INTEGER r, INTEGER s}。
func parseSM2DER(der []byte) (*big.Int, *big.Int, error) {
	bad := func(why string) (*big.Int, *big.Int, error) {
		return nil, nil, fmt.Errorf("%w: %s", ErrSM2Signature, why)
	}
	if len(der) < 8 || der[0] != 0x30 {
		return bad("not a SEQUENCE")
	}
	seqLen := int(der[1])
	if seqLen != len(der)-2 {
		return bad("length mismatch")
	}
	body := der[2:]
	readInt := func(b []byte) (*big.Int, []byte, error) {
		if len(b) < 2 || b[0] != 0x02 {
			return nil, nil, fmt.Errorf("%w: expected INTEGER", ErrSM2Signature)
		}
		l := int(b[1])
		if l == 0 || len(b) < 2+l {
			return nil, nil, fmt.Errorf("%w: bad INTEGER length", ErrSM2Signature)
		}
		raw := b[2 : 2+l]
		// 严格 DER：不允许多余前导零；最高位为 1 时必须且仅补一个 0x00。
		if l > 1 && raw[0] == 0x00 && raw[1]&0x80 == 0 {
			return nil, nil, fmt.Errorf("%w: non-minimal INTEGER", ErrSM2Signature)
		}
		if raw[0]&0x80 != 0 {
			return nil, nil, fmt.Errorf("%w: negative INTEGER", ErrSM2Signature)
		}
		return new(big.Int).SetBytes(raw), b[2+l:], nil
	}
	r, rest, err := readInt(body)
	if err != nil {
		return nil, nil, err
	}
	s, rest, err := readInt(rest)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return bad("trailing bytes")
	}
	return r, s, nil
}

// GeneratePrivateKey 生成 32 字节 SM2 私钥（d ∈ [1, n-2]）。
func GeneratePrivateKey() ([]byte, error) {
	one := big.NewInt(1)
	max := new(big.Int).Sub(sm2N, one)
	for {
		d, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if d.Sign() > 0 {
			return fixed32(d), nil
		}
	}
}

// SignSM2WithK 用固定 k 签名（仅用于向量核对与测试；生产签名在端侧）。
func SignSM2WithK(priv32, msg []byte, k *big.Int, id string) ([]byte, []byte, error) {
	if len(priv32) != 32 {
		return nil, nil, fmt.Errorf("%w: private key must be 32 bytes", ErrSM2Signature)
	}
	d := new(big.Int).SetBytes(priv32)
	pubRaw, err := PublicKeyFromPrivate(d)
	if err != nil {
		return nil, nil, err
	}
	pub, _ := ParseSM2PublicKey(pubRaw)
	e := sm2Digest(pub, msg, id)
	one := big.NewInt(1)
	for {
		if k == nil || k.Sign() == 0 {
			kk, err := rand.Int(rand.Reader, new(big.Int).Sub(sm2N, one))
			if err != nil {
				return nil, nil, err
			}
			k = kk.Add(kk, one)
		}
		kg := pointMul(k, sm2G)
		if kg.inf {
			if k != nil {
				k = nil
				continue
			}
			return nil, nil, ErrSM2Signature
		}
		r := new(big.Int).Add(e, kg.x)
		r.Mod(r, sm2N)
		if r.Sign() == 0 {
			k = nil
			continue
		}
		// s = ((1+d)^-1 · (k - r·d)) mod n
		onePlusD := new(big.Int).Add(one, d)
		inv := new(big.Int).ModInverse(onePlusD, sm2N)
		if inv == nil {
			return nil, nil, ErrSM2Signature
		}
		rd := new(big.Int).Mul(r, d)
		kmrd := new(big.Int).Sub(k, rd)
		s := new(big.Int).Mul(inv, kmrd)
		s.Mod(s, sm2N)
		if s.Sign() == 0 {
			if k != nil {
				k = nil
				continue
			}
			return nil, nil, ErrSM2Signature
		}
		return r.Bytes(), s.Bytes(), nil
	}
}

// SignSM2DER 用随机 k 生成 DER 签名。
func SignSM2DER(priv32, msg []byte, id string) ([]byte, error) {
	r, s, err := SignSM2WithK(priv32, msg, nil, id)
	if err != nil {
		return nil, err
	}
	return encodeSM2DER(new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)), nil
}

// PublicKeyFromPrivate 由 32 字节私钥导出 65 字节未压缩公钥。
func PublicKeyFromPrivate(d *big.Int) ([]byte, error) {
	if d.Sign() <= 0 || d.Cmp(sm2N) >= 0 {
		return nil, fmt.Errorf("%w: private key out of range", ErrSM2Signature)
	}
	pt := pointMul(d, sm2G)
	if pt.inf {
		return nil, ErrSM2Signature
	}
	out := make([]byte, 65)
	out[0] = 0x04
	copy(out[1:33], fixed32(pt.x))
	copy(out[33:], fixed32(pt.y))
	return out, nil
}

func encodeSM2DER(r, s *big.Int) []byte {
	encInt := func(v *big.Int) []byte {
		b := v.Bytes()
		if len(b) == 0 {
			return []byte{0x02, 0x01, 0x00}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(encInt(r), encInt(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}
