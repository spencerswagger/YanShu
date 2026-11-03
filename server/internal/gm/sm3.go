// Package gm 是雁书服务端自研的国密最小实现。
//
// 服务端只需要 SM3：一是按 docs/CRYPTO-PACK.md §3.4 从公钥派生用户码，
// 二是对 prelude/块做完整性摘要（CRYPTO-PACK §12 要求服务端另存 SM3(prelude)）。
// SM2 验签不在这里实现，见 internal/auth（接口 + 桩）。
//
// 实现依据：GB/T 32905-2016（SM3 密码杂凑算法）。
package gm

import (
	"encoding/binary"
	"math/bits"
)

const (
	sm3BlockSize = 64
	sm3Size      = 32
)

// sm3IV 是 GB/T 32905-2016 规定的初始值。
var sm3IV = [8]uint32{
	0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
	0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
}

// sm3Digest 是增量 SM3 状态。
type sm3Digest struct {
	h   [8]uint32
	buf [sm3BlockSize]byte
	n   int
	len uint64 // 已处理的字节数
}

// NewSM3 返回一个空的 SM3 摘要器。
func NewSM3() *sm3Digest {
	d := &sm3Digest{}
	d.h = sm3IV
	return d
}

// SM3 是便捷的一步式摘要。
func SM3(data []byte) [sm3Size]byte {
	d := NewSM3()
	_, _ = d.Write(data)
	var out [sm3Size]byte
	copy(out[:], d.Sum(nil))
	return out
}

func (d *sm3Digest) Size() int      { return sm3Size }
func (d *sm3Digest) BlockSize() int { return sm3BlockSize }

func (d *sm3Digest) Reset() {
	d.h = sm3IV
	d.n = 0
	d.len = 0
}

func (d *sm3Digest) Write(p []byte) (int, error) {
	written := len(p)
	d.len += uint64(len(p))
	if d.n > 0 {
		c := copy(d.buf[d.n:], p)
		d.n += c
		p = p[c:]
		if d.n == sm3BlockSize {
			sm3Block(d, d.buf[:])
			d.n = 0
		}
	}
	for len(p) >= sm3BlockSize {
		sm3Block(d, p[:sm3BlockSize])
		p = p[sm3BlockSize:]
	}
	if len(p) > 0 {
		d.n = copy(d.buf[:], p)
	}
	return written, nil
}

func (d *sm3Digest) Sum(in []byte) []byte {
	// 拷贝状态，保证 Sum 可重复调用。
	c := *d
	bitLen := c.len << 3

	// 填充：0x80 + 若干 0x00 + 64 位大端比特长度，使总长为 64 的倍数。
	pad := make([]byte, 0, 72)
	pad = append(pad, 0x80)
	for (c.n+len(pad))%sm3BlockSize != sm3BlockSize-8 {
		pad = append(pad, 0x00)
	}
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], bitLen)
	pad = append(pad, lenBuf[:]...)
	_, _ = c.Write(pad)
	var out [sm3Size]byte
	for i, v := range c.h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return append(in, out[:]...)
}

func rotl(x uint32, n int) uint32 {
	n &= 31
	return bits.RotateLeft32(x, n)
}

func sm3P0(x uint32) uint32 { return x ^ rotl(x, 9) ^ rotl(x, 17) }
func sm3P1(x uint32) uint32 { return x ^ rotl(x, 15) ^ rotl(x, 23) }

func sm3FF(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func sm3GG(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

func sm3Block(d *sm3Digest, block []byte) {
	var w [68]uint32
	var w1 [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}
	for i := 16; i < 68; i++ {
		w[i] = sm3P1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
	}
	for i := 0; i < 64; i++ {
		w1[i] = w[i] ^ w[i+4]
	}

	a, b, c, dv := d.h[0], d.h[1], d.h[2], d.h[3]
	e, f, g, h := d.h[4], d.h[5], d.h[6], d.h[7]
	for j := 0; j < 64; j++ {
		var t uint32
		if j < 16 {
			t = 0x79cc4519
		} else {
			t = 0x7a879d8a
		}
		ss1 := rotl(rotl(a, 12)+e+rotl(t, j), 7)
		ss2 := ss1 ^ rotl(a, 12)
		tt1 := sm3FF(j, a, b, c) + dv + ss2 + w1[j]
		tt2 := sm3GG(j, e, f, g) + h + ss1 + w[j]
		dv = c
		c = rotl(b, 9)
		b = a
		a = tt1
		h = g
		g = rotl(f, 19)
		f = e
		e = sm3P0(tt2)
	}
	d.h[0] ^= a
	d.h[1] ^= b
	d.h[2] ^= c
	d.h[3] ^= dv
	d.h[4] ^= e
	d.h[5] ^= f
	d.h[6] ^= g
	d.h[7] ^= h
}
