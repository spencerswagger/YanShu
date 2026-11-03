package auth

// 双向对账：端侧内核签 → Go 验；Go 签 → 端侧内核验。
// 这样"两边各自自测都过、互相之间不通"的情况不可能蒙混过关。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/gm"
)

// kernelCall 是测试用的通用调用器（直接访问 wasm 实例）。
type kernelCall struct{ v *WASMVerifier }

func (k kernelCall) allocBytes(t *testing.T, data []byte) uint32 {
	t.Helper()
	res, err := k.v.alloc.Call(bgCtx(), uint64(len(data)))
	if err != nil || len(res) == 0 || res[0] == 0 {
		t.Fatalf("alloc: %v", err)
	}
	ptr := uint32(res[0])
	if !k.v.mem.Write(ptr, data) {
		t.Fatalf("memory write failed")
	}
	return ptr
}

func (k kernelCall) free(t *testing.T, ptr uint32, n int) {
	t.Helper()
	if _, err := k.v.free.Call(bgCtx(), uint64(ptr), uint64(n)); err != nil {
		t.Fatalf("free: %v", err)
	}
}

func (k kernelCall) read(ptr uint32, n int) []byte {
	out, ok := k.v.mem.Read(ptr, uint32(n))
	if !ok {
		return nil
	}
	return out
}

// pubkey 调 ys_sm2_pubkey(priv32, out64)。
func (k kernelCall) pubkey(t *testing.T, priv []byte) []byte {
	t.Helper()
	fn := k.v.mod.ExportedFunction("ys_sm2_pubkey")
	if fn == nil {
		t.Fatal("missing ys_sm2_pubkey")
	}
	privPtr := k.allocBytes(t, priv)
	defer k.free(t, privPtr, len(priv))
	res, _ := k.v.alloc.Call(bgCtx(), 64)
	outPtr := uint32(res[0])
	defer k.free(t, outPtr, 64)
	if _, err := fn.Call(bgCtx(), uint64(privPtr), uint64(outPtr)); err != nil {
		t.Fatalf("ys_sm2_pubkey: %v", err)
	}
	return append([]byte(nil), k.read(outPtr, 64)...)
}

// signDER 调 ys_sm2_sign_der(priv32, seed, seed_len, msg, msg_len, out, cap, out_len)。
func (k kernelCall) signDER(t *testing.T, priv, msg []byte) []byte {
	t.Helper()
	fn := k.v.mod.ExportedFunction("ys_sm2_sign_der")
	if fn == nil {
		t.Fatal("missing ys_sm2_sign_der")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	privPtr := k.allocBytes(t, priv)
	defer k.free(t, privPtr, len(priv))
	seedPtr := k.allocBytes(t, seed)
	defer k.free(t, seedPtr, len(seed))
	msgPtr := k.allocBytes(t, msg)
	defer k.free(t, msgPtr, len(msg))

	res, _ := k.v.alloc.Call(bgCtx(), 72)
	outPtr := uint32(res[0])
	defer k.free(t, outPtr, 72)
	resLen, _ := k.v.alloc.Call(bgCtx(), 4)
	lenPtr := uint32(resLen[0])
	defer k.free(t, lenPtr, 4)

	rc, err := fn.Call(bgCtx(), uint64(privPtr), uint64(seedPtr), uint64(len(seed)),
		uint64(msgPtr), uint64(len(msg)), uint64(outPtr), 72, uint64(lenPtr))
	if err != nil || len(rc) == 0 || int32(uint32(rc[0])) != 0 {
		t.Fatalf("ys_sm2_sign_der failed: rc=%v err=%v", rc, err)
	}
	lenRaw := k.read(lenPtr, 4)
	n := int(uint32(lenRaw[0]) | uint32(lenRaw[1])<<8 | uint32(lenRaw[2])<<16 | uint32(lenRaw[3])<<24)
	if n < 70 || n > 72 {
		t.Fatalf("unexpected DER length %d", n)
	}
	return append([]byte(nil), k.read(outPtr, n)...)
}

func bgCtx() context.Context { return context.Background() }

// rawVerify 调内核的 `ys_sm2_verify`（裸 R‖S 64 字节），返回 1/0/负数。
func (k kernelCall) rawVerify(t *testing.T, pub64, msg, raw64 []byte) int32 {
	t.Helper()
	fn := k.v.mod.ExportedFunction("ys_sm2_verify")
	if fn == nil {
		t.Fatal("missing ys_sm2_verify")
	}
	pubPtr := k.allocBytes(t, pub64)
	defer k.free(t, pubPtr, len(pub64))
	msgPtr := k.allocBytes(t, msg)
	defer k.free(t, msgPtr, len(msg))
	sigPtr := k.allocBytes(t, raw64)
	defer k.free(t, sigPtr, len(raw64))
	res, err := fn.Call(bgCtx(), uint64(pubPtr), uint64(msgPtr), uint64(len(msg)), uint64(sigPtr))
	if err != nil || len(res) == 0 {
		t.Fatalf("ys_sm2_verify: %v", err)
	}
	return int32(uint32(res[0]))
}

// derToRaw 把 DER SEQUENCE{r,s} 拆成 64 字节 R‖S（测试辅助；服务端不自己解 DER 给内核用）。
func derToRaw(t *testing.T, der []byte) []byte {
	t.Helper()
	if len(der) < 8 || der[0] != 0x30 {
		t.Fatalf("bad DER")
	}
	body := der[2:]
	readInt := func(b []byte) ([]byte, []byte) {
		if len(b) < 2 || b[0] != 0x02 {
			t.Fatalf("bad DER int")
		}
		n := int(b[1])
		if len(b) < 2+n {
			t.Fatalf("bad DER len")
		}
		v := b[2 : 2+n]
		for len(v) > 32 && v[0] == 0x00 {
			v = v[1:]
		}
		out := make([]byte, 32)
		copy(out[32-len(v):], v)
		return out, b[2+n:]
	}
	r, rest := readInt(body)
	ss, _ := readInt(rest)
	return append(r, ss...)
}

// 端侧签 → Go 验 + 端侧验。
func TestKernelSignsGoVerifies(t *testing.T) {
	v := newTestVerifier(t)
	k := kernelCall{v}

	priv, err := gm.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub64 := k.pubkey(t, priv)
	pub65 := append([]byte{0x04}, pub64...)

	// 用真实的 SIG_INPUT 形状做消息，避免"随便一段字节"掩盖长度前缀问题。
	msg := []byte("YSAUTH1" + "\x05" + string(make([]byte, 32)) + "AWQW")

	der := k.signDER(t, priv, msg)
	if !gm.VerifySM2DER(pub65, msg, der) {
		t.Fatalf("Go 未验过端侧签名（DER=%s）", hex.EncodeToString(der))
	}
	if err := v.Verify(pub65, msg, der); err != nil {
		t.Fatalf("端侧内核未验过自己的签名: %v", err)
	}
	// 裸 R‖S 入口也必须一致（ys_sm2_verify）。
	raw := derToRaw(t, der)
	if !gm.VerifySM2(pub65, msg, raw) {
		t.Fatal("Go 未验过端侧裸签名")
	}
	if rc := k.rawVerify(t, pub64, msg, raw); rc != 1 {
		t.Fatalf("内核 ys_sm2_verify(raw) = %d, want 1", rc)
	}

	// 改一字节消息必须两边都拒。
	badMsg := append([]byte(nil), msg...)
	badMsg[len(badMsg)-1] ^= 0x01
	if gm.VerifySM2DER(pub65, badMsg, der) {
		t.Fatal("Go 接受了被篡改的消息")
	}
	if err := v.Verify(pub65, badMsg, der); err == nil {
		t.Fatal("内核接受了被篡改的消息")
	}
}

// Go 签 → 端侧验 + Go 验。
func TestGoSignsKernelVerifies(t *testing.T) {
	v := newTestVerifier(t)
	k := kernelCall{v}

	priv, err := gm.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub64 := k.pubkey(t, priv)
	pub65 := append([]byte{0x04}, pub64...)

	msg := []byte("YSAUTH1" + "\x03" + string(make([]byte, 32)) +
		"AWQW" + "WTJF" + string([]byte{0, 0, 0, 0, 0, 0, 0, 5}))

	der, err := gm.SignSM2DER(priv, msg, gm.DefaultSM2ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(pub65, msg, der); err != nil {
		t.Fatalf("端侧内核未验过 Go 签名（DER=%s）: %v", hex.EncodeToString(der), err)
	}
	if !gm.VerifySM2DER(pub65, msg, der) {
		t.Fatal("Go 未验过自己的签名")
	}
	if rc := k.rawVerify(t, pub64, msg, derToRaw(t, der)); rc != 1 {
		t.Fatalf("内核 ys_sm2_verify(raw) = %d, want 1", rc)
	}

	// 换公钥必须两边都拒。
	otherPriv, _ := gm.GeneratePrivateKey()
	otherPub65 := append([]byte{0x04}, k.pubkey(t, otherPriv)...)
	if gm.VerifySM2DER(otherPub65, msg, der) {
		t.Fatal("Go 用错误公钥验过了")
	}
	if err := v.Verify(otherPub65, msg, der); err == nil {
		t.Fatal("内核用错误公钥验过了")
	}
}
