package gm

// 向量来源：端侧 crate `crypto/sm/testdata/vectors.json`（分支 feat/endcrypto-wasm），
// 该实现已与 GmSSL 逐字节交叉验证（84 PASS）。这里把「固定 k 签名」与 ZA 抄成常量，
// 用来钉住服务端这套独立实现的曲线运算、ZA 与摘要口径。

import (
	"encoding/hex"
	"math/big"
	"testing"
)

type sm2Vector struct {
	name   string
	priv   string
	pub    string // 64 字节 X‖Y
	za     string
	k      string
	msg    string
	sigRaw string
	sigDER string
}

var sm2Vectors = []sm2Vector{
	{
		name:   "msg_short",
		priv:   "0069ffee11d447e54c8171a3f6a8fa4620b08648d843764115abd02801a9bf0b",
		pub:    "9bb03101c716d29cb96951d052a26dbf5def45eae46845694faa627ce8544cec07dee9d5bb614e2e0806361912a78d31cda307c3dddd9a2e58559ee8d22f59f5",
		za:     "635cb318fc202ff5f7e4175d7cb1d89d647b80ff86a4e9af4654c143f4cf1d32",
		k:      "0061d221c663e4500159e4a65720f6ef42f600b67e44c3b04627be57ebe54efb",
		msg:    "79616e736875206d616e6966657374",
		sigRaw: "427c0123314c60c5699c3c3138ae6e98f4f44e02451ad0588c828990a8842ddf79f1a7f75070d1cd941fcc536a1cd10587abf6c538e4420e345349a156bd3a6f",
		sigDER: "30440220427c0123314c60c5699c3c3138ae6e98f4f44e02451ad0588c828990a8842ddf022079f1a7f75070d1cd941fcc536a1cd10587abf6c538e4420e345349a156bd3a6f",
	},
	{
		name:   "msg_empty",
		priv:   "001721181d07edf2d36816f7e31648a4d88bfab560fe14414c2312729f71f40b",
		pub:    "07a164e6cb27f81e401d3edbf2cebfcfbe1385494d008d4d24ae6a5857ad9fccbf2b8c70bec1e28c66d6cf0cc4100b0fa16cf0b784c326f9fbcdcebc9ce4be73",
		za:     "a7c2757f306c4d2fe81a8843e5389e963a20f998ddf68b7fca06f122f00cf135",
		k:      "00720e8d105481335c58bd327b1774c2a591f9657d1b22c638e29b06c1fd6fb8",
		msg:    "",
		sigRaw: "1ec89d6336e818f7f5d03c6905dfaca14ec8b13a43014b0030c46893c89aa9525b1532eeedee0b8e3de0160f56af705e49c75eacfaaeb3ffd24c6477678de7f9",
		sigDER: "304402201ec89d6336e818f7f5d03c6905dfaca14ec8b13a43014b0030c46893c89aa95202205b1532eeedee0b8e3de0160f56af705e49c75eacfaaeb3ffd24c6477678de7f9",
	},
	{
		name:   "msg_64",
		priv:   "0041e9ac33dd21a8a91b52cc76fa72b14320a464b6a4d3a5a58632a60b43aaf2",
		pub:    "e0b763ca87e6e3384c981723a12bd589272db40dd93449a0598bc7844922aa7c28dcc6408acf2c25d9da13baf9f4d903044f2d510797646bb486824747f3921d",
		za:     "0dfad2566faced2645fce1a5bea1e538b8e52b3e213387cb5504f4651f480bec",
		k:      "00727aa8f0cc5738ff4b232add9cc700bece7b5fccd8148e327824f4262fc889",
		msg:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		sigRaw: "ebe29853c17aa1133073c48ecd0d0bd0b9abd0ac7fadd9c811787deaf46701e947d52ecc1b94f26dfcd02cd9c940f5e33b3d20de3142553a5f6828bef71887e4",
		sigDER: "3045022100ebe29853c17aa1133073c48ecd0d0bd0b9abd0ac7fadd9c811787deaf46701e9022047d52ecc1b94f26dfcd02cd9c940f5e33b3d20de3142553a5f6828bef71887e4",
	},
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestSM2VectorsPublicKeyAndZA(t *testing.T) {
	for _, v := range sm2Vectors {
		d := new(big.Int).SetBytes(mustDecode(t, v.priv))
		pub65, err := PublicKeyFromPrivate(d)
		if err != nil {
			t.Fatalf("%s: derive pub: %v", v.name, err)
		}
		if hex.EncodeToString(pub65[1:]) != v.pub {
			t.Fatalf("%s: public key mismatch", v.name)
		}
		pt, err := ParseSM2PublicKey(pub65)
		if err != nil {
			t.Fatalf("%s: parse: %v", v.name, err)
		}
		if got := hex.EncodeToString(sm2ZA(pt, DefaultSM2ID)); got != v.za {
			t.Fatalf("%s: ZA mismatch\n got %s\nwant %s", v.name, got, v.za)
		}
	}
}

func TestSM2VectorsFixedKSignature(t *testing.T) {
	for _, v := range sm2Vectors {
		priv := mustDecode(t, v.priv)
		msg := mustDecode(t, v.msg)
		k := new(big.Int).SetBytes(mustDecode(t, v.k))
		r, s, err := SignSM2WithK(priv, msg, k, DefaultSM2ID)
		if err != nil {
			t.Fatalf("%s: sign: %v", v.name, err)
		}
		r32 := make([]byte, 32)
		copy(r32[32-len(r):], r)
		s32 := make([]byte, 32)
		copy(s32[32-len(s):], s)
		got := hex.EncodeToString(append(r32, s32...))
		if got != v.sigRaw {
			t.Fatalf("%s: signature mismatch\n got %s\nwant %s", v.name, got, v.sigRaw)
		}
	}
}

func TestSM2VectorsVerify(t *testing.T) {
	for _, v := range sm2Vectors {
		pub64 := mustDecode(t, v.pub)
		pub65 := append([]byte{0x04}, pub64...)
		msg := mustDecode(t, v.msg)
		raw := mustDecode(t, v.sigRaw)
		der := mustDecode(t, v.sigDER)
		if !VerifySM2(pub65, msg, raw) {
			t.Fatalf("%s: raw signature rejected", v.name)
		}
		if !VerifySM2(pub64, msg, raw) {
			t.Fatalf("%s: 64-byte public key rejected", v.name)
		}
		if !VerifySM2DER(pub65, msg, der) {
			t.Fatalf("%s: DER signature rejected", v.name)
		}
	}
}

func TestSM2RejectsTampering(t *testing.T) {
	for _, v := range sm2Vectors {
		pub65 := append([]byte{0x04}, mustDecode(t, v.pub)...)
		msg := mustDecode(t, v.msg)
		raw := mustDecode(t, v.sigRaw)

		badMsg := append([]byte(nil), msg...)
		badMsg = append(badMsg, 0x00)
		if VerifySM2(pub65, badMsg, raw) {
			t.Fatalf("%s: tampered message accepted", v.name)
		}

		badSig := append([]byte(nil), raw...)
		badSig[10] ^= 0x01
		if VerifySM2(pub65, msg, badSig) {
			t.Fatalf("%s: tampered signature accepted", v.name)
		}

		other := mustDecode(t, sm2Vectors[(len(sm2Vectors)-1)%len(sm2Vectors)].pub)
		otherPub := append([]byte{0x04}, other...)
		if v.pub != hex.EncodeToString(other) && VerifySM2(otherPub, msg, raw) {
			t.Fatalf("%s: signature accepted under a different public key", v.name)
		}
	}
}

func TestSM2RejectsBadPoints(t *testing.T) {
	// 不在曲线上的点。
	bad := make([]byte, 65)
	bad[0] = 0x04
	bad[64] = 1
	if _, err := ParseSM2PublicKey(bad); err == nil {
		t.Fatal("off-curve point accepted")
	}
	// 压缩点前缀。
	compressed := make([]byte, 65)
	compressed[0] = 0x02
	if _, err := ParseSM2PublicKey(compressed); err == nil {
		t.Fatal("compressed point accepted")
	}
	// 长度错误。
	if _, err := ParseSM2PublicKey(make([]byte, 63)); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestSM2DERStrictness(t *testing.T) {
	v := sm2Vectors[0]
	der := mustDecode(t, v.sigDER)
	if _, _, err := parseSM2DER(der); err != nil {
		t.Fatalf("valid DER rejected: %v", err)
	}

	cases := map[string][]byte{
		"empty":         {},
		"wrong tag":     append([]byte{0x31}, der[1:]...),
		"trailing byte": append(append([]byte(nil), der...), 0x00),
		"truncated":     der[:len(der)-1],
		"bad length":    append([]byte{0x30, der[1] + 1}, der[2:]...),
	}
	for name, bad := range cases {
		if _, _, err := parseSM2DER(bad); err == nil {
			t.Fatalf("%s: malformed DER accepted", name)
		}
	}
}
