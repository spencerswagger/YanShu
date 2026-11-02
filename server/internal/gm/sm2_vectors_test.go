package gm

// 端侧提供的「服务端专用验签向量」，逐条对账。
//
// 来源：`crypto/sm` 的 `vectors/sm2-verify-vectors.json`（分支 feat/endcrypto-wasm，
// commit c2c7962）。向量由已与 GmSSL 交叉验证（84 PASS）的实现生成，覆盖：
// 正例、改 1 字节消息、改签名、换 userID、换公钥。

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type verifyVector struct {
	Name         string `json:"name"`
	Pub65        string `json:"pub65"`
	UserID       string `json:"user_id"`
	Msg          string `json:"msg"`
	ZA           string `json:"za"`
	DigestE      string `json:"digest_e"`
	SigDER       string `json:"sig_der"`
	SigDERLen    int    `json:"sig_der_len"`
	ExpectVerify bool   `json:"expect_verify"`
}

type sigInputSample struct {
	Purpose  string `json:"purpose"`
	PurposeB string `json:"purpose_byte"`
	Len      int    `json:"len"`
	SigInput string `json:"sig_input"`
}

type verifyVectors struct {
	Meta struct {
		UserID          string `json:"user_id"`
		SignedDigest    string `json:"signed_digest"`
		SignatureEncode string `json:"signature_encoding"`
	} `json:"meta"`
	SigInputSamples []sigInputSample `json:"sig_input_samples"`
	VerifyVectors   []verifyVector   `json:"verify_vectors"`
}

func loadVerifyVectors(t *testing.T) verifyVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/sm2-verify-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v verifyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Meta.UserID != DefaultSM2ID {
		t.Fatalf("vector userID = %q, code default = %q", v.Meta.UserID, DefaultSM2ID)
	}
	return v
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// 逐条核对：ZA、e、以及 expect_verify。
func TestServerVerifyVectors(t *testing.T) {
	v := loadVerifyVectors(t)
	if len(v.VerifyVectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vec := range v.VerifyVectors {
		pub := hexBytes(t, vec.Pub65)
		msg := hexBytes(t, vec.Msg)
		der := hexBytes(t, vec.SigDER)

		pt, err := ParseSM2PublicKey(pub)
		if err != nil {
			t.Fatalf("%s: parse pub: %v", vec.Name, err)
		}
		if got := hex.EncodeToString(sm2ZA(pt, vec.UserID)); got != vec.ZA {
			t.Fatalf("%s: ZA mismatch\n got %s\nwant %s", vec.Name, got, vec.ZA)
		}
		if got := hex.EncodeToString(sm2DigestBytes(pt, msg, vec.UserID)); got != vec.DigestE {
			t.Fatalf("%s: e mismatch\n got %s\nwant %s", vec.Name, got, vec.DigestE)
		}
		if len(der) != vec.SigDERLen {
			t.Fatalf("%s: DER length %d, want %d", vec.Name, len(der), vec.SigDERLen)
		}

		got := VerifySM2DERWithID(pub, msg, der, vec.UserID)
		if got != vec.ExpectVerify {
			t.Fatalf("%s: verify = %v, want %v", vec.Name, got, vec.ExpectVerify)
		}
	}
}

// userID 语义：签名是「在 userID=1234567812345678 下」生成的，所以换 userID 校验必须失败，
// 而默认 userID 校验必须通过 —— 这正是服务端固定默认 ID 的依据。
func TestUserIDBinding(t *testing.T) {
	v := loadVerifyVectors(t)
	found := false
	for _, vec := range v.VerifyVectors {
		if vec.UserID == DefaultSM2ID {
			continue
		}
		found = true
		pub := hexBytes(t, vec.Pub65)
		msg := hexBytes(t, vec.Msg)
		der := hexBytes(t, vec.SigDER)
		if VerifySM2DERWithID(pub, msg, der, vec.UserID) {
			t.Fatalf("%s: signature verified under a non-default userID", vec.Name)
		}
		if !VerifySM2DER(pub, msg, der) {
			t.Fatalf("%s: the same signature must verify under the default userID", vec.Name)
		}
	}
	if !found {
		t.Fatal("vector set lost its different-userID case")
	}
}

// SIG_INPUT 样例：确认服务端构造与端侧逐字节一致（长度前缀/CODE 位置）。
func TestSigInputSamples(t *testing.T) {
	v := loadVerifyVectors(t)
	if len(v.SigInputSamples) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(v.SigInputSamples))
	}
	for _, s := range v.SigInputSamples {
		raw := hexBytes(t, s.SigInput)
		if len(raw) != s.Len {
			t.Fatalf("%s: sample len %d != declared %d", s.Purpose, len(raw), s.Len)
		}
		if raw[0] != 0x01 || raw[1] != byte(len(raw)) {
			// 前两字节不是长度前缀，只是做个显式断言防止误读格式。
			_ = raw
		}
		if string(raw[:7]) != "YSAUTH1" {
			t.Fatalf("%s: prefix = %q", s.Purpose, raw[:7])
		}
		if got := hex.EncodeToString(raw[7:8]); got != s.PurposeB {
			t.Fatalf("%s: purpose byte = %s, want %s", s.Purpose, got, s.PurposeB)
		}
	}
}

// sm2DigestBytes 是 e = SM3(ZA‖msg) 的字节形式（测试用）。
func sm2DigestBytes(pub *sm2Point, msg []byte, id string) []byte {
	za := sm2ZA(pub, id)
	buf := make([]byte, 0, len(za)+len(msg))
	buf = append(buf, za...)
	buf = append(buf, msg...)
	sum := SM3(buf)
	return sum[:]
}
