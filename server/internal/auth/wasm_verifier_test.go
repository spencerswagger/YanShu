package auth

// 路线 B 的落地验证：用 wazero 加载端侧内核，调 `ys_sm2_verify_der` 跑端侧向量。
// 内核随仓库提供（server/kernel/yanshu_sm.wasm），所以这个测试不需要 Rust 工具链。

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const (
	kernelPath  = "../../kernel/yanshu_sm.wasm"
	vectorsPath = "../gm/testdata/sm2-verify-vectors.json"
)

type wasmVector struct {
	Name         string `json:"name"`
	Pub65        string `json:"pub65"`
	UserID       string `json:"user_id"`
	Msg          string `json:"msg"`
	SigDER       string `json:"sig_der"`
	ExpectVerify bool   `json:"expect_verify"`
}

func loadWASMVectors(t *testing.T) []wasmVector {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []wasmVector `json:"verify_vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc.Vectors
}

func newTestVerifier(t *testing.T) *WASMVerifier {
	t.Helper()
	if _, err := os.Stat(kernelPath); err != nil {
		t.Fatalf("kernel missing at %s: %v", kernelPath, err)
	}
	v, err := NewWASMVerifier(kernelPath)
	if err != nil {
		t.Fatalf("load kernel: %v", err)
	}
	t.Cleanup(v.Close)
	return v
}

func TestWASMKernelVersion(t *testing.T) {
	v := newTestVerifier(t)
	ver, err := v.Version()
	if err != nil {
		t.Fatal(err)
	}
	if ver != 0x00010000 {
		t.Fatalf("ys_version = 0x%08x, want 0x00010000", ver)
	}
}

func TestWASMVerifyVectors(t *testing.T) {
	v := newTestVerifier(t)
	vectors := loadWASMVectors(t)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vec := range vectors {
		pub, _ := hex.DecodeString(vec.Pub65)
		msg, _ := hex.DecodeString(vec.Msg)
		sig, _ := hex.DecodeString(vec.SigDER)

		err := v.Verify(pub, msg, sig)
		if vec.UserID != "1234567812345678" {
			// 内核固定默认 userID（没有 ID 入参）；这条向量的签名本来就是默认 ID 签的，
			// 它在服务端口径下应当通过 —— 换 userID 的语义由 Go 侧向量测试覆盖。
			if err != nil {
				t.Fatalf("%s: default-userID signature rejected by kernel: %v", vec.Name, err)
			}
			continue
		}
		if vec.ExpectVerify {
			if err != nil {
				t.Fatalf("%s: valid signature rejected: %v", vec.Name, err)
			}
			// 64 字节 X‖Y 也应接受（服务端内部会剥掉 0x04）。
			if err := v.Verify(pub[1:], msg, sig); err != nil {
				t.Fatalf("%s: 64-byte public key rejected: %v", vec.Name, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: bad signature accepted", vec.Name)
		}
		if !errors.Is(err, ErrSignature) {
			t.Fatalf("%s: want ErrSignature, got %v", vec.Name, err)
		}
	}
}

// 服务端固定默认 userID，因此 5 组向量的"服务端口径期望"是：
//
//	ok_register               通过
//	sig_flipped_1byte         拒绝
//	msg_changed               拒绝
//	wrong_public_key          拒绝
//	different_user_id         通过（它就是默认 ID 签的；"换 ID 必须拒"只在带 ID 入参时成立）
//
// 这条测试把该映射钉死，避免下游误以为 4 条都该拒。
func TestServerPolicyOnVerifyVectors(t *testing.T) {
	v := newTestVerifier(t)
	vectors := loadWASMVectors(t)

	want := map[string]bool{
		"ok_register":       true,
		"sig_flipped_1byte": false,
		"msg_changed":       false,
		"wrong_public_key":  false,
		"different_user_id": true,
	}
	seen := map[string]bool{}
	for _, vec := range vectors {
		expect, ok := want[vec.Name]
		if !ok {
			t.Fatalf("unexpected vector %q", vec.Name)
		}
		seen[vec.Name] = true
		pub, _ := hex.DecodeString(vec.Pub65)
		msg, _ := hex.DecodeString(vec.Msg)
		sig, _ := hex.DecodeString(vec.SigDER)
		err := v.Verify(pub, msg, sig)
		if expect && err != nil {
			t.Fatalf("%s: want accept, got %v", vec.Name, err)
		}
		if !expect && err == nil {
			t.Fatalf("%s: want reject, got accept", vec.Name)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 vectors, saw %d", len(seen))
	}
}

func TestWASMRejectsMalformedInput(t *testing.T) {
	v := newTestVerifier(t)
	vectors := loadWASMVectors(t)
	pub, _ := hex.DecodeString(vectors[0].Pub65)
	msg, _ := hex.DecodeString(vectors[0].Msg)
	sig, _ := hex.DecodeString(vectors[0].SigDER)

	cases := map[string]struct {
		pub, msg, sig []byte
	}{
		"empty signature": {pub, msg, nil},
		"empty message":   {pub, nil, sig},
		"bad public key":  {make([]byte, 65), msg, sig},
		"truncated DER":   {pub, msg, sig[:len(sig)-1]},
		"trailing DER":    {pub, msg, append(append([]byte(nil), sig...), 0x00)},
	}
	for name, c := range cases {
		if err := v.Verify(c.pub, c.msg, c.sig); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
