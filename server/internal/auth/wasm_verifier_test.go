package auth

// 路线 B 的落地验证 + 15 条端侧验签向量。
//
// 向量来源：`crypto/sm/vectors/sm2-verify-vectors.json`（分支 feat/endcrypto-wasm）：
// 7 条正例（七种 PURPOSE）+ 8 条负例，每条给 `expect_verify`（密码学结果）与
// `expect_server`（服务端策略结果）。

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/gm"
)

const (
	kernelPath  = "../../kernel/yanshu_sm.wasm"
	vectorsPath = "../gm/testdata/sm2-verify-vectors.json"
)

type verifyVector struct {
	Name         string `json:"name"`
	Purpose      string `json:"purpose"`
	Pub65        string `json:"pub65"`
	UserID       string `json:"user_id"`
	SigInput     string `json:"sig_input"`
	SigInputLen  int    `json:"sig_input_len"`
	SigDER       string `json:"sig_der"`
	ExpectVerify bool   `json:"expect_verify"`
	ExpectServer string `json:"expect_server"`
}

func loadVerifyVectors(t *testing.T) []verifyVector {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []verifyVector `json:"verify_vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Vectors) != 15 {
		t.Fatalf("expected 15 vectors, got %d", len(doc.Vectors))
	}
	return doc.Vectors
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
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

// 密码学层：Go 实现（按向量的 userID）与内核（固定默认 ID）都必须与 expect_verify 一致。
func TestVerifyVectorsCrypto(t *testing.T) {
	v := newTestVerifier(t)
	vectors := loadVerifyVectors(t)

	var pass, reject, okCount int
	for _, vec := range vectors {
		pub := mustHex(t, vec.Pub65)
		msg := mustHex(t, vec.SigInput)
		sig := mustHex(t, vec.SigDER)
		if len(msg) != vec.SigInputLen {
			t.Fatalf("%s: sig_input len %d != %d", vec.Name, len(msg), vec.SigInputLen)
		}

		if got := gm.VerifySM2DERWithID(pub, msg, sig, vec.UserID); got != vec.ExpectVerify {
			t.Fatalf("%s: Go(with id=%s) = %v, want %v", vec.Name, vec.UserID, got, vec.ExpectVerify)
		}
		if vec.UserID == gm.DefaultSM2ID {
			if got := gm.VerifySM2DER(pub, msg, sig); got != vec.ExpectVerify {
				t.Fatalf("%s: Go(default id) = %v, want %v", vec.Name, got, vec.ExpectVerify)
			}
			// 空/超长消息由服务端在入参层拒（BAD_INPUT），不走内核。
			if vec.ExpectServer != "BAD_INPUT" {
				err := v.Verify(pub, msg, sig)
				if (err == nil) != vec.ExpectVerify {
					t.Fatalf("%s: kernel = %v, want verify=%v", vec.Name, err, vec.ExpectVerify)
				}
			}
		}
		if vec.ExpectVerify {
			pass++
		} else {
			reject++
		}
		if vec.ExpectServer == "OK" {
			okCount++
			if !vec.ExpectVerify {
				t.Fatalf("%s: an OK vector must verify", vec.Name)
			}
		}
	}
	// 7 条正例（七种 PURPOSE）+ 8 条负例；负例里 code_mismatch / empty_message /
	// oversized_input 的**密码学**结果是"通过"，只是服务端策略要拒，所以 expect_verify
	// 为 true 的一共 10 条、false 5 条。
	if okCount != 7 || len(vectors) != 15 {
		t.Fatalf("OK vectors = %d, total = %d, want 7/15", okCount, len(vectors))
	}
	if pass != 10 || reject != 5 {
		t.Fatalf("expect_verify split = %d/%d, want 10/5", pass, reject)
	}
}

// 策略层：把 expect_server 映射到服务端的对外行为。
func TestVerifyVectorsServerPolicy(t *testing.T) {
	v := newTestVerifier(t)
	for _, vec := range loadVerifyVectors(t) {
		pub := mustHex(t, vec.Pub65)
		msg := mustHex(t, vec.SigInput)
		sig := mustHex(t, vec.SigDER)
		err := v.Verify(pub, msg, sig)

		switch vec.ExpectServer {
		case "OK":
			if err != nil {
				t.Fatalf("%s: want OK, got %v", vec.Name, err)
			}
		case "AUTH_CODE_MISMATCH":
			// 密码学通过；"码与请求头不一致"由 handler 在验签之后判定（HTTP 层用例覆盖）。
			if err != nil {
				t.Fatalf("%s: signature must verify before the code check, got %v", vec.Name, err)
			}
		case "CRYPTO_SIGNATURE_INVALID":
			// 已知向量文件缺陷：`different_user_id` 与 `REGISTER` 的消息、签名**完全相同**，
			// 只把 user_id 标成 ...5679。服务端固定默认 ID，因此这条签名在服务端口径下
			// 必然通过 —— 向量里的 expect_server 是按"可配置 ID 的验签器"写的，与 ABI 不符。
			// 这里按事实断言，并在测试里留痕；不为了绿灯改实现。
			if vec.Name == "different_user_id" {
				if err != nil {
					t.Fatalf("%s: under the fixed default ID this signature must verify, got %v", vec.Name, err)
				}
				t.Logf("WARN: %s 的 expect_server 与固定默认 ID 的 ABI 不一致（签名与 REGISTER 同字节）", vec.Name)
				continue
			}
			if !errors.Is(err, ErrSignature) {
				t.Fatalf("%s: want ErrSignature, got %v", vec.Name, err)
			}
		case "BAD_INPUT":
			if !errors.Is(err, ErrBadInput) {
				t.Fatalf("%s: want ErrBadInput, got %v", vec.Name, err)
			}
		default:
			t.Fatalf("%s: unknown expect_server %q", vec.Name, vec.ExpectServer)
		}
	}
}

func TestWASMRejectsMalformedInput(t *testing.T) {
	v := newTestVerifier(t)
	vectors := loadVerifyVectors(t)
	pub := mustHex(t, vectors[0].Pub65)
	msg := mustHex(t, vectors[0].SigInput)
	sig := mustHex(t, vectors[0].SigDER)

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
		err := v.Verify(c.pub, c.msg, c.sig)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if !errors.Is(err, ErrBadInput) && !errors.Is(err, ErrSignature) {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
	}
}
