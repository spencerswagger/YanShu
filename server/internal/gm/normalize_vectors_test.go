package gm

// 码归一化：与端侧 `ys_normalize_code` 逐条对账。
//
// 向量来源：`crypto/sm/testdata/normalize-vectors.json`（分支 feat/endcrypto-wasm），
// 20 组 = 13 接受 + 7 拒绝，源与端侧单测同表。

import (
	"encoding/json"
	"os"
	"testing"
)

type normalizeVector struct {
	In         string  `json:"in"`
	Out        *string `json:"out"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error"`
	Idempotent bool    `json:"idempotent"`
}

func TestNormalizeCodeVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/normalize-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Alphabet string            `json:"alphabet"`
		Vectors  []normalizeVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Alphabet != CrockfordAlphabet {
		t.Fatalf("alphabet mismatch: %q", doc.Alphabet)
	}
	if len(doc.Vectors) != 20 {
		t.Fatalf("expected 20 vectors, got %d", len(doc.Vectors))
	}

	var accepted, rejected int
	for _, v := range doc.Vectors {
		got, err := NormalizeCode(v.In)
		if v.OK {
			accepted++
			if err != nil {
				t.Fatalf("%q: rejected, want %q", v.In, *v.Out)
			}
			if v.Out == nil || got != *v.Out {
				t.Fatalf("%q: got %q, want %v", v.In, got, v.Out)
			}
			if len(got) != 4 {
				t.Fatalf("%q: result length %d", v.In, len(got))
			}
			if !IsNormalizedCode(got) {
				t.Fatalf("%q: result %q is not canonical", v.In, got)
			}
			// 幂等：f(f(x)) == f(x)
			again, err := NormalizeCode(got)
			if err != nil || again != got {
				t.Fatalf("%q: not idempotent (%q -> %q, err=%v)", v.In, got, again, err)
			}
			continue
		}

		rejected++
		if err == nil {
			t.Fatalf("%q: accepted as %q, want rejection", v.In, got)
		}
		if v.Error != "CRYPTO_CODE_INVALID" {
			t.Fatalf("%q: unexpected expected-error name %q", v.In, v.Error)
		}
		if got != "" {
			t.Fatalf("%q: rejected but returned %q", v.In, got)
		}
	}
	if accepted != 13 || rejected != 7 {
		t.Fatalf("vector split = %d accept / %d reject, want 13/7", accepted, rejected)
	}
}

func TestErrorNameParity(t *testing.T) {
	if ErrCodeInvalidName != "CRYPTO_CODE_INVALID" || ErrCodeInvalidValue != -21 {
		t.Fatalf("error parity drift: %s / %d", ErrCodeInvalidName, ErrCodeInvalidValue)
	}
}

// 五种分隔符是**唯一**允许静默丢弃的字符；其它空白必须拒绝。
func TestNormalizeOnlyFiveSeparators(t *testing.T) {
	// 五种分隔符都能被丢弃。
	for _, in := range []string{"K-7QF", "K 7QF", "K\t7QF", "K\r7QF", "K\n7QF"} {
		got, err := NormalizeCode(in)
		if err != nil || got != "K7QF" {
			t.Fatalf("%q: got %q err=%v", in, got, err)
		}
	}
	// 其它空白/控制字符不是分隔符 → 拒绝（不能静默吃掉）。
	for _, in := range []string{"K\v7QF", "K\f7QF", "K\u00a07QF", "K\u30007QF", "K7QF\u200b"} {
		if got, err := NormalizeCode(in); err == nil {
			t.Fatalf("%q: got %q, want rejection", in, got)
		}
	}
}

// 裁决 D3 ④：5 位输入必须整体拒绝，不得截断成 4 位。
func TestNormalizeNeverTruncates(t *testing.T) {
	for _, in := range []string{"K7QF0", "K7QFU", "K7QF!", "K7QF码", "0K7QF"} {
		if got, err := NormalizeCode(in); err == nil {
			t.Fatalf("%q: got %q, want rejection (no truncation)", in, got)
		}
	}
}
