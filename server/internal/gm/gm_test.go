package gm

import (
	"encoding/hex"
	"testing"
)

// 向量来自 GB/T 32905-2016 附录 A。
func TestSM3Vectors(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		{"abc", "abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{
			"abcd*16",
			"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
			"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
		},
	}
	for _, c := range cases {
		sum := SM3([]byte(c.in))
		got := hex.EncodeToString(sum[:])
		if got != c.want {
			t.Errorf("%s: SM3 = %s, want %s", c.name, got, c.want)
		}
	}
}

// 增量写必须与一次性写结果相同（覆盖 Sum 的填充边界）。
func TestSM3Incremental(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	want := SM3(data)
	for _, chunk := range []int{1, 7, 55, 56, 63, 64, 65, 127} {
		d := NewSM3()
		for i := 0; i < len(data); i += chunk {
			end := i + chunk
			if end > len(data) {
				end = len(data)
			}
			if _, err := d.Write(data[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		var got [32]byte
		copy(got[:], d.Sum(nil))
		if got != want {
			t.Fatalf("chunk=%d mismatch", chunk)
		}
	}
}

// CRYPTO-PACK §15.1 的样例：由 SENDER_PUB 派生的码是 AWQW、校验字符 X。
func TestDeriveCodeVector(t *testing.T) {
	pubHex := "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1" +
		"16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d"
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := SM3(pub)
	digest := hex.EncodeToString(digestBytes[:])
	const wantDigest = "572fcd0bf0efa3d2e0795a54408138ac5b4c4c0f43f8a219631b14b014428562"
	if digest != wantDigest {
		t.Fatalf("SM3(pub) = %s, want %s", digest, wantDigest)
	}
	if got := DeriveCode(pub); got != "AWQW" {
		t.Fatalf("DeriveCode = %s, want AWQW", got)
	}
	if got := CheckChar(pub); got != 'X' {
		t.Fatalf("CheckChar = %c, want X", got)
	}
}

// 易错点自查：码派生必须覆盖 65 字节公钥（含 0x04），不能用 64 字节 X‖Y。
func TestDeriveCodeUses65ByteKey(t *testing.T) {
	pubHex := "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1" +
		"16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d"
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	if DeriveCode(pub) != "AWQW" {
		t.Fatalf("65-byte derive = %s, want AWQW", DeriveCode(pub))
	}
	if DeriveCode(pub[1:]) == "AWQW" {
		t.Fatal("64-byte body must derive a different code (the 0x04 prefix is part of the hash)")
	}
}

func TestNormalizeCode(t *testing.T) {
	ok := map[string]string{
		"AWQW":   "AWQW",
		"awqw":   "AWQW",
		" awqw ": "AWQW",
		"AW-QW":  "AWQW",
		"o1l2":   "0112", // O→0、I→1、L→1、I 由 1 保持
		"0O0O":   "0000",
	}
	for in, want := range ok {
		got, err := NormalizeCode(in)
		if err != nil {
			t.Errorf("NormalizeCode(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}

	// 裁决 D3：禁止 5 位截断与猜测性纠错，所以 `AWQW-X` 这类必须被拒。
	bad := []string{"", "ABC", "ABCDE1", "AUQW", "AWQ!", "<script>", "AWQW-X", "AWQWM"}
	for _, in := range bad {
		if got, err := NormalizeCode(in); err == nil {
			t.Errorf("NormalizeCode(%q) = %q, want error", in, got)
		}
	}
}

// 归一化必须幂等（裁决 D3 ①）。
func TestNormalizeCodeIdempotent(t *testing.T) {
	inputs := []string{"AWQW", "awqw", " aw-qw ", "o1l2", "0O0O", "zzzz", "Zz-Zz"}
	for _, in := range inputs {
		once, err := NormalizeCode(in)
		if err != nil {
			t.Fatalf("NormalizeCode(%q): %v", in, err)
		}
		twice, err := NormalizeCode(once)
		if err != nil {
			t.Fatalf("NormalizeCode(%q) second pass: %v", once, err)
		}
		if once != twice {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

func TestIsNormalizedCode(t *testing.T) {
	for _, in := range []string{"AWQW", "0000", "ZZZZ"} {
		if !IsNormalizedCode(in) {
			t.Errorf("IsNormalizedCode(%q) = false", in)
		}
	}
	for _, in := range []string{"awqw", "AWQ", "UWQA", "AWQWX", "AWQ-"} {
		if IsNormalizedCode(in) {
			t.Errorf("IsNormalizedCode(%q) = true", in)
		}
	}
}
