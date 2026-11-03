package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// 契约 §1.3：合法上限 109 = 7(YSAUTH1)+1(PURPOSE)+32(NONCE)+69(最长字段串 REGISTER)。
// 七种 PURPOSE 各自的最大长度都必须 ≤ 109。
func TestPerPurposeSIGInputLengths(t *testing.T) {
	nonce := make([]byte, 32)
	pub := append([]byte{0x04}, make([]byte, 64)...)
	nickname := strings.Repeat("a", 32) // 昵称上限 32 字节

	cases := []struct {
		name    string
		build   func() ([]byte, error)
		wantLen int
	}{
		{"REGISTER", func() ([]byte, error) { return RegisterFields("AWQW", pub) }, 109},
		{"NICKNAME_UPDATE", func() ([]byte, error) { return NicknameUpdateFields("AWQW", nickname) }, 78},
		{"TRANSFER_CREATE", func() ([]byte, error) {
			return TransferCreateFields("AWQW", "X2EH", 1<<20, 1024, 1024, 100, bytes32())
		}, 100},
		{"TRANSFER_REVOKE", func() ([]byte, error) { return TransferRevokeFields("AWQW", hex32()) }, 76},
		{"TRANSFER_ACK", func() ([]byte, error) { return TransferAckFields("AWQW", hex32()) }, 76},
		{"INBOX_LIST", func() ([]byte, error) { return InboxListFields("AWQW") }, 44},
		{"WS_HELLO", func() ([]byte, error) { return WSHelloFields("AWQW") }, 44},
	}
	for _, c := range cases {
		fields, err := c.build()
		if err != nil {
			t.Fatalf("%s fields: %v", c.name, err)
		}
		in := BuildSignInput(0x01, nonce, fields)
		if len(in) != c.wantLen {
			t.Fatalf("%s SIG_INPUT len = %d, want %d", c.name, len(in), c.wantLen)
		}
		if len(in) > MaxLegitSIGInputLen {
			t.Fatalf("%s exceeds the 109-byte legit limit", c.name)
		}
	}
}

// 超过 512（防御性 DoS 门）→ ErrSIGInputTooLong，而不是普通 ErrBadInput。
func TestSIGInputTooLong(t *testing.T) {
	v := newTestVerifier(t)
	pub65 := append([]byte{0x04}, make([]byte, 64)...)
	big := make([]byte, MaxSIGInputLen+1)
	if err := v.Verify(pub65, big, make([]byte, 71)); !errors.Is(err, ErrSIGInputTooLong) {
		t.Fatalf("want ErrSIGInputTooLong, got %v", err)
	}
	// 109~512 之间仍走密码学（这里签名是垃圾 → 签名类错误，而不是 TOO_LONG）。
	mid := make([]byte, MaxLegitSIGInputLen+1)
	err := v.Verify(pub65, mid, make([]byte, 71))
	if errors.Is(err, ErrSIGInputTooLong) {
		t.Fatalf("400-byte input must not be TOO_LONG")
	}
}

// 109 字节的 REGISTER 输入必须能正常验签（不是被长度门挡掉）。
func TestRegisterSIGInputVerifies(t *testing.T) {
	v := newTestVerifier(t)
	k := kernelCall{v}
	priv, err := gm.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub65 := append([]byte{0x04}, k.pubkey(t, priv)...)
	if len(pub65) != 65 {
		t.Fatalf("pub len %d", len(pub65))
	}
	fields, err := RegisterFields("AWQW", pub65)
	if err != nil {
		t.Fatal(err)
	}
	in := BuildSignInput(spec.PurposeCodeRegister, make([]byte, 32), fields)
	if len(in) != MaxLegitSIGInputLen {
		t.Fatalf("register sig_input = %d, want %d", len(in), MaxLegitSIGInputLen)
	}
	if err := v.Verify(pub65, in, k.signDER(t, priv, in)); err != nil {
		t.Fatalf("109-byte register input rejected: %v", err)
	}
}

func bytes32() []byte { return make([]byte, 32) }
func hex32() string   { return strings.Repeat("0", 32) }
