package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestChallengeMessageIsStable(t *testing.T) {
	in := ChallengeInput{
		Purpose:   "session",
		Code:      "AWQW",
		PubKey:    []byte{0x04, 0x01, 0x02},
		Nonce:     []byte{0xaa, 0xbb},
		ExpiresAt: time.Date(2026, 11, 2, 21, 30, 0, 0, time.UTC),
	}
	msg := string(BuildChallengeMessage(in))
	want := "YANSHU-CHALLENGE/1\n" +
		"purpose=session\n" +
		"code=AWQW\n" +
		"pubkey=" + B64.EncodeToString(in.PubKey) + "\n" +
		"nonce=" + B64.EncodeToString(in.Nonce) + "\n" +
		"expiresAt=2026-11-02T21:30:00Z\n" +
		"context=" // 末行不带换行
	if msg != want {
		t.Fatalf("message mismatch:\n got: %q\nwant: %q", msg, want)
	}
}

func TestChallengeMessageBindsContext(t *testing.T) {
	base := ChallengeInput{
		Purpose:   "nickname",
		Code:      "AWQW",
		PubKey:    []byte{0x04},
		Nonce:     []byte{0x01},
		ExpiresAt: time.Unix(1000, 0).UTC(),
	}
	a := base
	a.Context = []byte("alice")
	b := base
	b.Context = []byte("mallory")
	if bytes.Equal(BuildChallengeMessage(a), BuildChallengeMessage(b)) {
		t.Fatal("nickname context does not change the signed message")
	}
}

func TestTokenHashing(t *testing.T) {
	token, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 40 {
		t.Fatalf("token too short: %q", token)
	}
	sum := sha256.Sum256([]byte(token))
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(hash) {
		t.Fatal("token hash mismatch")
	}
	other, _, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if other == token {
		t.Fatal("token reuse")
	}
}

func TestVerifierModes(t *testing.T) {
	pub := make([]byte, 65)
	pub[0] = 0x04
	msg := []byte("m")
	sig := []byte{0x30, 0x00}

	deny, err := NewVerifier(ModeStubDeny, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := deny.Verify(pub, msg, sig); err != ErrUnavailable {
		t.Fatalf("stub-deny = %v, want ErrUnavailable", err)
	}

	allow, err := NewVerifier(ModeStubAllow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := allow.Verify(pub, msg, sig); err != nil {
		t.Fatalf("stub-allow rejected valid shape: %v", err)
	}
	if err := allow.Verify([]byte{0x04}, msg, sig); err == nil {
		t.Fatal("stub-allow accepted malformed public key")
	}
	if err := allow.Verify(pub, nil, sig); err == nil {
		t.Fatal("stub-allow accepted empty message")
	}

	sm2, err := NewVerifier(ModeSM2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sm2.Verify(pub, msg, sig); err != ErrUnavailable {
		t.Fatalf("sm2 placeholder = %v, want ErrUnavailable", err)
	}

	if _, err := NewVerifier("bogus", nil); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown mode error = %v", err)
	}
}
