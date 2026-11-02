package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// 逐字节核对 API.md §1.3 的 SIG_INPUT 构造。
func TestBuildSignInput(t *testing.T) {
	nonce := make([]byte, 32)
	fields := []byte("AWQW")
	got := BuildSignInput(0x05, nonce, fields)
	wantPrefix := "YSAUTH1"
	if string(got[:7]) != wantPrefix {
		t.Fatalf("prefix = %q", string(got[:7]))
	}
	if got[7] != 0x05 {
		t.Fatalf("purpose byte = %#x", got[7])
	}
	if len(got) != 7+1+32+4 {
		t.Fatalf("length = %d", len(got))
	}
	if string(got[40:]) != "AWQW" {
		t.Fatalf("fields = %q", got[40:])
	}
}

func TestRegisterFields(t *testing.T) {
	pub := make([]byte, 65)
	pub[0] = 0x04
	fields, err := RegisterFields("AWQW", pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4+65 || string(fields[:4]) != "AWQW" || fields[4] != 0x04 {
		t.Fatalf("unexpected fields: %x", fields)
	}
	if _, err := RegisterFields("AWQ", pub); err == nil {
		t.Fatal("short code accepted")
	}
	if _, err := RegisterFields("AWQW", pub[:64]); err == nil {
		t.Fatal("short public key accepted")
	}
}

func TestNicknameUpdateFieldsHasU16Length(t *testing.T) {
	fields, err := NicknameUpdateFields("AWQW", "阿雁")
	if err != nil {
		t.Fatal(err)
	}
	// CODE(4) ‖ u16be(len=6) ‖ UTF-8
	if len(fields) != 4+2+6 {
		t.Fatalf("length = %d", len(fields))
	}
	if fields[4] != 0x00 || fields[5] != 0x06 {
		t.Fatalf("length prefix = %x", fields[4:6])
	}
	if string(fields[6:]) != "阿雁" {
		t.Fatalf("nickname = %q", string(fields[6:]))
	}
}

func TestTransferCreateFields(t *testing.T) {
	sm3 := make([]byte, 32)
	sm3[0] = 0xde
	fields, err := TransferCreateFields("AWQW", "WTJF", 5, 1048576, 1, 485, sm3)
	if err != nil {
		t.Fatal(err)
	}
	// 4+4+8+4+4+4+32 = 60
	if len(fields) != 60 {
		t.Fatalf("length = %d", len(fields))
	}
	if string(fields[:4]) != "AWQW" || string(fields[4:8]) != "WTJF" {
		t.Fatalf("codes = %q", string(fields[:8]))
	}
	if hex.EncodeToString(fields[8:16]) != "0000000000000005" {
		t.Fatalf("plaintext_size = %x", fields[8:16])
	}
	if hex.EncodeToString(fields[16:20]) != "00100000" || hex.EncodeToString(fields[20:24]) != "00000001" {
		t.Fatalf("chunk_size/count = %x", fields[16:24])
	}
	if hex.EncodeToString(fields[24:28]) != "000001e5" {
		t.Fatalf("prelude_len = %x", fields[24:28])
	}
	if fields[28] != 0xde {
		t.Fatalf("prelude_sm3 not appended: %x", fields[28:])
	}
}

func TestTransferIDFields(t *testing.T) {
	id := strings.Repeat("a", 32)
	fields, err := TransferRevokeFields("AWQW", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4+32 || string(fields[4:]) != id {
		t.Fatalf("unexpected fields: %q", fields)
	}
	if _, err := TransferAckFields("AWQW", "short"); err == nil {
		t.Fatal("non-hex transfer id accepted")
	}
	if _, err := TransferAckFields("AWQW", strings.Repeat("Z", 32)); err == nil {
		t.Fatal("uppercase transfer id accepted")
	}
}

func TestInboxAndWSHelloFields(t *testing.T) {
	for _, f := range []func(string) ([]byte, error){InboxListFields, WSHelloFields} {
		fields, err := f("AWQW")
		if err != nil {
			t.Fatal(err)
		}
		if len(fields) != 4 || string(fields) != "AWQW" {
			t.Fatalf("fields = %q", fields)
		}
	}
}

func TestUploadTokenIsDeterministic(t *testing.T) {
	issuer, err := NewTokenIssuer([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	t1, err := issuer.UploadToken(id)
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := issuer.UploadToken(id)
	if t1 != t2 {
		t.Fatal("upload token is not deterministic; idempotent replay cannot return the same token")
	}
	other, _ := issuer.UploadToken(strings.Repeat("c", 32))
	if other == t1 {
		t.Fatal("upload token does not depend on transfer id")
	}
	if !issuer.Validate(t1, id, UploadTokenHash(t1)) {
		t.Fatal("validate failed for its own token")
	}
	if issuer.Validate(t1, strings.Repeat("c", 32), UploadTokenHash(t1)) {
		t.Fatal("validate accepted a token for another transfer")
	}
	if issuer.Validate(other, id, UploadTokenHash(t1)) {
		t.Fatal("validate accepted a different token")
	}
	if issuer.Validate("", id, UploadTokenHash(t1)) {
		t.Fatal("empty token accepted")
	}
	// 轮换密钥后，旧 token 必须失效（裁决 G5）。
	rotated, _ := NewTokenIssuer([]byte("rotated-secret"))
	if rotated.Validate(t1, id, UploadTokenHash(t1)) {
		t.Fatal("token still valid after secret rotation")
	}
}

// 契约 G5：upload_token = base64url(HMAC-SHA256(TOKEN_SECRET, "yanshu/upload-token/v1"‖transfer_id))
func TestUploadTokenMatchesContract(t *testing.T) {
	const secret = "test-secret"
	id := strings.Repeat("b", 32)
	issuer, err := NewTokenIssuer([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	got, err := issuer.UploadToken(id)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("yanshu/upload-token/v1"))
	mac.Write([]byte(id))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("upload token = %q, want %q", got, want)
	}
}

func TestNewID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 32 {
		t.Fatalf("id = %q", id)
	}
	for _, r := range id {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("id contains non-hex char %q", r)
		}
	}
	other, _ := NewID()
	if id == other {
		t.Fatal("id collision")
	}
}
