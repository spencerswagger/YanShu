package auth

// 用端侧的 SIG_INPUT 样例核对服务端构造（docs/API.md §1.3）。
//
// 样例来源：`crypto/sm/vectors/sm2-verify-vectors.json` 的 `sig_input_samples`
// （7 种 PURPOSE 各一条，分支 feat/endcrypto-wasm）。每条按结构拆开后用本地构造器
// 重拼，要求逐字节相同。

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

type sigInputSample struct {
	Purpose  string `json:"purpose"`
	Len      int    `json:"len"`
	SigInput string `json:"sig_input"`
}

func loadSigInputSamples(t *testing.T) []sigInputSample {
	t.Helper()
	raw, err := os.ReadFile("../gm/testdata/sm2-verify-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Samples []sigInputSample `json:"sig_input_samples"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc.Samples
}

func TestSigInputMatchesVectors(t *testing.T) {
	samples := loadSigInputSamples(t)
	if len(samples) != 7 {
		t.Fatalf("expected 7 purpose samples, got %d", len(samples))
	}

	for _, s := range samples {
		raw, err := hex.DecodeString(s.SigInput)
		if err != nil {
			t.Fatalf("%s: hex: %v", s.Purpose, err)
		}
		if len(raw) != s.Len {
			t.Fatalf("%s: len %d != %d", s.Purpose, len(raw), s.Len)
		}
		nonce := raw[8:40]
		fields := raw[40:]

		var built []byte
		var purposeCode byte
		switch s.Purpose {
		case "REGISTER":
			purposeCode = spec.PurposeCodeRegister
			built, err = RegisterFields(string(fields[:4]), fields[4:])
		case "NICKNAME_UPDATE":
			purposeCode = spec.PurposeCodeNicknameUpdate
			n := int(binary.BigEndian.Uint16(fields[4:6]))
			built, err = NicknameUpdateFields(string(fields[:4]), string(fields[6:6+n]))
		case "TRANSFER_CREATE":
			purposeCode = spec.PurposeCodeTransferCreate
			built, err = TransferCreateFields(
				string(fields[:4]), string(fields[4:8]),
				binary.BigEndian.Uint64(fields[8:16]),
				binary.BigEndian.Uint32(fields[16:20]),
				binary.BigEndian.Uint32(fields[20:24]),
				binary.BigEndian.Uint32(fields[24:28]),
				fields[28:60],
			)
		case "TRANSFER_REVOKE":
			purposeCode = spec.PurposeCodeTransferRevoke
			built, err = TransferRevokeFields(string(fields[:4]), string(fields[4:36]))
		case "TRANSFER_ACK":
			purposeCode = spec.PurposeCodeTransferAck
			built, err = TransferAckFields(string(fields[:4]), string(fields[4:36]))
		case "INBOX_LIST":
			purposeCode = spec.PurposeCodeInboxList
			built, err = InboxListFields(string(fields[:4]))
		case "WS_HELLO":
			purposeCode = spec.PurposeCodeWSHello
			built, err = WSHelloFields(string(fields[:4]))
		default:
			t.Fatalf("unexpected sample purpose %q", s.Purpose)
		}
		if err != nil {
			t.Fatalf("%s fields: %v", s.Purpose, err)
		}
		res := BuildSignInput(purposeCode, nonce, built)
		if string(res) != string(raw) {
			t.Fatalf("%s SIG_INPUT mismatch\n got %x\nwant %x", s.Purpose, res, raw)
		}
	}
}

// 最关键的一条：调用方传的是 SIG_INPUT **原文**，不是它的 SM3。
// 用同一把私钥分别对原文与 SM3(原文) 签名，只有原文那版能验过。
func TestVerifierTakesRawInputNotDigest(t *testing.T) {
	v := newTestVerifier(t)
	k := kernelCall{v}
	priv, err := gm.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub65 := append([]byte{0x04}, k.pubkey(t, priv)...)

	input := BuildSignInput(spec.PurposeCodeInboxList, make([]byte, 32), []byte("AWQW"))
	rawSig := k.signDER(t, priv, input)
	sum := gm.SM3(input)
	digest := sum[:]
	digestSig := k.signDER(t, priv, digest)

	if err := v.Verify(pub65, input, rawSig); err != nil {
		t.Fatalf("raw SIG_INPUT rejected: %v", err)
	}
	if err := v.Verify(pub65, digest, rawSig); err == nil {
		t.Fatal("signature over raw input accepted when verifying the digest (or vice versa)")
	}
	if err := v.Verify(pub65, input, digestSig); err == nil {
		t.Fatal("signature over SM3(input) accepted for raw input — caller must not pre-hash")
	}
}
