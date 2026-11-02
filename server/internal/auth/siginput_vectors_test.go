package auth

// 用端侧的 SIG_INPUT 样例核对服务端构造（docs/API.md §1.3）。
//
// 样例来源：`crypto/sm/vectors/sm2-verify-vectors.json` 的 `sig_input_samples`
// （分支 feat/endcrypto-wasm，commit c2c7962）。三种用途各自给出完整字节，
// 这里按结构拆出来后用本地构造器重拼，要求逐字节相同。

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

type sigInputSample struct {
	Purpose  string `json:"purpose"`
	PurposeB string `json:"purpose_byte"`
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
	for _, s := range loadSigInputSamples(t) {
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
		switch s.Purpose {
		case "REGISTER":
			code := string(fields[:4])
			pub := fields[4:]
			built, err = RegisterFields(code, pub)
			if err != nil {
				t.Fatalf("REGISTER fields: %v", err)
			}
			res := BuildSignInput(spec.PurposeCodeRegister, nonce, built)
			if string(res) != string(raw) {
				t.Fatalf("REGISTER SIG_INPUT mismatch\n got %x\nwant %x", res, raw)
			}

		case "NICKNAME_UPDATE":
			code := string(fields[:4])
			n := int(binary.BigEndian.Uint16(fields[4:6]))
			nickname := string(fields[6 : 6+n])
			built, err = NicknameUpdateFields(code, nickname)
			if err != nil {
				t.Fatalf("NICKNAME_UPDATE fields: %v", err)
			}
			res := BuildSignInput(spec.PurposeCodeNicknameUpdate, nonce, built)
			if string(res) != string(raw) {
				t.Fatalf("NICKNAME_UPDATE SIG_INPUT mismatch\n got %x\nwant %x", res, raw)
			}

		case "TRANSFER_CREATE":
			sender := string(fields[:4])
			recipient := string(fields[4:8])
			size := binary.BigEndian.Uint64(fields[8:16])
			chunkSize := binary.BigEndian.Uint32(fields[16:20])
			chunkCount := binary.BigEndian.Uint32(fields[20:24])
			preludeLen := binary.BigEndian.Uint32(fields[24:28])
			sm3 := fields[28:60]
			built, err = TransferCreateFields(sender, recipient, size, chunkSize, chunkCount, preludeLen, sm3)
			if err != nil {
				t.Fatalf("TRANSFER_CREATE fields: %v", err)
			}
			res := BuildSignInput(spec.PurposeCodeTransferCreate, nonce, built)
			if string(res) != string(raw) {
				t.Fatalf("TRANSFER_CREATE SIG_INPUT mismatch\n got %x\nwant %x", res, raw)
			}

		default:
			t.Fatalf("unexpected sample purpose %q", s.Purpose)
		}
	}
}
