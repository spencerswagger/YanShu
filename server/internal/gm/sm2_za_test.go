package gm

// ZA 常量锚点：比"双方都验过一条签名"更强的定位能力 —— 签名对不上时，先看 ZA 是否相等，
// 就能区分是 ZA（ENTL/ID/坐标顺序）算错，还是 SIG_INPUT 拼错。
//
// 常量来源：端侧 `crypto/sm/tests/sig_conventions.rs`（`feat/endcrypto-wasm`），
// 已与 GmSSL `sm2_compute_z` 逐字节核对。被测公钥是契约 §15.1 的 `PB_S`。

import (
	"encoding/hex"
	"testing"
)

const (
	// PB_S：CRYPTO-PACK §15.1 的发送方公钥（65 字节未压缩）。
	pbSHex = "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1" +
		"16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d"

	// ZA(PB_S)：ID="1234567812345678"、ENTL=0x0080、a/b/G/P 全按大端拼接。
	pbSZAHex = "feb6483dfe16f70dc0f8f732b286c606a4c432cf093d2445ecdea3c19da4b75b"
)

func TestZAConstantForPB_S(t *testing.T) {
	pub, err := hex.DecodeString(pbSHex)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ParseSM2PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(sm2ZA(pt, DefaultSM2ID))
	if got != pbSZAHex {
		t.Fatalf("ZA(PB_S) mismatch\n got %s\nwant %s\n"+
			"（先查 ENTL 是否写成小端 8000、ID 是否 16 字节、坐标是否 X‖Y 顺序）", got, pbSZAHex)
	}
}

// 换 userID 必须改变 ZA —— 证明 ZA 真的把 ID 绑进去了。
func TestZADependsOnUserID(t *testing.T) {
	pub, _ := hex.DecodeString(pbSHex)
	pt, err := ParseSM2PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	other := hex.EncodeToString(sm2ZA(pt, "1234567812345679"))
	if other == pbSZAHex {
		t.Fatal("ZA did not change when userID changed")
	}
}
