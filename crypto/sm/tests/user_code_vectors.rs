//! 用户码跨实现锚点：原生实现必须与 `vectors/user-code-vectors.json` 逐条相同。
//!
//! 这些期望值是**冻结值**（含契约 §15.1 的 `AWQW`/`X`）；wasm 侧由
//! `scripts/wasm-smoke/smoke.mjs` 用同一个 JSON 断言，两边任何一侧改动都会红。

use yanshu_sm::code;

const VECTORS: &[(&str, &str, &str)] = &[
    // (pub65 hex, code, check)
    (
        "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d",
        "AWQW",
        "X",
    ),
    (
        "049bb03101c716d29cb96951d052a26dbf5def45eae46845694faa627ce8544cec07dee9d5bb614e2e0806361912a78d31cda307c3dddd9a2e58559ee8d22f59f5",
        "CBJ2",
        "K",
    ),
    (
        "0407a164e6cb27f81e401d3edbf2cebfcfbe1385494d008d4d24ae6a5857ad9fccbf2b8c70bec1e28c66d6cf0cc4100b0fa16cf0b784c326f9fbcdcebc9ce4be73",
        "J6AW",
        "R",
    ),
    (
        "04e0b763ca87e6e3384c981723a12bd589272db40dd93449a0598bc7844922aa7c28dcc6408acf2c25d9da13baf9f4d903044f2d510797646bb486824747f3921d",
        "GCVB",
        "T",
    ),
    (
        "0401ed139cfa3ce980de464b0404df213715b0f9dff61ddc2d848aac325318dbe36522f37e15feca755be1f9b49f685dfc296f18d56cb9c78ea93d1debfbb00896",
        "STZF",
        "C",
    ),
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn native_matches_frozen_vectors() {
    for (pub65_hex, want_code, want_check) in VECTORS {
        let v = unhex(pub65_hex);
        assert_eq!(v.len(), 65);
        let mut pub65 = [0u8; 65];
        pub65.copy_from_slice(&v);
        assert_eq!(pub65[0], 0x04);

        let code = code::from_public_key(&pub65);
        assert_eq!(
            &code,
            want_code,
            "码不一致（pub65 前 8 字节 {:02x?}）",
            &pub65[..8]
        );
        assert_eq!(code::check_symbol(&pub65).to_string(), *want_check);

        // 64 字节 X‖Y 走同一条路（内核内部补 0x04）必须同值
        let mut x = [0u8; 64];
        x.copy_from_slice(&pub65[1..]);
        let mut rebuilt = [0u8; 65];
        rebuilt[0] = 0x04;
        rebuilt[1..].copy_from_slice(&x);
        assert_eq!(code::from_public_key(&rebuilt), code);
    }
}
