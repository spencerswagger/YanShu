//! P0 锁死断言：**原生编译下的 `ys_user_code`（就是 wasm 导出的那个函数）**
//! 与 `code::from_public_key` 必须给出同一个码，且等于契约 §15.1 的 `AWQW`。
//!
//! 这里调用的是 `#[no_mangle] extern "C"` 的 FFI 函数本身——wasm 产物由同一份
//! 源码、同一个函数导出（没有任何 `cfg` 分叉）；wasm 侧由
//! `scripts/wasm-smoke/smoke.mjs` 用 `vectors/user-code-vectors.json` 再断言一次。

use yanshu_sm::code;
use yanshu_sm::ffi::{ys_check_symbol, ys_check_symbol_wire, ys_user_code, ys_user_code_wire};

const KEYS: &[(&str, &str, &str)] = &[
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
fn ffi_user_code_matches_contract_and_native() {
    for (pub65_hex, want_code, want_check) in KEYS {
        let v = unhex(pub65_hex);
        assert_eq!(v.len(), 65);
        assert_eq!(v[0], 0x04);

        // 64 字节 X‖Y 入参（ABI 口径）与 65 字节 wire 入参（_wire）都必须同值
        let mut out = [0u8; 4];
        unsafe {
            assert_eq!(ys_user_code(v[1..].as_ptr(), out.as_mut_ptr()), 0);
        }
        assert_eq!(
            core::str::from_utf8(&out).unwrap(),
            *want_code,
            "ys_user_code(64B) 与契约样例不一致"
        );

        let mut out_wire = [0u8; 4];
        unsafe {
            assert_eq!(ys_user_code_wire(v.as_ptr(), out_wire.as_mut_ptr()), 0);
        }
        assert_eq!(
            core::str::from_utf8(&out_wire).unwrap(),
            *want_code,
            "ys_user_code_wire(65B) 与契约样例不一致"
        );

        // 纯 Rust 路径（wasm 里也是这一份）必须一致
        let mut pub65 = [0u8; 65];
        pub65.copy_from_slice(&v);
        assert_eq!(code::from_public_key(&pub65), *want_code);

        // 校验字符两个入口也必须一致
        let mut s64 = [0u8; 1];
        let mut s65 = [0u8; 1];
        unsafe {
            assert_eq!(ys_check_symbol(v[1..].as_ptr(), s64.as_mut_ptr()), 0);
            assert_eq!(ys_check_symbol_wire(v.as_ptr(), s65.as_mut_ptr()), 0);
        }
        let want_char = want_check.chars().next().unwrap();
        assert_eq!(s64[0] as char, want_char);
        assert_eq!(s65[0] as char, want_char);
        assert_eq!(code::check_symbol(&pub65), want_char);
    }
}

/// 传错宽度（65 字节缓冲喂 64 字节接口）会得到不同的码——把这条"事故本身"固化，
/// 提醒后来者：入参宽度必须 64。合法调用不会有这个值。
#[test]
fn wrong_width_is_detectable_and_documented() {
    let v = unhex(KEYS[0].0);
    let mut out = [0u8; 4];
    // 把 65 字节缓冲当 64 字节用：内核读 `0x04‖X[0..63]` 再补 0x04，必然不是 AWQW
    unsafe {
        assert_eq!(ys_user_code(v.as_ptr(), out.as_mut_ptr()), 0);
    }
    assert_ne!(core::str::from_utf8(&out).unwrap(), "AWQW");
}
