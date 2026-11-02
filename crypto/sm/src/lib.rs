//! 雁书 YanShu · 端侧国密内核（Rust，自研，无外部密码库依赖）。
//!
//! 模块：
//! * [`sm3`] SM3 杂凑 + HMAC-SM3
//! * [`sm4`] SM4 分组密码
//! * [`gcm`] SM4-GCM（128 位 tag）
//! * [`hkdf`] HKDF-SM3
//! * [`sm2`] SM2 密钥对 / 加密（C1C3C2）/ 解密 / 签名 / 验签
//! * [`pack`] 加密包 v1 打包与严格解包
//! * [`code`] 4 位 Crockford Base32 用户码
//! * [`ffi`] raw C ABI（wasm32，供 Web 侧直接调用，不引 wasm-bindgen）
//!
//! 纯 Rust API 是宿主侧单测入口；wasm 只是另一种调用方式。

// 密码学实现里按 limb / 字下标循环更贴近规范写法，特此放开该 lint。
#![allow(clippy::needless_range_loop)]

pub mod bigint;
pub mod code;
pub mod der;
pub mod error;
pub mod ffi;
pub mod gcm;
pub mod hkdf;
pub mod pack;
pub mod pack_rune_v1;
pub mod rng;
pub mod sm2;
pub mod sm3;
pub mod sm4;

pub use error::{Error, Result};

/// 内核版本（C ABI `ys_version` 同源）。
pub const VERSION: u32 = 0x0001_0000;
