//! 用户码（契约 §3.4）：4 位 Crockford Base32 + 可选第 5 位校验字符。
//!
//! * 输入公钥是**未压缩 65 字节**（`0x04 ‖ X ‖ Y`）。
//! * `码 = Crockford32(SM3(PUB))` 的前 4 个符号，即取摘要**前 20 bit**
//!   （大端位序、每 5 bit 一个符号）。
//! * 校验字符：把前 20 bit 当无符号整数 `V`，取 `CHECK_ALPHA[V mod 37]`；
//!   UI 展示为 `CODE-CHECK`，**不占那 4 位**。
//! * 输入归一化：大写 → 去 `-`/空白 → `O→0`、`I/L→1` → 必须正好 4 位且都在字母表内（`U` 非法）。
//! * 撞码：客户端重新生成密钥对重试（不自动加长）。

use crate::error::{Error, Result};
use crate::rng::Rng;
use crate::sm2::{self, KeyPair};
use crate::sm3::sm3;

/// 32 符号的 Crockford 字母表。
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 37 符号的校验字母表（契约 §3.4）。
pub const CHECK_ALPHABET: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";
/// 用户码长度
pub const CODE_LEN: usize = 4;
/// 未压缩公钥长度
pub const PUBLIC_KEY_LEN: usize = 65;

fn symbol_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&x| x == c).map(|v| v as u8)
}

/// 摘要前 20 bit → 4 个符号。
fn encode_first4(digest: &[u8; 32]) -> [u8; CODE_LEN] {
    let mut out = [0u8; CODE_LEN];
    for (k, slot) in out.iter_mut().enumerate() {
        let mut v = 0u8;
        for j in 0..5 {
            let bit_index = k * 5 + j;
            let bit = (digest[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
            v = (v << 1) | bit;
        }
        *slot = ALPHABET[v as usize];
    }
    out
}

/// 前 20 bit 的无符号整数值（校验字符用）。
fn first20_value(digest: &[u8; 32]) -> u32 {
    ((digest[0] as u32) << 12) | ((digest[1] as u32) << 4) | ((digest[2] as u32) >> 4)
}

/// 由未压缩公钥（65 字节）派生 4 位用户码。
pub fn from_public_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> String {
    let digest = sm3(public_key);
    let code = encode_first4(&digest);
    String::from_utf8(code.to_vec()).expect("alphabet is ascii")
}

/// 由未压缩公钥派生校验字符（第 5 位，仅本地纠错用）。
pub fn check_symbol(public_key: &[u8; PUBLIC_KEY_LEN]) -> char {
    let digest = sm3(public_key);
    CHECK_ALPHABET[(first20_value(&digest) % 37) as usize] as char
}

/// 由码字符串（4 位）算校验字符：需要先把码还原成 20 bit 值。
pub fn check_symbol_for_code(code: &str) -> Result<char> {
    let normalized = normalize(code)?;
    let mut value: u32 = 0;
    for c in normalized.bytes() {
        value = (value << 5) | symbol_value(c).ok_or(Error::BadCode)? as u32;
    }
    Ok(CHECK_ALPHABET[(value % 37) as usize] as char)
}

/// 输入规范化。
pub fn normalize(input: &str) -> Result<String> {
    let mut out = String::with_capacity(CODE_LEN);
    for ch in input.chars() {
        let c = match ch {
            '-' | ' ' | '\t' | '\n' | '\r' => continue,
            _ => ch.to_ascii_uppercase(),
        };
        let c = match c {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if (c as u32) > 0x7f {
            return Err(Error::BadCode);
        }
        let cu = c as u8;
        if symbol_value(cu).is_none() {
            return Err(Error::BadCode);
        }
        out.push(c);
        if out.len() > CODE_LEN {
            return Err(Error::BadCode);
        }
    }
    if out.len() != CODE_LEN {
        return Err(Error::BadCode);
    }
    Ok(out)
}

/// 是否合法（规范化后）。
pub fn is_valid(input: &str) -> bool {
    normalize(input).is_ok()
}

/// 生成身份并处理撞码：`is_taken` 返回 true 时重新生成密钥对再试。
pub fn generate_until_free(
    rng: &mut impl Rng,
    max_attempts: usize,
    mut is_taken: impl FnMut(&str) -> bool,
) -> Result<(KeyPair, String)> {
    for _ in 0..max_attempts.max(1) {
        let kp = sm2::keygen(rng);
        let mut pub65 = [0u8; PUBLIC_KEY_LEN];
        pub65[0] = 0x04;
        pub65[1..].copy_from_slice(&kp.public_key);
        let code = from_public_key(&pub65);
        if !is_taken(&code) {
            return Ok((kp, code));
        }
    }
    Err(Error::CodeExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeedRng;

    /// 契约 §15.1 的发送方公钥 → `AWQW` / `X`
    const PB_S: [u8; 65] = [
        0x04, 0xbf, 0xd9, 0xdf, 0x73, 0x29, 0x0f, 0x50, 0xec, 0x16, 0xbd, 0x18, 0x4e, 0x31, 0xc0,
        0x43, 0xb6, 0xd7, 0x0f, 0xcf, 0xd2, 0x45, 0xf7, 0x6d, 0x10, 0xef, 0x26, 0xb6, 0x6c, 0x9d,
        0x19, 0xb1, 0x16, 0xf4, 0x25, 0xaf, 0xea, 0x1e, 0x7e, 0x84, 0x9b, 0x2f, 0x57, 0x3e, 0x56,
        0x2a, 0xba, 0xb6, 0x5c, 0xf4, 0x7c, 0x04, 0x5c, 0x32, 0xa2, 0xec, 0xc2, 0xf2, 0x3f, 0x86,
        0x51, 0x9a, 0x1e, 0xc2, 0x5d,
    ];

    #[test]
    fn contract_sample_code() {
        assert_eq!(from_public_key(&PB_S), "AWQW");
        assert_eq!(check_symbol(&PB_S), 'X');
        assert_eq!(check_symbol_for_code("AWQW").unwrap(), 'X');
    }

    #[test]
    fn encoding_shape_and_stability() {
        let mut rng = SeedRng::new(b"code-test");
        let kp = sm2::keygen(&mut rng);
        let mut pub65 = [0u8; 65];
        pub65[0] = 0x04;
        pub65[1..].copy_from_slice(&kp.public_key);
        let code = from_public_key(&pub65);
        assert_eq!(code.len(), 4);
        assert_eq!(code, from_public_key(&pub65));
        assert!(code.bytes().all(|c| symbol_value(c).is_some()));
        assert!(
            !code.contains('I')
                && !code.contains('L')
                && !code.contains('O')
                && !code.contains('U')
        );
    }

    #[test]
    fn normalize_rules() {
        assert_eq!(normalize("k7-qf").unwrap(), "K7QF");
        assert_eq!(normalize("o0il").unwrap(), "0011");
        assert_eq!(normalize("0oO0").unwrap(), "0000");
        assert_eq!(normalize(" u9z1").unwrap_err(), Error::BadCode);
        assert_eq!(normalize("K7Q").unwrap_err(), Error::BadCode);
        assert_eq!(normalize("K7QFA").unwrap_err(), Error::BadCode);
        assert_eq!(normalize("K7QF ").unwrap(), "K7QF");
        assert_eq!(normalize("awqw").unwrap(), "AWQW");
    }

    #[test]
    fn collision_regenerates() {
        let mut rng = SeedRng::new(b"collision-test");
        let mut seen = 0;
        let (kp, code) = generate_until_free(&mut rng, 8, |_| {
            seen += 1;
            seen < 3
        })
        .unwrap();
        assert_eq!(seen, 3);
        let mut pub65 = [0u8; 65];
        pub65[0] = 0x04;
        pub65[1..].copy_from_slice(&kp.public_key);
        assert_eq!(code, from_public_key(&pub65));
    }

    #[test]
    fn exhausted_returns_error() {
        let mut rng = SeedRng::new(b"exhaust-test");
        let err = generate_until_free(&mut rng, 2, |_| true).unwrap_err();
        assert_eq!(err, Error::CodeExhausted);
    }
}
