//! 用户码：4 位 Crockford Base32。
//!
//! 规则（与需求基线一致，**不擅自加长**）：
//! * 码 = `CrockfordBase32(SM3(公钥))` 的**前 4 个符号**（取摘要前 20 bit，大端位序）。
//! * 字母表 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`（去掉 `I L O U`）。
//! * 输入大小写不敏感；`O→0`、`I/L→1`；允许 `-` 分组；`U` 不是合法符号。
//! * 4 位 = 1,048,576 组合；撞码由客户端**重新生成密钥对**重试（不自动加长）。
//!
//! 基线第 3 节提到"建议加 1 位 Crockford 校验字符"：本实现**没有**把它放进用户码
//! （否则就是 5 位，违反"4 位"）。校验字符算法以 [`check_symbol`] 单独提供，
//! 仅供参考/未来输入校验用，不参与码生成。

use crate::error::{Error, Result};
use crate::rng::Rng;
use crate::sm2::{self, KeyPair};
use crate::sm3::sm3;

/// 32 符号的 Crockford 字母表。
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Crockford 校验字符表（37 符号，仅在 [`check_symbol`] 里使用）。
pub const CHECK_ALPHABET: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";
/// 用户码长度（位）
pub const CODE_LEN: usize = 4;

fn symbol_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&x| x == c).map(|v| v as u8)
}

/// 把摘要前 20 bit 编成 4 个 Crockford 符号。
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

/// 由 64 字节公钥派生 4 位用户码。
pub fn from_public_key(public_key: &[u8; 64]) -> String {
    let digest = sm3(public_key);
    let code = encode_first4(&digest);
    String::from_utf8(code.to_vec()).expect("alphabet is ascii")
}

/// 输入规范化：大小写、`O→0`、`I/L→1`、去掉 `-`，其余字符必须落在字母表内。
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

/// 是否是一个合法（规范化后）的 4 位码。
pub fn is_valid(input: &str) -> bool {
    normalize(input).is_ok()
}

/// Crockford 校验字符（mod 37）。**不参与用户码**，仅供输入校验工具使用。
pub fn check_symbol(code: &str) -> Option<char> {
    let normalized = normalize(code).ok()?;
    let mut sum: u32 = 0;
    for c in normalized.bytes() {
        sum += symbol_value(c)? as u32;
    }
    Some(CHECK_ALPHABET[(sum % 37) as usize] as char)
}

/// 生成身份并处理撞码：`is_taken` 回调返回 true 时重新生成密钥对再试。
///
/// 返回 `(密钥对, 用户码)`。重试次数上限 `max_attempts`（默认 8），
/// 超限返回 [`Error::CodeExhausted`]。
pub fn generate_until_free(
    rng: &mut impl Rng,
    max_attempts: usize,
    mut is_taken: impl FnMut(&str) -> bool,
) -> Result<(KeyPair, String)> {
    for _ in 0..max_attempts.max(1) {
        let kp = sm2::keygen(rng);
        let code = from_public_key(&kp.public_key);
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

    #[test]
    fn encoding_is_4_symbols_and_stable() {
        let mut rng = SeedRng::new(b"code-test");
        let kp = sm2::keygen(&mut rng);
        let code = from_public_key(&kp.public_key);
        assert_eq!(code.len(), 4);
        assert_eq!(code, from_public_key(&kp.public_key));
        assert!(code.bytes().all(|c| symbol_value(c).is_some()));
        // 不含易混字符
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
    }

    #[test]
    fn check_symbol_shape() {
        assert!(check_symbol("K7QF").is_some());
        assert_eq!(check_symbol("K7QF"), check_symbol("k7-qf"));
        assert!(check_symbol("UUUU").is_none());
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
        assert_eq!(code, from_public_key(&kp.public_key));
    }

    #[test]
    fn exhausted_returns_error() {
        let mut rng = SeedRng::new(b"exhaust-test");
        let err = generate_until_free(&mut rng, 2, |_| true).unwrap_err();
        assert_eq!(err, Error::CodeExhausted);
    }
}
