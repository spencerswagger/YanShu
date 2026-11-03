//! HKDF-SM3（RFC 5869 构造，PRF 换成 HMAC-SM3）。用于从文件密钥 DK 派生块密钥 / 清单密钥。

use crate::sm3::{hmac_sm3, DIGEST_SIZE};

/// HKDF-Extract：`prk = HMAC-SM3(salt, ikm)`；salt 为空时按 RFC 使用 32 字节零。
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; DIGEST_SIZE] {
    if salt.is_empty() {
        hmac_sm3(&[0u8; DIGEST_SIZE], ikm)
    } else {
        hmac_sm3(salt, ikm)
    }
}

/// HKDF-Expand：输出 `out.len()` 字节（上限 255*32）。
pub fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * DIGEST_SIZE, "HKDF output too long");
    let mut t: Vec<u8> = Vec::new();
    let mut produced = 0usize;
    let mut counter: u8 = 1;
    while produced < out.len() {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sm3(prk, &input).to_vec();
        let n = core::cmp::min(DIGEST_SIZE, out.len() - produced);
        out[produced..produced + n].copy_from_slice(&t[..n]);
        produced += n;
        counter = counter.wrapping_add(1);
    }
}

/// HKDF-SM3 一步到位。
pub fn hkdf_sm3(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = extract(salt, ikm);
    expand(&prk, info, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_lengths() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        hkdf_sm3(b"salt", b"ikm", b"info", &mut a);
        hkdf_sm3(b"salt", b"ikm", b"info", &mut b);
        assert_eq!(a, b);

        let mut long = [0u8; 64];
        hkdf_sm3(b"salt", b"ikm", b"info", &mut long);
        assert_eq!(&long[..16], &a[..]);
        // 前 32 字节应与短输出完全一致
        let mut mid = [0u8; 32];
        hkdf_sm3(b"salt", b"ikm", b"info", &mut mid);
        assert_eq!(&long[..32], &mid[..]);
        // 不同 info 派生不同密钥
        let mut c = [0u8; 16];
        hkdf_sm3(b"salt", b"ikm", b"info2", &mut c);
        assert_ne!(a, c);
    }
}
