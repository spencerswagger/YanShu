//! 严格 DER 签名编码（契约 §10.4）：`SEQUENCE { r INTEGER, s INTEGER }`。
//!
//! 只接受/只产出最短编码：INTEGER 去前导 0、最高位为 1 时补一个 0x00、
//! SEQUENCE 长度用单字节短形式。任何非规范编码一律拒绝（不给签名延展性留空间）。

use crate::error::{Error, Result};

fn encode_integer(v: &[u8; 32], out: &mut Vec<u8>) {
    let mut start = 0;
    while start < 31 && v[start] == 0 {
        start += 1;
    }
    let bytes = &v[start..];
    let pad = bytes[0] & 0x80 != 0;
    out.push(0x02);
    out.push((bytes.len() + if pad { 1 } else { 0 }) as u8);
    if pad {
        out.push(0x00);
    }
    out.extend_from_slice(bytes);
}

/// `r||s`（各 32 字节，大端）→ DER（70..72 字节）。
pub fn encode_signature(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(70);
    encode_integer(r, &mut body);
    encode_integer(s, &mut body);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

fn decode_integer(buf: &[u8], pos: &mut usize, out: &mut [u8; 32]) -> Result<()> {
    if *pos + 2 > buf.len() || buf[*pos] != 0x02 {
        return Err(Error::SignatureMismatch);
    }
    let len = buf[*pos + 1] as usize;
    *pos += 2;
    if len == 0 || len > 33 || *pos + len > buf.len() {
        return Err(Error::SignatureMismatch);
    }
    let bytes = &buf[*pos..*pos + len];
    *pos += len;
    // 非最短编码：前导 0x00 且下一个字节最高位为 0
    if len > 1 && bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
        return Err(Error::SignatureMismatch);
    }
    if bytes[0] & 0x80 != 0 {
        // 负数：SM2 的 r/s 非负
        return Err(Error::SignatureMismatch);
    }
    let significant = if len == 33 {
        if bytes[0] != 0x00 {
            return Err(Error::SignatureMismatch);
        }
        &bytes[1..]
    } else {
        bytes
    };
    if significant.len() > 32 {
        return Err(Error::SignatureMismatch);
    }
    out.fill(0);
    out[32 - significant.len()..].copy_from_slice(significant);
    Ok(())
}

/// DER → `(r, s)`；非规范编码返回 [`Error::SignatureMismatch`]。
pub fn decode_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if der.len() < 8 || der.len() > 72 || der[0] != 0x30 {
        return Err(Error::SignatureMismatch);
    }
    if der[1] as usize != der.len() - 2 {
        return Err(Error::SignatureMismatch);
    }
    let mut pos = 2usize;
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    decode_integer(der, &mut pos, &mut r)?;
    decode_integer(der, &mut pos, &mut s)?;
    if pos != der.len() {
        return Err(Error::SignatureMismatch);
    }
    Ok((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rnd(seed: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        for (i, b) in v.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        v
    }

    #[test]
    fn roundtrip_and_length() {
        for seed in [0u8, 1, 7, 0x7f, 0x80, 0xff] {
            let r = rnd(seed);
            let s = rnd(seed ^ 0x5a);
            let der = encode_signature(&r, &s);
            assert!((70..=72).contains(&der.len()), "len {}", der.len());
            let (r2, s2) = decode_signature(&der).expect("decode");
            assert_eq!(r2, r);
            assert_eq!(s2, s);
        }
    }

    #[test]
    fn rejects_noncanonical() {
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];
        let der = encode_signature(&r, &s);
        // 长度字段被改
        let mut bad = der.clone();
        bad[1] = bad[1].wrapping_add(1);
        assert!(decode_signature(&bad).is_err());
        // 尾部多余字节
        let mut bad = der.clone();
        bad.push(0);
        assert!(decode_signature(&bad).is_err());
        // 非最短 INTEGER：手工构造 r 前多一个 0x00
        let mut body = Vec::new();
        body.push(0x02);
        body.push(33);
        body.push(0x00);
        body.extend_from_slice(&r);
        body.push(0x02);
        body.push(32);
        body.extend_from_slice(&s);
        let mut crafted = vec![0x30, body.len() as u8];
        crafted.extend_from_slice(&body);
        assert!(decode_signature(&crafted).is_err());
    }
}
