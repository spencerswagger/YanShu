//! SM4-GCM（GB/T 36624-2018 / SP 800-38D 构造，分组密码为 SM4）。
//!
//! 提供 128 位 tag；`nonce` 长度任意（本项目固定 96 位，走 `J0 = nonce || 0x00000001` 快路径）。

use crate::sm3::ct_eq;
use crate::sm4::{Sm4Key, BLOCK_SIZE, KEY_SIZE};

/// GCM tag 长度（字节）
pub const TAG_SIZE: usize = 16;

#[inline]
fn xor_block(dst: &mut [u8; BLOCK_SIZE], src: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        dst[i] ^= src[i];
    }
}

/// 乘 x（GCM 位反射约定：整体右移 1 位，溢出位触发 0xe1 约简）。
#[inline]
fn mul_x(v: &mut [u8; BLOCK_SIZE]) {
    let hi = u64::from_be_bytes(v[0..8].try_into().expect("8"));
    let lo = u64::from_be_bytes(v[8..16].try_into().expect("8"));
    let lsb = lo & 1;
    let new_lo = (lo >> 1) | (hi << 63);
    let new_hi = hi >> 1;
    v[0..8].copy_from_slice(&new_hi.to_be_bytes());
    v[8..16].copy_from_slice(&new_lo.to_be_bytes());
    if lsb == 1 {
        v[0] ^= 0xe1;
    }
}

/// 8 位移出后的约简表（与 H 无关，进程内算一次）。
fn reduction_table() -> &'static [[u8; BLOCK_SIZE]; 256] {
    use std::sync::OnceLock;
    static RED: OnceLock<[[u8; BLOCK_SIZE]; 256]> = OnceLock::new();
    RED.get_or_init(|| {
        // p[r] = mul_x^r(0xe1 在最高字节)
        let mut p = [[0u8; BLOCK_SIZE]; 8];
        let mut base = [0u8; BLOCK_SIZE];
        base[0] = 0xe1;
        p[0] = base;
        for r in 1..8 {
            p[r] = p[r - 1];
            mul_x(&mut p[r]);
        }
        let mut table = [[0u8; BLOCK_SIZE]; 256];
        for (b, slot) in table.iter_mut().enumerate() {
            let mut acc = [0u8; BLOCK_SIZE];
            for s in 0..8 {
                // 第 s 个被移出的位（b 的 bit s，LSB 先出），还要再被移 7-s 次
                if (b >> s) & 1 == 1 {
                    xor_block(&mut acc, &p[7 - s]);
                }
            }
            *slot = acc;
        }
        table
    })
}

/// 乘 x^8：整字节右移，移出的字节走约简表。
#[inline]
fn mul_x8(v: &mut [u8; BLOCK_SIZE]) {
    let out = v[15] as usize;
    for i in (1..BLOCK_SIZE).rev() {
        v[i] = v[i - 1];
    }
    v[0] = 0;
    if out != 0 {
        let red = &reduction_table()[out];
        xor_block(v, red);
    }
}

/// 单块 GHASH 用的查表：`T[b] = b（作为最高 8 位）* H`。
fn mul_table(h: &[u8; BLOCK_SIZE]) -> Box<[[u8; BLOCK_SIZE]; 256]> {
    let mut p = [[0u8; BLOCK_SIZE]; 8];
    p[0] = *h;
    for k in 1..8 {
        p[k] = p[k - 1];
        mul_x(&mut p[k]);
    }
    let mut table = Box::new([[0u8; BLOCK_SIZE]; 256]);
    for b in 0..256usize {
        let mut acc = [0u8; BLOCK_SIZE];
        for k in 0..8 {
            if (b >> (7 - k)) & 1 == 1 {
                xor_block(&mut acc, &p[k]);
            }
        }
        table[b] = acc;
    }
    table
}

/// 查表版 GF(2^128) 乘法（用于 GHASH）。
///
/// 位序约定与 GCM 一致：`x` 的**最高位**对应 x^0。因此按字节从**右往左**累加：
/// `z = z*x^8 ^ T[x[j]]`。
fn gf_mul_table(x: &[u8; BLOCK_SIZE], table: &[[u8; BLOCK_SIZE]; 256]) -> [u8; BLOCK_SIZE] {
    let mut z = [0u8; BLOCK_SIZE];
    for j in (0..BLOCK_SIZE).rev() {
        mul_x8(&mut z);
        let byte = x[j];
        if byte != 0 {
            xor_block(&mut z, &table[byte as usize]);
        }
    }
    z
}

/// 逐位 GF(2^128) 乘法（仅测试用于与查表版对拍）。
#[cfg(test)]
fn gf_mul_slow(x: &[u8; BLOCK_SIZE], y: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut z = [0u8; BLOCK_SIZE];
    let mut v = *y;
    for i in 0..128 {
        if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            xor_block(&mut z, &v);
        }
        mul_x(&mut v);
    }
    z
}

fn ghash(h: &[[u8; BLOCK_SIZE]; 256], aad: &[u8], ct: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut y = [0u8; BLOCK_SIZE];
    let mut absorb = |data: &[u8]| {
        let mut i = 0;
        while i < data.len() {
            let n = core::cmp::min(BLOCK_SIZE, data.len() - i);
            let mut block = [0u8; BLOCK_SIZE];
            block[..n].copy_from_slice(&data[i..i + n]);
            xor_block(&mut y, &block);
            y = gf_mul_table(&y, h);
            i += n;
        }
    };
    absorb(aad);
    absorb(ct);

    let mut lens = [0u8; BLOCK_SIZE];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    xor_block(&mut y, &lens);
    gf_mul_table(&y, h)
}

fn j0_from_nonce(h: &[[u8; BLOCK_SIZE]; 256], nonce: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut j0 = [0u8; BLOCK_SIZE];
    if nonce.len() == 12 {
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
    } else {
        j0 = ghash(h, &[], nonce);
    }
    j0
}

#[inline]
fn inc32(block: &mut [u8; BLOCK_SIZE]) {
    let mut c = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    c = c.wrapping_add(1);
    block[12..].copy_from_slice(&c.to_be_bytes());
}

fn ctr_apply(key: &Sm4Key, j0: &[u8; BLOCK_SIZE], data: &[u8], out: &mut [u8]) {
    let mut ctr = *j0;
    let mut offset = 0;
    while offset < data.len() {
        inc32(&mut ctr);
        let ks = key.encrypt_block(&ctr);
        let n = core::cmp::min(BLOCK_SIZE, data.len() - offset);
        for i in 0..n {
            out[offset + i] = data[offset + i] ^ ks[i];
        }
        offset += n;
    }
}

/// 计算 tag（不写出密文），供解密封装复用。
fn compute_tag(
    key: &Sm4Key,
    table: &[[u8; BLOCK_SIZE]; 256],
    j0: &[u8; BLOCK_SIZE],
    aad: &[u8],
    ct: &[u8],
) -> [u8; TAG_SIZE] {
    let s = ghash(table, aad, ct);
    let ek = key.encrypt_block(j0);
    let mut tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        tag[i] = ek[i] ^ s[i];
    }
    tag
}

/// SM4-GCM 加密。`out` 必须与 `plaintext` 等长；tag 写入 `tag`。
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
    tag: &mut [u8; TAG_SIZE],
) {
    assert_eq!(out.len(), plaintext.len());
    let sm4 = Sm4Key::new(key);
    let h = sm4.encrypt_block(&[0u8; BLOCK_SIZE]);
    let table = mul_table(&h);
    let j0 = j0_from_nonce(&table, nonce);
    ctr_apply(&sm4, &j0, plaintext, out);
    *tag = compute_tag(&sm4, &table, &j0, aad, out);
}

/// SM4-GCM 解密（先校验 tag，再解密；tag 不匹配返回 `None`）。
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_SIZE],
) -> Option<Vec<u8>> {
    let sm4 = Sm4Key::new(key);
    let h = sm4.encrypt_block(&[0u8; BLOCK_SIZE]);
    let table = mul_table(&h);
    let j0 = j0_from_nonce(&table, nonce);
    let expect = compute_tag(&sm4, &table, &j0, aad, ciphertext);
    if !ct_eq(&expect, tag) {
        return None;
    }
    let mut out = vec![0u8; ciphertext.len()];
    ctr_apply(&sm4, &j0, ciphertext, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn roundtrip_various_lengths() {
        let key = [0x01u8; 16];
        let nonce = [0x02u8; 12];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 100, 1024] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
            let mut ct = vec![0u8; len];
            let mut tag = [0u8; TAG_SIZE];
            encrypt(&key, &nonce, b"aad", &pt, &mut ct, &mut tag);
            let back = decrypt(&key, &nonce, b"aad", &ct, &tag).expect("tag ok");
            assert_eq!(back, pt);
            // 篡改任意一位必须失败
            if len > 0 {
                let mut bad = ct.clone();
                bad[len / 2] ^= 0x01;
                assert!(decrypt(&key, &nonce, b"aad", &bad, &tag).is_none());
            }
            // AAD 改动必须失败
            assert!(decrypt(&key, &nonce, b"aad2", &ct, &tag).is_none());
        }
    }

    #[test]
    fn table_gf_mul_matches_bitwise() {
        // 用固定伪随机序列，确保查表版与逐位版完全一致
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..64 {
            let mut x = [0u8; 16];
            let mut y = [0u8; 16];
            for i in 0..2 {
                x[i * 8..i * 8 + 8].copy_from_slice(&next().to_be_bytes());
                y[i * 8..i * 8 + 8].copy_from_slice(&next().to_be_bytes());
            }
            let table = mul_table(&y);
            assert_eq!(gf_mul_table(&x, &table), gf_mul_slow(&x, &y));
        }
    }

    #[test]
    fn empty_plaintext_tag_stable() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut tag1 = [0u8; TAG_SIZE];
        encrypt(&key, &nonce, b"", b"", &mut [], &mut tag1);
        let mut tag2 = [0u8; TAG_SIZE];
        encrypt(&key, &nonce, b"", b"", &mut [], &mut tag2);
        assert_eq!(tag1, tag2);
        assert_eq!(
            decrypt(&key, &nonce, b"", b"", &tag1).unwrap(),
            Vec::<u8>::new()
        );
        let _ = hx("00");
    }
}
