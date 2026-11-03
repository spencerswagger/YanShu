//! SM4 分组密码（GB/T 32907-2016），128 位分组 / 128 位密钥。
//!
//! 只实现 ECB 单块加解密；GCM 模式在 [`crate::gcm`] 中基于单块加密构造。

/// SM4 分组长度（字节）
pub const BLOCK_SIZE: usize = 16;
/// SM4 密钥长度（字节）
pub const KEY_SIZE: usize = 16;

const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

#[inline]
fn ck(i: usize) -> u32 {
    // CK[i] 的四个字节：ck_{4i+j} = (4i + j) * 7 mod 256
    let b = 4 * i as u32;
    let f = |j: u32| ((b + j).wrapping_mul(7) & 0xff) as u8;
    u32::from_be_bytes([f(0), f(1), f(2), f(3)])
}

#[inline]
fn tau(x: u32) -> u32 {
    let b = x.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

#[inline]
fn t(x: u32) -> u32 {
    let b = tau(x);
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[inline]
fn t_prime(x: u32) -> u32 {
    let b = tau(x);
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

/// SM4 密钥（已展开的 32 轮子密钥）。
#[derive(Clone)]
pub struct Sm4Key {
    rk: [u32; 32],
}

impl Sm4Key {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let mut k = [0u32; 4];
        for i in 0..4 {
            k[i] = u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
                ^ FK[i];
        }
        let mut rk = [0u32; 32];
        for i in 0..32 {
            rk[i] = k[0] ^ t_prime(k[1] ^ k[2] ^ k[3] ^ ck(i));
            k[0] = k[1];
            k[1] = k[2];
            k[2] = k[3];
            k[3] = rk[i];
        }
        Sm4Key { rk }
    }

    /// ECB 加密单块。
    pub fn encrypt_block(&self, input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut x = [0u32; 4];
        for i in 0..4 {
            x[i] = u32::from_be_bytes([
                input[i * 4],
                input[i * 4 + 1],
                input[i * 4 + 2],
                input[i * 4 + 3],
            ]);
        }
        let mut s = x;
        for i in 0..32 {
            let v = s[1] ^ s[2] ^ s[3] ^ self.rk[i];
            let n = s[0] ^ t(v);
            s[0] = s[1];
            s[1] = s[2];
            s[2] = s[3];
            s[3] = n;
        }
        // 反序变换
        let mut out = [0u8; BLOCK_SIZE];
        out[0..4].copy_from_slice(&s[3].to_be_bytes());
        out[4..8].copy_from_slice(&s[2].to_be_bytes());
        out[8..12].copy_from_slice(&s[1].to_be_bytes());
        out[12..16].copy_from_slice(&s[0].to_be_bytes());
        out
    }

    /// ECB 解密单块（使用倒序子密钥）。
    pub fn decrypt_block(&self, input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut rev = [0u32; 32];
        for i in 0..32 {
            rev[i] = self.rk[31 - i];
        }
        Sm4Key { rk: rev }.encrypt_block(input)
    }
}

/// 一次性单块加密。
pub fn encrypt_block(key: &[u8; KEY_SIZE], input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    Sm4Key::new(key).encrypt_block(input)
}

/// 一次性单块解密。
pub fn decrypt_block(key: &[u8; KEY_SIZE], input: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    Sm4Key::new(key).decrypt_block(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sm4_known_vector() {
        let key: [u8; 16] = h("0123456789abcdeffedcba9876543210").try_into().unwrap();
        let pt: [u8; 16] = h("0123456789abcdeffedcba9876543210").try_into().unwrap();
        let ct = encrypt_block(&key, &pt);
        assert_eq!(
            ct.to_vec(),
            h("681edf34d206965e86b3e94f536e4246"),
            "GB/T 32907 标准向量"
        );
        assert_eq!(decrypt_block(&key, &ct), pt);
    }

    #[test]
    fn roundtrip_random() {
        let key = [0x42u8; 16];
        let pt = [0x17u8; 16];
        let ct = encrypt_block(&key, &pt);
        assert_ne!(ct, pt);
        assert_eq!(decrypt_block(&key, &ct), pt);
    }
}
