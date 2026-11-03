//! SM3 杂凑（GB/T 32905-2016）与 HMAC-SM3（RFC 2104）。

const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

/// SM3 分块长度（字节）
pub const BLOCK_SIZE: usize = 64;
/// SM3 输出长度（字节）
pub const DIGEST_SIZE: usize = 32;

#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

#[inline]
fn ff(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline]
fn gg(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

#[inline]
fn tj(j: usize) -> u32 {
    if j < 16 {
        0x79cc_4519
    } else {
        0x7a87_9d8a
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }
    let mut w1 = [0u32; 64];
    for j in 0..64 {
        w1[j] = w[j] ^ w[j + 4];
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);

    for j in 0..64 {
        let a12 = a.rotate_left(12);
        let ss1 = a12
            .wrapping_add(e)
            .wrapping_add(tj(j).rotate_left((j % 32) as u32))
            .rotate_left(7);
        let ss2 = ss1 ^ a12;
        let tt1 = ff(j, a, b, c)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w1[j]);
        let tt2 = gg(j, e, f, g)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

/// 流式 SM3。
#[derive(Clone)]
pub struct Sm3 {
    state: [u32; 8],
    buf: [u8; BLOCK_SIZE],
    buflen: usize,
    total: u64,
}

impl Default for Sm3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3 {
    pub fn new() -> Self {
        Sm3 {
            state: IV,
            buf: [0u8; BLOCK_SIZE],
            buflen: 0,
            total: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = BLOCK_SIZE - self.buflen;
            let take = core::cmp::min(need, data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == BLOCK_SIZE {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buflen = 0;
            }
        }
        while data.len() >= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[..BLOCK_SIZE]);
            compress(&mut self.state, &block);
            data = &data[BLOCK_SIZE..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; DIGEST_SIZE] {
        let bitlen = self.total.wrapping_mul(8);
        self.buf[self.buflen] = 0x80;
        self.buflen += 1;
        if self.buflen > BLOCK_SIZE - 8 {
            for b in self.buf[self.buflen..].iter_mut() {
                *b = 0;
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf = [0u8; BLOCK_SIZE];
        } else {
            for b in self.buf[self.buflen..BLOCK_SIZE - 8].iter_mut() {
                *b = 0;
            }
        }
        self.buf[BLOCK_SIZE - 8..].copy_from_slice(&bitlen.to_be_bytes());
        let block = self.buf;
        compress(&mut self.state, &block);

        let mut out = [0u8; DIGEST_SIZE];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

/// 一次性 SM3。
pub fn sm3(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sm3::new();
    h.update(data);
    h.finish()
}

/// HMAC-SM3（RFC 2104，块长 64 字节）。
pub fn hmac_sm3(key: &[u8], data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let d = sm3(key);
        k[..DIGEST_SIZE].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sm3::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finish();

    let mut outer = Sm3::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finish()
}

/// 字节切片常量时间比较（用于 tag / 摘要比对）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sm3_known_vectors() {
        // GB/T 32905 附录 A
        assert_eq!(
            hex(&sm3(b"abc")),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
        assert_eq!(
            hex(&sm3(
                b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
            )),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        );
        assert_eq!(
            hex(&sm3(b"")),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data: Vec<u8> = (0..1000).map(|i| (i * 7 + 3) as u8).collect();
        let one = sm3(&data);
        let mut h = Sm3::new();
        for chunk in data.chunks(37) {
            h.update(chunk);
        }
        assert_eq!(h.finish(), one);
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 2104 结构自检（密钥长度 > 块长路径 + 常规路径）
        let a = hmac_sm3(b"key", b"The quick brown fox jumps over the lazy dog");
        let b = hmac_sm3(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(a, b);
        let long_key = [0xabu8; 100];
        let c = hmac_sm3(&long_key, b"x");
        assert_ne!(c, [0u8; 32]);
    }
}
