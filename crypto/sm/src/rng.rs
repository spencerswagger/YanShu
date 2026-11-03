//! 随机源抽象。
//!
//! * 宿主（native / 测试）：[`OsRng`] 读 `/dev/urandom`。
//! * wasm：没有 OS 随机源，C ABI 由 JS 侧传入一包种子（`crypto.getRandomValues`），
//!   用 [`SeedRng`]（SM3 计数器 DRBG）展开。**种子必须每次操作重新取真随机**；
//!   `ffi` 层额外混入进程内单调计数器，降低"同一包种子被重复使用"的风险，
//!   但这只是兜底，正确性仍取决于调用方。

use crate::sm3::sm3;

/// 随机字节源。
pub trait Rng {
    fn fill(&mut self, out: &mut [u8]);
}

/// 操作系统随机源（仅 native）。
pub struct OsRng;

#[cfg(not(target_arch = "wasm32"))]
impl OsRng {
    pub fn new() -> Self {
        OsRng
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for OsRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Rng for OsRng {
    fn fill(&mut self, out: &mut [u8]) {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
        f.read_exact(out).expect("read /dev/urandom");
    }
}

/// 由外部种子驱动的确定性 DRBG（SM3 计数器模式）。仅用于 wasm 与测试向量。
pub struct SeedRng {
    seed: [u8; 32],
    counter: u64,
}

impl SeedRng {
    /// 种子先经一次 SM3 压缩，任意长度输入都可以。
    pub fn new(seed: &[u8]) -> Self {
        SeedRng {
            seed: sm3(seed),
            counter: 0,
        }
    }
}

impl Rng for SeedRng {
    fn fill(&mut self, out: &mut [u8]) {
        let mut offset = 0;
        while offset < out.len() {
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(&self.seed);
            input[32..].copy_from_slice(&self.counter.to_be_bytes());
            let block = sm3(&input);
            let n = core::cmp::min(32, out.len() - offset);
            out[offset..offset + n].copy_from_slice(&block[..n]);
            offset += n;
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

/// 固定字节流（测试用，可完全复现）。
pub struct FixedRng {
    data: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    pub fn new(data: Vec<u8>) -> Self {
        FixedRng { data, pos: 0 }
    }
}

impl Rng for FixedRng {
    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.data[self.pos % self.data.len()];
            self.pos += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_rng_is_deterministic_and_streaming() {
        let mut a = SeedRng::new(b"seed");
        let mut b = SeedRng::new(b"seed");
        let mut x = [0u8; 100];
        let mut y = [0u8; 100];
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y);
        let mut c = SeedRng::new(b"seed2");
        c.fill(&mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn os_rng_not_constant() {
        let mut r = OsRng::new();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        r.fill(&mut a);
        r.fill(&mut b);
        assert_ne!(a, b);
    }
}
