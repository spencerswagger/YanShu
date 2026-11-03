//! 256-bit fixed-width integer + Montgomery modular arithmetic.
//!
//! 自研实现（不引外部大数库）：SM2 需要 GF(p) 与 GF(n) 上的模加减乘逆，
//! 这里只提供这四种运算，足够椭圆曲线与签名标量运算使用。
//!
//! 所有坐标运算在 Montgomery 域内进行（`aR mod m`），进出场函数为
//! [`MontCtx::to_mont`] / [`MontCtx::from_mont`]。
//!
//! 说明：本实现对分支/时间不做常数时间保证（见 README 的风险说明）。

/// 无符号 256 位整数，小端 limb 顺序：`0` 为最低 64 位。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);

    /// 大端字节（网络序，密码学标准表示）→ U256
    pub fn from_be_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut w = 0u64;
            for j in 0..8 {
                w = (w << 8) | b[i * 8 + j] as u64;
            }
            limbs[3 - i] = w;
        }
        U256(limbs)
    }

    /// U256 → 大端 32 字节
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            let w = self.0[3 - i];
            for j in 0..8 {
                out[i * 8 + j] = (w >> (56 - 8 * j)) as u8;
            }
        }
        out
    }

    pub fn is_zero(self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }

    /// 第 `i` 位（0 = 最低位）；`i >= 256` 恒为 false。
    pub fn bit(self, i: usize) -> bool {
        if i >= 256 {
            return false;
        }
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    pub fn cmp_u(self, other: &U256) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        core::cmp::Ordering::Equal
    }

    pub fn add_carry(self, other: &U256) -> (U256, u64) {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + other.0[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        (U256(r), carry as u64)
    }

    pub fn sub_borrow(self, other: &U256) -> (U256, u64) {
        let mut r = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let s = self.0[i] as i128 - other.0[i] as i128 - borrow;
            r[i] = s as u64;
            borrow = if s < 0 { 1 } else { 0 };
        }
        (U256(r), borrow as u64)
    }

    /// 与 `m` 做一次条件减法（`self < 2m` 时结果正确）。
    fn cond_sub(self, m: &U256) -> U256 {
        let (d, borrow) = self.sub_borrow(m);
        if borrow == 0 {
            d
        } else {
            self
        }
    }
}

/// 一个模数的 Montgomery 上下文。
#[derive(Clone)]
pub struct MontCtx {
    pub m: U256,
    /// `-m^-1 mod 2^64`
    m0inv: u64,
    /// `R^2 mod m`，`R = 2^256`
    r2: U256,
    /// `R mod m`（Montgomery 域中的 1）
    one: U256,
    /// `m - 2`（费马小定理求逆的指数）
    exp_inv: U256,
}

impl MontCtx {
    pub fn new(m: U256) -> Self {
        assert!(m.0[0] & 1 == 1, "modulus must be odd");

        // m0inv = -m^-1 mod 2^64，Newton 迭代（对 2^64 收敛需 6 轮）
        let m0 = m.0[0];
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        let m0inv = inv.wrapping_neg();

        // r2 = 2^512 mod m（512 次加倍）
        let mut acc = U256::ONE;
        for _ in 0..512 {
            acc = add_mod(&acc, &acc, &m);
        }
        let r2 = acc;

        // one = R mod m（256 次加倍）
        let mut one = U256::ONE;
        for _ in 0..256 {
            one = add_mod(&one, &one, &m);
        }

        let (exp_inv, _) = m.sub_borrow(&U256([2, 0, 0, 0]));

        MontCtx {
            m,
            m0inv,
            r2,
            one,
            exp_inv,
        }
    }

    pub fn one_mont(&self) -> U256 {
        self.one
    }

    pub fn to_mont(&self, a: &U256) -> U256 {
        let am = *a;
        self.mont_mul(&am, &self.r2)
    }

    pub fn from_mont(&self, a: &U256) -> U256 {
        self.mont_mul(a, &U256::ONE)
    }

    pub fn add(&self, a: &U256, b: &U256) -> U256 {
        add_mod(a, b, &self.m)
    }

    pub fn sub(&self, a: &U256, b: &U256) -> U256 {
        if a.cmp_u(b) != core::cmp::Ordering::Less {
            let (d, _) = a.sub_borrow(b);
            d
        } else {
            let (t, _) = self.m.sub_borrow(b);
            let (r, _) = t.add_carry(a);
            // t + a < m（因 a < m 且 t < m），故不需要再减
            r
        }
    }

    pub fn neg(&self, a: &U256) -> U256 {
        if a.is_zero() {
            U256::ZERO
        } else {
            let (r, _) = self.m.sub_borrow(a);
            r
        }
    }

    pub fn mul(&self, a: &U256, b: &U256) -> U256 {
        self.mont_mul(a, b)
    }

    pub fn sqr(&self, a: &U256) -> U256 {
        self.mont_mul(a, a)
    }

    /// `a^e`（Montgomery 域内），e 为 256 位。
    pub fn pow(&self, a: &U256, e: &U256) -> U256 {
        let mut result = self.one;
        let mut started = false;
        for i in (0..256).rev() {
            if started {
                result = self.sqr(&result);
            }
            if e.bit(i) {
                if started {
                    result = self.mul(&result, a);
                } else {
                    result = *a;
                    started = true;
                }
            }
        }
        if started {
            result
        } else {
            self.one
        }
    }

    /// Montgomery 域内求逆（`a^(m-2)`，m 为素数）。0 的逆返回 0。
    pub fn inv(&self, a: &U256) -> U256 {
        if a.is_zero() {
            return U256::ZERO;
        }
        let e = self.exp_inv;
        self.pow(a, &e)
    }

    /// Montgomery 乘法：`a * b * R^-1 mod m`。
    fn mont_mul(&self, a: &U256, b: &U256) -> U256 {
        let mut t = [0u64; 9];
        // 512 位乘积
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let s = t[i + j] as u128 + (a.0[i] as u128) * (b.0[j] as u128) + carry;
                t[i + j] = s as u64;
                carry = s >> 64;
            }
            let mut k = i + 4;
            while carry != 0 {
                let s = t[k] as u128 + carry;
                t[k] = s as u64;
                carry = s >> 64;
                k += 1;
            }
        }
        // Montgomery 约简（REDC）
        for i in 0..4 {
            let mm = t[i].wrapping_mul(self.m0inv);
            let mut carry: u128 = 0;
            for j in 0..4 {
                let s = t[i + j] as u128 + (mm as u128) * (self.m.0[j] as u128) + carry;
                t[i + j] = s as u64;
                carry = s >> 64;
            }
            let mut k = i + 4;
            while carry != 0 {
                let s = t[k] as u128 + carry;
                t[k] = s as u64;
                carry = s >> 64;
                k += 1;
            }
        }
        let r = U256([t[4], t[5], t[6], t[7]]);
        // 结果 < 2m，至多减一次；t[8] 非零时表示 r + 2^256，环绕减法同样正确
        if t[8] != 0 {
            let (d, _) = r.sub_borrow(&self.m);
            d
        } else {
            r.cond_sub(&self.m)
        }
    }
}

fn add_mod(a: &U256, b: &U256, m: &U256) -> U256 {
    let (s, carry) = a.add_carry(b);
    if carry != 0 {
        let (d, _) = s.sub_borrow(m);
        d
    } else {
        s.cond_sub(m)
    }
}

/// 便于测试：普通（非 Montgomery）模乘，使用 Montgomery 上下文进出场。
pub fn mod_mul_plain(ctx: &MontCtx, a: &U256, b: &U256) -> U256 {
    let am = ctx.to_mont(a);
    let bm = ctx.to_mont(b);
    ctx.from_mont(&ctx.mul(&am, &bm))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(x: u64) -> U256 {
        U256([x, 0, 0, 0])
    }

    #[test]
    fn bytes_roundtrip() {
        let mut b = [0u8; 32];
        for (i, v) in b.iter_mut().enumerate() {
            *v = i as u8;
        }
        assert_eq!(U256::from_be_bytes(&b).to_be_bytes(), b);
    }

    #[test]
    fn small_mod_arith() {
        let m = U256::from_be_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 0x0d; // 13
            b
        });
        let ctx = MontCtx::new(m);
        let a = u(10);
        let b = u(9);
        let am = ctx.to_mont(&a);
        let bm = ctx.to_mont(&b);
        // 10*9 mod 13 = 12
        assert_eq!(ctx.from_mont(&ctx.mul(&am, &bm)), u(12));
        // 10+9 mod 13 = 6
        assert_eq!(ctx.from_mont(&ctx.add(&am, &bm)), u(6));
        // 10-9 = 1
        assert_eq!(ctx.from_mont(&ctx.sub(&am, &bm)), u(1));
        // inv(2) mod 13 = 7
        assert_eq!(ctx.from_mont(&ctx.inv(&ctx.to_mont(&u(2)))), u(7));
    }

    #[test]
    fn p256_mod_ops() {
        // p = 2^256 - 2^32 - 977
        let p = U256::from_be_bytes(&hex32(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        ));
        let ctx = MontCtx::new(p);
        let a = U256::from_be_bytes(&hex32(
            "1234567890abcdeffedcba0987654321aabbccddeeff00112233445566778899",
        ));
        let b = U256::from_be_bytes(&hex32(
            "deadbeefcafebabe0123456789abcdef0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ));
        let a_m = ctx.to_mont(&a);
        let b_m = ctx.to_mont(&b);
        // (a*b) * inv(b) == a
        let prod = ctx.mul(&a_m, &b_m);
        let inv_b = ctx.inv(&b_m);
        assert_eq!(ctx.from_mont(&ctx.mul(&prod, &inv_b)), a);
        // a + p - a == 0
        let neg_a = ctx.neg(&a_m);
        assert_eq!(ctx.from_mont(&ctx.add(&a_m, &neg_a)), U256::ZERO);
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
