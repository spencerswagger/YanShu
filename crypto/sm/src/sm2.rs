//! SM2 椭圆曲线（GB/T 32918，推荐曲线参数 256 位素数域）。
//!
//! 能力：密钥对生成、公钥派生、加密（C1C3C2 平文拼接）、解密、签名、验签。
//!
//! 密文编码**写死为 C1C3C2 平文拼接**：`C1 = x1(32) || y1(32)`（不带 0x04 前缀）、
//! `C3 = 32` 字节 SM3、`C2 = 与明文等长`。与 GmSSL `sm2_do_encrypt` 的
//! `SM2_CIPHERTEXT` 平文串接顺序一致，交叉验证见 `scripts/crosscheck`。
//!
//! 签名输出 `r(32) || s(32)`（不是 DER），验签只接受该平文格式。

use crate::bigint::{MontCtx, U256};
use crate::error::{Error, Result};
use crate::rng::Rng;
use crate::sm3::sm3;

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = 64;
pub const MAX_PLAINTEXT_SIZE: usize = 255;
/// 默认用户标识（GB/T 32918.2 推荐值），本项目不改变身份标识。
pub const DEFAULT_ID: &[u8] = b"1234567812345678";

#[derive(Clone, Copy)]
struct Jac {
    x: U256,
    y: U256,
    z: U256,
}

struct Curve {
    fp: MontCtx,
    fq: MontCtx,
    n: U256,
    a: U256,
    b: U256,
    g: Jac,
    two: U256,
    three: U256,
    four: U256,
    eight: U256,
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 64);
    for i in 0..32 {
        let hi = (bytes[i * 2] as char).to_digit(16).expect("hex") as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).expect("hex") as u8;
        out[i] = (hi << 4) | lo;
    }
    out
}

fn u(s: &str) -> U256 {
    U256::from_be_bytes(&hex32(s))
}

const P_HEX: &str = "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff";
const A_HEX: &str = "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc";
const B_HEX: &str = "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93";
const N_HEX: &str = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123";
const GX_HEX: &str = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7";
const GY_HEX: &str = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";

fn curve() -> &'static Curve {
    use std::sync::OnceLock;
    static CURVE: OnceLock<Curve> = OnceLock::new();
    CURVE.get_or_init(|| {
        let fp = MontCtx::new(u(P_HEX));
        let fq = MontCtx::new(u(N_HEX));
        let a = u(A_HEX);
        let b = u(B_HEX);
        let gx = fp.to_mont(&u(GX_HEX));
        let gy = fp.to_mont(&u(GY_HEX));
        let g = Jac {
            x: gx,
            y: gy,
            z: fp.one_mont(),
        };
        Curve {
            a: fp.to_mont(&a),
            b: fp.to_mont(&b),
            two: fp.to_mont(&U256([2, 0, 0, 0])),
            three: fp.to_mont(&U256([3, 0, 0, 0])),
            four: fp.to_mont(&U256([4, 0, 0, 0])),
            eight: fp.to_mont(&U256([8, 0, 0, 0])),
            n: u(N_HEX),
            fp,
            fq,
            g,
        }
    })
}

impl Curve {
    fn inf(&self) -> Jac {
        Jac {
            x: U256::ZERO,
            y: U256::ZERO,
            z: U256::ZERO,
        }
    }

    fn is_inf(&self, p: &Jac) -> bool {
        p.z.is_zero()
    }

    fn double(&self, p: Jac) -> Jac {
        if self.is_inf(&p) {
            return p;
        }
        let f = &self.fp;
        let y2 = f.sqr(&p.y);
        let s = f.mul(&self.four, &f.mul(&p.x, &y2));
        let z2 = f.sqr(&p.z);
        let z4 = f.sqr(&z2);
        let m = f.add(&f.mul(&self.three, &f.sqr(&p.x)), &f.mul(&self.a, &z4));
        let x3 = f.sub(&f.sqr(&m), &f.add(&s, &s));
        let y3 = f.sub(
            &f.mul(&m, &f.sub(&s, &x3)),
            &f.mul(&self.eight, &f.sqr(&y2)),
        );
        let z3 = f.mul(&self.two, &f.mul(&p.y, &p.z));
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, p: Jac, q: Jac) -> Jac {
        if self.is_inf(&p) {
            return q;
        }
        if self.is_inf(&q) {
            return p;
        }
        let f = &self.fp;
        let z1z1 = f.sqr(&p.z);
        let z2z2 = f.sqr(&q.z);
        let u1 = f.mul(&p.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&p.y, &f.mul(&z2z2, &q.z));
        let s2 = f.mul(&q.y, &f.mul(&z1z1, &p.z));
        if u1 == u2 {
            if s1 == s2 {
                return self.double(p);
            }
            return self.inf();
        }
        let h = f.sub(&u2, &u1);
        let r = f.sub(&s2, &s1);
        let h2 = f.sqr(&h);
        let h3 = f.mul(&h2, &h);
        let u1h2 = f.mul(&u1, &h2);
        let x3 = f.sub(&f.sub(&f.sqr(&r), &h3), &f.add(&u1h2, &u1h2));
        let y3 = f.sub(&f.mul(&r, &f.sub(&u1h2, &x3)), &f.mul(&s1, &h3));
        let z3 = f.mul(&h, &f.mul(&p.z, &q.z));
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn mul(&self, k: &U256, p: &Jac) -> Jac {
        let mut r = self.inf();
        for i in (0..256).rev() {
            r = self.double(r);
            if k.bit(i) {
                r = self.add(r, *p);
            }
        }
        r
    }

    fn to_affine(&self, p: &Jac) -> Option<(U256, U256)> {
        if self.is_inf(p) {
            return None;
        }
        let f = &self.fp;
        let zi = f.inv(&p.z);
        let zi2 = f.sqr(&zi);
        let x = f.mul(&p.x, &zi2);
        let y = f.mul(&p.y, &f.mul(&zi2, &zi));
        Some((f.from_mont(&x), f.from_mont(&y)))
    }

    fn point_from_affine(&self, x: &U256, y: &U256) -> Jac {
        Jac {
            x: self.fp.to_mont(x),
            y: self.fp.to_mont(y),
            z: self.fp.one_mont(),
        }
    }

    /// 曲线方程校验：`y^2 == x^3 + a*x + b`。
    fn on_curve(&self, x: &U256, y: &U256) -> bool {
        if x.cmp_u(&self.fp.m) != core::cmp::Ordering::Less
            || y.cmp_u(&self.fp.m) != core::cmp::Ordering::Less
        {
            return false;
        }
        let f = &self.fp;
        let xm = f.to_mont(x);
        let ym = f.to_mont(y);
        let lhs = f.sqr(&ym);
        let rhs = f.add(
            &f.add(&f.mul(&f.sqr(&xm), &xm), &f.mul(&self.a, &xm)),
            &self.b,
        );
        lhs == rhs
    }

    // 标量域（mod n）运算，进出 Montgomery 域
    fn nmul(&self, a: &U256, b: &U256) -> U256 {
        let f = &self.fq;
        f.from_mont(&f.mul(&f.to_mont(a), &f.to_mont(b)))
    }
    fn nadd(&self, a: &U256, b: &U256) -> U256 {
        let f = &self.fq;
        f.from_mont(&f.add(&f.to_mont(a), &f.to_mont(b)))
    }
    fn nsub(&self, a: &U256, b: &U256) -> U256 {
        let f = &self.fq;
        f.from_mont(&f.sub(&f.to_mont(a), &f.to_mont(b)))
    }
    fn ninv(&self, a: &U256) -> U256 {
        let f = &self.fq;
        f.from_mont(&f.inv(&f.to_mont(a)))
    }
}

/// 一个 SM2 身份（私钥 32 字节 / 公钥 64 字节 `x||y`）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyPair {
    pub private_key: [u8; PRIVATE_KEY_SIZE],
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

impl KeyPair {
    pub fn public_hex(&self) -> String {
        self.public_key
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

fn scalar_from_bytes(b: &[u8; 32]) -> U256 {
    let c = curve();
    let v = U256::from_be_bytes(b);
    // 按 SM2 要求 d ∈ [1, n-2]
    let n_minus_1 = c.nsub(&c.n, &U256([1, 0, 0, 0]));
    if v.is_zero() || v.cmp_u(&n_minus_1) == core::cmp::Ordering::Greater {
        U256::ZERO
    } else {
        v
    }
}

/// 由 32 字节私钥派生 64 字节公钥；私钥非法时返回 [`Error::BadArgument`]。
pub fn public_from_private(priv_bytes: &[u8; PRIVATE_KEY_SIZE]) -> Result<[u8; PUBLIC_KEY_SIZE]> {
    let c = curve();
    let d = scalar_from_bytes(priv_bytes);
    if d.is_zero() {
        return Err(Error::BadArgument);
    }
    let p = c.mul(&d, &c.g);
    let (x, y) = c.to_affine(&p).ok_or(Error::BadPoint)?;
    let mut out = [0u8; PUBLIC_KEY_SIZE];
    out[..32].copy_from_slice(&x.to_be_bytes());
    out[32..].copy_from_slice(&y.to_be_bytes());
    Ok(out)
}

fn parse_public(pub_bytes: &[u8; PUBLIC_KEY_SIZE]) -> Result<Jac> {
    let c = curve();
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&pub_bytes[..32]);
    yb.copy_from_slice(&pub_bytes[32..]);
    let x = U256::from_be_bytes(&xb);
    let y = U256::from_be_bytes(&yb);
    if !c.on_curve(&x, &y) {
        return Err(Error::BadPoint);
    }
    Ok(c.point_from_affine(&x, &y))
}

fn random_scalar(rng: &mut impl Rng) -> U256 {
    let c = curve();
    let n_minus_1 = c.nsub(&c.n, &U256([1, 0, 0, 0]));
    loop {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        let v = U256::from_be_bytes(&b);
        if !v.is_zero() && v.cmp_u(&n_minus_1) != core::cmp::Ordering::Greater {
            return v;
        }
    }
}

/// 生成密钥对（每次调用消耗 32 字节随机数，拒绝采样）。
pub fn keygen(rng: &mut impl Rng) -> KeyPair {
    loop {
        let d = random_scalar(rng);
        let mut priv_bytes = [0u8; PRIVATE_KEY_SIZE];
        priv_bytes.copy_from_slice(&d.to_be_bytes());
        if let Ok(public_key) = public_from_private(&priv_bytes) {
            return KeyPair {
                private_key: priv_bytes,
                public_key,
            };
        }
    }
}

fn kdf(z: &[u8], outlen: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(outlen + 32);
    let mut ct: u32 = 1;
    while out.len() < outlen {
        let mut input = Vec::with_capacity(z.len() + 4);
        input.extend_from_slice(z);
        input.extend_from_slice(&ct.to_be_bytes());
        out.extend_from_slice(&sm3(&input));
        ct += 1;
    }
    out.truncate(outlen);
    if out.iter().all(|&b| b == 0) {
        return Err(Error::BadKdf);
    }
    Ok(out)
}

/// SM2 加密，`k` 为显式指定的临时标量（测试向量需要可复现；
/// 生产中由 [`encrypt_with_rng`] 用 CSPRNG 生成）。
pub fn encrypt(pub_bytes: &[u8; PUBLIC_KEY_SIZE], msg: &[u8], k: &U256) -> Result<Vec<u8>> {
    if msg.is_empty() || msg.len() > MAX_PLAINTEXT_SIZE {
        return Err(Error::BadArgument);
    }
    let c = curve();
    let p = parse_public(pub_bytes)?;
    if k.is_zero() || k.cmp_u(&c.n) != core::cmp::Ordering::Less {
        return Err(Error::BadArgument);
    }
    let c1 = c.mul(k, &c.g);
    let (x1, y1) = c.to_affine(&c1).ok_or(Error::BadPoint)?;
    let kp = c.mul(k, &p);
    let (x2, y2) = c.to_affine(&kp).ok_or(Error::BadPoint)?;

    let mut z = [0u8; 64];
    z[..32].copy_from_slice(&x2.to_be_bytes());
    z[32..].copy_from_slice(&y2.to_be_bytes());
    let t = kdf(&z, msg.len())?;
    let mut c2 = vec![0u8; msg.len()];
    for i in 0..msg.len() {
        c2[i] = msg[i] ^ t[i];
    }
    let mut hash_input = Vec::with_capacity(64 + msg.len());
    hash_input.extend_from_slice(&x2.to_be_bytes());
    hash_input.extend_from_slice(msg);
    hash_input.extend_from_slice(&y2.to_be_bytes());
    let c3 = sm3(&hash_input);

    let mut out = Vec::with_capacity(64 + 32 + msg.len());
    out.extend_from_slice(&x1.to_be_bytes());
    out.extend_from_slice(&y1.to_be_bytes());
    out.extend_from_slice(&c3);
    out.extend_from_slice(&c2);
    Ok(out)
}

/// 用 CSPRNG 生成临时标量的加密。
pub fn encrypt_with_rng(
    pub_bytes: &[u8; PUBLIC_KEY_SIZE],
    msg: &[u8],
    rng: &mut impl Rng,
) -> Result<Vec<u8>> {
    let k = random_scalar(rng);
    encrypt(pub_bytes, msg, &k)
}

/// SM2 解密（C1C3C2 平文拼接）。
pub fn decrypt(priv_bytes: &[u8; PRIVATE_KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 64 + 32 + 1 {
        return Err(Error::Truncated);
    }
    let c = curve();
    let d = scalar_from_bytes(priv_bytes);
    if d.is_zero() {
        return Err(Error::BadArgument);
    }
    let mut x1b = [0u8; 32];
    let mut y1b = [0u8; 32];
    x1b.copy_from_slice(&ciphertext[..32]);
    y1b.copy_from_slice(&ciphertext[32..64]);
    let x1 = U256::from_be_bytes(&x1b);
    let y1 = U256::from_be_bytes(&y1b);
    if !c.on_curve(&x1, &y1) {
        return Err(Error::BadPoint);
    }
    let c1 = c.point_from_affine(&x1, &y1);
    let dp = c.mul(&d, &c1);
    let (x2, y2) = c.to_affine(&dp).ok_or(Error::BadPoint)?;

    let c3 = &ciphertext[64..96];
    let c2 = &ciphertext[96..];
    let mut z = [0u8; 64];
    z[..32].copy_from_slice(&x2.to_be_bytes());
    z[32..].copy_from_slice(&y2.to_be_bytes());
    let t = kdf(&z, c2.len())?;
    let mut msg = vec![0u8; c2.len()];
    for i in 0..c2.len() {
        msg[i] = c2[i] ^ t[i];
    }
    let mut hash_input = Vec::with_capacity(64 + msg.len());
    hash_input.extend_from_slice(&x2.to_be_bytes());
    hash_input.extend_from_slice(&msg);
    hash_input.extend_from_slice(&y2.to_be_bytes());
    let u = sm3(&hash_input);
    if !crate::sm3::ct_eq(&u, c3) {
        return Err(Error::BadCiphertext);
    }
    Ok(msg)
}

/// 计算 `ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)`。
pub fn z_a(pub_bytes: &[u8; PUBLIC_KEY_SIZE], id: &[u8]) -> [u8; 32] {
    let entl = ((id.len() as u64) * 8) as u16;
    let mut input = Vec::with_capacity(2 + id.len() + 32 * 6);
    input.extend_from_slice(&entl.to_be_bytes());
    input.extend_from_slice(id);
    input.extend_from_slice(&hex32(A_HEX));
    input.extend_from_slice(&hex32(B_HEX));
    input.extend_from_slice(&hex32(GX_HEX));
    input.extend_from_slice(&hex32(GY_HEX));
    input.extend_from_slice(&pub_bytes[..32]);
    input.extend_from_slice(&pub_bytes[32..]);
    sm3(&input)
}

/// 待签名摘要 `e = SM3(ZA || M)`。
pub fn message_digest(pub_bytes: &[u8; PUBLIC_KEY_SIZE], msg: &[u8], id: &[u8]) -> [u8; 32] {
    let za = z_a(pub_bytes, id);
    let mut input = Vec::with_capacity(32 + msg.len());
    input.extend_from_slice(&za);
    input.extend_from_slice(msg);
    sm3(&input)
}

/// 返回 `None` 表示该 `k` 不可用（r 或 s 为 0 / r+k==n），调用方应换一个 k。
pub fn sign_with_k(
    priv_bytes: &[u8; PRIVATE_KEY_SIZE],
    msg: &[u8],
    id: &[u8],
    k: &U256,
) -> Result<Option<[u8; SIGNATURE_SIZE]>> {
    let c = curve();
    let d = scalar_from_bytes(priv_bytes);
    if d.is_zero() {
        return Err(Error::BadArgument);
    }
    if k.is_zero() || k.cmp_u(&c.n) != core::cmp::Ordering::Less {
        return Err(Error::BadArgument);
    }
    let pub_bytes = public_from_private(priv_bytes)?;
    let e = U256::from_be_bytes(&message_digest(&pub_bytes, msg, id));

    let kg = c.mul(k, &c.g);
    let (x1, y1) = c.to_affine(&kg).ok_or(Error::BadPoint)?;
    let _ = y1;
    let x1 = U256::from_be_bytes(&x1.to_be_bytes());
    let r = c.nadd(&e, &x1);
    if r.is_zero() || c.nadd(&r, k) == c.n {
        return Ok(None);
    }
    let one = U256::ONE;
    let one_plus_d = c.nadd(&one, &d);
    let inv = c.ninv(&one_plus_d);
    let rd = c.nmul(&r, &d);
    let s = c.nmul(&inv, &c.nsub(k, &rd));
    if s.is_zero() {
        return Ok(None);
    }
    let mut sig = [0u8; SIGNATURE_SIZE];
    sig[..32].copy_from_slice(&r.to_be_bytes());
    sig[32..].copy_from_slice(&s.to_be_bytes());
    Ok(Some(sig))
}

/// 用 CSPRNG 生成签名（`k` 不可用时自动重取）。
pub fn sign(
    priv_bytes: &[u8; PRIVATE_KEY_SIZE],
    msg: &[u8],
    id: &[u8],
    rng: &mut impl Rng,
) -> Result<[u8; SIGNATURE_SIZE]> {
    for _ in 0..32 {
        let k = random_scalar(rng);
        if let Some(sig) = sign_with_k(priv_bytes, msg, id, &k)? {
            return Ok(sig);
        }
    }
    Err(Error::Internal)
}

/// SM2 验签。
pub fn verify(
    pub_bytes: &[u8; PUBLIC_KEY_SIZE],
    msg: &[u8],
    id: &[u8],
    sig: &[u8; SIGNATURE_SIZE],
) -> Result<bool> {
    let c = curve();
    let p = parse_public(pub_bytes)?;
    let mut rb = [0u8; 32];
    let mut sb = [0u8; 32];
    rb.copy_from_slice(&sig[..32]);
    sb.copy_from_slice(&sig[32..]);
    let r = U256::from_be_bytes(&rb);
    let s = U256::from_be_bytes(&sb);
    let one = U256::ONE;
    let n_minus_1 = c.nsub(&c.n, &one);
    if r.is_zero() || r.cmp_u(&n_minus_1) == core::cmp::Ordering::Greater {
        return Ok(false);
    }
    if s.is_zero() || s.cmp_u(&n_minus_1) == core::cmp::Ordering::Greater {
        return Ok(false);
    }
    let e = U256::from_be_bytes(&message_digest(pub_bytes, msg, id));
    let t = c.nadd(&r, &s);
    if t.is_zero() {
        return Ok(false);
    }
    let sg = c.mul(&s, &c.g);
    let tp = c.mul(&t, &p);
    let point = c.add(sg, tp);
    let (x1, _y1) = match c.to_affine(&point) {
        Some(v) => v,
        None => return Ok(false),
    };
    let r_check = c.nadd(&e, &x1);
    Ok(r_check == r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeedRng;

    #[test]
    fn curve_constants_and_generator() {
        let c = curve();
        let (gx, gy) = c.to_affine(&c.g).unwrap();
        assert_eq!(gx.to_be_bytes(), hex32(GX_HEX));
        assert_eq!(gy.to_be_bytes(), hex32(GY_HEX));
        assert!(c.on_curve(&gx, &gy));
        // n*G == 无穷远点
        let inf = c.mul(&c.n, &c.g);
        assert!(c.is_inf(&inf));
    }

    #[test]
    fn keygen_and_pubkey_match() {
        let mut rng = SeedRng::new(b"keypair-test");
        let kp = keygen(&mut rng);
        assert_eq!(public_from_private(&kp.private_key).unwrap(), kp.public_key);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = SeedRng::new(b"enc-test");
        let kp = keygen(&mut rng);
        for len in [1usize, 32, 100, 255] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let ct = encrypt_with_rng(&kp.public_key, &msg, &mut rng).unwrap();
            assert_eq!(ct.len(), 64 + 32 + len);
            assert_eq!(decrypt(&kp.private_key, &ct).unwrap(), msg);
            // 改 1 字节必须失败
            let mut bad = ct.clone();
            bad[64] ^= 1;
            assert!(decrypt(&kp.private_key, &bad).is_err());
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = SeedRng::new(b"sign-test");
        let kp = keygen(&mut rng);
        let msg = b"yanshu manifest";
        let sig = sign(&kp.private_key, msg, DEFAULT_ID, &mut rng).unwrap();
        assert!(verify(&kp.public_key, msg, DEFAULT_ID, &sig).unwrap());
        assert!(!verify(&kp.public_key, b"other", DEFAULT_ID, &sig).unwrap());
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&kp.public_key, msg, DEFAULT_ID, &bad).unwrap());
    }
}
