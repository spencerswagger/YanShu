//! 加密包 `YSPK/1.0` 打包 / 解包 —— 严格按 `docs/CRYPTO-PACK.md` v1 实现。
//!
//! 包结构（§4）：
//!
//! ```text
//! HEADER(112) | SENDER_PUB(65) | WRAPPED_KEY(129) | MANIFEST_SEC | SIG_SEC | CHUNK_SEC
//! ```
//!
//! * HEADER 字段偏移见 [`v1`] 的常量表；`HDR_CORE = HEADER[0..72)` 参与签名。
//! * 块记录 = 16 字节块头 + 密文 + 16 字节 tag；nonce 与 AAD 都是纯字节拼接（§6.4/§7.2）。
//! * 清单整体加密（`YSM1` 明文结构见 §8.2），每块 `SM3(明文)` 进清单。
//! * 签名输入 `SIG_INPUT = "YSSIG1" ‖ 0100 ‖ HDR_CORE ‖ SENDER_PUB ‖ MANIFEST_SEC`，
//!   签名值 DER（§10）。
//!
//! 解包按 §13 的校验顺序执行，任何不一致都返回具体错误码，没有"尽力恢复"。

use crate::bigint::U256;
use crate::der;
use crate::error::{Error, Result};
use crate::gcm;
use crate::hkdf::hkdf_sm3;
use crate::rng::Rng;
use crate::sm2;
use crate::sm3::{ct_eq, sm3};

/// `YSPK/1.0` 的字段偏移、长度与常量（契约 §5/§6/§7/§8/§10/§11）。
pub mod v1 {
    pub const MAGIC: [u8; 4] = *b"YSPK";
    pub const VERSION_MAJOR: u8 = 1;
    pub const VERSION_MINOR: u8 = 0;
    pub const VERSION_STRING: &str = "YSPK/1.0";
    pub const HEADER_LEN: usize = 112;

    pub const AEAD_ID_SM4_GCM: u8 = 1;
    pub const KDF_ID_HKDF_SM3: u8 = 1;
    pub const SM2_WRAP_ID_C1C3C2: u8 = 1;
    pub const SIG_ID_SM2_SM3_DER: u8 = 1;

    pub const FLAG_NAME_OBFUSCATED: u32 = 1 << 0;
    pub const FLAG_SENDER_SIGNED: u32 = 1 << 1;

    // HEADER 偏移
    pub const OFF_MAGIC: usize = 0;
    pub const OFF_VERSION_MAJOR: usize = 4;
    pub const OFF_VERSION_MINOR: usize = 5;
    pub const OFF_HEADER_LEN: usize = 6;
    pub const OFF_FLAGS: usize = 8;
    pub const OFF_AEAD_ID: usize = 12;
    pub const OFF_KDF_ID: usize = 13;
    pub const OFF_WRAP_ID: usize = 14;
    pub const OFF_SIG_ID: usize = 15;
    pub const OFF_CHUNK_SIZE: usize = 16;
    pub const OFF_CHUNK_COUNT: usize = 20;
    pub const OFF_PLAINTEXT_SIZE: usize = 24;
    pub const OFF_WRAPPED_KEY_LEN: usize = 32;
    pub const OFF_MANIFEST_LEN: usize = 40;
    pub const OFF_MANIFEST_PT_LEN: usize = 48;
    pub const OFF_SENDER_PUB_LEN: usize = 52;
    pub const OFF_KDF_SALT: usize = 56;
    pub const OFF_SIG_LEN: usize = 72;
    pub const OFF_RESERVED: usize = 80;
    pub const HDR_CORE_LEN: usize = 72;

    pub const KDF_SALT_LEN: usize = 16;
    pub const SENDER_PUB_LEN: usize = 65;
    pub const WRAPPED_KEY_LEN: usize = 129;
    pub const TAG_LEN: usize = 16;
    pub const CHUNK_HEADER_LEN: usize = 16;
    pub const MIN_SIG_LEN: usize = 70;
    pub const MAX_SIG_LEN: usize = 72;

    pub const MIN_CHUNK_SIZE: u32 = 16;
    pub const MAX_CHUNK_SIZE: u32 = 1_048_576;
    pub const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;
    pub const MAX_CHUNK_COUNT: u32 = 1_048_576;
    pub const MAX_PLAINTEXT_SIZE: u64 = 4_294_967_296;

    pub const MANIFEST_MAGIC: [u8; 4] = *b"YSM1";
    pub const MANIFEST_VERSION: u8 = 1;
    pub const NAME_MODE_REAL: u8 = 0;
    pub const NAME_MODE_OBFUSCATED: u8 = 1;
    pub const DIGEST_ALG_SM3: u8 = 1;
    pub const DIGEST_LEN: u8 = 32;

    pub const SIG_PREFIX: [u8; 6] = *b"YSSIG1";

    pub const AAD_LABEL_CHUNK: u8 = 0x01;
    pub const AAD_LABEL_MANIFEST: u8 = 0x02;

    pub const KDF_INFO_CHUNK: &[u8] = b"YANSHU/v1/chunk-key";
    pub const KDF_INFO_MANIFEST: &[u8] = b"YANSHU/v1/manifest-key";
    pub const KEK_LEN: usize = 16;

    /// 清单 nonce：`ff*8 ‖ 00 00 00 01`
    pub const MANIFEST_NONCE: [u8; 12] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    ];

    /// 块 nonce：`u64be(index) ‖ 00 00 00 ‖ last_flag`
    pub fn chunk_nonce(index: u32, last: bool) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&(index as u64).to_be_bytes());
        n[11] = if last { 0x01 } else { 0x00 };
        n
    }
}

use v1::*;

/// 包头（HEADER，112 字节）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: u32,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub plaintext_size: u64,
    pub wrapped_key_len: u64,
    pub manifest_len: u64,
    pub manifest_pt_len: u32,
    pub sender_pub_len: u32,
    pub kdf_salt: [u8; KDF_SALT_LEN],
    pub sig_len: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        out[OFF_VERSION_MAJOR] = VERSION_MAJOR;
        out[OFF_VERSION_MINOR] = VERSION_MINOR;
        out[OFF_HEADER_LEN..OFF_HEADER_LEN + 2].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        out[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&self.flags.to_be_bytes());
        out[OFF_AEAD_ID] = AEAD_ID_SM4_GCM;
        out[OFF_KDF_ID] = KDF_ID_HKDF_SM3;
        out[OFF_WRAP_ID] = SM2_WRAP_ID_C1C3C2;
        out[OFF_SIG_ID] = SIG_ID_SM2_SM3_DER;
        out[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4].copy_from_slice(&self.chunk_size.to_be_bytes());
        out[OFF_CHUNK_COUNT..OFF_CHUNK_COUNT + 4].copy_from_slice(&self.chunk_count.to_be_bytes());
        out[OFF_PLAINTEXT_SIZE..OFF_PLAINTEXT_SIZE + 8]
            .copy_from_slice(&self.plaintext_size.to_be_bytes());
        out[OFF_WRAPPED_KEY_LEN..OFF_WRAPPED_KEY_LEN + 8]
            .copy_from_slice(&self.wrapped_key_len.to_be_bytes());
        out[OFF_MANIFEST_LEN..OFF_MANIFEST_LEN + 8]
            .copy_from_slice(&self.manifest_len.to_be_bytes());
        out[OFF_MANIFEST_PT_LEN..OFF_MANIFEST_PT_LEN + 4]
            .copy_from_slice(&self.manifest_pt_len.to_be_bytes());
        out[OFF_SENDER_PUB_LEN..OFF_SENDER_PUB_LEN + 4]
            .copy_from_slice(&self.sender_pub_len.to_be_bytes());
        out[OFF_KDF_SALT..OFF_KDF_SALT + KDF_SALT_LEN].copy_from_slice(&self.kdf_salt);
        out[OFF_SIG_LEN..OFF_SIG_LEN + 8].copy_from_slice(&self.sig_len.to_be_bytes());
        // OFF_RESERVED..HEADER_LEN 保持全 0
        out
    }

    /// 严格解析（契约 §13 的第 1–11 项）。
    pub fn decode(buf: &[u8]) -> Result<Header> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if buf[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
            return Err(Error::BadMagic);
        }
        if buf[OFF_VERSION_MAJOR] != VERSION_MAJOR || buf[OFF_VERSION_MINOR] != VERSION_MINOR {
            return Err(Error::UnsupportedVersion);
        }
        let header_len = u16::from_be_bytes(
            buf[OFF_HEADER_LEN..OFF_HEADER_LEN + 2]
                .try_into()
                .expect("2"),
        ) as usize;
        if header_len != HEADER_LEN {
            return Err(Error::HeaderInvalid);
        }
        if buf[OFF_AEAD_ID] != AEAD_ID_SM4_GCM
            || buf[OFF_KDF_ID] != KDF_ID_HKDF_SM3
            || buf[OFF_WRAP_ID] != SM2_WRAP_ID_C1C3C2
            || buf[OFF_SIG_ID] != SIG_ID_SM2_SM3_DER
        {
            return Err(Error::AlgUnsupported);
        }
        let flags = u32::from_be_bytes(buf[OFF_FLAGS..OFF_FLAGS + 4].try_into().expect("4"));
        if flags & !(FLAG_NAME_OBFUSCATED | FLAG_SENDER_SIGNED) != 0 {
            return Err(Error::BadFlags);
        }
        if flags & FLAG_SENDER_SIGNED == 0 {
            return Err(Error::Unsigned);
        }
        if buf[OFF_RESERVED..HEADER_LEN].iter().any(|&b| b != 0) {
            return Err(Error::HeaderInvalid);
        }
        let chunk_size = u32::from_be_bytes(
            buf[OFF_CHUNK_SIZE..OFF_CHUNK_SIZE + 4]
                .try_into()
                .expect("4"),
        );
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::HeaderInvalid);
        }
        let chunk_count = u32::from_be_bytes(
            buf[OFF_CHUNK_COUNT..OFF_CHUNK_COUNT + 4]
                .try_into()
                .expect("4"),
        );
        let plaintext_size = u64::from_be_bytes(
            buf[OFF_PLAINTEXT_SIZE..OFF_PLAINTEXT_SIZE + 8]
                .try_into()
                .expect("8"),
        );
        if plaintext_size > MAX_PLAINTEXT_SIZE {
            return Err(Error::HeaderInvalid);
        }
        if chunk_count == 0
            || chunk_count > MAX_CHUNK_COUNT
            || chunk_count as u64 != expected_chunk_count(plaintext_size, chunk_size)
        {
            return Err(Error::LengthInconsistent);
        }
        let wrapped_key_len = u64::from_be_bytes(
            buf[OFF_WRAPPED_KEY_LEN..OFF_WRAPPED_KEY_LEN + 8]
                .try_into()
                .expect("8"),
        );
        let manifest_len = u64::from_be_bytes(
            buf[OFF_MANIFEST_LEN..OFF_MANIFEST_LEN + 8]
                .try_into()
                .expect("8"),
        );
        let manifest_pt_len = u32::from_be_bytes(
            buf[OFF_MANIFEST_PT_LEN..OFF_MANIFEST_PT_LEN + 4]
                .try_into()
                .expect("4"),
        );
        let sender_pub_len = u32::from_be_bytes(
            buf[OFF_SENDER_PUB_LEN..OFF_SENDER_PUB_LEN + 4]
                .try_into()
                .expect("4"),
        );
        if wrapped_key_len != WRAPPED_KEY_LEN as u64
            || sender_pub_len != SENDER_PUB_LEN as u32
            || manifest_len != manifest_pt_len as u64 + TAG_LEN as u64
        {
            return Err(Error::LengthInconsistent);
        }
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        kdf_salt.copy_from_slice(&buf[OFF_KDF_SALT..OFF_KDF_SALT + KDF_SALT_LEN]);
        let sig_len = u64::from_be_bytes(buf[OFF_SIG_LEN..OFF_SIG_LEN + 8].try_into().expect("8"));
        if sig_len < MIN_SIG_LEN as u64 || sig_len > MAX_SIG_LEN as u64 {
            return Err(Error::HeaderInvalid);
        }
        Ok(Header {
            flags,
            chunk_size,
            chunk_count,
            plaintext_size,
            wrapped_key_len,
            manifest_len,
            manifest_pt_len,
            sender_pub_len,
            kdf_salt,
            sig_len,
        })
    }
}

/// 块数：`n = ceil(S / C)`，空文件 `n = 1`。
pub fn expected_chunk_count(plaintext_size: u64, chunk_size: u32) -> u64 {
    if plaintext_size == 0 {
        1
    } else {
        plaintext_size.div_ceil(chunk_size as u64)
    }
}

/// 第 `index` 块的明文字节数（契约 §4.2）。
pub fn chunk_plain_len(plaintext_size: u64, chunk_size: u32, chunk_count: u32, index: u32) -> u32 {
    if index + 1 < chunk_count {
        chunk_size
    } else {
        (plaintext_size - chunk_size as u64 * (chunk_count as u64 - 1)) as u32
    }
}

/// `AAD_CHUNK`（32 字节，§7.2）。
pub fn aad_chunk(header: &Header, index: u32, last: bool, pt_len: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = AAD_LABEL_CHUNK;
    out[1..5].copy_from_slice(&MAGIC);
    out[5] = VERSION_MAJOR;
    out[6] = VERSION_MINOR;
    out[7..11].copy_from_slice(&header.chunk_size.to_be_bytes());
    out[11..15].copy_from_slice(&header.chunk_count.to_be_bytes());
    out[15..23].copy_from_slice(&header.plaintext_size.to_be_bytes());
    out[23..27].copy_from_slice(&index.to_be_bytes());
    out[27] = if last { 1 } else { 0 };
    out[28..32].copy_from_slice(&pt_len.to_be_bytes());
    out
}

/// `AAD_MANIFEST`（31 字节，§7.3）。
pub fn aad_manifest(header: &Header) -> [u8; 31] {
    let mut out = [0u8; 31];
    out[0] = AAD_LABEL_MANIFEST;
    out[1..5].copy_from_slice(&MAGIC);
    out[5] = VERSION_MAJOR;
    out[6] = VERSION_MINOR;
    out[7..11].copy_from_slice(&header.flags.to_be_bytes());
    out[11..15].copy_from_slice(&header.chunk_size.to_be_bytes());
    out[15..19].copy_from_slice(&header.chunk_count.to_be_bytes());
    out[19..27].copy_from_slice(&header.plaintext_size.to_be_bytes());
    out[27..31].copy_from_slice(&header.manifest_pt_len.to_be_bytes());
    out
}

/// 清单明文（`YSM1`，§8.2）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name_mode: u8,
    pub file_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub created_at_ms: u64,
    pub name: String,
    pub mime: String,
    pub ext: String,
    pub digests: Vec<[u8; 32]>,
}

/// 契约 §3.3：文件名只允许 basename（不含 `/`、`\`、NUL、0x00–0x1F），≤255 字节。
pub fn valid_name(s: &str) -> bool {
    s.len() <= 255 && !s.bytes().any(|b| b < 0x20 || b == b'/' || b == b'\\')
}

/// 契约 §3.3：MIME 为 ASCII 小写，字符集 `[a-z0-9!#$&^_.+-]` 与单个 `/`，1..=127 字节。
pub fn valid_mime(s: &str) -> bool {
    if s.is_empty() || s.len() > 127 {
        return false;
    }
    let mut slashes = 0usize;
    for b in s.bytes() {
        match b {
            b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'^'
            | b'_'
            | b'.'
            | b'+'
            | b'-' => {}
            b'/' => slashes += 1,
            _ => return false,
        }
    }
    slashes == 1
}

/// 契约 §3.3：扩展名为 ASCII 小写字母/数字，≤16 字节，不含点。
pub fn valid_ext(s: &str) -> bool {
    s.len() <= 16
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !valid_name(&self.name) || !valid_mime(&self.mime) || !valid_ext(&self.ext) {
            return Err(Error::BadArgument);
        }
        let mut out = Vec::with_capacity(
            42 + self.name.len() + self.mime.len() + self.ext.len() + self.digests.len() * 32,
        );
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.push(MANIFEST_VERSION);
        out.push(self.name_mode);
        out.push(DIGEST_ALG_SM3);
        out.push(DIGEST_LEN);
        out.extend_from_slice(&self.file_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&(self.mime.len() as u16).to_be_bytes());
        out.extend_from_slice(self.mime.as_bytes());
        out.extend_from_slice(&(self.ext.len() as u16).to_be_bytes());
        out.extend_from_slice(self.ext.as_bytes());
        out.extend_from_slice(&((self.digests.len() * 32) as u32).to_be_bytes());
        for d in &self.digests {
            out.extend_from_slice(d);
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Manifest> {
        if buf.len() < 42 {
            return Err(Error::BadManifestRecord);
        }
        if buf[0..4] != MANIFEST_MAGIC
            || buf[4] != MANIFEST_VERSION
            || buf[6] != DIGEST_ALG_SM3
            || buf[7] != DIGEST_LEN
        {
            return Err(Error::BadManifestRecord);
        }
        let name_mode = buf[5];
        if name_mode != NAME_MODE_REAL && name_mode != NAME_MODE_OBFUSCATED {
            return Err(Error::BadManifestRecord);
        }
        let file_size = u64::from_be_bytes(buf[8..16].try_into().expect("8"));
        let chunk_size = u32::from_be_bytes(buf[16..20].try_into().expect("4"));
        let chunk_count = u32::from_be_bytes(buf[20..24].try_into().expect("4"));
        let created_at_ms = u64::from_be_bytes(buf[24..32].try_into().expect("8"));

        let mut pos = 32usize;
        let name_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().expect("2")) as usize;
        pos += 2;
        if name_len > 255 || pos + name_len > buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let name = core::str::from_utf8(&buf[pos..pos + name_len])
            .map_err(|_| Error::BadManifestRecord)?
            .to_string();
        pos += name_len;

        if pos + 2 > buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let mime_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().expect("2")) as usize;
        pos += 2;
        if mime_len == 0 || mime_len > 127 || pos + mime_len > buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let mime = core::str::from_utf8(&buf[pos..pos + mime_len])
            .map_err(|_| Error::BadManifestRecord)?
            .to_string();
        pos += mime_len;

        if pos + 2 > buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let ext_len = u16::from_be_bytes(buf[pos..pos + 2].try_into().expect("2")) as usize;
        pos += 2;
        if ext_len > 16 || pos + ext_len > buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let ext = core::str::from_utf8(&buf[pos..pos + ext_len])
            .map_err(|_| Error::BadManifestRecord)?
            .to_string();
        pos += ext_len;
        if !valid_name(&name) || !valid_mime(&mime) || !valid_ext(&ext) {
            return Err(Error::BadManifestRecord);
        }

        if pos + 4 > buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let digest_table_len =
            u32::from_be_bytes(buf[pos..pos + 4].try_into().expect("4")) as usize;
        pos += 4;
        if digest_table_len != chunk_count as usize * 32 {
            return Err(Error::LengthInconsistent);
        }
        if pos + digest_table_len != buf.len() {
            return Err(Error::BadManifestRecord);
        }
        let mut digests = Vec::with_capacity(chunk_count as usize);
        for _ in 0..chunk_count {
            let mut d = [0u8; 32];
            d.copy_from_slice(&buf[pos..pos + 32]);
            digests.push(d);
            pos += 32;
        }
        Ok(Manifest {
            name_mode,
            file_size,
            chunk_size,
            chunk_count,
            created_at_ms,
            name,
            mime,
            ext,
            digests,
        })
    }
}

/// 打包输入（契约口径：65 字节未压缩公钥、清单 `ext`/`created_at`）。
pub struct PackInput<'a> {
    /// 接收方公钥（65 字节，`0x04 ‖ X ‖ Y`）
    pub recipient_public: &'a [u8; SENDER_PUB_LEN],
    /// 发送方私钥（32 字节）
    pub sender_private: &'a [u8; 32],
    pub name: &'a str,
    pub mime: &'a str,
    /// 清单里的扩展名（可为空，ASCII 小写、不含点）
    pub ext: &'a str,
    /// 清单 `CREATED_AT`（Unix 毫秒）
    pub created_at_ms: u64,
    /// 明文块大小（契约 `CHUNK_SIZE`）
    pub chunk_size: u32,
    pub data: &'a [u8],
}

/// 可复现打包参数（测试向量用；生产中由 [`pack`] 用 CSPRNG 生成）。
pub struct PackParams {
    pub dk: [u8; 32],
    pub kdf_salt: [u8; KDF_SALT_LEN],
    pub k_enc: U256,
    pub k_sig: U256,
}

fn strip_pub_prefix(pub65: &[u8; SENDER_PUB_LEN]) -> Result<[u8; 64]> {
    if pub65[0] != 0x04 {
        return Err(Error::BadPoint);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&pub65[1..]);
    Ok(out)
}

fn kek_chunk(dk: &[u8; 32], salt: &[u8; KDF_SALT_LEN]) -> [u8; KEK_LEN] {
    let mut k = [0u8; KEK_LEN];
    hkdf_sm3(salt, dk, KDF_INFO_CHUNK, &mut k);
    k
}

fn kek_manifest(dk: &[u8; 32], salt: &[u8; KDF_SALT_LEN]) -> [u8; KEK_LEN] {
    let mut k = [0u8; KEK_LEN];
    hkdf_sm3(salt, dk, KDF_INFO_MANIFEST, &mut k);
    k
}

fn random_scalar(rng: &mut impl Rng) -> Result<U256> {
    let c = crate::sm2::curve_order();
    for _ in 0..64 {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        let v = U256::from_be_bytes(&b);
        if !v.is_zero() && v.cmp_u(&c) == core::cmp::Ordering::Less {
            return Ok(v);
        }
    }
    Err(Error::Rng)
}

/// 打包（随机 DK / KDF_SALT / k_enc / k_sig）。
pub fn pack(input: &PackInput, rng: &mut impl Rng) -> Result<Vec<u8>> {
    let mut dk = [0u8; 32];
    rng.fill(&mut dk);
    let mut kdf_salt = [0u8; KDF_SALT_LEN];
    rng.fill(&mut kdf_salt);
    let k_enc = random_scalar(rng)?;
    let k_sig = random_scalar(rng)?;
    pack_with_params(
        input,
        &PackParams {
            dk,
            kdf_salt,
            k_enc,
            k_sig,
        },
    )
}

/// 打包结果的**上界**（不消耗随机数）。
///
/// 唯一不确定的是 DER 签名长度（70..72），这里按 72 算。调用方可以先用它申请缓冲区，
/// 再真正打包一次——这样"先问大小再分配"不会因为随机 k 而差 1~2 字节。
pub fn pack_bound(input: &PackInput) -> Result<usize> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&input.chunk_size) {
        return Err(Error::BadArgument);
    }
    if input.data.len() as u64 > MAX_PLAINTEXT_SIZE {
        return Err(Error::BadArgument);
    }
    if !valid_name(input.name) || !valid_mime(input.mime) || !valid_ext(input.ext) {
        return Err(Error::BadArgument);
    }
    let n = expected_chunk_count(input.data.len() as u64, input.chunk_size);
    if n > MAX_CHUNK_COUNT as u64 {
        return Err(Error::BadArgument);
    }
    let manifest_pt =
        42 + input.name.len() + input.mime.len() + input.ext.len() + (n as usize) * 32;
    let prelude =
        HEADER_LEN + SENDER_PUB_LEN + WRAPPED_KEY_LEN + (manifest_pt + TAG_LEN) + MAX_SIG_LEN;
    let chunks = input.data.len() + (n as usize) * (CHUNK_HEADER_LEN + TAG_LEN);
    Ok(prelude + chunks)
}

/// 用固定参数打包（测试向量可复现；生产 MUST NOT 用固定值）。
pub fn pack_with_params(input: &PackInput, params: &PackParams) -> Result<Vec<u8>> {
    let chunk_size = input.chunk_size;
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(Error::BadArgument);
    }
    if input.data.len() as u64 > MAX_PLAINTEXT_SIZE {
        return Err(Error::BadArgument);
    }
    let chunk_count64 = expected_chunk_count(input.data.len() as u64, chunk_size);
    if chunk_count64 > MAX_CHUNK_COUNT as u64 {
        return Err(Error::BadArgument);
    }
    let chunk_count = chunk_count64 as u32;

    let sender_pub64 = sm2::public_from_private(input.sender_private)?;
    let mut sender_pub = [0u8; SENDER_PUB_LEN];
    sender_pub[0] = 0x04;
    sender_pub[1..].copy_from_slice(&sender_pub64);

    let kc = kek_chunk(&params.dk, &params.kdf_salt);
    let km = kek_manifest(&params.dk, &params.kdf_salt);

    // 块先加密（清单里要放每块明文的 SM3）
    let mut chunk_bytes: Vec<u8> = Vec::with_capacity(input.data.len() + chunk_count as usize * 32);
    let mut digests: Vec<[u8; 32]> = Vec::with_capacity(chunk_count as usize);
    for index in 0..chunk_count {
        let start = index as usize * chunk_size as usize;
        let pt_len =
            chunk_plain_len(input.data.len() as u64, chunk_size, chunk_count, index) as usize;
        let end = core::cmp::min(start + pt_len, input.data.len());
        let pt = &input.data[start..end];
        let last = index + 1 == chunk_count;
        digests.push(sm3(pt));

        // AAD 依赖 header 的若干字段，先用等价值拼出来
        let header_for_aad = Header {
            flags: FLAG_SENDER_SIGNED,
            chunk_size,
            chunk_count,
            plaintext_size: input.data.len() as u64,
            wrapped_key_len: WRAPPED_KEY_LEN as u64,
            manifest_len: 0,
            manifest_pt_len: 0,
            sender_pub_len: SENDER_PUB_LEN as u32,
            kdf_salt: params.kdf_salt,
            sig_len: 0,
        };
        let aad = aad_chunk(&header_for_aad, index, last, pt_len as u32);
        let nonce = chunk_nonce(index, last);
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm::encrypt(&kc, &nonce, &aad, pt, &mut ct, &mut tag);

        chunk_bytes.extend_from_slice(&index.to_be_bytes());
        chunk_bytes.extend_from_slice(&(pt_len as u32).to_be_bytes());
        chunk_bytes.extend_from_slice(&(pt.len() as u32).to_be_bytes());
        chunk_bytes.push(if last { 1 } else { 0 });
        chunk_bytes.push(0);
        chunk_bytes.extend_from_slice(&0u16.to_be_bytes());
        chunk_bytes.extend_from_slice(&ct);
        chunk_bytes.extend_from_slice(&tag);
    }

    let manifest = Manifest {
        name_mode: NAME_MODE_REAL,
        file_size: input.data.len() as u64,
        chunk_size,
        chunk_count,
        created_at_ms: input.created_at_ms,
        name: input.name.to_string(),
        mime: input.mime.to_string(),
        ext: input.ext.to_string(),
        digests,
    };
    let manifest_pt = manifest.encode()?;

    let mut header = Header {
        flags: FLAG_SENDER_SIGNED,
        chunk_size,
        chunk_count,
        plaintext_size: input.data.len() as u64,
        wrapped_key_len: WRAPPED_KEY_LEN as u64,
        manifest_len: manifest_pt.len() as u64 + TAG_LEN as u64,
        manifest_pt_len: manifest_pt.len() as u32,
        sender_pub_len: SENDER_PUB_LEN as u32,
        kdf_salt: params.kdf_salt,
        sig_len: MIN_SIG_LEN as u64, // 先占位，签名后回填（SIG_LEN 不在 HDR_CORE 里）
    };

    let aad_m = aad_manifest(&header);
    let mut manifest_ct = vec![0u8; manifest_pt.len()];
    let mut manifest_tag = [0u8; TAG_LEN];
    gcm::encrypt(
        &km,
        &MANIFEST_NONCE,
        &aad_m,
        &manifest_pt,
        &mut manifest_ct,
        &mut manifest_tag,
    );
    let mut manifest_sec = manifest_ct;
    manifest_sec.extend_from_slice(&manifest_tag);

    // SIG_INPUT = "YSSIG1" ‖ 0100 ‖ HDR_CORE ‖ SENDER_PUB ‖ MANIFEST_SEC
    let header_bytes = header.encode();
    let mut sig_input = Vec::with_capacity(8 + HDR_CORE_LEN + SENDER_PUB_LEN + manifest_sec.len());
    sig_input.extend_from_slice(&SIG_PREFIX);
    sig_input.push(VERSION_MAJOR);
    sig_input.push(VERSION_MINOR);
    sig_input.extend_from_slice(&header_bytes[..HDR_CORE_LEN]);
    sig_input.extend_from_slice(&sender_pub);
    sig_input.extend_from_slice(&manifest_sec);

    let raw = sm2::sign_with_k(
        input.sender_private,
        &sig_input,
        sm2::DEFAULT_ID,
        &params.k_sig,
    )?
    .ok_or(Error::Internal)?;
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..]);
    let sig_der = der::encode_signature(&r, &s);
    if sig_der.len() < MIN_SIG_LEN || sig_der.len() > MAX_SIG_LEN {
        return Err(Error::Internal);
    }
    header.sig_len = sig_der.len() as u64;

    // 封装 DK（契约 C1 带 0x04 前缀；API 入参是 65 字节未压缩点）
    let recipient64 = strip_pub_prefix(input.recipient_public)?;
    let wrapped64 = sm2::encrypt(&recipient64, &params.dk, &params.k_enc)?;
    if wrapped64.len() != WRAPPED_KEY_LEN - 1 {
        return Err(Error::Internal);
    }
    let mut wrapped = Vec::with_capacity(WRAPPED_KEY_LEN);
    wrapped.push(0x04);
    wrapped.extend_from_slice(&wrapped64);

    let header_bytes = header.encode();
    let mut out = Vec::with_capacity(
        HEADER_LEN
            + SENDER_PUB_LEN
            + WRAPPED_KEY_LEN
            + manifest_sec.len()
            + sig_der.len()
            + chunk_bytes.len(),
    );
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&sender_pub);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&manifest_sec);
    out.extend_from_slice(&sig_der);
    out.extend_from_slice(&chunk_bytes);
    Ok(out)
}

/// 解包结果。
#[derive(Debug)]
pub struct Unpacked {
    pub header: Header,
    pub manifest: Manifest,
    pub sender_public: [u8; SENDER_PUB_LEN],
    pub sender_code: String,
    pub data: Vec<u8>,
}

struct Opened {
    header: Header,
    manifest: Manifest,
    sender_public: [u8; SENDER_PUB_LEN],
    sender_code: String,
    dk: [u8; 32],
    chunk_offset: usize,
}

fn total_envelope_len(header: &Header) -> Result<usize> {
    let prelude = HEADER_LEN
        + SENDER_PUB_LEN
        + WRAPPED_KEY_LEN
        + header.manifest_len as usize
        + header.sig_len as usize;
    let mut chunks = 0usize;
    for i in 0..header.chunk_count {
        chunks += CHUNK_HEADER_LEN
            + TAG_LEN
            + chunk_plain_len(
                header.plaintext_size,
                header.chunk_size,
                header.chunk_count,
                i,
            ) as usize;
    }
    prelude.checked_add(chunks).ok_or(Error::LengthInconsistent)
}

/// 解到清单为止（含验签），不解数据块。
/// prelude 长度（契约 §4.2）：`112 + 65 + 129 + MANIFEST_LEN + SIG_LEN`。
fn prelude_len(header: &Header) -> Result<usize> {
    HEADER_LEN
        .checked_add(SENDER_PUB_LEN)
        .and_then(|v| v.checked_add(WRAPPED_KEY_LEN))
        .and_then(|v| v.checked_add(header.manifest_len as usize))
        .and_then(|v| v.checked_add(header.sig_len as usize))
        .ok_or(Error::HeaderInvalid)
}

/// 只要 **prelude 完整** 就能解到清单并验签（契约 §4.3：清单与签名都在 prelude 里）。
///
/// 这对应"收件人还没下完块，先看到发件人码/文件名/大小/块数"的能力。
/// **注意**：此时只验证了来源（`SENDER_PUB` 的签名）与清单本身；块摘要 / 块 AEAD
/// 都还没校验，调用方不能据此宣称"数据完整"。
fn open_from_prelude(pack: &[u8], recipient_private: &[u8; 32]) -> Result<Opened> {
    let header = Header::decode(pack)?;
    let plen = prelude_len(&header)?;
    if pack.len() < plen {
        return Err(Error::Truncated);
    }

    let mut pos = HEADER_LEN;
    let mut sender_public = [0u8; SENDER_PUB_LEN];
    sender_public.copy_from_slice(&pack[pos..pos + SENDER_PUB_LEN]);
    pos += SENDER_PUB_LEN;
    if sender_public[0] != 0x04 {
        return Err(Error::BadPoint);
    }

    let wrapped = &pack[pos..pos + WRAPPED_KEY_LEN];
    pos += WRAPPED_KEY_LEN;
    if wrapped[0] != 0x04 {
        return Err(Error::BadKeyRecord);
    }
    let dk_vec = sm2::decrypt(recipient_private, &wrapped[1..]).map_err(|_| Error::BadKeyRecord)?;
    if dk_vec.len() != 32 {
        return Err(Error::BadKeyRecord);
    }
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dk_vec);

    let manifest_sec = &pack[pos..pos + header.manifest_len as usize];
    pos += header.manifest_len as usize;
    let sig_sec = &pack[pos..pos + header.sig_len as usize];
    pos += header.sig_len as usize;

    // 清单解密
    let km = kek_manifest(&dk, &header.kdf_salt);
    let aad_m = aad_manifest(&header);
    let ct = &manifest_sec[..manifest_sec.len() - TAG_LEN];
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&manifest_sec[manifest_sec.len() - TAG_LEN..]);
    let manifest_pt =
        gcm::decrypt(&km, &MANIFEST_NONCE, &aad_m, ct, &tag).ok_or(Error::ManifestAuthFailed)?;
    let manifest = Manifest::decode(&manifest_pt)?;

    if manifest.file_size != header.plaintext_size
        || manifest.chunk_size != header.chunk_size
        || manifest.chunk_count != header.chunk_count
        || manifest.digests.len() != header.chunk_count as usize
    {
        return Err(Error::LengthInconsistent);
    }

    // 验签（SIG_INPUT 用包内的 HDR_CORE / SENDER_PUB / MANIFEST_SEC）
    let mut sig_input = Vec::with_capacity(8 + HDR_CORE_LEN + SENDER_PUB_LEN + manifest_sec.len());
    sig_input.extend_from_slice(&SIG_PREFIX);
    sig_input.push(VERSION_MAJOR);
    sig_input.push(VERSION_MINOR);
    sig_input.extend_from_slice(&pack[..HDR_CORE_LEN]);
    sig_input.extend_from_slice(&sender_public);
    sig_input.extend_from_slice(manifest_sec);

    // §13 #11：SIG_LEN 必须等于 DER 自述长度，否则 HEADER_INVALID（先于验签）
    if sig_sec.len() < 2 || sig_sec[0] != 0x30 || sig_sec[1] as usize + 2 != sig_sec.len() {
        return Err(Error::HeaderInvalid);
    }
    let (r, s) = der::decode_signature(sig_sec)?;
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    let pub64 = {
        let mut p = [0u8; 64];
        p.copy_from_slice(&sender_public[1..]);
        p
    };
    if !sm2::verify(&pub64, &sig_input, sm2::DEFAULT_ID, &raw)? {
        return Err(Error::SignatureMismatch);
    }

    let sender_code = crate::code::from_public_key(&sender_public);

    Ok(Opened {
        header,
        manifest,
        sender_public,
        sender_code,
        dk,
        chunk_offset: pos,
    })
}

/// 严格入口：要求整包长度与 `ENVELOPE_LEN` 完全一致（截断/尾随都拒）。
fn open(pack: &[u8], recipient_private: &[u8; 32]) -> Result<Opened> {
    let header = Header::decode(pack)?;
    let expected_len = total_envelope_len(&header)?;
    if pack.len() < expected_len {
        return Err(Error::Truncated);
    }
    if pack.len() > expected_len {
        return Err(Error::TrailingBytes);
    }
    open_from_prelude(pack, recipient_private)
}

/// 只解到清单（不解数据块）的结果。
#[derive(Debug)]
pub struct OpenedInfo {
    pub header: Header,
    pub manifest: Manifest,
    pub sender_public: [u8; SENDER_PUB_LEN],
    pub sender_code: String,
}

/// 只解 prelude（允许整包还没到齐）：返回包头、清单与包内自证的发送方信息。
pub fn open_only_prelude(pack: &[u8], recipient_private: &[u8; 32]) -> Result<OpenedInfo> {
    let o = open_from_prelude(pack, recipient_private)?;
    Ok(OpenedInfo {
        header: o.header,
        manifest: o.manifest,
        sender_public: o.sender_public,
        sender_code: o.sender_code,
    })
}

/// 只解到清单（不解数据块，不做发送方校验）。
pub fn open_only(pack: &[u8], recipient_private: &[u8; 32]) -> Result<OpenedInfo> {
    let o = open(pack, recipient_private)?;
    Ok(OpenedInfo {
        header: o.header,
        manifest: o.manifest,
        sender_public: o.sender_public,
        sender_code: o.sender_code,
    })
}

/// 只解到清单（不解数据块），返回包头、清单与包内自证的发送方信息。
pub fn open_manifest(
    pack: &[u8],
    recipient_private: &[u8; 32],
) -> Result<(Header, Manifest, [u8; SENDER_PUB_LEN], String)> {
    let o = open(pack, recipient_private)?;
    Ok((o.header, o.manifest, o.sender_public, o.sender_code))
}

/// 严格解包（契约 §13 全表）。
///
/// 来源由包内 `SENDER_PUB` 自证：验签用包里的公钥，发送方 4 位码也由它派生
/// （契约 §10.3），调用方**不需要**再传公钥。`expected_sender_code` 给了就顺带做
/// §13 #18 的比对（可与 API 元数据里的码对一遍）。
pub fn unpack(
    pack: &[u8],
    recipient_private: &[u8; 32],
    expected_sender_code: Option<&str>,
) -> Result<Unpacked> {
    let opened = open(pack, recipient_private)?;
    if let Some(code) = expected_sender_code {
        if opened.sender_code != code {
            return Err(Error::SenderMismatch);
        }
    }
    finish_unpack(pack, opened)
}

/// 按发送方 4 位码校验后解包（等价于 `unpack(..., Some(code))`）。
pub fn unpack_with_code(
    pack: &[u8],
    recipient_private: &[u8; 32],
    expected_sender_code: &str,
) -> Result<Unpacked> {
    unpack(pack, recipient_private, Some(expected_sender_code))
}

/// 解包并额外核对调用方手里的发送方公钥（64 字节 `X‖Y`）。
/// 验签仍然是包内公钥做的，这里只是多一道"是不是同一个人"的比对。
pub fn unpack_expect_sender(
    pack: &[u8],
    recipient_private: &[u8; 32],
    sender_public: &[u8; 64],
) -> Result<Unpacked> {
    let opened = open(pack, recipient_private)?;
    if opened.sender_public[1..] != sender_public[..] {
        return Err(Error::SenderMismatch);
    }
    finish_unpack(pack, opened)
}

/// 不做发送方校验的解包（仅测试/内部用）。
pub fn unpack_unchecked(pack: &[u8], recipient_private: &[u8; 32]) -> Result<Unpacked> {
    let opened = open(pack, recipient_private)?;
    finish_unpack(pack, opened)
}

fn finish_unpack(pack: &[u8], opened: Opened) -> Result<Unpacked> {
    let header = opened.header;
    let manifest = opened.manifest;
    let kc = kek_chunk(&opened.dk, &header.kdf_salt);

    let mut data = Vec::with_capacity(header.plaintext_size as usize);
    let mut pos = opened.chunk_offset;
    for index in 0..header.chunk_count {
        let end_of_header = pos + CHUNK_HEADER_LEN;
        if end_of_header > pack.len() {
            return Err(Error::ChunkMissing);
        }
        let hdr = &pack[pos..end_of_header];
        let got_index = u32::from_be_bytes(hdr[0..4].try_into().expect("4"));
        let pt_len = u32::from_be_bytes(hdr[4..8].try_into().expect("4"));
        let ct_len = u32::from_be_bytes(hdr[8..12].try_into().expect("4"));
        let last_flag = hdr[12];
        let reserved8 = hdr[13];
        let reserved16 = u16::from_be_bytes(hdr[14..16].try_into().expect("2"));

        if got_index != index {
            return if got_index < index {
                Err(Error::ChunkOrder)
            } else {
                Err(Error::ChunkMissing)
            };
        }
        let last = index + 1 == header.chunk_count;
        if last_flag != if last { 1 } else { 0 } {
            return Err(Error::ChunkOrder);
        }
        if reserved8 != 0 || reserved16 != 0 {
            return Err(Error::HeaderInvalid);
        }
        let expected_pt_len = chunk_plain_len(
            header.plaintext_size,
            header.chunk_size,
            header.chunk_count,
            index,
        );
        if pt_len != expected_pt_len || ct_len != expected_pt_len {
            return Err(Error::LengthInconsistent);
        }

        pos = end_of_header;
        let ct_end = pos + ct_len as usize;
        let tag_end = ct_end + TAG_LEN;
        if tag_end > pack.len() {
            return Err(Error::ChunkMissing);
        }
        let ct = &pack[pos..ct_end];
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&pack[ct_end..tag_end]);
        pos = tag_end;

        let aad = aad_chunk(&header, index, last, pt_len);
        let nonce = chunk_nonce(index, last);
        let pt = gcm::decrypt(&kc, &nonce, &aad, ct, &tag).ok_or(Error::ChunkAuthFailed)?;
        if !ct_eq(&sm3(&pt), &manifest.digests[index as usize]) {
            return Err(Error::DigestMismatch);
        }
        data.extend_from_slice(&pt);
    }

    if pos != pack.len() {
        return Err(Error::TrailingBytes);
    }
    if data.len() as u64 != header.plaintext_size {
        return Err(Error::LengthInconsistent);
    }

    Ok(Unpacked {
        header,
        manifest,
        sender_public: opened.sender_public,
        sender_code: opened.sender_code,
        data,
    })
}

/// 只读包头（不解密），用于上传前/展示前的快速校验。
pub fn read_header(pack: &[u8]) -> Result<Header> {
    Header::decode(pack)
}

// ============================================================================
// 流式打包 / 解包（常量内存；产出与整包接口**逐字节相同**）
//
// 设计：包结构是 prelude（含全部块摘要）在前、块记录在后，所以打包必然两遍：
//   ① `PackStream::hash_update` 顺序喂明文 → 只留每块 SM3（32B/块，1 GiB/1 MiB ≈ 32 KiB）
//   ② `PackStream::prelude` 出 prelude（清单+签名，可先上传）
//   ③ `PackStream::chunk(i, ...)` 逐块出记录（一次一块明文，可边读边传）
// 解包同理：`open_stream(prelude)` 后逐块 `chunk()`。
// ============================================================================

/// 流式打包会话。
pub struct PackStream {
    sender_private: [u8; 32],
    sender_pub: [u8; SENDER_PUB_LEN],
    wrapped: [u8; WRAPPED_KEY_LEN],
    dk: [u8; 32],
    kdf_salt: [u8; KDF_SALT_LEN],
    chunk_size: u32,
    chunk_count: u32,
    total: u64,
    created_at_ms: u64,
    name: String,
    mime: String,
    ext: String,
    digests: Vec<[u8; 32]>,
    cur: Vec<u8>,
    hashed: u64,
    sig_k: U256,
    header: Option<Header>,
    prelude: Vec<u8>,
}

impl PackStream {
    /// 开始一次流式打包。`total_size` 必须等于后续 `hash_update` 的字节总数。
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        recipient_public: &[u8; 64],
        sender_private: &[u8; 32],
        name: &str,
        mime: &str,
        ext: &str,
        created_at_ms: u64,
        chunk_size: u32,
        total_size: u64,
        rng: &mut impl Rng,
    ) -> Result<Self> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::BadArgument);
        }
        if total_size > MAX_PLAINTEXT_SIZE {
            return Err(Error::BadArgument);
        }
        let chunk_count64 = expected_chunk_count(total_size, chunk_size);
        if chunk_count64 > MAX_CHUNK_COUNT as u64 {
            return Err(Error::BadArgument);
        }
        // 随机数消耗顺序必须与 `pack()` 完全一致：dk → salt → k_enc → k_sig
        let mut dk = [0u8; 32];
        rng.fill(&mut dk);
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        rng.fill(&mut kdf_salt);
        let k_enc = random_scalar(rng)?;
        let sig_k = random_scalar(rng)?;
        Self::begin_with_params(
            recipient_public,
            sender_private,
            name,
            mime,
            ext,
            created_at_ms,
            chunk_size,
            total_size,
            &PackParams {
                dk,
                kdf_salt,
                k_enc,
                k_sig: sig_k,
            },
        )
    }

    /// 固定参数的流式打包（测试/复现用；与 `pack_with_params` 同一套字节）。
    #[allow(clippy::too_many_arguments)]
    pub fn begin_with_params(
        recipient_public: &[u8; 64],
        sender_private: &[u8; 32],
        name: &str,
        mime: &str,
        ext: &str,
        created_at_ms: u64,
        chunk_size: u32,
        total_size: u64,
        params: &PackParams,
    ) -> Result<Self> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::BadArgument);
        }
        if total_size > MAX_PLAINTEXT_SIZE {
            return Err(Error::BadArgument);
        }
        let chunk_count64 = expected_chunk_count(total_size, chunk_size);
        if chunk_count64 > MAX_CHUNK_COUNT as u64 {
            return Err(Error::BadArgument);
        }
        let chunk_count = chunk_count64 as u32;
        let dk = params.dk;
        let kdf_salt = params.kdf_salt;
        let k_enc = params.k_enc;
        let sig_k = params.k_sig;

        let sender_pub64 = sm2::public_from_private(sender_private)?;
        let mut sender_pub = [0u8; SENDER_PUB_LEN];
        sender_pub[0] = 0x04;
        sender_pub[1..].copy_from_slice(&sender_pub64);

        let wrapped64 = sm2::encrypt(recipient_public, &dk, &k_enc)?;
        if wrapped64.len() != WRAPPED_KEY_LEN - 1 {
            return Err(Error::Internal);
        }
        let mut wrapped = [0u8; WRAPPED_KEY_LEN];
        wrapped[0] = 0x04;
        wrapped[1..].copy_from_slice(&wrapped64);

        Ok(PackStream {
            sender_private: *sender_private,
            sender_pub,
            wrapped,
            dk,
            kdf_salt,
            chunk_size,
            chunk_count,
            total: total_size,
            created_at_ms,
            name: name.to_string(),
            mime: mime.to_string(),
            ext: ext.to_string(),
            digests: Vec::with_capacity(chunk_count as usize),
            cur: Vec::with_capacity(chunk_size as usize),
            hashed: 0,
            sig_k,
            header: None,
            prelude: Vec::new(),
        })
    }

    /// 顺序喂入明文（只做分块 SM3，不保留明文）。
    pub fn hash_update(&mut self, data: &[u8]) -> Result<()> {
        if self.header.is_some() {
            return Err(Error::BadArgument);
        }
        self.hashed += data.len() as u64;
        if self.hashed > self.total {
            return Err(Error::BadArgument);
        }
        let mut rest = data;
        while !rest.is_empty() {
            let room = self.chunk_size as usize - self.cur.len();
            let take = core::cmp::min(room, rest.len());
            self.cur.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            // 满一块且后面还有块 → 落摘要
            if self.cur.len() == self.chunk_size as usize
                && (self.digests.len() + 1) < self.chunk_count as usize
            {
                self.digests.push(sm3(&self.cur));
                self.cur.clear();
            }
        }
        Ok(())
    }

    /// 生成 prelude（清单 + 签名），之后才能逐块出记录。返回 prelude 长度。
    pub fn make_prelude(&mut self) -> Result<usize> {
        // 幂等：调用方常用"先问长度再分配"的模式，重复调用不能改变状态
        if self.header.is_some() {
            return Ok(self.prelude.len());
        }
        if self.hashed != self.total {
            return Err(Error::LengthInconsistent);
        }
        if self.digests.len() + 1 != self.chunk_count as usize {
            return Err(Error::LengthInconsistent);
        }
        // 最后一块（可能为空文件 → SM3("")）
        self.digests.push(sm3(&self.cur));
        self.cur.clear();

        let manifest = Manifest {
            name_mode: NAME_MODE_REAL,
            file_size: self.total,
            chunk_size: self.chunk_size,
            chunk_count: self.chunk_count,
            created_at_ms: self.created_at_ms,
            name: self.name.clone(),
            mime: self.mime.clone(),
            ext: self.ext.clone(),
            digests: self.digests.clone(),
        };
        let manifest_pt = manifest.encode()?;

        let mut header = Header {
            flags: FLAG_SENDER_SIGNED,
            chunk_size: self.chunk_size,
            chunk_count: self.chunk_count,
            plaintext_size: self.total,
            wrapped_key_len: WRAPPED_KEY_LEN as u64,
            manifest_len: manifest_pt.len() as u64 + TAG_LEN as u64,
            manifest_pt_len: manifest_pt.len() as u32,
            sender_pub_len: SENDER_PUB_LEN as u32,
            kdf_salt: self.kdf_salt,
            sig_len: MIN_SIG_LEN as u64,
        };

        let km = kek_manifest(&self.dk, &self.kdf_salt);
        let aad_m = aad_manifest(&header);
        let mut manifest_ct = vec![0u8; manifest_pt.len()];
        let mut manifest_tag = [0u8; TAG_LEN];
        gcm::encrypt(
            &km,
            &MANIFEST_NONCE,
            &aad_m,
            &manifest_pt,
            &mut manifest_ct,
            &mut manifest_tag,
        );
        let mut manifest_sec = manifest_ct;
        manifest_sec.extend_from_slice(&manifest_tag);

        let header_bytes = header.encode();
        let mut sig_input =
            Vec::with_capacity(8 + HDR_CORE_LEN + SENDER_PUB_LEN + manifest_sec.len());
        sig_input.extend_from_slice(&SIG_PREFIX);
        sig_input.push(VERSION_MAJOR);
        sig_input.push(VERSION_MINOR);
        sig_input.extend_from_slice(&header_bytes[..HDR_CORE_LEN]);
        sig_input.extend_from_slice(&self.sender_pub);
        sig_input.extend_from_slice(&manifest_sec);

        let raw = sm2::sign_with_k(
            &self.sender_private,
            &sig_input,
            sm2::DEFAULT_ID,
            &self.sig_k,
        )?
        .ok_or(Error::Internal)?;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..]);
        let sig_der = der::encode_signature(&r, &s);
        if sig_der.len() < MIN_SIG_LEN || sig_der.len() > MAX_SIG_LEN {
            return Err(Error::Internal);
        }
        header.sig_len = sig_der.len() as u64;

        let header_bytes = header.encode();
        self.prelude = Vec::with_capacity(
            HEADER_LEN + SENDER_PUB_LEN + WRAPPED_KEY_LEN + manifest_sec.len() + sig_der.len(),
        );
        self.prelude.extend_from_slice(&header_bytes);
        self.prelude.extend_from_slice(&self.sender_pub);
        self.prelude.extend_from_slice(&self.wrapped);
        self.prelude.extend_from_slice(&manifest_sec);
        self.prelude.extend_from_slice(&sig_der);
        self.header = Some(header);
        Ok(self.prelude.len())
    }

    /// prelude 字节（调用 `make_prelude` 之后可用）。
    pub fn prelude(&self) -> &[u8] {
        &self.prelude
    }

    /// 出一块记录（16B 头 + 密文 + 16B tag），与整包产出逐字节相同。
    pub fn chunk(&self, index: u32, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let header = self.header.as_ref().ok_or(Error::BadArgument)?;
        if index >= self.chunk_count {
            return Err(Error::ChunkOrder);
        }
        let pt_len = chunk_plain_len(self.total, self.chunk_size, self.chunk_count, index);
        if plaintext.len() != pt_len as usize {
            return Err(Error::LengthInconsistent);
        }
        let last = index + 1 == self.chunk_count;
        let kc = kek_chunk(&self.dk, &self.kdf_salt);
        let aad = aad_chunk(header, index, last, pt_len);
        let nonce = chunk_nonce(index, last);
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm::encrypt(&kc, &nonce, &aad, plaintext, &mut ct, &mut tag);

        out.clear();
        out.extend_from_slice(&index.to_be_bytes());
        out.extend_from_slice(&pt_len.to_be_bytes());
        out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        out.push(if last { 1 } else { 0 });
        out.push(0);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// 记录块数（便于调用方分配）。
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// 某块的明文长度。
    pub fn chunk_len(&self, index: u32) -> u32 {
        chunk_plain_len(self.total, self.chunk_size, self.chunk_count, index)
    }
}

/// 流式解包会话（先喂 prelude，再逐块喂记录）。
pub struct UnpackStream {
    header: Header,
    manifest: Manifest,
    sender_public: [u8; SENDER_PUB_LEN],
    sender_code: String,
    dk: [u8; 32],
    next: u32,
}

impl UnpackStream {
    pub fn sender_code(&self) -> &str {
        &self.sender_code
    }
    pub fn sender_public(&self) -> &[u8; SENDER_PUB_LEN] {
        &self.sender_public
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn chunk_count(&self) -> u32 {
        self.header.chunk_count
    }
    /// 第 `index` 块的明文长度（调用方据此切记录）。
    pub fn chunk_len(&self, index: u32) -> u32 {
        chunk_plain_len(
            self.header.plaintext_size,
            self.header.chunk_size,
            self.header.chunk_count,
            index,
        )
    }
    pub fn done(&self) -> bool {
        self.next == self.header.chunk_count
    }

    /// 只校验记录头并返回该块明文长度（**不消耗状态**，用于"先问大小再分配"）。
    pub fn peek_plain_len(&self, record: &[u8]) -> Result<usize> {
        if self.next >= self.header.chunk_count {
            return Err(Error::ChunkOrder);
        }
        if record.len() < CHUNK_HEADER_LEN + TAG_LEN {
            return Err(Error::Truncated);
        }
        let hdr = &record[..CHUNK_HEADER_LEN];
        let index = u32::from_be_bytes(hdr[0..4].try_into().expect("4"));
        if index != self.next {
            return Err(Error::ChunkOrder);
        }
        let last = index + 1 == self.header.chunk_count;
        if (hdr[12] == 1) != last {
            return Err(Error::ChunkOrder);
        }
        let pt_len = u32::from_be_bytes(hdr[4..8].try_into().expect("4"));
        let ct_len = u32::from_be_bytes(hdr[8..12].try_into().expect("4"));
        let expected = chunk_plain_len(
            self.header.plaintext_size,
            self.header.chunk_size,
            self.header.chunk_count,
            index,
        );
        if pt_len != expected || ct_len != pt_len {
            return Err(Error::LengthInconsistent);
        }
        if record.len() != CHUNK_HEADER_LEN + ct_len as usize + TAG_LEN {
            return Err(Error::LengthInconsistent);
        }
        Ok(pt_len as usize)
    }

    /// 逐块解密：记录必须是**下一块**（乱序/重复/跨包 → `CRYPTO_CHUNK_ORDER`）。
    pub fn chunk(&mut self, record: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.next >= self.header.chunk_count {
            return Err(Error::ChunkOrder);
        }
        if record.len() < CHUNK_HEADER_LEN + TAG_LEN {
            return Err(Error::Truncated);
        }
        let hdr = &record[..CHUNK_HEADER_LEN];
        let index = u32::from_be_bytes(hdr[0..4].try_into().expect("4"));
        let pt_len = u32::from_be_bytes(hdr[4..8].try_into().expect("4"));
        let ct_len = u32::from_be_bytes(hdr[8..12].try_into().expect("4"));
        let last_flag = hdr[12];
        let expected_index = self.next;
        if index != expected_index {
            return Err(Error::ChunkOrder);
        }
        let last = index + 1 == self.header.chunk_count;
        if (last_flag == 1) != last {
            return Err(Error::ChunkOrder);
        }
        let expected_pt = chunk_plain_len(
            self.header.plaintext_size,
            self.header.chunk_size,
            self.header.chunk_count,
            index,
        );
        if pt_len != expected_pt || ct_len != pt_len {
            return Err(Error::LengthInconsistent);
        }
        let end = CHUNK_HEADER_LEN + ct_len as usize + TAG_LEN;
        if record.len() != end {
            return Err(Error::LengthInconsistent);
        }
        let ct = &record[CHUNK_HEADER_LEN..CHUNK_HEADER_LEN + ct_len as usize];
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&record[CHUNK_HEADER_LEN + ct_len as usize..end]);
        let kc = kek_chunk(&self.dk, &self.header.kdf_salt);
        let aad = aad_chunk(&self.header, index, last, pt_len);
        let nonce = chunk_nonce(index, last);
        let pt = gcm::decrypt(&kc, &nonce, &aad, ct, &tag).ok_or(Error::ChunkAuthFailed)?;
        out.clear();
        out.extend_from_slice(&pt);
        // 明文摘要必须与清单一致
        let want = self
            .manifest
            .digests
            .get(index as usize)
            .ok_or(Error::LengthInconsistent)?;
        if sm3(out) != *want {
            return Err(Error::DigestMismatch);
        }
        self.next += 1;
        Ok(())
    }
}

/// 打开流式解包会话：只要求 **prelude 完整**。
pub fn open_stream(prelude: &[u8], recipient_private: &[u8; 32]) -> Result<UnpackStream> {
    let o = open_from_prelude(prelude, recipient_private)?;
    Ok(UnpackStream {
        header: o.header,
        manifest: o.manifest,
        sender_public: o.sender_public,
        sender_code: o.sender_code,
        dk: o.dk,
        next: 0,
    })
}
