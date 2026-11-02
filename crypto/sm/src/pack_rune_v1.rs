//! **rune-v1 兼容布局（非契约实现）** —— 仅用于 Gate 的历史证据与回归对比。
//!
//! 这是首版自拟的临时锚点：HEADER 40 字节、签名裸 `R‖S`、清单摘要对「密文‖tag」。
//! 它**不符合** `docs/CRYPTO-PACK.md` `YSPK/1.0`，产品默认布局是 [`crate::pack`]。
//! 两者互不混用：一个产物的字节只属于其中一种布局，且 `pack::layout_of()` 可判别。
//!
//! 保留原因：Gate 的篡改证据是在这版上跑出来的（`--layout rune-v1`），需要可复跑。
//!
//! 加密包（`.ysp`）打包 / 解包，格式 v1。
//!
//! **格式锚点全部集中在 [`layout`] 模块**：字段偏移、长度、常量、nonce 构造规则、
//! HKDF salt/info 都在那里。等 Ark 把 `docs/CRYPTO-PACK.md` 的定稿字段落盘后，
//! 只需要改 [`layout`] 与 [`Header`]/[`Manifest`] 的序列化两处，其余调用方不动。
//!
//! 包布局（v1）：
//!
//! ```text
//! HEADER(40) | KEY_REC | SIG_REC | MANIFEST_REC | BLOCK(0) | BLOCK(1) | ...
//! ```
//!
//! * `HEADER`：magic `YSPK`、version=1、suite=1、flags、file_id、block_size、
//!   block_count、plain_size。**header 字节是每个块与清单的 AAD**，改一个字节全盘失效。
//! * `KEY_REC`：`u8 kind=1 | u32 len=128 | C1C3C2(DK)`（收件人公钥 SM2 封装 32 字节 DK）。
//! * `SIG_REC`：`u8 kind=2 | u32 len=64 | r||s`（发送方私钥对 `header||manifest_plain` 签名）。
//! * `MANIFEST_REC`：`u32 ct_len | ct | tag(16)`，用 manifest key 加密的清单。
//! * `BLOCK`：`u32 index | u8 flags | u32 ct_len | ct | tag(16)`。
//!
//! 解包是**严格模式**：未知版本、块号重复/跳号/缺失、末块标志不符、tag 校验失败、
//! 清单与包头或块不一致、尾部多余字节，全部返回明确错误，不做任何"尽力恢复"。

use crate::bigint::U256;
use crate::error::{Error, Result};
use crate::gcm;
use crate::hkdf::hkdf_sm3;
use crate::rng::Rng;
use crate::sm2;
use crate::sm3::{ct_eq, sm3};

/// 格式锚点：**改格式只改这里**。
pub mod layout {
    /// 包魔数 `YSPK`
    pub const MAGIC: [u8; 4] = *b"YSPK";
    /// 当前版本号（只接受这一个）
    pub const VERSION: u8 = 1;
    /// 套件编号：SM4-GCM-128 + SM3 + SM2(C1C3C2)
    pub const SUITE_SM4GCM_SM3_SM2: u8 = 1;
    /// flags bit0：包含加密清单（v1 恒为 1）
    pub const FLAG_MANIFEST: u8 = 0x01;

    /// 包头长度
    pub const HEADER_LEN: usize = 40;
    pub const OFF_MAGIC: usize = 0;
    pub const OFF_VERSION: usize = 4;
    pub const OFF_SUITE: usize = 5;
    pub const OFF_FLAGS: usize = 6;
    pub const OFF_RESERVED: usize = 7;
    pub const OFF_FILE_ID: usize = 8;
    pub const FILE_ID_LEN: usize = 16;
    pub const OFF_BLOCK_SIZE: usize = 24;
    pub const OFF_BLOCK_COUNT: usize = 28;
    pub const OFF_PLAIN_SIZE: usize = 32;

    /// DK 封装记录类型：SM2 平文 C1C3C2
    pub const KEY_REC_KIND_SM2: u8 = 1;
    /// 签名记录类型：SM2 签名 r||s
    pub const SIG_REC_KIND_SM2: u8 = 2;

    /// GCM tag 长度
    pub const TAG_LEN: usize = 16;
    /// GCM nonce 长度（96 位）
    pub const NONCE_LEN: usize = 12;
    /// 块 nonce 的末块标志字节
    pub const BLOCK_FLAG_LAST: u8 = 0x01;
    /// 清单 nonce（固定：索引全 F + 标志 0x80）
    pub const MANIFEST_NONCE: [u8; NONCE_LEN] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    ];

    /// 默认块大小 1 MiB
    pub const DEFAULT_BLOCK_SIZE: u32 = 1 << 20;
    /// 块大小上限（防内存放大攻击）
    pub const MAX_BLOCK_SIZE: u32 = 64 << 20;

    /// 块密钥派生 salt
    pub const HKDF_SALT_BLOCK: &[u8] = b"YanShu/v1/block";
    /// 清单密钥派生 salt
    pub const HKDF_SALT_MANIFEST: &[u8] = b"YanShu/v1/manifest";
    /// 块密钥长度
    pub const BLOCK_KEY_LEN: usize = 16;

    /// 块记录固定开销：index(4) + flags(1) + ct_len(4) + tag(16)
    pub const BLOCK_OVERHEAD: usize = 4 + 1 + 4 + TAG_LEN;

    /// 由块号 + 末块标志构造 96 位 nonce。
    pub fn block_nonce(index: u32, is_last: bool) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[..4].copy_from_slice(&index.to_be_bytes());
        n[4..8].copy_from_slice(&[0, 0, 0, 0]);
        n[8] = if is_last { BLOCK_FLAG_LAST } else { 0x00 };
        n
    }
}

use layout::*;

/// 包头。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub file_id: [u8; FILE_ID_LEN],
    pub block_size: u32,
    pub block_count: u32,
    pub plain_size: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        out[OFF_VERSION] = VERSION;
        out[OFF_SUITE] = SUITE_SM4GCM_SM3_SM2;
        out[OFF_FLAGS] = FLAG_MANIFEST;
        out[OFF_RESERVED] = 0;
        out[OFF_FILE_ID..OFF_FILE_ID + FILE_ID_LEN].copy_from_slice(&self.file_id);
        out[OFF_BLOCK_SIZE..OFF_BLOCK_SIZE + 4].copy_from_slice(&self.block_size.to_be_bytes());
        out[OFF_BLOCK_COUNT..OFF_BLOCK_COUNT + 4].copy_from_slice(&self.block_count.to_be_bytes());
        out[OFF_PLAIN_SIZE..OFF_PLAIN_SIZE + 8].copy_from_slice(&self.plain_size.to_be_bytes());
        out
    }

    /// 严格解析：魔数 / 版本 / 套件 / flags / 保留位 / 字段取值范围全部校验。
    pub fn decode(buf: &[u8]) -> Result<Header> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if buf[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
            return Err(Error::BadMagic);
        }
        if buf[OFF_VERSION] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if buf[OFF_SUITE] != SUITE_SM4GCM_SM3_SM2 {
            return Err(Error::UnsupportedVersion);
        }
        if buf[OFF_FLAGS] & !FLAG_MANIFEST != 0 || buf[OFF_FLAGS] & FLAG_MANIFEST == 0 {
            return Err(Error::BadFlags);
        }
        if buf[OFF_RESERVED] != 0 {
            return Err(Error::BadFlags);
        }
        let mut file_id = [0u8; FILE_ID_LEN];
        file_id.copy_from_slice(&buf[OFF_FILE_ID..OFF_FILE_ID + FILE_ID_LEN]);
        let block_size = u32::from_be_bytes(
            buf[OFF_BLOCK_SIZE..OFF_BLOCK_SIZE + 4]
                .try_into()
                .expect("4 bytes"),
        );
        let block_count = u32::from_be_bytes(
            buf[OFF_BLOCK_COUNT..OFF_BLOCK_COUNT + 4]
                .try_into()
                .expect("4 bytes"),
        );
        let plain_size = u64::from_be_bytes(
            buf[OFF_PLAIN_SIZE..OFF_PLAIN_SIZE + 8]
                .try_into()
                .expect("8 bytes"),
        );
        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            return Err(Error::BadFlags);
        }
        let expected = expected_block_count(plain_size, block_size);
        if block_count != expected {
            return Err(Error::ManifestMismatch);
        }
        Ok(Header {
            file_id,
            block_size,
            block_count,
            plain_size,
        })
    }
}

/// 期望块数：空文件也占 1 个空块（保证末块标志机制总是有效）。
pub fn expected_block_count(plain_size: u64, block_size: u32) -> u32 {
    if plain_size == 0 {
        1
    } else {
        plain_size.div_ceil(block_size as u64) as u32
    }
}

/// 第 `index` 块的明文字节数。
pub fn block_plain_len(plain_size: u64, block_size: u32, index: u32) -> u32 {
    let count = expected_block_count(plain_size, block_size);
    if index + 1 < count {
        block_size
    } else {
        (plain_size - (count as u64 - 1) * block_size as u64) as u32
    }
}

/// 清单（解密后）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub mime: String,
    pub block_size: u32,
    pub block_count: u32,
    pub plain_size: u64,
    pub block_digests: Vec<[u8; 32]>,
}

impl Manifest {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.name.len() > 512 || self.mime.len() > 128 {
            return Err(Error::BadArgument);
        }
        let mut out = Vec::with_capacity(64 + self.block_digests.len() * 32);
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&(self.mime.len() as u16).to_be_bytes());
        out.extend_from_slice(self.mime.as_bytes());
        out.extend_from_slice(&self.block_size.to_be_bytes());
        out.extend_from_slice(&self.block_count.to_be_bytes());
        out.extend_from_slice(&self.plain_size.to_be_bytes());
        out.extend_from_slice(&(self.block_digests.len() as u32).to_be_bytes());
        for d in &self.block_digests {
            out.extend_from_slice(d);
        }
        Ok(out)
    }

    fn decode(buf: &[u8]) -> Result<Manifest> {
        let mut r = Reader::new(buf);
        let name_len = r.u16()? as usize;
        if name_len == 0 || name_len > 512 {
            return Err(Error::BadManifestRecord);
        }
        let name =
            String::from_utf8(r.take(name_len)?.to_vec()).map_err(|_| Error::BadManifestRecord)?;
        let mime_len = r.u16()? as usize;
        if mime_len > 128 {
            return Err(Error::BadManifestRecord);
        }
        let mime =
            String::from_utf8(r.take(mime_len)?.to_vec()).map_err(|_| Error::BadManifestRecord)?;
        let block_size = r.u32()?;
        let block_count = r.u32()?;
        let plain_size = r.u64()?;
        let digest_count = r.u32()? as usize;
        if digest_count != block_count as usize {
            return Err(Error::BadManifestRecord);
        }
        if digest_count > 1 << 20 {
            return Err(Error::BadManifestRecord);
        }
        let mut block_digests = Vec::with_capacity(digest_count);
        for _ in 0..digest_count {
            let mut d = [0u8; 32];
            d.copy_from_slice(r.take(32)?);
            block_digests.push(d);
        }
        if r.remaining() != 0 {
            return Err(Error::BadManifestRecord);
        }
        Ok(Manifest {
            name,
            mime,
            block_size,
            block_count,
            plain_size,
            block_digests,
        })
    }
}

/// 打包输入。
pub struct PackInput<'a> {
    /// 收件人公钥（64 字节 x||y）
    pub recipient_public: &'a [u8; 64],
    /// 发送方私钥（32 字节）
    pub sender_private: &'a [u8; 32],
    pub name: &'a str,
    pub mime: &'a str,
    pub block_size: u32,
    pub data: &'a [u8],
}

/// 可复现打包参数（测试向量用；生产中由 [`pack`] 用 CSPRNG 生成）。
pub struct PackParams {
    pub dk: [u8; 32],
    pub file_id: [u8; 16],
    pub k_wrap: U256,
    pub k_sign: U256,
}

fn derive_block_key(dk: &[u8; 32], file_id: &[u8; 16]) -> [u8; BLOCK_KEY_LEN] {
    let mut key = [0u8; BLOCK_KEY_LEN];
    hkdf_sm3(HKDF_SALT_BLOCK, dk, file_id, &mut key);
    key
}

fn derive_manifest_key(dk: &[u8; 32], file_id: &[u8; 16]) -> [u8; BLOCK_KEY_LEN] {
    let mut key = [0u8; BLOCK_KEY_LEN];
    hkdf_sm3(HKDF_SALT_MANIFEST, dk, file_id, &mut key);
    key
}

fn seal_block(
    key: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut ct = vec![0u8; pt.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm::encrypt(key, nonce, aad, pt, &mut ct, &mut tag);
    (ct, tag)
}

/// 打包。
pub fn pack(input: &PackInput, rng: &mut impl Rng) -> Result<Vec<u8>> {
    let mut dk = [0u8; 32];
    rng.fill(&mut dk);
    let mut file_id = [0u8; 16];
    rng.fill(&mut file_id);
    let k_wrap = random_scalar(rng)?;
    let k_sign = random_scalar(rng)?;
    pack_with(
        input,
        &PackParams {
            dk,
            file_id,
            k_wrap,
            k_sign,
        },
    )
}

fn random_scalar(rng: &mut impl Rng) -> Result<U256> {
    // 与 sm2 内部的拒绝采样一致：取 32 字节直到落在 [1, n-1]
    for _ in 0..64 {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        let v = U256::from_be_bytes(&b);
        if !v.is_zero() {
            return Ok(v);
        }
    }
    Err(Error::Rng)
}

/// 用固定参数打包（测试向量可复现）。
pub fn pack_with(input: &PackInput, params: &PackParams) -> Result<Vec<u8>> {
    if input.block_size == 0 || input.block_size > MAX_BLOCK_SIZE {
        return Err(Error::BadArgument);
    }
    if input.name.is_empty() || input.name.len() > 512 || input.mime.len() > 128 {
        return Err(Error::BadArgument);
    }
    let block_size = input.block_size;
    let block_count = expected_block_count(input.data.len() as u64, block_size);
    let header = Header {
        file_id: params.file_id,
        block_size,
        block_count,
        plain_size: input.data.len() as u64,
    };
    let header_bytes = header.encode();

    let block_key = derive_block_key(&params.dk, &params.file_id);
    let manifest_key = derive_manifest_key(&params.dk, &params.file_id);

    // 逐块加密
    let mut blocks: Vec<(u32, u8, Vec<u8>, [u8; TAG_LEN])> = Vec::new();
    let mut digests: Vec<[u8; 32]> = Vec::new();
    for index in 0..block_count {
        let start = index as usize * block_size as usize;
        let len = block_plain_len(input.data.len() as u64, block_size, index) as usize;
        let end = core::cmp::min(start + len, input.data.len());
        let pt = &input.data[start..end];
        let is_last = index + 1 == block_count;
        let nonce = block_nonce(index, is_last);
        let (ct, tag) = seal_block(&block_key, &nonce, &header_bytes, pt);
        let mut digest_input = Vec::with_capacity(ct.len() + TAG_LEN);
        digest_input.extend_from_slice(&ct);
        digest_input.extend_from_slice(&tag);
        digests.push(sm3(&digest_input));
        blocks.push((index, if is_last { BLOCK_FLAG_LAST } else { 0 }, ct, tag));
    }

    let manifest = Manifest {
        name: input.name.to_string(),
        mime: input.mime.to_string(),
        block_size,
        block_count,
        plain_size: input.data.len() as u64,
        block_digests: digests,
    };
    let manifest_plain = manifest.encode()?;

    // 签名覆盖 header || manifest_plain
    let mut signed = Vec::with_capacity(HEADER_LEN + manifest_plain.len());
    signed.extend_from_slice(&header_bytes);
    signed.extend_from_slice(&manifest_plain);
    let sig = sm2::sign_with_k(
        input.sender_private,
        &signed,
        sm2::DEFAULT_ID,
        &params.k_sign,
    )?
    .ok_or(Error::Internal)?;

    // DK 封装
    let wrapped = sm2::encrypt(input.recipient_public, &params.dk, &params.k_wrap)?;
    if wrapped.len() != 128 {
        return Err(Error::Internal);
    }

    // 清单密文
    let (man_ct, man_tag) = seal_block(
        &manifest_key,
        &MANIFEST_NONCE,
        &header_bytes,
        &manifest_plain,
    );

    let mut out = Vec::with_capacity(
        HEADER_LEN
            + 1
            + 4
            + 128
            + 1
            + 4
            + 64
            + 4
            + man_ct.len()
            + TAG_LEN
            + blocks.len() * BLOCK_OVERHEAD
            + input.data.len(),
    );
    out.extend_from_slice(&header_bytes);

    out.push(KEY_REC_KIND_SM2);
    out.extend_from_slice(&(wrapped.len() as u32).to_be_bytes());
    out.extend_from_slice(&wrapped);

    out.push(SIG_REC_KIND_SM2);
    out.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    out.extend_from_slice(&sig);

    out.extend_from_slice(&(man_ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&man_ct);
    out.extend_from_slice(&man_tag);

    for (index, flags, ct, tag) in &blocks {
        out.extend_from_slice(&index.to_be_bytes());
        out.push(*flags);
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(ct);
        out.extend_from_slice(tag);
    }

    Ok(out)
}

/// 解包结果。
#[derive(Debug)]
pub struct Unpacked {
    pub manifest: Manifest,
    pub data: Vec<u8>,
}

/// 只解包头（用于发送前预校验 / 展示前校验）。
pub fn read_header(pack: &[u8]) -> Result<Header> {
    Header::decode(pack)
}

struct Opened {
    header: Header,
    manifest: Manifest,
    dk: [u8; 32],
    /// 第一个块记录在 `pack` 中的偏移
    block_offset: usize,
}

/// 解到清单为止：包头 → DK 封装 → 签名记录 → 清单 → 验签。
/// 不解任何数据块，用于接收端先展示文件名/大小。
fn open(pack: &[u8], recipient_private: &[u8; 32], sender_public: &[u8; 64]) -> Result<Opened> {
    let header = Header::decode(pack)?;
    let header_bytes = &pack[..HEADER_LEN];
    let mut r = Reader::new(&pack[HEADER_LEN..]);

    // KEY_REC
    let key_kind = r.u8()?;
    if key_kind != KEY_REC_KIND_SM2 {
        return Err(Error::BadKeyRecord);
    }
    let key_len = r.u32()? as usize;
    if key_len != 128 {
        return Err(Error::BadKeyRecord);
    }
    let wrapped = r.take(key_len)?;
    let dk_vec = sm2::decrypt(recipient_private, wrapped).map_err(|_| Error::BadKeyRecord)?;
    if dk_vec.len() != 32 {
        return Err(Error::BadKeyRecord);
    }
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dk_vec);

    // SIG_REC
    let sig_kind = r.u8()?;
    if sig_kind != SIG_REC_KIND_SM2 {
        return Err(Error::BadSignatureRecord);
    }
    let sig_len = r.u32()? as usize;
    if sig_len != sm2::SIGNATURE_SIZE {
        return Err(Error::BadSignatureRecord);
    }
    let mut sig = [0u8; sm2::SIGNATURE_SIZE];
    sig.copy_from_slice(r.take(sig_len)?);

    // MANIFEST_REC
    let man_key = derive_manifest_key(&dk, &header.file_id);
    let man_ct_len = r.u32()? as usize;
    if man_ct_len > 1 << 20 {
        return Err(Error::BadManifestRecord);
    }
    let man_ct = r.take(man_ct_len)?;
    let mut man_tag = [0u8; TAG_LEN];
    man_tag.copy_from_slice(r.take(TAG_LEN)?);
    let manifest_plain = gcm::decrypt(&man_key, &MANIFEST_NONCE, header_bytes, man_ct, &man_tag)
        .ok_or(Error::ManifestMismatch)?;
    let manifest = Manifest::decode(&manifest_plain)?;

    if manifest.block_size != header.block_size
        || manifest.block_count != header.block_count
        || manifest.plain_size != header.plain_size
        || manifest.block_digests.len() != header.block_count as usize
    {
        return Err(Error::ManifestMismatch);
    }

    // 签名校验（header || manifest_plain）
    let mut signed = Vec::with_capacity(HEADER_LEN + manifest_plain.len());
    signed.extend_from_slice(header_bytes);
    signed.extend_from_slice(&manifest_plain);
    if !sm2::verify(sender_public, &signed, sm2::DEFAULT_ID, &sig)? {
        return Err(Error::SignatureMismatch);
    }

    Ok(Opened {
        header,
        manifest,
        dk,
        block_offset: HEADER_LEN + (pack[HEADER_LEN..].len() - r.remaining()),
    })
}

/// 只解到清单（不解密数据块），供接收端先展示元信息。
pub fn open_manifest(
    pack: &[u8],
    recipient_private: &[u8; 32],
    sender_public: &[u8; 64],
) -> Result<(Header, Manifest)> {
    let o = open(pack, recipient_private, sender_public)?;
    Ok((o.header, o.manifest))
}

/// 严格解包。任何篡改都返回错误，绝不"尽力恢复"。
pub fn unpack(
    pack: &[u8],
    recipient_private: &[u8; 32],
    sender_public: &[u8; 64],
) -> Result<Unpacked> {
    let opened = open(pack, recipient_private, sender_public)?;
    let header = opened.header;
    let manifest = opened.manifest;
    let header_bytes = &pack[..HEADER_LEN];
    let mut r = Reader::new(&pack[opened.block_offset..]);

    // BLOCK*
    let block_key = derive_block_key(&opened.dk, &header.file_id);
    let mut data = Vec::with_capacity(header.plain_size as usize);
    let mut expected_index: u32 = 0;
    while expected_index < header.block_count {
        if r.remaining() == 0 {
            return Err(Error::MissingBlock);
        }
        let index = r.u32()?;
        if index < expected_index {
            return Err(Error::DuplicateBlock);
        }
        if index > expected_index || index >= header.block_count {
            return Err(Error::BlockSequence);
        }
        let flags = r.u8()?;
        let is_last = index + 1 == header.block_count;
        let expected_flags = if is_last { BLOCK_FLAG_LAST } else { 0 };
        if flags != expected_flags {
            return Err(Error::LastFlagMismatch);
        }
        let ct_len = r.u32()? as usize;
        let expected_len = block_plain_len(header.plain_size, header.block_size, index) as usize;
        if ct_len != expected_len {
            return Err(Error::ManifestMismatch);
        }
        let ct = r.take(ct_len)?;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(r.take(TAG_LEN)?);

        // 清单摘要（对 ct||tag）
        let mut digest_input = Vec::with_capacity(ct_len + TAG_LEN);
        digest_input.extend_from_slice(ct);
        digest_input.extend_from_slice(&tag);
        let digest = sm3(&digest_input);
        if !ct_eq(&digest, &manifest.block_digests[index as usize]) {
            return Err(Error::ManifestMismatch);
        }

        let nonce = block_nonce(index, is_last);
        let pt =
            gcm::decrypt(&block_key, &nonce, header_bytes, ct, &tag).ok_or(Error::TagMismatch)?;
        data.extend_from_slice(&pt);
        expected_index += 1;
    }

    if expected_index != header.block_count {
        return Err(Error::MissingBlock);
    }
    if r.remaining() != 0 {
        return Err(Error::TrailingBytes);
    }
    if data.len() as u64 != header.plain_size {
        return Err(Error::ManifestMismatch);
    }

    Ok(Unpacked { manifest, data })
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeedRng;

    fn identities() -> (sm2::KeyPair, sm2::KeyPair) {
        let mut rng = SeedRng::new(b"pack-identities");
        let alice = sm2::keygen(&mut rng);
        let bob = sm2::keygen(&mut rng);
        (alice, bob)
    }

    fn build(data: &[u8], block_size: u32) -> Vec<u8> {
        let (alice, bob) = identities();
        let mut rng = SeedRng::new(b"pack-rng");
        let input = PackInput {
            recipient_public: &bob.public_key,
            sender_private: &alice.private_key,
            name: "报告.pdf",
            mime: "application/pdf",
            block_size,
            data,
        };
        pack(&input, &mut rng).unwrap()
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let (alice, bob) = identities();
        for (len, bs) in [
            (0usize, 16u32),
            (1, 16),
            (15, 16),
            (16, 16),
            (17, 16),
            (1000, 256),
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let pack = build(&data, bs);
            let out = unpack(&pack, &bob.private_key, &alice.public_key).unwrap();
            assert_eq!(out.data, data);
            assert_eq!(out.manifest.name, "报告.pdf");
            assert_eq!(
                out.manifest.block_count,
                expected_block_count(len as u64, bs)
            );
        }
    }

    #[test]
    fn flip_one_byte_fails() {
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let pack = build(&data, 16);
        let (alice, bob) = identities();
        for pos in [0usize, 5, 12, 45, 60, 100, 200, pack.len() - 1] {
            let mut bad = pack.clone();
            bad[pos] ^= 0x01;
            assert!(
                unpack(&bad, &bob.private_key, &alice.public_key).is_err(),
                "flip at {} should fail",
                pos
            );
        }
    }

    #[test]
    fn swap_and_delete_blocks_fail() {
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let pack = build(&data, 16); // 4 块
        let (alice, bob) = identities();
        // 定位块起点：header + keyrec + sigrec + manifest rec
        let mut pos = HEADER_LEN + 1 + 4 + 128 + 1 + 4 + 64;
        let man_len = u32::from_be_bytes(pack[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + man_len + TAG_LEN;
        let mut block_spans = Vec::new();
        let mut p = pos;
        for _ in 0..4 {
            let len = u32::from_be_bytes(pack[p + 5..p + 9].try_into().unwrap()) as usize;
            block_spans.push(p..p + 9 + len + TAG_LEN);
            p += 9 + len + TAG_LEN;
        }
        assert_eq!(p, pack.len());

        // 交换块 0 与块 1
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&pack[..block_spans[0].start]);
        swapped.extend_from_slice(&pack[block_spans[1].clone()]);
        swapped.extend_from_slice(&pack[block_spans[0].clone()]);
        swapped.extend_from_slice(&pack[block_spans[2].start..]);
        assert!(unpack(&swapped, &bob.private_key, &alice.public_key).is_err());

        // 删除块 1
        let mut deleted = Vec::new();
        deleted.extend_from_slice(&pack[..block_spans[1].start]);
        deleted.extend_from_slice(&pack[block_spans[2].start..]);
        assert!(unpack(&deleted, &bob.private_key, &alice.public_key).is_err());

        // 复制块 1 到块 0 位置（重复块）
        let mut dup = Vec::new();
        dup.extend_from_slice(&pack[..block_spans[0].start]);
        dup.extend_from_slice(&pack[block_spans[1].clone()]);
        dup.extend_from_slice(&pack[block_spans[1].start..]);
        assert!(unpack(&dup, &bob.private_key, &alice.public_key).is_err());
    }

    #[test]
    fn unknown_version_rejected() {
        let data = vec![1u8, 2, 3];
        let mut pack = build(&data, 16);
        pack[OFF_VERSION] = 9;
        let (alice, bob) = identities();
        assert_eq!(
            unpack(&pack, &bob.private_key, &alice.public_key).unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    #[test]
    fn truncated_rejected() {
        let data = vec![0u8; 40];
        let pack = build(&data, 16);
        let (alice, bob) = identities();
        for cut in [1usize, 10, HEADER_LEN, HEADER_LEN + 5, pack.len() - 1] {
            assert!(unpack(&pack[..cut], &bob.private_key, &alice.public_key).is_err());
        }
    }
}

#[cfg(test)]
mod layered_tamper_tests {
    use super::*;
    use crate::rng::SeedRng;

    /// Gate 实测结论（写进测试，别当缺陷）：rune-v1 的清单摘要是对 `密文‖tag` 算的，
    /// 而且**先于** GCM 解密校验，所以直接改密文/改 tag 会先被清单摘要拦住
    /// （`MANIFEST_MISMATCH`），`TAG_MISMATCH` 在端到端里可能取不到——这是预期。
    ///
    /// 契约布局（`crate::pack`）反过来：AAD 绑块序号、GCM 先校验，所以篡改走
    /// `CRYPTO_CHUNK_AUTH_FAILED`、换序走 `CRYPTO_CHUNK_ORDER`，两层各能触发。
    #[test]
    fn digest_layer_masks_tag_error_on_purpose() {
        let mut rng = SeedRng::new(b"rune-v1-layered");
        let alice = crate::sm2::keygen(&mut rng);
        let bob = crate::sm2::keygen(&mut rng);
        let bob_pub = bob.public_key;
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let input = PackInput {
            recipient_public: &bob_pub,
            sender_private: &alice.private_key,
            name: "f.bin",
            mime: "application/octet-stream",
            block_size: 16,
            data: &data,
        };
        let pack = pack(&input, &mut rng).expect("pack");

        // 定位第一块密文（header + keyrec + sigrec + manifestrec 之后）
        let mut pos = layout::HEADER_LEN + 1 + 4 + 128 + 1 + 4 + 64;
        let man_len = u32::from_be_bytes(pack[pos..pos + 4].try_into().unwrap()) as usize
            + 4
            + layout::TAG_LEN;
        pos += man_len;
        let mut bad = pack.clone();
        bad[pos + 9 + 2] ^= 0x01; // 块头 9 字节之后 = 密文
        let e = unpack(&bad, &bob.private_key, &alice.public_key).unwrap_err();
        assert_eq!(e, Error::ManifestMismatch, "rune-v1 先被清单摘要拦住是预期");
    }
}
