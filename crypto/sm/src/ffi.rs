//! raw C ABI（wasm32-unknown-unknown 直接导出，**不引 wasm-bindgen**）。
//!
//! **首版公布的 25 个导出签名一个都没改**（Web `feat/web-min-loop` 与 Gate 探针按它编译/调用）。
//! 契约 `YSPK/1.0` 需要的差异（65 字节未压缩点、DER 签名、清单 `created_at`/`ext`）
//! 全部在**内核内部**转换；需要完整参数的调用方用新增的 `*_v1` 导出。
//!
//! 只有一种格式：`docs/CRYPTO-PACK.md` 的 `YSPK/1.0`。首版的 rune-v1 兼容布局已删除。
//!
//! 通用约定：
//! * 长度参数为 `size_t`（wasm32 = 4 字节）；指针为线性内存偏移；`u64` 在 JS 里是 BigInt。
//! * 返回值 `0` = 成功，负数 = 错误码；**-4..-23 与首版完全一致**，新增从 -24 起。
//! * `out_len` 在缓冲区不足时写所需长度并返回 -2；`ys_pack*` 返回的是上界（+2）。
//! * 需要随机的接口都接收 `seed`（JS 用 `crypto.getRandomValues` 现取，>=16 字节）。
//! * `ys_alloc(n)` ↔ `ys_free(p, n)` 必须成对、长度一致。

#![allow(clippy::missing_safety_doc)]

use core::sync::atomic::Ordering;

use crate::code;
use crate::der;
use crate::error::{Error, Result};
use crate::gcm;
use crate::hkdf::hkdf_sm3;
use crate::pack::{self, Manifest, PackInput};
use crate::rng::SeedRng;
use crate::sm2;
use crate::sm3;
use crate::sm4;
use crate::VERSION;

#[inline]
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Error::BadArgument);
    }
    Ok(core::slice::from_raw_parts(ptr, len))
}

#[inline]
unsafe fn as_slice_mut<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8]> {
    if len == 0 {
        return Ok(core::slice::from_raw_parts_mut(1 as *mut u8, 0));
    }
    if ptr.is_null() {
        return Err(Error::BadArgument);
    }
    Ok(core::slice::from_raw_parts_mut(ptr, len))
}

#[inline]
unsafe fn fixed<const N: usize>(ptr: *const u8) -> Result<[u8; N]> {
    if ptr.is_null() {
        return Err(Error::BadArgument);
    }
    let mut out = [0u8; N];
    core::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), N);
    Ok(out)
}

unsafe fn write_out(src: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> Result<()> {
    if out_len.is_null() {
        return Err(Error::BadArgument);
    }
    if cap < src.len() {
        core::ptr::write(out_len, src.len());
        return Err(Error::BufferTooSmall);
    }
    if !src.is_empty() {
        if out.is_null() {
            return Err(Error::BadArgument);
        }
        core::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len());
    }
    core::ptr::write(out_len, src.len());
    Ok(())
}

fn rc(r: Result<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

/// P2：同一个 seed 复用会直接报错（不再静默混计数器续用）。
///
/// 保留最近 64 个 seed 的 SM3 指纹做判重；命中 → `CRYPTO_RNG_FAILED`。
/// 调用方每次操作都应该用 `crypto.getRandomValues` 现取新 seed。
fn note_seed_once(seed: &[u8]) -> Result<()> {
    use std::sync::Mutex;
    const CAP: usize = 64;
    static SEEN: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
    let digest = sm3::sm3(seed);
    let mut seen = SEEN.lock().map_err(|_| Error::Internal)?;
    if seen.contains(&digest) {
        return Err(Error::Rng);
    }
    if seen.len() >= CAP {
        seen.remove(0);
    }
    seen.push(digest);
    Ok(())
}

fn seeded_rng(seed: &[u8]) -> Result<SeedRng> {
    if seed.is_empty() {
        return Err(Error::Rng);
    }
    note_seed_once(seed)?;
    use core::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut material = Vec::with_capacity(seed.len() + 8);
    material.extend_from_slice(seed);
    material.extend_from_slice(&COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes());
    Ok(SeedRng::new(&material))
}

fn to_pub65(pub64: &[u8; 64]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..].copy_from_slice(pub64);
    out
}

// ---------------------------------------------------------------- 内存 / 元信息 / 布局

#[no_mangle]
pub extern "C" fn ys_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    let mut v: Vec<u8> = Vec::with_capacity(len);
    let ptr = v.as_mut_ptr();
    core::mem::forget(v);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn ys_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Vec::from_raw_parts(ptr, 0, len));
}

#[no_mangle]
pub extern "C" fn ys_version() -> u32 {
    VERSION
}

/// 默认块大小（1 MiB）。首版名字，保留。
#[no_mangle]
pub extern "C" fn ys_default_block_size() -> u32 {
    pack::v1::DEFAULT_CHUNK_SIZE
}

/// 包头长度（契约 `YSPK/1.0` 固定 112 字节）。
#[no_mangle]
pub extern "C" fn ys_header_len() -> u32 {
    pack::v1::HEADER_LEN as u32
}

static ERROR_TABLE: &[Error] = &[
    Error::BadArgument,
    Error::BufferTooSmall,
    Error::Rng,
    Error::BadMagic,
    Error::UnsupportedVersion,
    Error::BadFlags,
    Error::Truncated,
    Error::BadKeyRecord,
    Error::BadSignatureRecord,
    Error::BadManifestRecord,
    Error::BlockSequence,
    Error::DuplicateBlock,
    Error::MissingBlock,
    Error::LastFlagMismatch,
    Error::TagMismatch,
    Error::ManifestMismatch,
    Error::SignatureMismatch,
    Error::TrailingBytes,
    Error::BadPoint,
    Error::BadKdf,
    Error::BadCode,
    Error::CodeExhausted,
    Error::BadCiphertext,
    Error::HeaderInvalid,
    Error::AlgUnsupported,
    Error::Unsigned,
    Error::LengthInconsistent,
    Error::ChunkOrder,
    Error::ChunkAuthFailed,
    Error::ChunkMissing,
    Error::ManifestAuthFailed,
    Error::DigestMismatch,
    Error::SenderMismatch,
    Error::Internal,
];

fn name_for(code: i32, contract_style: bool) -> &'static str {
    if code == 0 {
        return "OK";
    }
    match ERROR_TABLE.iter().find(|e| e.code() == code) {
        Some(e) => {
            if contract_style {
                e.name()
            } else {
                e.legacy_name()
            }
        }
        None => {
            if contract_style {
                "CRYPTO_UNKNOWN"
            } else {
                "UNKNOWN"
            }
        }
    }
}

/// 首版 ABI 的错误名（`BAD_MAGIC` 等；Web 的映射表按这套查）。
#[no_mangle]
pub unsafe extern "C" fn ys_error_name(
    code: i32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc(write_out(
        name_for(code, false).as_bytes(),
        out,
        cap,
        out_len,
    ))
}

/// 契约口径的错误名（`CRYPTO_*`）；新增导出，不影响首版行为。
#[no_mangle]
pub unsafe extern "C" fn ys_error_name_v1(
    code: i32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc(write_out(
        name_for(code, true).as_bytes(),
        out,
        cap,
        out_len,
    ))
}

// ---------------------------------------------------------------- SM3 / HMAC / HKDF

#[no_mangle]
pub unsafe extern "C" fn ys_sm3(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    rc((|| {
        let digest = sm3::sm3(as_slice(input, input_len)?);
        as_slice_mut(out, 32)?.copy_from_slice(&digest);
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_hmac_sm3(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let tag = sm3::hmac_sm3(as_slice(key, key_len)?, as_slice(msg, msg_len)?);
        as_slice_mut(out, 32)?.copy_from_slice(&tag);
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_hkdf_sm3(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    rc((|| {
        hkdf_sm3(
            as_slice(salt, salt_len)?,
            as_slice(ikm, ikm_len)?,
            as_slice(info, info_len)?,
            as_slice_mut(out, out_len)?,
        );
        Ok(())
    })())
}

// ---------------------------------------------------------------- SM4 / GCM

#[no_mangle]
pub unsafe extern "C" fn ys_sm4_encrypt_block(
    key: *const u8,
    input: *const u8,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let key = fixed::<16>(key)?;
        let block = fixed::<16>(input)?;
        as_slice_mut(out, 16)?.copy_from_slice(&sm4::encrypt_block(&key, &block));
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_sm4_decrypt_block(
    key: *const u8,
    input: *const u8,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let key = fixed::<16>(key)?;
        let block = fixed::<16>(input)?;
        as_slice_mut(out, 16)?.copy_from_slice(&sm4::decrypt_block(&key, &block));
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_sm4_gcm_encrypt(
    key: *const u8,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    tag_out: *mut u8,
) -> i32 {
    rc((|| {
        let key = fixed::<16>(key)?;
        let nonce = as_slice(nonce, nonce_len)?;
        let aad = as_slice(aad, aad_len)?;
        let pt = as_slice(input, input_len)?;
        let out = as_slice_mut(out, input_len)?;
        let mut tag = [0u8; 16];
        gcm::encrypt(&key, nonce, aad, pt, out, &mut tag);
        as_slice_mut(tag_out, 16)?.copy_from_slice(&tag);
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_sm4_gcm_decrypt(
    key: *const u8,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    input: *const u8,
    input_len: usize,
    tag: *const u8,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let key = fixed::<16>(key)?;
        let nonce = as_slice(nonce, nonce_len)?;
        let aad = as_slice(aad, aad_len)?;
        let ct = as_slice(input, input_len)?;
        let tag = fixed::<16>(tag)?;
        let pt = gcm::decrypt(&key, nonce, aad, ct, &tag).ok_or(Error::TagMismatch)?;
        as_slice_mut(out, input_len)?.copy_from_slice(&pt);
        Ok(())
    })())
}

// ---------------------------------------------------------------- SM2（首版口径：64 字节公钥 / 裸 R‖S）

#[no_mangle]
pub unsafe extern "C" fn ys_sm2_keygen(
    seed: *const u8,
    seed_len: usize,
    priv_out: *mut u8,
    pub_out: *mut u8,
) -> i32 {
    rc((|| {
        let mut rng = seeded_rng(as_slice(seed, seed_len)?)?;
        let kp = sm2::keygen(&mut rng);
        as_slice_mut(priv_out, 32)?.copy_from_slice(&kp.private_key);
        as_slice_mut(pub_out, 64)?.copy_from_slice(&kp.public_key);
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_sm2_pubkey(priv_key: *const u8, pub_out: *mut u8) -> i32 {
    rc((|| {
        let pk = sm2::public_from_private(&fixed::<32>(priv_key)?)?;
        as_slice_mut(pub_out, 64)?.copy_from_slice(&pk);
        Ok(())
    })())
}

/// 入参公钥 64 字节 `X‖Y`，输出裸 `C1C3C2`（不带 0x04）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_encrypt(
    public_key: *const u8,
    seed: *const u8,
    seed_len: usize,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let pub64 = fixed::<64>(public_key)?;
        let mut rng = seeded_rng(as_slice(seed, seed_len)?)?;
        let ct = sm2::encrypt_with_rng(&pub64, as_slice(input, input_len)?, &mut rng)?;
        write_out(&ct, out, out_cap, out_len)
    })())
}

/// 入参裸 `C1C3C2`（不带 0x04）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_decrypt(
    priv_key: *const u8,
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let msg = sm2::decrypt(&fixed::<32>(priv_key)?, as_slice(input, input_len)?)?;
        write_out(&msg, out, out_cap, out_len)
    })())
}

/// 输出裸 `R‖S`（64 字节）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_sign(
    priv_key: *const u8,
    seed: *const u8,
    seed_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> i32 {
    rc((|| {
        let sk = fixed::<32>(priv_key)?;
        let mut rng = seeded_rng(as_slice(seed, seed_len)?)?;
        let raw = sm2::sign(&sk, as_slice(msg, msg_len)?, sm2::DEFAULT_ID, &mut rng)?;
        as_slice_mut(sig_out, 64)?.copy_from_slice(&raw);
        Ok(())
    })())
}

/// 入参裸 `R‖S`（64 字节）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_verify(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> i32 {
    let r = (|| -> Result<bool> {
        let pub64 = fixed::<64>(public_key)?;
        let sig = fixed::<64>(sig)?;
        sm2::verify(&pub64, as_slice(msg, msg_len)?, sm2::DEFAULT_ID, &sig)
    })();
    match r {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => e.code(),
    }
}

/// 契约口径的签名（DER 70..72 字节），新增导出。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_sign_der(
    priv_key: *const u8,
    seed: *const u8,
    seed_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_cap: usize,
    sig_len_out: *mut usize,
) -> i32 {
    rc((|| {
        let sk = fixed::<32>(priv_key)?;
        let mut rng = seeded_rng(as_slice(seed, seed_len)?)?;
        let raw = sm2::sign(&sk, as_slice(msg, msg_len)?, sm2::DEFAULT_ID, &mut rng)?;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..]);
        write_out(
            &der::encode_signature(&r, &s),
            sig_out,
            sig_cap,
            sig_len_out,
        )
    })())
}

// ---------------------------------------------------------------- 用户码

/// 入参 64 字节公钥；内核内部补 `0x04` 后按契约（SM3 覆盖 65 字节）派生。
#[no_mangle]
pub unsafe extern "C" fn ys_user_code(public_key: *const u8, out: *mut u8) -> i32 {
    rc((|| {
        let pub65 = to_pub65(&fixed::<64>(public_key)?);
        let code = code::from_public_key(&pub65);
        as_slice_mut(out, 4)?.copy_from_slice(code.as_bytes());
        Ok(())
    })())
}

/// 校验字符（第 5 位，仅 UI 防误输入；**不是用户码的一部分**）。
#[no_mangle]
pub unsafe extern "C" fn ys_check_symbol(public_key: *const u8, out: *mut u8) -> i32 {
    rc((|| {
        let pub65 = to_pub65(&fixed::<64>(public_key)?);
        as_slice_mut(out, 1)?.copy_from_slice(&[code::check_symbol(&pub65) as u8]);
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_normalize_code(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let s = core::str::from_utf8(as_slice(input, input_len)?).map_err(|_| Error::BadCode)?;
        as_slice_mut(out, 4)?.copy_from_slice(code::normalize(s)?.as_bytes());
        Ok(())
    })())
}

// ---------------------------------------------------------------- 加密包（首版签名）

/// 打包（`YSPK/1.0`）。清单 `ext` 为空、`created_at = 0`；完整字段用 [`ys_pack_v1`]。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ys_pack(
    recipient_public: *const u8,
    sender_private: *const u8,
    name: *const u8,
    name_len: usize,
    mime: *const u8,
    mime_len: usize,
    block_size: u32,
    seed: *const u8,
    seed_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let recipient = fixed::<64>(recipient_public)?;
        let sender = fixed::<32>(sender_private)?;
        let name =
            core::str::from_utf8(as_slice(name, name_len)?).map_err(|_| Error::BadArgument)?;
        let mime =
            core::str::from_utf8(as_slice(mime, mime_len)?).map_err(|_| Error::BadArgument)?;
        let seed = as_slice(seed, seed_len)?;
        let data = as_slice(data, data_len)?;
        let block_size = if block_size == 0 {
            pack::v1::DEFAULT_CHUNK_SIZE
        } else {
            block_size
        };

        let input = PackInput {
            recipient_public: &to_pub65(&recipient),
            sender_private: &sender,
            name,
            mime,
            ext: "",
            created_at_ms: 0,
            chunk_size: block_size,
            data,
        };
        // 先算上界（不消耗随机数），缓冲区不够就直接返回上界。
        let bound = pack::pack_bound(&input)?;
        if out_cap < bound {
            if out_len.is_null() {
                return Err(Error::BadArgument);
            }
            core::ptr::write(out_len, bound);
            return Err(Error::BufferTooSmall);
        }
        let mut rng = seeded_rng(seed)?;
        let envelope = pack::pack(&input, &mut rng)?;
        write_out(&envelope, out, out_cap, out_len)
    })())
}

/// 解包。来源由包内 `SENDER_PUB` 自证（验签 + 派生发送方码），**不再需要调用方传公钥**。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let data = pack::unpack(bytes, &sk, None)?.data;
        write_out(&data, out, out_cap, out_len)
    })())
}

/// 只解清单（不解数据块），输出 JSON 元信息（含包内 `SENDER_PUB` 派生的发送方码）。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_meta(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let opened = pack::open_only(bytes, &sk)?;
        let json = meta_json(&opened.header, &opened.manifest, &opened.sender_public);
        write_out(json.as_bytes(), out, out_cap, out_len)
    })())
}

// ---------------------------------------------------------------- 契约口径的完整参数版本（新增）

/// 打包（完整参数）：65 字节公钥 + `ext` + `created_at_ms`。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ys_pack_v1(
    recipient_public: *const u8,
    sender_private: *const u8,
    name: *const u8,
    name_len: usize,
    mime: *const u8,
    mime_len: usize,
    ext: *const u8,
    ext_len: usize,
    created_at_ms: u64,
    chunk_size: u32,
    seed: *const u8,
    seed_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let pub65 = fixed::<65>(recipient_public)?;
        if pub65[0] != 0x04 {
            return Err(Error::BadPoint);
        }
        let sender = fixed::<32>(sender_private)?;
        let name =
            core::str::from_utf8(as_slice(name, name_len)?).map_err(|_| Error::BadArgument)?;
        let mime =
            core::str::from_utf8(as_slice(mime, mime_len)?).map_err(|_| Error::BadArgument)?;
        let ext = core::str::from_utf8(as_slice(ext, ext_len)?).map_err(|_| Error::BadArgument)?;
        let mut rng = seeded_rng(as_slice(seed, seed_len)?)?;
        let input = PackInput {
            recipient_public: &pub65,
            sender_private: &sender,
            name,
            mime,
            ext,
            created_at_ms,
            chunk_size: if chunk_size == 0 {
                pack::v1::DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            data: as_slice(data, data_len)?,
        };
        let bound = pack::pack_bound(&input)?;
        if out_cap < bound {
            if out_len.is_null() {
                return Err(Error::BadArgument);
            }
            core::ptr::write(out_len, bound);
            return Err(Error::BufferTooSmall);
        }
        let envelope = pack::pack(&input, &mut rng)?;
        write_out(&envelope, out, out_cap, out_len)
    })())
}

// ---------------------------------------------------------------- JSON

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn meta_json(header: &pack::Header, manifest: &Manifest, sender_public: &[u8; 65]) -> String {
    format!(
        "{{\"version\":\"{}\",\"name\":\"{}\",\"mime\":\"{}\",\"ext\":\"{}\",\"size\":{},\"chunk_size\":{},\"chunk_count\":{},\"created_at_ms\":{},\"sender_code\":\"{}\",\"sender_pub\":\"{}\",\"kdf_salt\":\"{}\"}}",
        pack::v1::VERSION_STRING,
        json_escape(&manifest.name),
        json_escape(&manifest.mime),
        json_escape(&manifest.ext),
        manifest.file_size,
        manifest.chunk_size,
        manifest.chunk_count,
        manifest.created_at_ms,
        crate::code::from_public_key(sender_public),
        hex(sender_public),
        hex(&header.kdf_salt),
    )
}
