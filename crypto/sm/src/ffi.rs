//! raw C ABI（wasm32-unknown-unknown 直接导出，**不引 wasm-bindgen**）。
//!
//! 约定：
//! * 所有长度参数为 `size_t`（wasm32 下 4 字节）；所有指针为线性内存偏移。
//! * 返回值 `0` = 成功，负数为错误码（见 [`crate::error::Error::code`]，命名对齐
//!   `docs/CRYPTO-PACK.md` §13 的端侧错误码）。
//! * `out_len` 指针在成功时写入实际字节数；缓冲区不足时也写入所需字节数并返回 -2。
//! * 需要随机数的接口都接收 `seed`（JS 侧用 `crypto.getRandomValues` 现取），
//!   ABI 内部再混入进程内单调计数器展开为 SM3-DRBG。**同一个 seed 不要复用**。
//! * 分配：`ys_alloc(len)` 申请、`ys_free(ptr, len)` 释放；两者必须成对、长度一致。

// 本模块的每个导出函数都是 C ABI，安全契约统一写在模块头（长度/指针成对、内存归属），
// 不逐个重复 `# Safety` 段。
#![allow(clippy::missing_safety_doc)]

use crate::code;
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

fn seeded_rng(seed: &[u8]) -> Result<SeedRng> {
    if seed.is_empty() {
        return Err(Error::Rng);
    }
    use core::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut material = Vec::with_capacity(seed.len() + 8);
    material.extend_from_slice(seed);
    material.extend_from_slice(&COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes());
    Ok(SeedRng::new(&material))
}

// ---------------------------------------------------------------- 内存 / 元信息

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

#[no_mangle]
pub extern "C" fn ys_default_chunk_size() -> u32 {
    pack::v1::DEFAULT_CHUNK_SIZE
}

#[no_mangle]
pub extern "C" fn ys_header_len() -> u32 {
    pack::v1::HEADER_LEN as u32
}

static ERROR_TABLE: &[Error] = &[
    Error::BadArgument,
    Error::BufferTooSmall,
    Error::Rng,
    Error::MagicMismatch,
    Error::VersionUnsupported,
    Error::HeaderInvalid,
    Error::LengthInconsistent,
    Error::AlgUnsupported,
    Error::FlagsUnknown,
    Error::Unsigned,
    Error::KeyUnwrapFailed,
    Error::ManifestAuthFailed,
    Error::ManifestInvalid,
    Error::SignatureInvalid,
    Error::SenderMismatch,
    Error::ChunkOrder,
    Error::ChunkAuthFailed,
    Error::ChunkMissing,
    Error::DigestMismatch,
    Error::BadCode,
    Error::CodeExhausted,
    Error::BadPoint,
    Error::BadCiphertext,
    Error::Internal,
];

#[no_mangle]
pub unsafe extern "C" fn ys_error_name(
    code: i32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let name = if code == 0 {
        "OK"
    } else {
        ERROR_TABLE
            .iter()
            .find(|e| e.code() == code)
            .map(|e| e.name())
            .unwrap_or("CRYPTO_UNKNOWN")
    };
    rc(write_out(name.as_bytes(), out, cap, out_len))
}

// ---------------------------------------------------------------- SM3 / HMAC / HKDF

#[no_mangle]
pub unsafe extern "C" fn ys_sm3(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    rc((|| {
        let data = as_slice(input, input_len)?;
        let digest = sm3::sm3(data);
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
        let k = as_slice(key, key_len)?;
        let m = as_slice(msg, msg_len)?;
        let tag = sm3::hmac_sm3(k, m);
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
        let ikm = as_slice(ikm, ikm_len)?;
        let salt = as_slice(salt, salt_len)?;
        let info = as_slice(info, info_len)?;
        hkdf_sm3(salt, ikm, info, as_slice_mut(out, out_len)?);
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
        let pt = gcm::decrypt(&key, nonce, aad, ct, &tag).ok_or(Error::ChunkAuthFailed)?;
        as_slice_mut(out, input_len)?.copy_from_slice(&pt);
        Ok(())
    })())
}

// ---------------------------------------------------------------- SM2

#[no_mangle]
pub unsafe extern "C" fn ys_sm2_keygen(
    seed: *const u8,
    seed_len: usize,
    priv_out: *mut u8,
    pub_out: *mut u8,
) -> i32 {
    rc((|| {
        let seed = as_slice(seed, seed_len)?;
        let mut rng = seeded_rng(seed)?;
        let kp = sm2::keygen(&mut rng);
        as_slice_mut(priv_out, 32)?.copy_from_slice(&kp.private_key);
        let pub65 = as_slice_mut(pub_out, 65)?;
        pub65[0] = 0x04;
        pub65[1..].copy_from_slice(&kp.public_key);
        Ok(())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn ys_sm2_pubkey(priv_key: *const u8, pub_out: *mut u8) -> i32 {
    rc((|| {
        let sk = fixed::<32>(priv_key)?;
        let pk = sm2::public_from_private(&sk)?;
        let pub65 = as_slice_mut(pub_out, 65)?;
        pub65[0] = 0x04;
        pub65[1..].copy_from_slice(&pk);
        Ok(())
    })())
}

/// 加密：公钥 65 字节（`0x04‖X‖Y`），输出 `0x04‖C1‖C3‖C2`（= 96+明文长度+1）。
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
        let pub65 = fixed::<65>(public_key)?;
        if pub65[0] != 0x04 {
            return Err(Error::BadPoint);
        }
        let seed = as_slice(seed, seed_len)?;
        let msg = as_slice(input, input_len)?;
        let pub64: [u8; 64] = pub65[1..].try_into().expect("64");
        let mut rng = seeded_rng(seed)?;
        let ct = sm2::encrypt_with_rng(&pub64, msg, &mut rng)?;
        let mut outv = Vec::with_capacity(ct.len() + 1);
        outv.push(0x04);
        outv.extend_from_slice(&ct);
        write_out(&outv, out, out_cap, out_len)
    })())
}

/// 解密：输入 `0x04‖C1‖C3‖C2`。
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
        let sk = fixed::<32>(priv_key)?;
        let ct = as_slice(input, input_len)?;
        if ct.len() < 98 || ct[0] != 0x04 {
            return Err(Error::BadCiphertext);
        }
        let msg = sm2::decrypt(&sk, &ct[1..])?;
        write_out(&msg, out, out_cap, out_len)
    })())
}

/// 签名：输入任意消息字节，输出 DER（70..72 字节）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_sign(
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
        let seed = as_slice(seed, seed_len)?;
        let msg = as_slice(msg, msg_len)?;
        let mut rng = seeded_rng(seed)?;
        let raw = sm2::sign(&sk, msg, sm2::DEFAULT_ID, &mut rng)?;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..]);
        let der = crate::der::encode_signature(&r, &s);
        write_out(&der, sig_out, sig_cap, sig_len_out)
    })())
}

/// 验签：1 = 通过，0 = 不通过，负数 = 参数/曲线错误。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_verify(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_der: *const u8,
    sig_len: usize,
) -> i32 {
    let r = (|| -> Result<bool> {
        let pub65 = fixed::<65>(public_key)?;
        if pub65[0] != 0x04 {
            return Err(Error::BadPoint);
        }
        let msg = as_slice(msg, msg_len)?;
        let der = as_slice(sig_der, sig_len)?;
        let (r, s) = crate::der::decode_signature(der)?;
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&r);
        raw[32..].copy_from_slice(&s);
        let pub64: [u8; 64] = pub65[1..].try_into().expect("64");
        sm2::verify(&pub64, msg, sm2::DEFAULT_ID, &raw)
    })();
    match r {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => e.code(),
    }
}

// ---------------------------------------------------------------- 用户码

#[no_mangle]
pub unsafe extern "C" fn ys_user_code(public_key: *const u8, out: *mut u8) -> i32 {
    rc((|| {
        let pub65 = fixed::<65>(public_key)?;
        if pub65[0] != 0x04 {
            return Err(Error::BadPoint);
        }
        let code = code::from_public_key(&pub65);
        as_slice_mut(out, 4)?.copy_from_slice(code.as_bytes());
        Ok(())
    })())
}

/// 校验字符（第 5 位，展示用），写入 `out` 1 字节。
#[no_mangle]
pub unsafe extern "C" fn ys_check_symbol(public_key: *const u8, out: *mut u8) -> i32 {
    rc((|| {
        let pub65 = fixed::<65>(public_key)?;
        if pub65[0] != 0x04 {
            return Err(Error::BadPoint);
        }
        let sym = code::check_symbol(&pub65) as u8;
        as_slice_mut(out, 1)?.copy_from_slice(&[sym]);
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
        let raw = as_slice(input, input_len)?;
        let s = core::str::from_utf8(raw).map_err(|_| Error::BadCode)?;
        let normalized = code::normalize(s)?;
        as_slice_mut(out, 4)?.copy_from_slice(normalized.as_bytes());
        Ok(())
    })())
}

// ---------------------------------------------------------------- 加密包

/// 打包（`YSPK/1.0`）。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ys_pack(
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
        let recipient_public = fixed::<65>(recipient_public)?;
        let sender_private = fixed::<32>(sender_private)?;
        let name =
            core::str::from_utf8(as_slice(name, name_len)?).map_err(|_| Error::BadArgument)?;
        let mime =
            core::str::from_utf8(as_slice(mime, mime_len)?).map_err(|_| Error::BadArgument)?;
        let ext = core::str::from_utf8(as_slice(ext, ext_len)?).map_err(|_| Error::BadArgument)?;
        let seed = as_slice(seed, seed_len)?;
        let data = as_slice(data, data_len)?;
        let mut rng = seeded_rng(seed)?;
        let input = PackInput {
            recipient_public: &recipient_public,
            sender_private: &sender_private,
            name,
            mime,
            ext,
            created_at_ms,
            chunk_size: if chunk_size == 0 {
                pack::v1::DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            data,
        };
        let envelope = pack::pack(&input, &mut rng)?;
        write_out(&envelope, out, out_cap, out_len)
    })())
}

unsafe fn opt_code<'a>(ptr: *const u8, len: usize) -> Result<Option<&'a str>> {
    if len == 0 {
        return Ok(None);
    }
    let raw = as_slice(ptr, len)?;
    let s = core::str::from_utf8(raw).map_err(|_| Error::BadCode)?;
    Ok(Some(s))
}

/// 只解清单（不解数据块），输出 JSON 元信息。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_meta(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    expected_sender_code: *const u8,
    expected_sender_code_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let pack_bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let (header, manifest, sender_public, sender_code) = pack::open_manifest(pack_bytes, &sk)?;
        if let Some(expected) = opt_code(expected_sender_code, expected_sender_code_len)? {
            if sender_code != expected {
                return Err(Error::SenderMismatch);
            }
        }
        let json = manifest_json(&header, &manifest, &sender_public, &sender_code);
        write_out(json.as_bytes(), out, out_cap, out_len)
    })())
}

/// 完整解包（严格模式），输出明文。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    expected_sender_code: *const u8,
    expected_sender_code_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let pack_bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let expected = opt_code(expected_sender_code, expected_sender_code_len)?;
        let unpacked = pack::unpack(pack_bytes, &sk, expected)?;
        write_out(&unpacked.data, out, out_cap, out_len)
    })())
}

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

fn manifest_json(
    header: &pack::Header,
    manifest: &Manifest,
    sender_public: &[u8; 65],
    sender_code: &str,
) -> String {
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
        sender_code,
        hex(sender_public),
        hex(&header.kdf_salt),
    )
}
