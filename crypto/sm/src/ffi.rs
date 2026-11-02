//! raw C ABI（wasm32-unknown-unknown 直接导出，**不引 wasm-bindgen**）。
//!
//! 约定：
//! * 所有长度参数为 `size_t`（wasm32 下 4 字节）；所有指针为线性内存偏移。
//! * 返回值 `0` = 成功，负数为错误码（见 [`crate::error::Error::code`]）。
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
use crate::pack::{self, layout, Header, Manifest, PackInput};
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

/// 由 JS 传入的种子构造 DRBG，并混入进程内计数器。
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

/// 申请 `len` 字节线性内存，返回指针（失败返回 0）。
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

/// 释放 `ys_alloc` 申请的内存（长度必须与申请时一致）。
#[no_mangle]
pub unsafe extern "C" fn ys_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Vec::from_raw_parts(ptr, 0, len));
}

/// 内核版本，`0x0001_0000` = 1.0。
#[no_mangle]
pub extern "C" fn ys_version() -> u32 {
    VERSION
}

/// 默认块大小（字节）。
#[no_mangle]
pub extern "C" fn ys_default_block_size() -> u32 {
    layout::DEFAULT_BLOCK_SIZE
}

/// 包头长度（字节）。
#[no_mangle]
pub extern "C" fn ys_header_len() -> u32 {
    layout::HEADER_LEN as u32
}

/// 错误名写入 `out`（ASCII，不含结尾 0）。
#[no_mangle]
pub unsafe extern "C" fn ys_error_name(
    code: i32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    let name = match code {
        0 => "OK",
        c => {
            let mut found = "UNKNOWN";
            for e in ERROR_TABLE {
                if e.code() == c {
                    found = e.name();
                    break;
                }
            }
            found
        }
    };
    rc(write_out(name.as_bytes(), out, cap, out_len))
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
    Error::Internal,
];

// ---------------------------------------------------------------- SM3 / HMAC / HKDF

/// SM3：`out` 32 字节。
#[no_mangle]
pub unsafe extern "C" fn ys_sm3(input: *const u8, input_len: usize, out: *mut u8) -> i32 {
    rc((|| {
        let data = as_slice(input, input_len)?;
        let digest = sm3::sm3(data);
        let out = as_slice_mut(out, 32)?;
        out.copy_from_slice(&digest);
        Ok(())
    })())
}

/// HMAC-SM3：`out` 32 字节。
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
        let out = as_slice_mut(out, 32)?;
        out.copy_from_slice(&tag);
        Ok(())
    })())
}

/// HKDF-SM3。
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
        let out = as_slice_mut(out, out_len)?;
        hkdf_sm3(salt, ikm, info, out);
        Ok(())
    })())
}

// ---------------------------------------------------------------- SM4 / GCM

/// SM4 单块加密（16 字节）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm4_encrypt_block(
    key: *const u8,
    input: *const u8,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let key = fixed::<16>(key)?;
        let block = fixed::<16>(input)?;
        let ct = sm4::encrypt_block(&key, &block);
        let out = as_slice_mut(out, 16)?;
        out.copy_from_slice(&ct);
        Ok(())
    })())
}

/// SM4 单块解密（16 字节）。
#[no_mangle]
pub unsafe extern "C" fn ys_sm4_decrypt_block(
    key: *const u8,
    input: *const u8,
    out: *mut u8,
) -> i32 {
    rc((|| {
        let key = fixed::<16>(key)?;
        let block = fixed::<16>(input)?;
        let pt = sm4::decrypt_block(&key, &block);
        let out = as_slice_mut(out, 16)?;
        out.copy_from_slice(&pt);
        Ok(())
    })())
}

/// SM4-GCM 加密：`out` 与明文等长，`tag_out` 16 字节。
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
        let tag_out = as_slice_mut(tag_out, 16)?;
        tag_out.copy_from_slice(&tag);
        Ok(())
    })())
}

/// SM4-GCM 解密：tag 校验失败返回 -15（TAG_MISMATCH）。
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
        let out = as_slice_mut(out, input_len)?;
        out.copy_from_slice(&pt);
        Ok(())
    })())
}

// ---------------------------------------------------------------- SM2

/// 生成密钥对：`priv_out` 32 字节，`pub_out` 64 字节。
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
        let p = as_slice_mut(priv_out, 32)?;
        p.copy_from_slice(&kp.private_key);
        let q = as_slice_mut(pub_out, 64)?;
        q.copy_from_slice(&kp.public_key);
        Ok(())
    })())
}

/// 由私钥派生公钥。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_pubkey(priv_key: *const u8, pub_out: *mut u8) -> i32 {
    rc((|| {
        let sk = fixed::<32>(priv_key)?;
        let pk = sm2::public_from_private(&sk)?;
        let q = as_slice_mut(pub_out, 64)?;
        q.copy_from_slice(&pk);
        Ok(())
    })())
}

/// SM2 加密（C1C3C2 平文拼接）。
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
        let pk = fixed::<64>(public_key)?;
        let seed = as_slice(seed, seed_len)?;
        let msg = as_slice(input, input_len)?;
        let mut rng = seeded_rng(seed)?;
        let ct = sm2::encrypt_with_rng(&pk, msg, &mut rng)?;
        write_out(&ct, out, out_cap, out_len)
    })())
}

/// SM2 解密（C1C3C2）。
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
        let msg = sm2::decrypt(&sk, ct)?;
        write_out(&msg, out, out_cap, out_len)
    })())
}

/// SM2 签名：`sig_out` 64 字节（r||s）。
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
        let seed = as_slice(seed, seed_len)?;
        let msg = as_slice(msg, msg_len)?;
        let mut rng = seeded_rng(seed)?;
        let sig = sm2::sign(&sk, msg, sm2::DEFAULT_ID, &mut rng)?;
        let out = as_slice_mut(sig_out, 64)?;
        out.copy_from_slice(&sig);
        Ok(())
    })())
}

/// SM2 验签：1 = 通过，0 = 不通过，负数 = 参数/曲线错误。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_verify(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> i32 {
    let r = (|| -> Result<bool> {
        let pk = fixed::<64>(public_key)?;
        let msg = as_slice(msg, msg_len)?;
        let sig = fixed::<64>(sig)?;
        sm2::verify(&pk, msg, sm2::DEFAULT_ID, &sig)
    })();
    match r {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => e.code(),
    }
}

// ---------------------------------------------------------------- 用户码

/// 由公钥派生 4 位用户码，`out` 4 字节 ASCII（大写）。
#[no_mangle]
pub unsafe extern "C" fn ys_user_code(public_key: *const u8, out: *mut u8) -> i32 {
    rc((|| {
        let pk = fixed::<64>(public_key)?;
        let code = code::from_public_key(&pk);
        let out = as_slice_mut(out, 4)?;
        out.copy_from_slice(code.as_bytes());
        Ok(())
    })())
}

/// 规范化用户输入（大小写 / O→0 / I,L→1 / 去 `-`），`out` 4 字节 ASCII。
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
        let out = as_slice_mut(out, 4)?;
        out.copy_from_slice(normalized.as_bytes());
        Ok(())
    })())
}

// ---------------------------------------------------------------- 加密包

/// 打包。返回包字节；`out_len` 写实际长度（缓冲区不足时也写所需长度）。
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
        let recipient_public = fixed::<64>(recipient_public)?;
        let sender_private = fixed::<32>(sender_private)?;
        let name =
            core::str::from_utf8(as_slice(name, name_len)?).map_err(|_| Error::BadArgument)?;
        let mime =
            core::str::from_utf8(as_slice(mime, mime_len)?).map_err(|_| Error::BadArgument)?;
        let seed = as_slice(seed, seed_len)?;
        let data = as_slice(data, data_len)?;
        let mut rng = seeded_rng(seed)?;
        let input = PackInput {
            recipient_public: &recipient_public,
            sender_private: &sender_private,
            name,
            mime,
            block_size: if block_size == 0 {
                layout::DEFAULT_BLOCK_SIZE
            } else {
                block_size
            },
            data,
        };
        let pack = pack::pack(&input, &mut rng)?;
        write_out(&pack, out, out_cap, out_len)
    })())
}

/// 只解清单（不解数据块），输出 JSON 元信息。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_meta(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    sender_public: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let pack_bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let pk = fixed::<64>(sender_public)?;
        let (header, manifest) = pack::open_manifest(pack_bytes, &sk, &pk)?;
        let json = manifest_json(&header, &manifest);
        write_out(json.as_bytes(), out, out_cap, out_len)
    })())
}

/// 完整解包（解密全部数据块），输出明文。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    sender_public: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let pack_bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let pk = fixed::<64>(sender_public)?;
        let unpacked = pack::unpack(pack_bytes, &sk, &pk)?;
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

fn manifest_json(header: &Header, manifest: &Manifest) -> String {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!("\"name\":\"{}\"", json_escape(&manifest.name)));
    s.push_str(&format!(",\"mime\":\"{}\"", json_escape(&manifest.mime)));
    s.push_str(&format!(",\"size\":{}", manifest.plain_size));
    s.push_str(&format!(",\"block_size\":{}", manifest.block_size));
    s.push_str(&format!(",\"block_count\":{}", manifest.block_count));
    s.push_str(&format!(",\"version\":{}", layout::VERSION));
    s.push_str(",\"file_id\":\"");
    for b in header.file_id.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('"');
    s.push_str(",\"block_digests\":[");
    for (i, d) in manifest.block_digests.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        for b in d.iter() {
            s.push_str(&format!("{:02x}", b));
        }
        s.push('"');
    }
    s.push_str("]}");
    s
}
