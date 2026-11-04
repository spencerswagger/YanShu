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

/// 分配头：8 字节长度 + 8 字节对齐填充。释放时不依赖调用方传的 `len`。
const ALLOC_HDR: usize = 16;
const ALLOC_ALIGN: usize = 16;

/// 分配 `len` 字节。返回的指针已跳过 16 字节头。
///
/// **不依赖 `Vec` 的容量**：用精确 `Layout` 分配，`ys_free` 用同一 `Layout` 释放，
/// 避免 `Vec::with_capacity` 的容量取整与调用方传入长度不一致导致的堆损坏。
#[no_mangle]
pub extern "C" fn ys_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    let total = match len.checked_add(ALLOC_HDR) {
        Some(v) => v,
        None => return core::ptr::null_mut(),
    };
    let layout = match std::alloc::Layout::from_size_align(total, ALLOC_ALIGN) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };
    unsafe {
        let base = std::alloc::alloc(layout);
        if base.is_null() {
            return core::ptr::null_mut();
        }
        // 头里记长度，释放时用它（调用方传错 len 也不会破坏堆）
        core::ptr::write(base as *mut u64, len as u64);
        base.add(ALLOC_HDR)
    }
}

/// 释放 `ys_alloc` 的指针。`len` 仅作兼容保留——真实长度取自分配头。
#[no_mangle]
pub unsafe extern "C" fn ys_free(ptr: *mut u8, _len: usize) {
    if ptr.is_null() {
        return;
    }
    let base = ptr.sub(ALLOC_HDR);
    let len = core::ptr::read(base as *const u64) as usize;
    let total = match len.checked_add(ALLOC_HDR) {
        Some(v) => v,
        None => return,
    };
    let layout = match std::alloc::Layout::from_size_align(total, ALLOC_ALIGN) {
        Ok(l) => l,
        Err(_) => return,
    };
    std::alloc::dealloc(base, layout);
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

/// 首版重复数值 → 契约 §13.1 的规范值（只用于**解析**旧数值，不再产出）。
const ALIASES: &[(i32, i32)] = &[
    (-11, -28), // BLOCK_SEQUENCE      → CHUNK_ORDER
    (-12, -28), // DUPLICATE_BLOCK     → CHUNK_ORDER
    (-14, -28), // LAST_FLAG_MISMATCH  → CHUNK_ORDER
    (-13, -30), // MISSING_BLOCK       → CHUNK_MISSING
    (-15, -29), // TAG_MISMATCH        → CHUNK_AUTH_FAILED
    (-16, -31), // MANIFEST_MISMATCH   → MANIFEST_AUTH_FAILED
    (-20, -19), // BAD_KDF             → CIPHERTEXT_INVALID
    (-23, -19), // BAD_CIPHERTEXT      → CIPHERTEXT_INVALID
];

fn canonical_code(code: i32) -> i32 {
    ALIASES
        .iter()
        .find(|(old, _)| *old == code)
        .map(|(_, new)| *new)
        .unwrap_or(code)
}

fn name_for(code: i32) -> &'static str {
    if code == 0 {
        return "OK";
    }
    let code = canonical_code(code);
    ERROR_TABLE
        .iter()
        .find(|e| e.code() == code)
        .map(|e| e.name())
        .unwrap_or("CRYPTO_UNKNOWN")
}

/// 错误名（**唯一格式 `CRYPTO_*`**，与 Rust 侧 `Error::name()` 完全一致）。
///
/// 例：`-4 → "CRYPTO_MAGIC_MISMATCH"`、`-33 → "CRYPTO_SENDER_MISMATCH"`。
/// 不再返回首版的 `BAD_MAGIC` 之类旧名，避免 wasm 与 Rust 两套自由格式。
#[no_mangle]
pub unsafe extern "C" fn ys_error_name(
    code: i32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc(write_out(name_for(code).as_bytes(), out, cap, out_len))
}

/// `ys_error_name` 的别名（保留旧符号，输出与之一致）。
#[no_mangle]
pub unsafe extern "C" fn ys_error_name_v1(
    code: i32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    ys_error_name(code, out, cap, out_len)
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

/// 契约口径的验签：入参公钥 64 字节 `X‖Y`、签名 DER（70..72 字节）。
///
/// 1 = 通过，0 = 不通过，负数 = 参数/曲线/DER 非规范错误。
/// 服务端（Go/wazero 等）校验 `X-YS-Signature` 时用这个，不用自己解 DER。
#[no_mangle]
pub unsafe extern "C" fn ys_sm2_verify_der(
    public_key: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_der: *const u8,
    sig_len: usize,
) -> i32 {
    let r = (|| -> Result<bool> {
        let pub64 = fixed::<64>(public_key)?;
        let msg = as_slice(msg, msg_len)?;
        let der_bytes = as_slice(sig_der, sig_len)?;
        let (r, s) = der::decode_signature(der_bytes)?;
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&r);
        raw[32..].copy_from_slice(&s);
        sm2::verify(&pub64, msg, sm2::DEFAULT_ID, &raw)
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

/// 由 **65 字节 wire 公钥**（`0x04‖X‖Y`）派生 4 位码。
///
/// 与 [`ys_user_code`] 的区别只有一个：入参已经是包内/meta 里的 wire 形态（65 字节）。
/// 两个函数对"同一把钥匙"必须给出同一个码；`vectors/user-code-vectors.json` 把这条钉死。
#[no_mangle]
pub unsafe extern "C" fn ys_user_code_wire(public_key: *const u8, out: *mut u8) -> i32 {
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

/// 由 65 字节 wire 公钥派生第 5 位校验字符（仅 UI 防误输入）。
#[no_mangle]
pub unsafe extern "C" fn ys_check_symbol_wire(public_key: *const u8, out: *mut u8) -> i32 {
    rc((|| {
        let pub65 = fixed::<65>(public_key)?;
        if pub65[0] != 0x04 {
            return Err(Error::BadPoint);
        }
        as_slice_mut(out, 1)?.copy_from_slice(&[code::check_symbol(&pub65) as u8]);
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

/// 解包（首版 7 参原型，保留）。
///
/// `sender_public` 现在**可选**：传 `0`/NULL 表示不传；非空则与包内 `SENDER_PUB` 比对
/// （不一致 → `CRYPTO_SENDER_MISMATCH`）。验签始终用包内公钥。
/// 新代码建议直接用 [`ys_unpack_v1`]（6 参，无公钥入参）。
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
        let bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let data = if sender_public.is_null() {
            pack::unpack(bytes, &sk, None)?.data
        } else {
            pack::unpack_expect_sender(bytes, &sk, &fixed::<64>(sender_public)?)?.data
        };
        write_out(&data, out, out_cap, out_len)
    })())
}

/// 解包（P1 新原型，6 参）：来源完全由包内 `SENDER_PUB` 自证，不给公钥。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_v1(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let data = pack::unpack(
            as_slice(pack, pack_len)?,
            &fixed::<32>(recipient_private)?,
            None,
        )?
        .data;
        write_out(&data, out, out_cap, out_len)
    })())
}

/// 只解清单（首版 7 参原型，保留）。`sender_public` 可选（NULL 表示不比对）。
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
        let bytes = as_slice(pack, pack_len)?;
        let sk = fixed::<32>(recipient_private)?;
        let opened = pack::open_only(bytes, &sk)?;
        if !sender_public.is_null() {
            let sp = fixed::<64>(sender_public)?;
            if opened.sender_public[1..] != sp[..] {
                return Err(Error::SenderMismatch);
            }
        }
        let json = meta_json(
            &opened.header,
            &opened.manifest,
            &opened.sender_public,
            "full",
        );
        write_out(json.as_bytes(), out, out_cap, out_len)
    })())
}

/// 只解清单（P1 新原型，6 参）。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_meta_v1(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let opened = pack::open_only(as_slice(pack, pack_len)?, &fixed::<32>(recipient_private)?)?;
        let json = meta_json(
            &opened.header,
            &opened.manifest,
            &opened.sender_public,
            "full",
        );
        write_out(json.as_bytes(), out, out_cap, out_len)
    })())
}

/// 只凭 **prelude** 解元信息（允许整包未到齐）。
///
/// 等价于"收件人还没下完块，先看到发件人码 / 文件名 / 大小 / 块数"。
/// 返回 JSON 里 `"scope":"prelude"`、`"data_verified":false`：
/// 来源（`SENDER_PUB` 签名）与清单已校验，**块摘要 / 块 AEAD 尚未校验**。
/// 要数据完整性必须走 `ys_unpack` / `ys_unpack_v1`（成功即代表块都验过）。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_meta_prelude(
    pack: *const u8,
    pack_len: usize,
    recipient_private: *const u8,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let opened =
            pack::open_only_prelude(as_slice(pack, pack_len)?, &fixed::<32>(recipient_private)?)?;
        let json = meta_json(
            &opened.header,
            &opened.manifest,
            &opened.sender_public,
            "prelude",
        );
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
        // ABI 公钥统一 64 字节 `X‖Y`；0x04 前缀由内核内部补（与 ys_pack / ys_sm2_* 一致）
        let pub65 = to_pub65(&fixed::<64>(recipient_public)?);
        let sender = fixed::<32>(sender_private)?;
        let name =
            core::str::from_utf8(as_slice(name, name_len)?).map_err(|_| Error::BadArgument)?;
        let mime =
            core::str::from_utf8(as_slice(mime, mime_len)?).map_err(|_| Error::BadArgument)?;
        let ext = core::str::from_utf8(as_slice(ext, ext_len)?).map_err(|_| Error::BadArgument)?;
        let seed = as_slice(seed, seed_len)?;
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
        // 先算上界（不消耗随机数），"先问大小再分配"不会误触 seed 复用
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

fn meta_json(
    header: &pack::Header,
    manifest: &Manifest,
    sender_public: &[u8; 65],
    scope: &str,
) -> String {
    format!(
        "{{\"version\":\"{}\",\"name\":\"{}\",\"mime\":\"{}\",\"ext\":\"{}\",\"size\":{},\"chunk_size\":{},\"chunk_count\":{},\"created_at_ms\":{},\"sender_code\":\"{}\",\"sender_pub\":\"{}\",\"kdf_salt\":\"{}\",\"scope\":\"{}\",\"data_verified\":false}}",
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
        scope,
    )
}

// ============================================================================
// 流式打包 / 解包（常量内存；产出与整包接口逐字节相同）
// ============================================================================

static mut PACK_STREAM: Option<pack::PackStream> = None;
static mut UNPACK_STREAM: Option<pack::UnpackStream> = None;

fn pack_stream_slot() -> &'static mut Option<pack::PackStream> {
    // wasm 单线程；用 addr_of_mut 避免 static_mut_refs
    unsafe { &mut *core::ptr::addr_of_mut!(PACK_STREAM) }
}

fn unpack_stream_slot() -> &'static mut Option<pack::UnpackStream> {
    unsafe { &mut *core::ptr::addr_of_mut!(UNPACK_STREAM) }
}

/// 开始流式打包。`total_size` 必须等于后续 `ys_pack_hash_update` 的字节总数。
///
/// 随机数消耗顺序与 `ys_pack_v1` 完全一致（dk → salt → k_enc → k_sig），
/// 因此同一 seed 下流式产出与整包产出**逐字节相同**。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ys_pack_stream_begin(
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
    total_size: u64,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    rc((|| {
        let recipient = fixed::<64>(recipient_public)?;
        let sender = fixed::<32>(sender_private)?;
        let name =
            core::str::from_utf8(as_slice(name, name_len)?).map_err(|_| Error::BadArgument)?;
        let mime =
            core::str::from_utf8(as_slice(mime, mime_len)?).map_err(|_| Error::BadArgument)?;
        let ext = core::str::from_utf8(as_slice(ext, ext_len)?).map_err(|_| Error::BadArgument)?;
        let mut rng = seeded_rng(as_slice(seed, seed_len)?)?;
        let s = pack::PackStream::begin(
            &recipient,
            &sender,
            name,
            mime,
            ext,
            created_at_ms,
            if chunk_size == 0 {
                pack::v1::DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            total_size,
            &mut rng,
        )?;
        *pack_stream_slot() = Some(s);
        Ok(())
    })())
}

/// 顺序喂入明文（只做分块 SM3；内存增量 = 一个块缓冲 + 每块 32B 摘要）。
#[no_mangle]
pub unsafe extern "C" fn ys_pack_hash_update(data: *const u8, data_len: usize) -> i32 {
    rc((|| {
        let slot = pack_stream_slot();
        let s = slot.as_mut().ok_or(Error::BadArgument)?;
        s.hash_update(as_slice(data, data_len)?)
    })())
}

/// 生成 prelude（清单 + 签名），之后才能逐块取记录。`*out_len` 给所需长度。
#[no_mangle]
pub unsafe extern "C" fn ys_pack_stream_prelude(
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let slot = pack_stream_slot();
        let s = slot.as_mut().ok_or(Error::BadArgument)?;
        let n = s.make_prelude()?;
        let prelude = s.prelude();
        let _ = n;
        write_out(prelude, out, out_cap, out_len)
    })())
}

/// 出一块记录（16B 头 + 密文 + 16B tag）。`plaintext` 长度必须是 `chunk_len(index)`。
#[no_mangle]
pub unsafe extern "C" fn ys_pack_stream_chunk(
    index: u32,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let slot = pack_stream_slot();
        let s = slot.as_ref().ok_or(Error::BadArgument)?;
        let pt = as_slice(plaintext, plaintext_len)?;
        let need = 16 + pt.len() + 16;
        if out_cap < need {
            if out_len.is_null() {
                return Err(Error::BadArgument);
            }
            core::ptr::write(out_len, need);
            return Err(Error::BufferTooSmall);
        }
        let mut rec = Vec::new();
        s.chunk(index, pt, &mut rec)?;
        write_out(&rec, out, out_cap, out_len)
    })())
}

/// 第 `index` 块的明文长度（调用方据此切数据）。
#[no_mangle]
pub unsafe extern "C" fn ys_pack_stream_chunk_len(index: u32) -> i32 {
    let slot = pack_stream_slot();
    match slot.as_ref() {
        Some(s) if index < s.chunk_count() => s.chunk_len(index) as i32,
        _ => Error::BadArgument.code(),
    }
}

/// 结束（丢弃）打包会话。
#[no_mangle]
pub unsafe extern "C" fn ys_pack_stream_end() -> i32 {
    *pack_stream_slot() = None;
    0
}

/// 用 **prelude** 打开流式解包会话（要求 prelude 完整；元信息可用
/// `ys_unpack_meta_prelude` 取）。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_stream_begin(
    prelude: *const u8,
    prelude_len: usize,
    recipient_private: *const u8,
) -> i32 {
    rc((|| {
        let s = pack::open_stream(
            as_slice(prelude, prelude_len)?,
            &fixed::<32>(recipient_private)?,
        )?;
        *unpack_stream_slot() = Some(s);
        Ok(())
    })())
}

/// 喂一条块记录，解出该块明文（顺序必须严格递增）。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_stream_chunk(
    record: *const u8,
    record_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    rc((|| {
        let slot = unpack_stream_slot();
        let s = slot.as_mut().ok_or(Error::BadArgument)?;
        let record = as_slice(record, record_len)?;
        let need = s.peek_plain_len(record)?;
        if out_cap < need {
            if out_len.is_null() {
                return Err(Error::BadArgument);
            }
            core::ptr::write(out_len, need);
            return Err(Error::BufferTooSmall);
        }
        let mut pt = Vec::new();
        s.chunk(record, &mut pt)?;
        write_out(&pt, out, out_cap, out_len)
    })())
}

/// 结束解包会话：所有块都到齐返回 0，否则 `CRYPTO_CHUNK_MISSING`。
#[no_mangle]
pub unsafe extern "C" fn ys_unpack_stream_end() -> i32 {
    let slot = unpack_stream_slot();
    let done = match slot.as_ref() {
        Some(s) => s.done(),
        None => false,
    };
    *slot = None;
    if done {
        0
    } else {
        Error::ChunkMissing.code()
    }
}
