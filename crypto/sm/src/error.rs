//! 统一错误类型。
//!
//! 两套名字，一套数值：
//! * **数值（C ABI 契约）**：首版公布的错误码**一个都没有改**；新增语义用新槽位（-24 起），
//!   老调用方（Web 的 `ERROR_CODES` 表）不受影响。
//! * **`name()`**：契约 `docs/CRYPTO-PACK.md` §13 的端侧错误名（`CRYPTO_*`），
//!   给 Gate 的探针与日志用。
//! * **`legacy_name()`**：首版 ABI 的旧名（`BAD_MAGIC` 等），`ys_error_name` 返回它，
//!   保证已发布的 Web 绑定查表仍然命中。
//!
//! 新旧变体是**同一语义的粗细两档**：契约布局用细的（`ChunkAuthFailed`…），
//! rune-v1 兼容布局用旧的（`TagMismatch`…），数值互不冲突。

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    // ---- 首版 ABI 的变体（数值与名字都不动，rune-v1 布局继续用它们）
    BadArgument,
    BufferTooSmall,
    Rng,
    BadMagic,
    UnsupportedVersion,
    BadFlags,
    Truncated,
    BadKeyRecord,
    BadSignatureRecord,
    BadManifestRecord,
    BlockSequence,
    DuplicateBlock,
    MissingBlock,
    LastFlagMismatch,
    TagMismatch,
    ManifestMismatch,
    SignatureMismatch,
    TrailingBytes,
    BadPoint,
    BadKdf,
    BadCode,
    CodeExhausted,
    BadCiphertext,

    // ---- 契约 §13 需要的细粒度（新槽位，-24 起；老调用方只会看到"未知码"）
    HeaderInvalid,
    AlgUnsupported,
    Unsigned,
    LengthInconsistent,
    ChunkOrder,
    ChunkAuthFailed,
    ChunkMissing,
    ManifestAuthFailed,
    DigestMismatch,
    SenderMismatch,

    Internal,
}

impl Error {
    /// 数值错误码：**-4..-23 与首版完全一致**，新增从 -24 起。
    pub fn code(self) -> i32 {
        match self {
            Error::BadArgument => -1,
            Error::BufferTooSmall => -2,
            Error::Rng => -3,
            Error::BadMagic => -4,
            Error::UnsupportedVersion => -5,
            Error::BadFlags => -6,
            Error::Truncated => -7,
            Error::BadKeyRecord => -8,
            Error::BadSignatureRecord => -9,
            Error::BadManifestRecord => -10,
            Error::BlockSequence => -11,
            Error::DuplicateBlock => -12,
            Error::MissingBlock => -13,
            Error::LastFlagMismatch => -14,
            Error::TagMismatch => -15,
            Error::ManifestMismatch => -16,
            Error::SignatureMismatch => -17,
            Error::TrailingBytes => -18,
            Error::BadPoint => -19,
            Error::BadKdf => -20,
            Error::BadCode => -21,
            Error::CodeExhausted => -22,
            Error::BadCiphertext => -23,
            Error::HeaderInvalid => -24,
            Error::AlgUnsupported => -25,
            Error::Unsigned => -26,
            Error::LengthInconsistent => -27,
            Error::ChunkOrder => -28,
            Error::ChunkAuthFailed => -29,
            Error::ChunkMissing => -30,
            Error::ManifestAuthFailed => -31,
            Error::DigestMismatch => -32,
            Error::SenderMismatch => -33,
            Error::Internal => -99,
        }
    }

    /// 契约 §13 的端侧错误名（Gate 探针/日志用这套）。
    pub fn name(self) -> &'static str {
        match self {
            Error::BadArgument => "CRYPTO_BAD_ARGUMENT",
            Error::BufferTooSmall => "CRYPTO_BUFFER_TOO_SMALL",
            Error::Rng => "CRYPTO_RNG_FAILED",
            Error::BadMagic => "CRYPTO_MAGIC_MISMATCH",
            Error::UnsupportedVersion => "CRYPTO_VERSION_UNSUPPORTED",
            Error::BadFlags => "CRYPTO_FLAGS_UNKNOWN",
            Error::Truncated => "CRYPTO_LENGTH_INCONSISTENT",
            Error::BadKeyRecord => "CRYPTO_KEY_UNWRAP_FAILED",
            Error::BadSignatureRecord => "CRYPTO_SIGNATURE_INVALID",
            Error::BadManifestRecord => "CRYPTO_MANIFEST_INVALID",
            Error::BlockSequence => "CRYPTO_CHUNK_ORDER",
            Error::DuplicateBlock => "CRYPTO_CHUNK_ORDER",
            Error::MissingBlock => "CRYPTO_CHUNK_MISSING",
            Error::LastFlagMismatch => "CRYPTO_CHUNK_ORDER",
            Error::TagMismatch => "CRYPTO_CHUNK_AUTH_FAILED",
            Error::ManifestMismatch => "CRYPTO_MANIFEST_AUTH_FAILED",
            Error::SignatureMismatch => "CRYPTO_SIGNATURE_INVALID",
            Error::TrailingBytes => "CRYPTO_LENGTH_INCONSISTENT",
            Error::BadPoint => "CRYPTO_CURVE_INVALID",
            Error::BadKdf => "CRYPTO_CIPHERTEXT_INVALID",
            Error::BadCode => "CRYPTO_CODE_INVALID",
            Error::CodeExhausted => "CRYPTO_CODE_EXHAUSTED",
            Error::BadCiphertext => "CRYPTO_CIPHERTEXT_INVALID",
            Error::HeaderInvalid => "CRYPTO_HEADER_INVALID",
            Error::AlgUnsupported => "CRYPTO_ALG_UNSUPPORTED",
            Error::Unsigned => "CRYPTO_UNSIGNED",
            Error::LengthInconsistent => "CRYPTO_LENGTH_INCONSISTENT",
            Error::ChunkOrder => "CRYPTO_CHUNK_ORDER",
            Error::ChunkAuthFailed => "CRYPTO_CHUNK_AUTH_FAILED",
            Error::ChunkMissing => "CRYPTO_CHUNK_MISSING",
            Error::ManifestAuthFailed => "CRYPTO_MANIFEST_AUTH_FAILED",
            Error::DigestMismatch => "CRYPTO_DIGEST_MISMATCH",
            Error::SenderMismatch => "CRYPTO_SENDER_MISMATCH",
            Error::Internal => "CRYPTO_INTERNAL",
        }
    }

    /// 首版 ABI 的旧名（Web 已发布的映射表按这套查）。
    pub fn legacy_name(self) -> &'static str {
        match self {
            Error::BadArgument => "BAD_ARGUMENT",
            Error::BufferTooSmall => "BUFFER_TOO_SMALL",
            Error::Rng => "RNG",
            Error::BadMagic => "BAD_MAGIC",
            Error::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Error::BadFlags => "BAD_FLAGS",
            Error::Truncated => "TRUNCATED",
            Error::BadKeyRecord => "BAD_KEY_RECORD",
            Error::BadSignatureRecord => "BAD_SIGNATURE_RECORD",
            Error::BadManifestRecord => "BAD_MANIFEST_RECORD",
            Error::BlockSequence => "BLOCK_SEQUENCE",
            Error::DuplicateBlock => "DUPLICATE_BLOCK",
            Error::MissingBlock => "MISSING_BLOCK",
            Error::LastFlagMismatch => "LAST_FLAG_MISMATCH",
            Error::TagMismatch => "TAG_MISMATCH",
            Error::ManifestMismatch => "MANIFEST_MISMATCH",
            Error::SignatureMismatch => "SIGNATURE_MISMATCH",
            Error::TrailingBytes => "TRAILING_BYTES",
            Error::BadPoint => "BAD_POINT",
            Error::BadKdf => "BAD_KDF",
            Error::BadCode => "BAD_CODE",
            Error::CodeExhausted => "CODE_EXHAUSTED",
            Error::BadCiphertext => "BAD_CIPHERTEXT",
            // 新码 → 最接近的旧名，保证 Web 的旧映射表仍能落到有意义的 CRYPTO_*
            Error::HeaderInvalid => "BAD_FLAGS",
            Error::AlgUnsupported => "UNSUPPORTED_VERSION",
            Error::Unsigned => "BAD_SIGNATURE_RECORD",
            Error::LengthInconsistent => "TRUNCATED",
            Error::ChunkOrder => "BLOCK_SEQUENCE",
            Error::ChunkAuthFailed => "TAG_MISMATCH",
            Error::ChunkMissing => "MISSING_BLOCK",
            Error::ManifestAuthFailed => "MANIFEST_MISMATCH",
            Error::DigestMismatch => "MANIFEST_MISMATCH",
            Error::SenderMismatch => "SIGNATURE_MISMATCH",
            Error::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.code())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
